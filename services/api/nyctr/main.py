"""Nyctr API: observations and proposals; no infrastructure mutation endpoints."""

import asyncio
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.staticfiles import StaticFiles

from . import __version__
from .config import Settings
from .database import make_engine, migrate, session_factory
from .middleware import RequestBodyLimit
from .models import (
    AccessRequest,
    Audit,
    DeviceGrant,
    Finding,
    Integration,
    Observation,
    Relationship,
    Resource,
    User,
    utc,
    utcnow,
)
from .oidc import router as oidc_router
from .security import (
    COOKIE_NAME,
    audit,
    authenticate,
    check_login_attempt,
    issue_session,
    local_user,
    user_response,
    verify_password,
)
from .seed import bootstrap


def columns(instance, fields):
    return {key: utc(value) if isinstance(value := getattr(instance, key), datetime) else value
            for key in fields.split()}


def resource_json(row):
    return columns(row, "id name kind provider source_id site_id observed_at evidence_kind classification owner_id attributes")


def relationship_json(row):
    return columns(row, "id source target kind provider evidence_kind observed_at attributes")


def finding_json(row):
    return columns(row, "id title severity summary resource_ids relationship_ids evidence status")


def integration_json(row):
    return columns(row, "id provider name status last_sync last_error config secret_ref capabilities")


def observation_json(row):
    return columns(row, "id device_id device_name domain source reason observed_at expires_at evidence_kind attribution risk_score risk_explanation")


def request_json(row):
    return columns(row, "id block_id domain device_name requester_id reason duration_minutes status created_at review_note")


def get_db(request: Request):
    with request.app.state.session_factory() as db:
        yield db


def identity(request: Request, db: Session = Depends(get_db)):
    return authenticate(request, db)


def admin(auth=Depends(identity)):
    if auth[0].role != "admin":
        raise HTTPException(403, "Administrator access required")
    return auth[0]


def grant_at(db, device: str, user_id: str, when):
    return db.scalar(select(DeviceGrant.id).where(
        DeviceGrant.device_id == device, DeviceGrant.user_id == user_id,
        DeviceGrant.valid_from <= when,
        or_(DeviceGrant.valid_until.is_(None), DeviceGrant.valid_until > when)).limit(1)) is not None


def device_permitted(db, resource, user, when=None):
    return (resource is not None and resource.classification in {"personal", "shared"}
            and (resource.classification != "personal" or resource.owner_id == user.id)
            and grant_at(db, resource.id, user.id, when or utcnow()))


def observation_permitted(db, row, user):
    if user.role == "admin":
        return True
    resource = db.get(Resource, row.device_id) if row.device_id else None
    return (row.attribution == "assigned" and device_permitted(db, resource, user)
            and device_permitted(db, resource, user, utc(row.observed_at)))


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginInput(InputModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


class IntegrationInput(InputModel):
    provider: Literal["unifi_network", "nextdns"]
    name: str = Field(min_length=1, max_length=160)
    config: dict
    secret_ref: str = Field(pattern=r"^NYCTR_CONNECTOR_SECRET_[A-Z0-9_]{1,100}$")


class RequestInput(InputModel):
    block_id: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=5, max_length=2000)
    duration_minutes: int = Field(ge=15, le=240)


class ReviewInput(InputModel):
    decision: Literal["reviewed", "denied"]
    note: str = Field(min_length=3, max_length=2000)


class AssignmentInput(InputModel):
    classification: Literal["personal", "shared", "infrastructure", "unassigned"]
    user_ids: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("user_ids")
    @classmethod
    def unique_ids(cls, value):
        if len(value) != len(set(value)) or any(len(x) > 128 for x in value):
            raise ValueError("Provide unique user identifiers")
        return value


def parsed_date(value):
    if isinstance(value, datetime):
        return utc(value)
    return utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def apply_snapshot(db, integration, snapshot, settings):
    now = utcnow()
    seen = set()
    for data in snapshot.resources:
        row = db.get(Resource, data["id"])
        if row and row.integration_id != integration.id:
            raise ValueError("Resource identity crosses integration boundary")
        values = {key: data.get(key) for key in ["name", "kind", "provider", "source_id", "site_id", "evidence_kind"]}
        values.update(observed_at=parsed_date(data.get("observed_at", now)), attributes=data.get("attributes", {}))
        if row:
            for key, value in values.items():
                setattr(row, key, value)
        else:
            # Importing an endpoint never assigns it to a person.
            row = Resource(id=data["id"], integration_id=integration.id, classification="unassigned",
                           owner_id=None, **values)
            db.add(row)
        seen.add(data["id"])
    db.flush()
    # Keep previously seen inventory and ownership but explicitly flag missing sources.
    for row in db.scalars(select(Resource).where(Resource.integration_id == integration.id)):
        if row.id not in seen:
            row.attributes = {**row.attributes, "missing_from_latest_snapshot": True}
    db.execute(delete(Relationship).where(Relationship.integration_id == integration.id))
    for data in snapshot.relationships:
        if data["source"] not in seen or data["target"] not in seen:
            raise ValueError("Relationship endpoints are outside this snapshot")
        values = {key: data[key] for key in ["id", "source", "target", "kind", "provider", "evidence_kind"]}
        db.add(Relationship(integration_id=integration.id, observed_at=parsed_date(data.get("observed_at", now)),
                            attributes=data.get("attributes", {}), **values))
    for data in snapshot.blocks:
        when = parsed_date(data["observed_at"])
        expires = min(parsed_date(data.get("expires_at", when + timedelta(hours=settings.block_retention_hours))),
                      when + timedelta(hours=settings.block_retention_hours))
        if expires <= now or when > now + timedelta(minutes=5):
            continue
        previous = db.get(Observation, data["id"])
        if previous:
            if previous.integration_id != integration.id:
                raise ValueError("Observation identity crosses integration boundary")
            continue  # Do not extend the lifetime of a replayed event.
        values = {key: data.get(key) for key in ["id", "device_id", "device_name", "domain", "source", "reason",
                                                "evidence_kind", "attribution", "risk_score", "risk_explanation"]}
        db.add(Observation(integration_id=integration.id, observed_at=when, expires_at=expires, **values))
    integration.status = "connected"
    integration.last_sync = now
    integration.last_error = None
    integration.sync_started_at = None
    integration.capabilities = snapshot.capabilities


def create_app(settings: Settings | None = None):
    settings = settings or Settings()
    engine = make_engine(settings.database_url)
    factory = session_factory(engine)

    @asynccontextmanager
    async def lifespan(app):
        migrate(engine)
        with factory() as db:
            bootstrap(db, settings)
        yield
        engine.dispose()

    app = FastAPI(title="Nyctr API", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = factory
    app.add_middleware(RequestBodyLimit, max_body_size=32768)

    @app.middleware("http")
    async def security_headers(request, call_next):
        if request.url.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            if origin and origin.rstrip("/") != settings.public_url:
                return JSONResponse({"detail": "Request origin is not permitted"}, status_code=403)
            length = request.headers.get("content-length", "0")
            if not length.isdigit() or int(length) > 32768:
                return JSONResponse({"detail": "Request body is too large"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def health(db: Session = Depends(get_db)):
        db.execute(select(1))
        return {"status": "ok", "version": __version__}

    @app.get("/api/auth/config")
    def auth_config():
        return {"mode": settings.mode, "local_enabled": settings.local_login_enabled or settings.mode == "demo",
                "oidc_enabled": settings.oidc_enabled}

    @app.post("/api/auth/login")
    def login(body: LoginInput, request: Request, response: Response, db: Session = Depends(get_db)):
        if not settings.local_login_enabled and settings.mode != "demo":
            raise HTTPException(403, "Local sign-in is disabled")
        if request.headers.get("content-type", "").split(";")[0].strip() != "application/json":
            raise HTTPException(415, "Use application/json")
        email = body.email.strip().casefold()
        check_login_attempt(db, request, email)
        user = local_user(db, email)
        valid = verify_password(body.password, user.password_hash if user else None)
        if not user or not valid or not user.active:
            audit(db, None, "auth.login_failed")
            db.commit()
            raise HTTPException(401, "Invalid email or password")
        session = issue_session(db, user, response, settings, request.cookies.get(COOKIE_NAME, ""))
        return user_response(user, session, settings)

    @app.get("/api/auth/me")
    def me(auth=Depends(identity)):
        return user_response(*auth, settings)

    @app.post("/api/auth/logout")
    def logout(response: Response, auth=Depends(identity), db: Session = Depends(get_db)):
        db.delete(auth[1])
        audit(db, auth[0].id, "auth.logout", auth[0].id)
        db.commit()
        response.delete_cookie(COOKIE_NAME, path="/")
        return {"ok": True}

    app.include_router(oidc_router)

    @app.get("/api/overview")
    def overview(_user=Depends(admin), db: Session = Depends(get_db)):
        def count(model):
            return db.scalar(select(func.count()).select_from(model))
        return {"resource_count": count(Resource), "relationship_count": count(Relationship),
                "finding_count": count(Finding), "recent_block_count": db.scalar(
                    select(func.count()).select_from(Observation).where(Observation.expires_at > utcnow())),
                "integration_count": count(Integration), "mode": settings.mode}

    @app.get("/api/resources")
    def resources(_user=Depends(admin), db: Session = Depends(get_db)):
        return [resource_json(x) for x in db.scalars(select(Resource).order_by(Resource.name))]

    @app.get("/api/graph")
    def graph(focus: str | None = Query(None, max_length=255), depth: int = Query(1, ge=1, le=3),
              _user=Depends(admin), db: Session = Depends(get_db)):
        nodes = list(db.scalars(select(Resource)))
        edges = list(db.scalars(select(Relationship)))
        if focus:
            if not any(n.id == focus for n in nodes):
                raise HTTPException(404, "Resource not found")
            included = {focus}
            for _ in range(depth):
                included |= {v for e in edges if e.source in included or e.target in included for v in [e.source, e.target]}
            nodes = [n for n in nodes if n.id in included]
            edges = [e for e in edges if e.source in included and e.target in included]
        return {"nodes": [resource_json(n) for n in nodes], "edges": [relationship_json(e) for e in edges]}

    @app.get("/api/findings")
    def findings(_user=Depends(admin), db: Session = Depends(get_db)):
        return [finding_json(f) for f in db.scalars(select(Finding).order_by(Finding.title))]

    @app.get("/api/integrations")
    def integrations(_user=Depends(admin), db: Session = Depends(get_db)):
        return [integration_json(i) for i in db.scalars(select(Integration).order_by(Integration.name))]

    @app.post("/api/integrations", status_code=201)
    def add_integration(body: IntegrationInput, user=Depends(admin), db: Session = Depends(get_db)):
        if settings.mode == "demo":
            raise HTTPException(409, "Live integration setup is disabled in demo mode")
        from .integrations import IntegrationError, capabilities_for, validate_config
        try:
            config = validate_config(body.provider, body.config)
        except (IntegrationError, ValueError):
            raise HTTPException(422, "Invalid integration configuration; check the server allowlist and provider settings") from None
        row = Integration(provider=body.provider, name=body.name, config=config,
                          secret_ref=body.secret_ref, capabilities=capabilities_for(body.provider))
        db.add(row)
        db.flush()
        audit(db, user.id, "integration.created", row.id, provider=row.provider)
        db.commit()
        return integration_json(row)

    @app.post("/api/integrations/{integration_id}/sync")
    async def sync_integration(integration_id: str, user=Depends(admin), db: Session = Depends(get_db)):
        if settings.mode == "demo":
            raise HTTPException(409, "Live collection is disabled in demo mode")
        integration = db.get(Integration, integration_id)
        if not integration:
            raise HTTPException(404, "Integration not found")
        if not re.fullmatch(r"NYCTR_CONNECTOR_SECRET_[A-Z0-9_]{1,100}", integration.secret_ref):
            raise HTTPException(409, "Integration secret reference is invalid")
        api_key = os.environ.get(integration.secret_ref)
        if not api_key:
            raise HTTPException(409, "The integration secret is not configured on the server")
        locked = db.execute(update(Integration).where(
            Integration.id == integration.id,
            or_(Integration.status != "syncing", Integration.sync_started_at < utcnow() - timedelta(minutes=5))
        ).values(status="syncing", sync_started_at=utcnow()))
        if locked.rowcount != 1:
            db.rollback()
            raise HTTPException(409, "A collection is already running")
        db.commit()
        from .integrations import IntegrationError, collect
        try:
            snapshot = await asyncio.wait_for(collect(integration.provider, integration.id, integration.config, api_key), timeout=90)
            apply_snapshot(db, integration, snapshot, settings)
            audit(db, user.id, "integration.collected", integration.id,
                  resources=len(snapshot.resources), observations=len(snapshot.blocks))
            db.commit()
        except Exception as exc:
            db.rollback()
            integration = db.get(Integration, integration_id)
            integration.status = "error"
            integration.last_error = str(exc) if isinstance(exc, IntegrationError) else "Collection failed. Check provider reachability and configuration."
            integration.sync_started_at = None
            audit(db, user.id, "integration.collection_failed", integration.id)
            db.commit()
            raise HTTPException(502, integration.last_error) from None
        return {"ok": True, "resource_count": len(snapshot.resources), "observation_count": len(snapshot.blocks)}

    @app.get("/api/devices")
    def devices(auth=Depends(identity), db: Session = Depends(get_db)):
        user = auth[0]
        rows = db.scalars(select(Resource).where(Resource.kind == "client").order_by(Resource.name))
        return [resource_json(r) for r in rows if user.role == "admin" or device_permitted(db, r, user)]

    @app.put("/api/devices/{device_id}/assignment")
    def assign(device_id: str, body: AssignmentInput, user=Depends(admin), db: Session = Depends(get_db)):
        # One transaction owns the assignment transition. Postgres row locking
        # prevents concurrent administrators creating overlapping current grants.
        row = db.scalar(select(Resource).where(Resource.id == device_id).with_for_update())
        if not row or row.kind != "client":
            raise HTTPException(404, "Device not found")
        if (body.classification == "personal" and len(body.user_ids) != 1
                or body.classification == "shared" and not body.user_ids
                or body.classification in {"infrastructure", "unassigned"} and body.user_ids):
            raise HTTPException(422, "Classification and user assignment do not match")
        for id_ in body.user_ids:
            owner = db.get(User, id_)
            if not owner or not owner.active:
                raise HTTPException(422, "Assigned user does not exist or is disabled")
        now = utcnow()
        db.execute(update(DeviceGrant).where(DeviceGrant.device_id == device_id,
                                              DeviceGrant.valid_until.is_(None)).values(valid_until=now))
        for id_ in body.user_ids:
            db.add(DeviceGrant(device_id=device_id, user_id=id_, valid_from=now))
        row.classification = body.classification
        row.owner_id = body.user_ids[0] if body.classification == "personal" else None
        audit(db, user.id, "device.assignment_changed", device_id, classification=body.classification,
              user_ids=body.user_ids)
        db.commit()
        return resource_json(row)

    @app.get("/api/blocks")
    def blocks(auth=Depends(identity), db: Session = Depends(get_db)):
        # Requests retain their own domain/device snapshot after inbox observations expire.
        db.execute(delete(Observation).where(Observation.expires_at <= utcnow()))
        db.commit()
        rows = db.scalars(select(Observation).where(Observation.expires_at > utcnow()).order_by(Observation.observed_at.desc()))
        return [observation_json(r) for r in rows if observation_permitted(db, r, auth[0])]

    @app.get("/api/requests")
    def requests(auth=Depends(identity), db: Session = Depends(get_db)):
        query = select(AccessRequest).order_by(AccessRequest.created_at.desc())
        if auth[0].role != "admin":
            query = query.where(AccessRequest.requester_id == auth[0].id)
        return [request_json(r) for r in db.scalars(query)]

    @app.post("/api/requests", status_code=201)
    def create_request(body: RequestInput, auth=Depends(identity), db: Session = Depends(get_db)):
        user = auth[0]
        observation = db.get(Observation, body.block_id)
        if not observation or not observation_permitted(db, observation, user):
            raise HTTPException(404, "Block event not found")
        if utc(observation.expires_at) <= utcnow():
            raise HTTPException(409, "This block event has expired. Try accessing the site again.")
        existing = db.scalar(select(AccessRequest).where(AccessRequest.requester_id == user.id,
                                                        AccessRequest.block_id == observation.id))
        if existing:
            return request_json(existing)
        row = AccessRequest(block_id=observation.id, domain=observation.domain, device_name=observation.device_name,
                            requester_id=user.id, reason=body.reason, duration_minutes=body.duration_minutes)
        db.add(row)
        try:
            db.flush()
            audit(db, user.id, "access.requested", row.id, block_id=observation.id,
                  duration_minutes=body.duration_minutes)
            db.commit()
        except IntegrityError:
            db.rollback()
            existing = db.scalar(select(AccessRequest).where(AccessRequest.requester_id == user.id,
                                                            AccessRequest.block_id == observation.id))
            if not existing:
                raise
            return request_json(existing)
        return request_json(row)

    @app.post("/api/requests/{request_id}/review")
    def review(request_id: str, body: ReviewInput, user=Depends(admin), db: Session = Depends(get_db)):
        row = db.get(AccessRequest, request_id)
        if not row:
            raise HTTPException(404, "Request not found")
        if row.status != "pending":
            raise HTTPException(409, "This request has already been reviewed")
        # Compare and swap prevents simultaneous administrators overwriting each other.
        result = db.execute(update(AccessRequest).where(AccessRequest.id == request_id,
                                                       AccessRequest.status == "pending").values(
            status=body.decision, review_note=body.note))
        if result.rowcount != 1:
            db.rollback()
            raise HTTPException(409, "This request has already been reviewed")
        audit(db, user.id, "access." + body.decision, row.id, execution="not_performed")
        db.commit()
        db.refresh(row)
        return request_json(row)

    @app.get("/api/audit")
    def audit_events(_user=Depends(admin), db: Session = Depends(get_db)):
        return [columns(r, "id created_at actor_id action target_id details")
                for r in db.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(500))]

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    def missing_api(path: str):
        raise HTTPException(404, "API endpoint not found")

    if settings.static_dir:
        if not Path(settings.static_dir, "index.html").is_file():
            raise RuntimeError("NYCTR_STATIC_DIR must contain the built web application's index.html")
        app.mount("/", StaticFiles(directory=settings.static_dir, html=True), name="web")
    return app


app = create_app()
