"""Nyctr API. Collection is read-only; provider changes exist only in the gated access and guest modules."""

import asyncio
import contextlib
import hmac
import time
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.staticfiles import StaticFiles

from . import __version__, access, assistant, guests, query, removal, worker
from . import blocks as block_list
from .collection import after_collection, apply_snapshot, collect_integration, last_gaps, parsed_date  # noqa: F401
from .config import Settings
from .database import make_engine, migrate, session_factory
from .deps import (  # noqa: F401  (re-exported for callers that import them from here)
    admin,
    columns,
    device_permitted,
    finding_json,
    get_db,
    grant_at,
    identity,
    integration_json,
    observation_json,
    observation_permitted,
    relationship_json,
    request_json,
    resource_json,
)
from .diagnostics import DiagnosticReport, diagnose_integration
from .links import derived_links
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
    check_login_attempt,
    issue_session,
    local_user,
    user_response,
    verify_password,
)
from .seed import bootstrap
from .sites import members_use_portal, origin_of, seen_as, site_of


class InputModel(BaseModel):
    """Reject unexpected input fields and trim ordinary user-supplied text."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LoginInput(InputModel):
    """Validate bounded login fields while preserving significant password whitespace."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


def _settled_status(db: Session, integration: Integration) -> str:
    """Work out the status a source had before an abandoned lease replaced it with "syncing".

    The lease overwrites the stored status, so it is rebuilt from what the last
    finished collection left behind: its error, else the audit record of the
    last stored collection, which says whether that read was partial. A partial
    source therefore stays partial until its next collection.
    """
    if integration.last_error:
        return "error"
    if not integration.last_sync:
        return "configured"
    last = db.scalar(select(Audit).where(Audit.action == "integration.collected", Audit.target_id == integration.id)
                     .order_by(Audit.created_at.desc()).limit(1))
    return "partial" if last is not None and last.details.get("partial") is True else "connected"


# The edit form shows the same sentence (FIXED_SOURCE in the web app's Integrations page).
MOVED_SOURCE = ("This source has already collected, so where it reads can no longer change. "
                "To read from somewhere else, add a new source. Its name and numeric settings can still change.")


class IntegrationEdit(InputModel):
    """Accept what may change on a saved source. The kind of source is not among it."""
    name: str = Field(min_length=1, max_length=160)
    config: dict
    secret_ref: str = Field(pattern=r"^NYCTR_CONNECTOR_SECRET_[A-Z0-9_]{1,100}$")


class RemovalInput(InputModel):
    """The source's name, typed by the administrator to confirm its removal."""
    name: str = Field(min_length=1, max_length=160)


class IntegrationInput(IntegrationEdit):
    """Accept any registered integration and a constrained server-side secret reference."""
    provider: str = Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_]+$")


class RequestInput(InputModel):
    """Validate an event-backed access reason and requested duration of 15 to 240 minutes."""
    block_id: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=5, max_length=2000)
    duration_minutes: int = Field(ge=15, le=240)


class ReviewInput(InputModel):
    """Limit administrative review to reviewed or denied states with an explanatory note."""
    decision: Literal["reviewed", "denied", "approved"]
    note: str = Field(min_length=3, max_length=2000)
    minutes: int | None = Field(default=None, ge=15, le=240)


class AssignmentInput(InputModel):
    """Describe a device classification and bounded explicit set of member identities."""
    classification: Literal["personal", "shared", "infrastructure", "unassigned"]
    user_ids: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("user_ids")
    @classmethod
    def unique_ids(cls, value):
        """Reject duplicate or oversized user identifiers before changing device grants."""
        if len(value) != len(set(value)) or any(len(x) > 128 for x in value):
            raise ValueError("Provide unique user identifiers")
        return value


def create_app(settings: Settings | None = None):
    """Build the configured API, authorization dependencies, database lifecycle, and optional static host.

    Database migration and bootstrap occur at lifespan startup. API routes take
    precedence over static files, and missing API paths remain JSON errors.
    """
    settings = settings or Settings()
    engine = make_engine(settings.database_url)
    factory = session_factory(engine)

    @asynccontextmanager
    async def lifespan(app):
        """Migrate and bootstrap before serving, then release the engine when the app stops."""
        migrate(engine)
        with factory() as db:
            bootstrap(db, settings)
        upkeep = asyncio.create_task(worker.run(app)) if settings.worker_enabled else None
        yield
        if upkeep:
            upkeep.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await upkeep
        engine.dispose()

    app = FastAPI(title="Nyctr API", version=__version__, lifespan=lifespan,
                  docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = factory
    app.add_middleware(RequestBodyLimit, max_body_size=32768)

    @app.middleware("http")
    async def security_headers(request, call_next):
        """Reject disallowed mutation origins and obvious oversized bodies, then add response protections.

        API responses are not cached. The ASGI body-limit middleware separately
        enforces the actual streamed byte count when Content-Length is absent.
        """
        if request.url.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            # The origin must be the address the request arrived on: the portal's
            # pages cannot change anything through the console address, or the reverse.
            origin = request.headers.get("origin")
            if origin and origin.rstrip("/") != origin_of(settings, site_of(request)):
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
        """Check database connectivity and return the public service status and API version."""
        db.execute(select(1))
        return {"status": "ok", "version": __version__}

    @app.get("/api/auth/config")
    def auth_config(request: Request):
        """Return public sign-in capabilities, mode and which address this is, without provider credentials."""
        return {"mode": settings.mode, "local_enabled": settings.local_login_enabled or settings.mode == "demo",
                "oidc_enabled": settings.oidc_enabled, "site": site_of(request),
                "portal_url": settings.portal_url or None}

    @app.post("/api/auth/login")
    def login(body: LoginInput, request: Request, response: Response, db: Session = Depends(get_db)):
        """Authenticate a JSON local-login request under the account and peer attempt quotas.

        Failed credentials produce a generic 401 and audit event. Success rotates
        the HTTP-only session cookie and returns the current user and CSRF token.
        """
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
        if members_use_portal(request, user):
            # Decided only after the password was checked, so it says nothing to a stranger.
            raise HTTPException(403, f"This address is for administrators. Sign in at {settings.portal_url}")
        session = issue_session(db, user, response, settings, request.cookies.get(COOKIE_NAME, ""))
        return user_response(seen_as(request, user), session, settings)

    @app.get("/api/auth/me")
    def me(auth=Depends(identity)):
        """Return the authenticated identity and its session-bound CSRF token."""
        return user_response(*auth, settings)

    @app.post("/api/auth/logout")
    def logout(response: Response, auth=Depends(identity), db: Session = Depends(get_db)):
        """Revoke the authenticated session, commit its audit event, and remove the cookie."""
        db.delete(auth[1])
        audit(db, auth[0].id, "auth.logout", auth[0].id)
        db.commit()
        response.delete_cookie(COOKIE_NAME, path="/")
        return {"ok": True}

    app.include_router(oidc_router)
    for feature in (access, guests, query, assistant):
        app.include_router(feature.router)

    @app.get("/api/overview")
    def overview(_user=Depends(admin), db: Session = Depends(get_db)):
        """Return administrator workspace counts, excluding expired blocks from the recent total.

        Inventory is counted per kind so the console can name what it counts, and
        the stored blocked lookups carry the span they cover: the oldest and newest
        lookup kept, not a fixed window.
        """
        def count(model):
            """Count all persisted rows of one overview model within the current session."""
            return db.scalar(select(func.count()).select_from(model))
        live = Observation.expires_at > utcnow()
        blocks, oldest, newest = db.execute(select(func.count(), func.min(Observation.observed_at),
                                                   func.max(Observation.observed_at)).where(live)).one()
        kinds = dict(db.execute(select(Resource.kind, func.count()).group_by(Resource.kind)).all())
        return {"resource_count": count(Resource), "kind_counts": kinds,
                "relationship_count": count(Relationship), "finding_count": count(Finding),
                "recent_block_count": blocks, "oldest_block_at": oldest and utc(oldest),
                "newest_block_at": newest and utc(newest),
                "integration_count": count(Integration), "mode": settings.mode}

    @app.get("/api/resources")
    def resources(_user=Depends(admin), db: Session = Depends(get_db)):
        """List administrator-visible inventory ordered by display name."""
        return [resource_json(x) for x in db.scalars(select(Resource).order_by(Resource.name))]

    @app.get("/api/graph")
    def graph(focus: str | None = Query(None, max_length=255), depth: int = Query(1, ge=1, le=3),
              _user=Depends(admin), db: Session = Depends(get_db)):
        """Return administrator graph evidence, optionally bounded to one through three neighbor hops.

        An unknown focus returns 404. Expansion follows relationships in either
        direction and does not treat them as proof of successful network access.
        """
        nodes = list(db.scalars(select(Resource)))
        edges = [relationship_json(e) for e in db.scalars(select(Relationship))]
        # Cross-source links are worked out at read time and always labelled inferred.
        edges += derived_links(nodes)
        if focus:
            if not any(n.id == focus for n in nodes):
                raise HTTPException(404, "Resource not found")
            included = {focus}
            for _ in range(depth):
                included |= {v for e in edges if e["source"] in included or e["target"] in included
                             for v in [e["source"], e["target"]]}
            nodes = [n for n in nodes if n.id in included]
            edges = [e for e in edges if e["source"] in included and e["target"] in included]
        # Which source each item came from, so two with one name can be told apart on the Map.
        return {"nodes": [{**resource_json(n), "integration_id": n.integration_id} for n in nodes], "edges": edges}

    @app.get("/api/findings")
    def findings(_user=Depends(admin), db: Session = Depends(get_db)):
        """List evidence-backed findings for an administrator without running new analysis."""
        return [finding_json(f) for f in db.scalars(select(Finding).order_by(Finding.title))]

    @app.get("/api/findings/checks")
    def finding_checks(_user=Depends(admin), db: Session = Depends(get_db)):
        """Say what the finding rules check with the sources connected and what they never look at."""
        from .analysis import coverage
        return coverage(db)

    @app.get("/api/integrations")
    def integrations(_user=Depends(admin), db: Session = Depends(get_db)):
        """List administrator connector metadata while excluding resolved secrets.

        `gaps` is what each source's last stored collection could not read, as
        (id, title, summary) in its integration's words; empty when it read everything.
        """
        return [{**integration_json(i), "gaps": last_gaps(db, i)}
                for i in db.scalars(select(Integration).order_by(Integration.name))]

    @app.get("/api/integrations/catalog")
    def integration_catalog(_user=Depends(admin)):
        """List every integration this release ships, with what each adds to Nyctr.

        The console builds its source list, connection form and capability table
        from this, so adding an integration needs no change to the web app.
        """
        from .integrations import registry
        return {"capabilities": [{"id": key, "name": name, "changes_provider": key in registry.WRITES}
                                 for key, name in registry.CAPABILITIES.items()],
                "providers": [provider.describe(settings.write_mode(provider.id))
                              for provider in registry.providers().values()]}

    @app.post("/api/integrations", status_code=201)
    def add_integration(body: IntegrationInput, user=Depends(admin), db: Session = Depends(get_db)):
        """Persist a validated read-only connector and audit its creation for a live administrator.

        Demo mode returns 409. Invalid provider configuration returns a sanitized
        422 response; the secret stays in the server environment and is not copied.
        """
        if settings.mode == "demo":
            raise HTTPException(409, "Live integration setup is disabled in demo mode")
        from .integrations import IntegrationError, capabilities_for, registry, validate_config
        if registry.find(body.provider) is None:
            raise HTTPException(422, "This release has no integration with that name")
        try:
            config = validate_config(body.provider, body.config)
        except IntegrationError as error:
            # The integration's own wording, as an edit answers: the rule that failed, never a value.
            raise HTTPException(422, f"Not saved. {error}") from None
        except ValueError:
            raise HTTPException(422, "Not saved. Check the settings and try again.") from None
        row = Integration(provider=body.provider, name=body.name, config=config,
                          secret_ref=body.secret_ref, capabilities=capabilities_for(body.provider))
        db.add(row)
        db.flush()
        audit(db, user.id, "integration.created", row.id, provider=row.provider, name=row.name)
        db.commit()
        return integration_json(row)

    @app.put("/api/integrations/{integration_id}")
    def edit_integration(integration_id: str, body: IntegrationEdit, user=Depends(admin),
                         db: Session = Depends(get_db)):
        """Change a saved source, validated as a new one is; a refused change leaves the row untouched.

        Name and numeric settings change at any time and keep the status. Where it reads (other
        settings, secret name) changes only until it first stores a collection (`last_sync` set,
        partial included) and sends it back to "configured"; after that, add a new source. The
        audit record names changed fields, never values. No credential is read here.
        """
        if settings.mode == "demo":
            raise HTTPException(409, "Sources cannot be changed in the demo workspace")
        from .integrations import IntegrationError, registry, validate_config
        row = db.get(Integration, integration_id)
        if not row:
            raise HTTPException(404, "Integration not found")
        provider = registry.find(row.provider)
        if provider is None:
            raise HTTPException(422, "This release has no integration for this source, so it cannot be changed")
        try:
            config = validate_config(row.provider, body.config)
        except IntegrationError as error:
            # The integration's own wording: it states the rule that failed and repeats no value.
            raise HTTPException(422, f"Not saved. {error}") from None
        except ValueError:
            raise HTTPException(422, "Not saved. Check the settings and try again.") from None
        # Take the row's write lock first, with the collection lease's guard, then read it again:
        # nothing can change it until this request commits, and no running read is changed under.
        locked = db.execute(update(Integration).where(
            Integration.id == integration_id,
            or_(Integration.status != "syncing", Integration.sync_started_at < utcnow() - timedelta(minutes=5))
        ).values(name=Integration.name).execution_options(synchronize_session=False))
        if locked.rowcount != 1:
            db.rollback()
            raise HTTPException(409, "This source is being collected or tested right now. "
                                     "Try again when that has finished.")
        db.refresh(row)
        try:
            before = validate_config(row.provider, row.config)
        except (IntegrationError, ValueError):
            before = row.config
        settings_changed = sorted(key for key in set(before) | set(config) if before.get(key) != config.get(key))
        fields = ((["name"] if body.name != row.name else []) + [f"config.{key}" for key in settings_changed]
                  + (["secret_ref"] if body.secret_ref != row.secret_ref else []))
        kinds = {field.key: field.kind for field in provider.fields}
        moves = "secret_ref" in fields or any(kinds.get(key) != "number" for key in settings_changed)
        if not fields or (moves and row.last_sync is not None):
            db.rollback()
            if not fields:
                return integration_json(row)
            raise HTTPException(409, MOVED_SOURCE)
        row.name, row.config, row.secret_ref = body.name, config, body.secret_ref
        if moves:
            row.status, row.last_error, row.sync_started_at = "configured", None, None
        audit(db, user.id, "integration.updated", integration_id, provider=row.provider, fields=fields, retest=moves)
        db.commit()
        return integration_json(row)

    @app.get("/api/integrations/{integration_id}/removal")
    def removal_preview(integration_id: str, _user=Depends(admin), db: Session = Depends(get_db)):
        """Count what removing this source would delete and keep, and what of Nyctr's own holds it back."""
        row = db.get(Integration, integration_id)
        if not row:
            raise HTTPException(404, "Integration not found")
        resources = list(db.scalars(select(Resource).where(Resource.integration_id == integration_id)))
        counts = removal.plan(db, row, resources)
        return {**counts, "refusal": removal.held_message(counts["held"]),
                "notice": removal.let_on_message(counts["let_on"])}

    @app.delete("/api/integrations/{integration_id}")
    def remove_integration(integration_id: str, body: RemovalInput, user=Depends(admin),
                           db: Session = Depends(get_db)):
        """Remove a source and everything collected from it in one transaction, sending nothing to the source.

        Locks: the source row first (refused while a collection or test holds its lease), then the
        source's items in id order, then the rows that refer to them. Collection takes the source row
        before its items too, and an assignment takes only its device, so no two paths wait on each
        other in opposite order. Refused while Nyctr still has something of its own at the source.
        """
        if settings.mode == "demo":
            raise HTTPException(409, "Sources cannot be removed in the demo workspace")
        row = db.get(Integration, integration_id)
        if not row:
            raise HTTPException(404, "Integration not found")
        locked = db.execute(update(Integration).where(
            Integration.id == integration_id,
            or_(Integration.status != "syncing", Integration.sync_started_at < utcnow() - timedelta(minutes=5))
        ).values(name=Integration.name).execution_options(synchronize_session=False))
        if locked.rowcount != 1:
            db.rollback()
            if db.get(Integration, integration_id) is None:
                raise HTTPException(404, "Integration not found")
            raise HTTPException(409, "This source is being collected or tested right now. "
                                     "Try again when that has finished.")
        db.refresh(row)
        if body.name.strip() != row.name:
            db.rollback()
            raise HTTPException(422, "Not removed. Type the source's name exactly as it is shown to remove it.")
        resources = list(db.scalars(select(Resource).where(Resource.integration_id == integration_id)
                                    .order_by(Resource.id).with_for_update()))
        counts = removal.plan(db, row, resources)
        refusal = removal.held_message(counts["held"])
        if refusal:
            db.rollback()
            raise HTTPException(409, refusal)
        removal.remove(db, row)
        audit(db, user.id, "integration.removed", integration_id, name=counts["name"], provider=counts["provider"],
              removed=counts["remove"])
        db.commit()
        return counts

    @app.post("/api/integrations/{integration_id}/diagnostics", response_model=DiagnosticReport)
    async def integration_diagnostics(integration_id: str, user=Depends(admin), db: Session = Depends(get_db)):
        """Inspect a saved live integration under the same lease as collection, without importing evidence.

        Require administrator CSRF authorization. Return categorized diagnostic
        results even when a provider check fails, and audit only sanitized result
        metadata. Restore prior integration health after completion or cancellation;
        a timestamp guard prevents releasing a newer operation's lease.
        """
        if settings.mode == "demo":
            raise HTTPException(409, "Live diagnostics are disabled in demo mode")
        integration = db.get(Integration, integration_id)
        if not integration:
            raise HTTPException(404, "Integration not found")
        previous_status = integration.status
        previous_started_at = integration.sync_started_at
        if previous_status == "syncing":
            # A claim can replace only an expired syncing lease. Restoring that
            # abandoned lease would leave a finished probe displayed as running.
            previous_status = _settled_status(db, integration)
            previous_started_at = None
        claimed_at = utcnow()
        locked = db.execute(update(Integration).where(
            Integration.id == integration_id,
            or_(Integration.status != "syncing", Integration.sync_started_at < claimed_at - timedelta(minutes=5))
        ).values(status="syncing", sync_started_at=claimed_at).execution_options(synchronize_session="fetch"))
        if locked.rowcount != 1:
            db.rollback()
            raise HTTPException(409, "A collection or diagnostic is already running")
        db.commit()
        read = (integration.config, integration.secret_ref)
        db.refresh(integration)
        if (integration.config, integration.secret_ref) != read:
            # An edit was saved just before the lease: probe what is saved now, and afterwards
            # hand back the status that edit left, not the one read before it.
            previous_status, previous_started_at = _settled_status(db, integration), None
        try:
            report = await diagnose_integration(integration.provider, integration_id,
                                                integration.config, integration.secret_ref)
            audit(db, user.id, "integration.diagnosed", integration_id, name=integration.name, outcome=report.outcome,
                  failures=[check.category for check in report.checks if check.status == "failed"],
                  snapshot_counts=report.snapshot_counts.model_dump() if report.snapshot_counts else None,
                  imported=False)
            db.commit()
            return report
        finally:
            # Use a fresh session so a failed or cancelled request cannot prevent
            # best-effort release, and never overwrite another operation's lease.
            db.rollback()
            with factory() as release_db:
                release_db.execute(update(Integration).where(
                    Integration.id == integration_id, Integration.status == "syncing",
                    Integration.sync_started_at == claimed_at,
                ).values(status=previous_status, sync_started_at=previous_started_at))
                release_db.commit()

    @app.post("/api/integrations/{integration_id}/sync")
    async def sync_integration(integration_id: str, user=Depends(admin), db: Session = Depends(get_db)):
        """Collect a live connector under a database lease and a 210-second backstop.

        Requires administrator CSRF authorization and a configured server secret.
        Success atomically stores the snapshot and audit event. Failure rolls back
        snapshot changes, records a sanitized error, and releases the collection lease.
        """
        if settings.mode == "demo":
            raise HTTPException(409, "Live collection is disabled in demo mode")
        snapshot, error = await collect_integration(factory, settings, integration_id, user.id)
        if error == "missing":
            raise HTTPException(404, "Integration not found")
        if error == "secret_ref":
            raise HTTPException(409, "Integration secret reference is invalid")
        if error == "secret":
            raise HTTPException(409, "The integration secret is not configured on the server")
        if error == "busy":
            raise HTTPException(409, "A collection is already running")
        if error == "replaced":
            raise HTTPException(409, "The source was changed while it was being read, so nothing was stored")
        if error:
            raise HTTPException(502, error)
        # Deterministic analysis and the written guest rule run on the stored evidence.
        due = after_collection(db, settings)
        db.commit()
        await guests.enforce(db, settings, due)
        return {"ok": True, "resource_count": len(snapshot.resources), "observation_count": len(snapshot.blocks),
                "partial": snapshot.partial_rows is not None,
                "gaps": len(last_gaps(db, stored)) if (stored := db.get(Integration, integration_id)) else 0}

    @app.get("/api/devices")
    def devices(auth=Depends(identity), db: Session = Depends(get_db)):
        """Return all client devices to admins or only currently authorized devices to members."""
        user = auth[0]
        rows = db.scalars(select(Resource).where(Resource.kind == "client").order_by(Resource.name))
        return [resource_json(r) for r in rows if user.role == "admin" or device_permitted(db, r, user)]

    @app.put("/api/devices/{device_id}/assignment")
    def assign(device_id: str, body: AssignmentInput, user=Depends(admin), db: Session = Depends(get_db)):
        # One transaction owns the assignment transition. Postgres row locking
        # prevents concurrent administrators creating overlapping current grants.
        """Replace explicit device grants in a serialized administrator transaction.

        Validate classification and active users, close existing grants at the current
        time, and open the new grants without backdating visibility. Record the
        classification change in the same committed transaction.
        """
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
    def blocks(band: Literal["high", "medium", "low", "unknown"] | None = None,
               q: str = Query("", max_length=120), before: str | None = Query(None, max_length=320),
               auth=Depends(identity), db: Session = Depends(get_db)):
        # Requests retain their own domain/device snapshot after inbox observations expire.
        """Prune expired inbox observations and return one page of the events the caller may currently inspect.

        Expiry cleanup leaves stored request snapshots and audit history intact.
        Members additionally require reliable event-time and current device access,
        applied before the page is cut and before anything is counted. See
        `blocks.page` for the paging and the counts.
        """
        db.execute(delete(Observation).where(Observation.expires_at <= utcnow()))
        db.commit()
        return block_list.page(db, auth[0], band, q, before)

    @app.get("/api/blocks/one")
    def one_block(id: str = Query(max_length=255), auth=Depends(identity), db: Session = Depends(get_db)):
        """Return one event the caller may inspect, so one found by address can be opened from any page.

        Missing, expired and hidden events answer the same 404 as a request for one.
        """
        return block_list.one(db, auth[0], id)

    @app.get("/api/blocks/coverage")
    def block_coverage(_auth=Depends(identity), db: Session = Depends(get_db)):
        """Tell a signed-in person why their list of blocked sites may be empty or short, and nothing else.

        Returns exactly two keys and is the same for every caller:

        - `collected`: `none` when no connected source reports blocked lookups,
          `failed` when the latest collection of any such source failed (even if an
          earlier one worked), `no` when one has not been collected yet, else `yes`.
        - `unassigned`: true when a stored lookup that has not expired is assigned to
          no device. Members are shown assigned lookups only, so one of theirs may be
          among these.

        No source, count, address or device is given. A lookup assigned to a device
        never changes the answer, so nobody can tell from it that a site was blocked
        on another person's device.
        """
        from .integrations import registry
        sources = [i for i in db.scalars(select(Integration)) if registry.provides(i.provider, "dns.blocks")]
        failing = any(i.last_error or i.status == "error" for i in sources)
        unassigned = db.scalar(select(Observation.id).where(
            Observation.expires_at > utcnow(), Observation.attribution != "assigned").limit(1))
        return {"collected": ("none" if not sources else "failed" if failing
                              else "yes" if all(i.last_sync for i in sources) else "no"),
                "unassigned": unassigned is not None}

    @app.get("/api/requests")
    def requests(auth=Depends(identity), db: Session = Depends(get_db)):
        """List all access requests for admins or only the authenticated member requests."""
        query = select(AccessRequest).order_by(AccessRequest.created_at.desc())
        if auth[0].role != "admin":
            query = query.where(AccessRequest.requester_id == auth[0].id)
            return [request_json(r) for r in db.scalars(query)]
        # Administrators see which source each came from, by the name it had if it was removed.
        names = removal.removed_names(db)
        return [{**request_json(r), "source_name": names.get(r.integration_id)} for r in db.scalars(query)]

    @app.post("/api/requests", status_code=201)
    async def create_request(body: RequestInput, auth=Depends(identity), db: Session = Depends(get_db)):
        """Persist an authorized, fresh event request once per user and observation, then assess it.

        Hidden or missing events return 404; expired events return 409. The stored
        domain/device snapshot survives inbox expiry. Concurrent duplicate submits
        return the existing request. The assessment is always stored and returned;
        access is opened only when the administrator-written rule allows it.
        """
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
            await access.decide(db, settings, row, observation)
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
    async def review(request_id: str, body: ReviewInput, user=Depends(admin), db: Session = Depends(get_db)):
        """Record an administrator decision on a pending request with a compare-and-swap update.

        Concurrent or repeated reviews return 409. `reviewed` and `denied` change
        nothing on the network. `approved` opens a temporary lease whose recorded
        execution says whether the provider was actually changed.
        """
        from .integrations import IntegrationError

        row = db.get(AccessRequest, request_id)
        if not row:
            raise HTTPException(404, "Request not found")
        if row.status != "pending":
            raise HTTPException(409, "This request has already been reviewed")
        approving = body.decision == "approved"
        if approving:
            # An approval changes a provider, so the evidence behind it must still be current.
            # Saying no, or only noting a request, needs no fresh evidence.
            source = db.get(Observation, row.block_id)
            if not source or utc(source.expires_at) <= utcnow():
                raise HTTPException(409, "The blocked lookup behind this request is no longer current. "
                                         "Ask the person to open the page again and send a new request.")
        # Every decision takes the request's claim first, then (an approval) the entry's. Nothing is unsaved
        # while the source is called, so a second decision is answered at once and never waits on a lock.
        gate = access.hold_review(db, request_id)
        if gate is None:
            raise HTTPException(409, access.REVIEWING)
        claim, opened, execution = None, False, "not_performed"
        try:
            db.refresh(row)
            if row.status != "pending":
                raise HTTPException(409, "This request has already been reviewed")
            if approving:
                integration = db.get(Integration, row.integration_id) if row.integration_id else None
                claim = await access.hold_entry(db, settings, integration, row.domain)
                lease = await access.open_lease(
                    db, settings, integration=integration, domain=row.domain, device_name=row.device_name,
                    requester_id=row.requester_id, request_id=row.id, minutes=body.minutes or row.duration_minutes,
                    decided_by=user.id, risk_score=row.risk_score, claim=claim)
                opened, execution = True, lease.execution
            # Compare and swap: a copy that does not know the request's claim may have decided meanwhile.
            if db.execute(update(AccessRequest).where(AccessRequest.id == request_id, AccessRequest.status == "pending")
                          .values(status=body.decision, review_note=body.note, decided_by=user.id)).rowcount != 1:
                raise HTTPException(409, "This request has already been reviewed")
            audit(db, user.id, "access." + body.decision, request_id, execution=execution)
            access.end_review(db, gate)  # Commits the decision, the exception and both claims given back.
        except BaseException as error:  # Every way out gives both claims back; failed work is rolled back first.
            db.rollback()
            access.release_entry(db, claim, unstored=opened)
            if isinstance(error, access.SourceGone):
                error.record(db)  # the request stays waiting; what was done at the source is kept
            known = isinstance(error, (IntegrationError, HTTPException))
            words = str(error) if isinstance(error, IntegrationError) else getattr(error, "detail", None) if known \
                else "Nyctr met an error. Nothing was recorded as opened."
            access.end_review(db, gate, f"An approval did not go through, so this is still waiting. {words}"
                              if approving else None)
            if not isinstance(error, IntegrationError):
                raise
            refused = isinstance(error, (access.SourceGone, access.NotCollected, access.EntryBusy))
            raise HTTPException(409 if refused else 502, str(error)) from None
        db.refresh(row)
        return request_json(row)

    @app.api_route("/api/hooks/collect", methods=["GET", "POST"], status_code=202)
    @app.api_route("/api/hooks/collect/{token}", methods=["GET", "POST"], status_code=202)
    async def nudge(request: Request, token: str = ""):
        """Let a network console ask for a collection now, for example from its own alert webhook.

        The caller proves a shared secret (Authorization: Bearer, or the path form
        for senders that cannot set headers). Nothing in the request is read or
        stored: it only starts the same read-only collection an administrator can
        start, at most once every 30 seconds. Disabled unless a token is configured.
        """
        supplied = token or request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        expected = settings.nudge_token
        if settings.mode != "live" or not expected or not supplied \
                or not hmac.compare_digest(supplied.encode(), expected.encode()):
            raise HTTPException(404, "API endpoint not found")
        now = time.monotonic()
        if now - getattr(app.state, "last_nudge", float("-inf")) < 30:
            return {"queued": False}
        app.state.last_nudge = now
        # Keep a reference so the task is not collected before it finishes.
        app.state.nudge_task = asyncio.create_task(worker.collect_all(factory, settings))
        with factory() as db:
            audit(db, None, "integration.nudged", None)
            db.commit()
        return {"queued": True}

    @app.get("/api/users")
    def users(_user=Depends(admin), db: Session = Depends(get_db)):
        """List people for administrator views. Never includes credentials or identity-provider subjects."""
        return [columns(u, "id name email role active") for u in db.scalars(select(User).order_by(User.name))]

    @app.get("/api/audit")
    def audit_events(_user=Depends(admin), db: Session = Depends(get_db)):
        """Return the 500 most recent sanitized audit records to an administrator."""
        return [columns(r, "id created_at actor_id action target_id details")
                for r in db.scalars(select(Audit).order_by(Audit.created_at.desc()).limit(500))]

    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    def missing_api(path: str):
        """Return a JSON 404 for an unknown API path before any static-site fallback."""
        raise HTTPException(404, "API endpoint not found")

    if settings.static_dir:
        if not Path(settings.static_dir, "index.html").is_file():
            raise RuntimeError("NYCTR_STATIC_DIR must contain the built web application's index.html")
        app.mount("/", StaticFiles(directory=settings.static_dir, html=True), name="web")
    return app


app = create_app()
