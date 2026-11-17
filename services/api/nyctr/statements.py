"""A member on a recognised device says which site did not open.

The DNS source on this network names no device, so that member is shown nothing
to ask for. This route checks the typed name was blocked in the last few
minutes and files one request for the device they are on. It reveals only that.
"""

from __future__ import annotations

import json
from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import case, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import access, facts, peer, presence
from .deps import device_permitted, get_db
from .integrations import registry
from .models import AccessRequest, Integration, Observation, StatementQuota, utc, utcnow
from .security import audit, authenticate
from .sites import PORTAL, seen_as, site_of

router = APIRouter(prefix="/api")

WINDOW = timedelta(minutes=15)
HOUR = timedelta(hours=1)
LIMIT = 5
OPEN = ("analysing", "pending")
FILED = "That name was blocked recently. Nyctr has filed your request."
DUPLICATE = "Nyctr already has your request for that name."
MISSED = ("Nyctr saw no recent block of that name. Open the page once more on this device, "
          "then try again in a few minutes.")
LIMITED = "You have asked about five sites since the first one in this hour. Try again when that hour resets."
CONSOLE = "Ask from the address members use, not this one."
NO_DEVICE = "Nyctr does not recognise this device as yours, so it cannot take this request."


class StatementInput(BaseModel):
    """The site a member typed. The server reduces it to one plain domain."""
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(min_length=1, max_length=2000)


def _typed(value: str) -> str:
    """A bounded printable copy of what was typed, for the audit when it is not a domain."""
    return "".join(char for char in value if char.isprintable() and char != "\x00")[:253]


def one_domain(value: str) -> str:
    """Reduce typed text to the one plain domain the existing lookup accepts.

    A scheme, a page and a port are taken off first, the same way the member
    page's find does, and then the shared name rules refuse an address, a path
    or a name the lookup would change.
    """
    text = value.strip()
    if not text or "\x00" in text:
        raise facts.NotAName("Give the site as a name, like example.com.")
    lowered = text.lower()
    if "://" in lowered:
        lowered = lowered.split("://", 1)[1]
    lowered = lowered.split("/")[0].split("?")[0].split("#")[0]
    if "@" in lowered:
        lowered = lowered.rsplit("@", 1)[-1]
    host, separator, port = lowered.rpartition(":")
    if separator and port.isdigit() and host and ":" not in host:
        lowered = host
    return facts._name(lowered)


def _denial(why: str) -> str:
    """The sentence for a refusal. Console wording is this route's. The rest are the presence sentences."""
    if why == "console":
        return CONSOLE
    if why == "off":
        return presence.WHY["off"]
    return presence.WHY.get(why, NO_DEVICE)


def _device(request: Request, db: Session, user, session):
    """The device this member is on, or why a statement cannot be taken.

    Recognition has to be on. Outside the demonstration the presence contract
    names the current device or refuses. A refusal stands: a stored address is
    not a second guess. Assignment or a live tie is checked only after that
    device is known. The demonstration has no gateway, so it uses the same
    stand-in as the member's own device page. When a member address is
    configured, the console address is refused before any of that, including
    before a name is looked up.
    """
    settings = request.app.state.settings
    if settings.portal_url and site_of(request) != PORTAL:
        return None, "console"
    if not presence.settings(db).enabled:
        return None, "off"
    if settings.mode != "demo":
        # Recognising commits. It runs before the quota transaction for that reason.
        found = presence.recognise(db, settings, user, session, peer.seen(request), site_of(request))
        if found.why or found.device is None or not device_permitted(db, found.device, user):
            return None, found.why or "no_device"
        return found.device, None
    # The same stand-in the member page uses. A recognition refusal never reaches this branch.
    match, _simulated = access.stand_in_device(db, user, peer.seen(request))
    return (match, None) if match is not None else (None, "no_device")


def _record(db: Session, user_id: str, device_id: str, device_name: str, domain: str, outcome: str,
            target: str | None = None) -> None:
    """Audit the name, this member's device and the outcome. Nothing about another device or person."""
    audit(db, user_id, "access.statement", target or device_id, domain=domain, device_id=device_id,
          device_name=device_name, outcome=outcome)


def _take(db: Session, user_id: str) -> bool:
    """Consume one attempt in this member's fixed hour, or say the hour is already full.

    The upsert is the lock. A second statement waits until the first commits, so
    it sees the request the first one filed, and two of them cannot both pass
    the fifth attempt.
    """
    now = utcnow()
    reset = now + HOUR
    insert = pg_insert if db.bind.dialect.name == "postgresql" else sqlite_insert
    expired = StatementQuota.reset_at <= now
    statement = insert(StatementQuota).values(user_id=user_id, count=1, reset_at=reset)
    statement = statement.on_conflict_do_update(
        index_elements=["user_id"],
        set_={"count": case((expired, 1), else_=StatementQuota.count + 1),
              "reset_at": case((expired, reset), else_=StatementQuota.reset_at)},
        where=or_(expired, StatementQuota.count < LIMIT),
    ).returning(StatementQuota.count)
    return db.execute(statement).scalar_one_or_none() is not None


def _fresh(row: Observation, now, window) -> bool:
    """A block observed in the window, not after now, that the inbox has not expired."""
    observed = utc(row.observed_at)
    return window <= observed <= now and utc(row.expires_at) > now


def _candidates(db: Session, name: str) -> list[Observation]:
    """Exact history of this name, and every recent block, from a source that declares blocked lookups.

    The core names no vendor: it asks the registry which sources offer the capability.
    """
    providers = tuple(registry.with_capability("dns.blocks"))
    if not providers:
        return []
    return list(db.scalars(
        select(Observation).join(Integration, Observation.integration_id == Integration.id).where(
            Integration.provider.in_(providers),
            or_(Observation.domain == name, Observation.observed_at >= utcnow() - WINDOW))))


def _match(rows: list[Observation], name: str):
    """The newest exact block of this name in the window, or why there is none.

    A parent or a child is not a match. An exact name older than the window, or
    one the inbox has expired, is stale. The caller tells the member the same
    plain sentence either way.
    """
    now = utcnow()
    window = now - WINDOW
    exact = [row for row in rows if row.domain == name]
    fresh = [row for row in exact if _fresh(row, now, window)]
    if fresh:
        return max(fresh, key=lambda row: utc(row.observed_at)), "filed"
    if exact:
        return None, "stale"
    related = [row for row in rows if _fresh(row, now, window)
               and (row.domain.endswith("." + name) or name.endswith("." + row.domain))]
    return None, "not_exact" if related else "miss"


def _open_request(db: Session, user_id: str, device_id: str, name: str,
                  block_id: str | None = None) -> AccessRequest | None:
    """This member's request on this device: an open one for the name, or any for this block.

    Another device's row is not a match. A display name is not the device.
    """
    same_name = db.scalar(select(AccessRequest).where(
        AccessRequest.requester_id == user_id, AccessRequest.device_id == device_id,
        AccessRequest.domain == name, AccessRequest.status.in_(OPEN),
    ).order_by(AccessRequest.created_at.desc()).limit(1))
    if same_name is not None:
        return same_name
    if block_id is None:
        return None
    return db.scalar(select(AccessRequest).where(
        AccessRequest.requester_id == user_id, AccessRequest.device_id == device_id,
        AccessRequest.block_id == block_id).limit(1))


def _duplicate(db: Session, user_id: str, device_id: str, device_name: str, name: str, existing):
    """Return this device's request. None when the row is not this member's on this device."""
    if existing is None or existing.requester_id != user_id or existing.device_id != device_id:
        return None
    shown = access.shown(db, existing, admin=False)
    _record(db, user_id, device_id, device_name, name, "duplicate", existing.id)
    db.commit()
    return _answer(200, DUPLICATE, shown, matched=True)


def _answer(status: int, message: str, request: dict | None = None, *, matched: bool):
    body = {"matched": matched, "message": message}
    if request is not None:
        body["request"] = request
    return JSONResponse(jsonable_encoder(body), status_code=status)


async def _typed_domain(request: Request) -> str:
    """A short printable copy of `domain`, or nothing when the body has no such string.

    Called only after sign-in has already been refused. It does not look anything up,
    and it keeps no other field from the body.
    """
    try:
        payload = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return ""
    if not isinstance(payload, dict):
        return ""
    domain = payload.get("domain")
    if not isinstance(domain, str):
        return ""
    return _typed(domain)


def _record_unsigned(db: Session, domain: str) -> None:
    """Audit a refused sign-in. No member is invented, and no device or address is stored."""
    audit(db, None, "access.statement", domain=domain, device_id="", device_name="", outcome="no_session")
    db.commit()


async def signed_member(request: Request, db: Session = Depends(get_db)):
    """Sign-in for this route. A missing session is audited, then refused unchanged.

    The shared check still returns 401 for a missing, unknown, expired or disabled
    session, and 403 when a live session has no matching mutation token. Only the
    401 is audited, with no member attached.
    """
    try:
        user, session = authenticate(request, db)
    except HTTPException as exc:
        if exc.status_code == 401:
            _record_unsigned(db, await _typed_domain(request))
        raise
    return seen_as(request, user), session


@router.post("/statements")
def state_a_site(body: StatementInput, background: BackgroundTasks, request: Request,
                 auth=Depends(signed_member), db: Session = Depends(get_db)):
    """File one statement for the device the member is on, or say the name was not blocked recently.

    Five attempts an hour for each member, including a name that matches nothing.
    After the attempt is counted, this device's open request is returned even when
    the block has left the window. A new request still needs a block from that window.
    """
    user, session = auth
    device, why = _device(request, db, user, session)
    typed = _typed(body.domain)
    if device is None:
        _record(db, user.id, "", "", typed, why)
        db.commit()
        raise HTTPException(403, _denial(why))
    user_id, device_id, device_name = user.id, device.id, device.name
    try:
        name = one_domain(body.domain)
    except facts.NotAName as error:
        _record(db, user_id, device_id, device_name, typed, "not_a_name")
        db.commit()
        raise HTTPException(422, str(error)) from None
    if not _take(db, user_id):
        db.rollback()
        _record(db, user_id, device_id, device_name, name, "limited")
        db.commit()
        raise HTTPException(429, LIMITED)
    # The open request is this member's on this device. Fresh evidence is required only for a new one.
    existing = _open_request(db, user_id, device_id, name)
    if (answer := _duplicate(db, user_id, device_id, device_name, name, existing)) is not None:
        return answer
    chosen, outcome = _match(_candidates(db, name), name)
    if chosen is None:
        _record(db, user_id, device_id, device_name, name, outcome)
        db.commit()
        return _answer(200, MISSED, matched=False)
    block_id = chosen.id
    existing = _open_request(db, user_id, device_id, name, block_id)
    if (answer := _duplicate(db, user_id, device_id, device_name, name, existing)) is not None:
        return answer
    row = AccessRequest(block_id=block_id, domain=name, device_name=device_name, device_id=device_id,
                        requester_id=user_id, reason="The page did not open.", duration_minutes=60,
                        status="analysing", basis="statement")
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        if not _take(db, user_id):
            _record(db, user_id, device_id, device_name, name, "limited")
            db.commit()
            raise HTTPException(429, LIMITED) from None
        existing = _open_request(db, user_id, device_id, name, block_id)
        answer = _duplicate(db, user_id, device_id, device_name, name, existing)
        if answer is None:
            db.rollback()
            raise
        return answer
    shown = access.shown(db, row, admin=False)
    _record(db, user_id, device_id, device_name, name, "filed", row.id)
    db.commit()
    # Imported here: the application module includes this router while it is still loading.
    from .main import _finish_request

    background.add_task(_finish_request, request.app, row.id)
    return _answer(201, FILED, shown, matched=True)
