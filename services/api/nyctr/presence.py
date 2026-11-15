"""Device at sign-in: a signed-in person is tied to the device their request came from.

A tie is its own record (`DevicePresence`), never an administrator's assignment:
it changes no device's owner or classification. It is made on a person's first
portal request after signing in, never inside sign-in, and only once an
administrator has switched recognition on. The address comes from `peer`, the
device that holds it from the gateway's own client list, read through the
`devices.lookup` capability its integration declares. What a tie lets a member
see is decided in `deps` and nowhere else; this module makes, lists and ends
ties, and records a conflict where one must not be made.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from dataclasses import dataclass
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from .collection import SECRET_REF
from .deps import TIE_DAYS, admin, columns, get_db, identity, live_ties
from .integrations import IntegrationError, core, registry
from .models import DevicePresence, Integration, Resource, Setting, User, utc, utcnow
from .retention import is_missing
from .security import audit, digest
from .sites import PORTAL

router = APIRouter(prefix="/api")
KEY = "device_recognition"
PROXY_SEEN = "device_recognition_proxy"
# One read of the gateway may take this long, and its answer for an address is remembered this long.
READ_SECONDS = 5.0
REMEMBER_SECONDS = 60.0
# The stored inventory stands in for a read that failed only while the last collection is this fresh.
STORED_MINUTES = 15
# An ended tie, and a conflict, stay on record this long.
KEPT_DAYS = 90
monotonic = time.monotonic
_answers: dict[tuple[str, str], tuple[float, list | None]] = {}

# Why no device was tied, in the words the person reads. Nothing here says whose a device is.
WHY = {
    "off": "Nyctr is not set to recognise devices when people sign in.",
    "console": "Devices are recognised on the address for members, not on this one.",
    "no_address": "Nyctr could not tell which address this request came from, so it cannot tell which device this is.",
    "proxy": "This request reached Nyctr from an address your device shares with other people, so Nyctr cannot "
             "tell which device this is.",
    "outside": "This request did not come from your network, so Nyctr cannot tell which device this is.",
    "not_answering": "Nyctr could not ask your network which device this is just now. Open this page again in a "
                     "few minutes.",
    "nobody": "Your network lists no device at the address this request came from, so Nyctr cannot tell which "
              "device this is.",
    "several": "Your network lists more than one device at the address this request came from, so Nyctr cannot "
               "tell which one this is.",
    "not_collected": "Nyctr has not read this device from your network yet. Open this page again in a few minutes.",
    "infrastructure": "This device is set as not a personal device, so Nyctr ties nobody to it.",
    "other_person": "This device belongs to another person's account, so Nyctr shows you nothing from it.",
    "forgotten": "Nyctr was asked to forget this device. Sign in again to have it recognised.",
}


class Recognition(BaseModel):
    """Whether signing in ties a person to a device, and how far back a new tie reaches."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    reach_back_hours: int = Field(default=2, ge=0, le=24)


@dataclass
class Found:
    """What one request showed: the device and its tie, or why there is none."""
    device: Resource | None = None
    tie: DevicePresence | None = None
    why: str | None = None


def settings(db: Session) -> Recognition:
    """Read the setting in force. Never written, or no longer valid, is off."""
    row = db.get(Setting, KEY)
    try:
        return Recognition(**row.value) if row else Recognition()
    except ValueError:
        return Recognition()


def _sweep(db: Session, now) -> None:
    """Close the ties whose 30 days ran out and drop what has been on record for 90 days. Record keeping only."""
    for tie in db.scalars(select(DevicePresence).where(
            DevicePresence.kind == "tie", DevicePresence.ended_at.is_(None),
            DevicePresence.last_at <= now - timedelta(days=TIE_DAYS))):
        tie.ended_at, tie.ended_by = utc(tie.last_at) + timedelta(days=TIE_DAYS), "expired"
    old = now - timedelta(days=KEPT_DAYS)
    db.execute(delete(DevicePresence).where(or_(
        DevicePresence.ended_at <= old, (DevicePresence.kind == "conflict") & (DevicePresence.last_at <= old))))


def _sources(db: Session, address) -> list[Integration]:
    """The sources that collected a network whose range holds this address."""
    found = set()
    for network in db.scalars(select(Resource).where(Resource.kind == "network")):
        for subnet in network.attributes.get("subnets") or []:
            try:
                if address in ipaddress.ip_network(subnet):
                    found.add(network.integration_id)
            except (TypeError, ValueError):
                continue
    return [row for id_ in sorted(found) if (row := db.get(Integration, id_)) is not None]


async def _holders(db: Session, integration: Integration, address, now) -> tuple[list | None, str]:
    """Say which clients hold the address now: the gateway's answer, or fresh stored inventory if it gave none.

    One paced, read-only call with a time limit, remembered for a minute whatever it
    answered. None means nobody can say: the read failed and the inventory is old.
    """
    provider = registry.find(integration.provider)
    secret = os.environ.get(integration.secret_ref) if SECRET_REF.fullmatch(integration.secret_ref or "") else None
    answer = None
    if provider and provider.client_at and secret:
        key = (integration.id, str(address))
        cached = _answers.get(key)
        if cached and monotonic() - cached[0] < REMEMBER_SECONDS:
            answer = cached[1]
        else:
            try:
                async with asyncio.timeout(READ_SECONDS):
                    with core.patience(READ_SECONDS):
                        answer = await provider.client_at(
                            integration.id, provider.validate(integration.config), secret, str(address))
            except (IntegrationError, TimeoutError):
                answer = None
            if len(_answers) >= 512:
                _answers.clear()
            _answers[key] = (monotonic(), answer)
    if answer is not None:
        return answer, "live"
    if integration.last_sync is None or utc(integration.last_sync) <= now - timedelta(minutes=STORED_MINUTES):
        return None, "stored"
    clients = db.scalars(select(Resource).where(Resource.integration_id == integration.id, Resource.kind == "client"))
    return [{"id": row.id, "mac": row.attributes.get("mac")} for row in clients
            if core.plain_address(row.attributes.get("ip")) == address
            and not is_missing(row)], "stored"


def _record(db: Session, kind: str, user, device: Resource, holder: dict, basis: str, mark: str, now,
            address) -> DevicePresence:
    """Move the time of this person's open tie or conflict on the device, or put a new one on record."""
    live = live_ties(now) if kind == "tie" else [DevicePresence.kind == "conflict"]
    row = db.scalar(select(DevicePresence).where(
        *live, DevicePresence.user_id == user.id, DevicePresence.device_id == device.id).limit(1))
    if row is None:
        reach = now - timedelta(hours=settings(db).reach_back_hours) if kind == "tie" else None
        row = DevicePresence(kind=kind, user_id=user.id, device_id=device.id, first_at=now, reach_from=reach)
        db.add(row)
        if kind == "tie":
            audit(db, user.id, "presence.tied", device.id)
        else:
            audit(db, user.id, "presence.conflict", device.id)
    mac = holder.get("mac")
    row.last_at, row.session, row.basis = now, mark, basis
    row.address, row.mac = str(address), mac[:64] if isinstance(mac, str) else None
    return row


def _barred(device: Resource, user) -> str | None:
    """Say why this person can never be tied to this device, whoever else is on it: None when they can."""
    if device.classification == "infrastructure":
        return "infrastructure"
    return "other_person" if device.classification == "personal" and device.owner_id != user.id else None


async def recognise(db: Session, app_settings, user, session, seen, site: str) -> Found:
    """Find the device this signed-in request came from and tie the person to it, or say why not.

    Each step fails to no tie. A tie this sign-in already made, or was told to
    forget, is answered from the record, so the gateway is read once a sign-in.
    """
    if not settings(db).enabled:
        return Found(why="off")
    if app_settings.portal_url and site != PORTAL:
        return Found(why="console")
    now, mark = utcnow(), digest("presence:" + session.token_hash)
    _sweep(db, now)
    db.commit()
    known = db.scalar(select(DevicePresence).where(
        DevicePresence.kind == "tie", DevicePresence.user_id == user.id, DevicePresence.session == mark)
        .order_by(DevicePresence.last_at.desc()).limit(1))
    if known is not None:
        device = db.get(Resource, known.device_id)
        if known.ended_at is not None or device is None:
            return Found(why="forgotten")
        return Found(why=barred) if (barred := _barred(device, user)) else Found(device, known)
    if seen.address is None:
        return Found(why="no_address")
    if seen.address_is_proxy:
        row = db.get(Setting, PROXY_SEEN) or Setting(key=PROXY_SEEN, updated_at=now - timedelta(days=1))
        if utc(row.updated_at) <= now - timedelta(hours=1):  # noted once an hour, not on every request
            row.value, row.updated_at = {"at": now.isoformat()}, now
            db.add(row)
            db.commit()
        return Found(why="proxy")
    address = core.plain_address(seen.address)
    sources = _sources(db, address) if address is not None else []
    if not sources:
        return Found(why="outside")
    holders, basis = [], "live"
    for integration in sources:
        answer, how = await _holders(db, integration, address, now)
        if answer is None:
            return Found(why="not_answering")
        holders += [{**holder, "source": integration.id} for holder in answer]
        basis = "stored" if how == "stored" else basis
    if len(holders) != 1:
        return Found(why="several" if holders else "nobody")
    # The row is held while the tie is made, so two people cannot both be the first on one device.
    device = db.scalar(select(Resource).where(Resource.id == holders[0]["id"]).with_for_update())
    if device is None or device.kind != "client" or device.integration_id != holders[0]["source"]:
        return Found(why="not_collected")
    barred = _barred(device, user)
    if barred == "infrastructure":
        return Found(why=barred)
    taken = db.scalar(select(DevicePresence.id).where(
        *live_ties(now), DevicePresence.device_id == device.id, DevicePresence.user_id != user.id).limit(1))
    kind = "conflict" if barred or (taken and device.classification != "shared") else "tie"
    row = _record(db, kind, user, device, holders[0], basis, mark, now, address)
    db.commit()
    return Found(device, row) if kind == "tie" else Found(why="other_person")


def attention(db: Session) -> list[dict]:
    """The line administrators read when members arrived from a proxy's own address in the last day."""
    row = db.get(Setting, PROXY_SEEN)
    at = (row.value or {}).get("at") if row else None
    if not at or not settings(db).enabled or utc(row.updated_at) <= utcnow() - timedelta(days=1):
        return []
    return [{"kind": "presence", "id": KEY, "severity": "medium", "at": at,
             "title": "Members are arriving from a proxy's address",
             "detail": "Nyctr cannot tell their devices apart, so it ties nobody to a device. Check the address "
                       "Nyctr sees for you under Setup, This installation."}]


def _end(db: Session, tie: DevicePresence, by: str, now) -> None:
    """End every tie in force of that person on that device, at once."""
    for row in db.scalars(select(DevicePresence).where(
            *live_ties(now), DevicePresence.user_id == tie.user_id, DevicePresence.device_id == tie.device_id)):
        row.ended_at, row.ended_by = now, by
    if tie.ended_at is None:
        tie.ended_at, tie.ended_by = now, by


@router.get("/presence")
def listed(auth=Depends(identity), db: Session = Depends(get_db)):
    """List sign-in ties. A member gets their own ties in force; an administrator every tie and conflict on record."""
    user, now = auth[0], utcnow()
    _sweep(db, now)
    db.commit()
    mine = [] if user.role == "admin" else [*live_ties(now), DevicePresence.user_id == user.id]
    rows = db.scalars(select(DevicePresence).where(*mine).order_by(DevicePresence.last_at.desc()))
    names = {row.id: row.name for row in db.scalars(select(User))}
    items = []
    for row in rows:
        device = db.get(Resource, row.device_id)
        items.append({**columns(row, "id kind user_id device_id basis first_at last_at ended_at"),
                      "user_name": names.get(row.user_id, ""), "device_name": device.name if device else ""})
    return {"items": items, **(settings(db).model_dump() if user.role == "admin" else {})}


@router.put("/presence")
def switch(body: Recognition, user=Depends(admin), db: Session = Depends(get_db)):
    """Switch recognition on or off and set how far back a tie reaches.

    Switching it off ends every tie at once. A shorter reach applies to ties
    already made; a longer one never widens them.
    """
    now, ended = utcnow(), 0
    for tie in db.scalars(select(DevicePresence).where(*live_ties(now))):
        if not body.enabled:
            tie.ended_at, tie.ended_by, ended = now, user.id, ended + 1
        tie.reach_from = max(utc(tie.reach_from), utc(tie.first_at) - timedelta(hours=body.reach_back_hours))
    row = db.get(Setting, KEY) or Setting(key=KEY)
    row.value, row.updated_at, row.updated_by = body.model_dump(), now, user.id
    db.add(row)
    audit(db, user.id, "presence.setting_changed", KEY, **body.model_dump(), ties_ended=ended)
    db.commit()
    return body.model_dump()


@router.delete("/presence/{tie_id}")
def forget(tie_id: str, auth=Depends(identity), db: Session = Depends(get_db)):
    """End a tie at once: a member their own, an administrator anyone's. Asked twice, it stays ended."""
    user = auth[0]
    tie = None if "\x00" in tie_id else db.get(DevicePresence, tie_id)
    if tie is None or tie.kind != "tie" or (user.role != "admin" and tie.user_id != user.id):
        raise HTTPException(404, "That device is not on record")
    if tie.ended_at is None:
        _end(db, tie, user.id, utcnow())
        audit(db, user.id, "presence.ended", tie.device_id, user_id=tie.user_id)
        db.commit()
    return {"ok": True}
