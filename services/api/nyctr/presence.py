"""Device at sign-in: a signed-in person is tied to the device their request came from.

A tie is its own record (`DevicePresence`), never an administrator's assignment:
it changes no device's owner or classification. It is made on a person's first
portal request after signing in, never inside sign-in, and only once an
administrator has switched recognition on. The address comes from `peer`, the
device that holds it from the gateway's own client list, read through the
`devices.lookup` capability its integration declares, asked only of the site
whose network holds the address. What a tie lets a member see is decided in
`deps` and nowhere else; this module makes, lists and ends ties, and records a
conflict where one must not be made. Its record keeping runs in the worker
(`keep`), so that a member's page writes nothing unless a tie is made.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from dataclasses import dataclass
from datetime import timedelta

from anyio import from_thread
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from .collection import SECRET_REF
from .deps import TIE_DAYS, admin, columns, get_db, identity, live_ties
from .integrations import IntegrationError, core, registry
from .models import Audit, DevicePresence, Integration, Resource, Setting, User, utc, utcnow
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
_answers: dict[tuple[str, str | None, str], tuple[float, list | None]] = {}

# Why no device was tied, in the words the person reads. Nothing here says whose a device is.
WHY = {
    "off": "Nyctr is not set to recognise devices when people sign in.",
    "console": "Devices are recognised on the address for members, not on this one.",
    "no_address": "Nyctr could not tell which address this request came from, so it cannot tell which device this is.",
    "proxy": "This request reached Nyctr from an address your device shares with other people, so Nyctr cannot "
             "tell which device this is.",
    "outside": "This request did not come from your network, so Nyctr cannot tell which device this is.",
    "two_networks": "More than one of your networks uses the address this request came from, so Nyctr cannot "
                    "tell which device this is.",
    "busy": "Nyctr was busy and has not worked out which device this is. Open this page again in a minute.",
    "ipv6": "This request reached Nyctr over IPv6, a kind of address Nyctr cannot yet match to a device, so it "
            "cannot tell which device this is.",
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
    # The stored value itself is read, never a copy this session already holds: see `_held`.
    value = db.scalar(select(Setting.value).where(Setting.key == KEY))
    try:
        return Recognition(**value) if value is not None else Recognition()
    except ValueError:
        return Recognition()


def _held(db: Session) -> Recognition:
    """Hold the setting's row until this transaction ends, and read the setting again under that hold.

    The one lock that making a tie and switching recognition off both take. Whichever comes
    second waits for the first to commit, so a tie is never committed after the switch: either
    the switch finds it and ends it, or the sign-in finds recognition off and makes none. Two
    sign-ins wait for each other the same way, so two people cannot both be first on a device.
    Written as an update that changes nothing, which locks the row on PostgreSQL and takes the
    one write lock on SQLite.
    """
    db.execute(update(Setting).where(Setting.key == KEY).values(updated_at=Setting.updated_at)
               .execution_options(synchronize_session=False))
    return settings(db)


def _said(db: Session, by: str | None, tie: DevicePresence, because: str | None = None) -> None:
    """One audit record that a tie ended: whose it was, on which device by name, and why unless a person ended it."""
    device = db.get(Resource, tie.device_id)
    audit(db, by, "presence.ended", tie.device_id, user_id=tie.user_id, device_name=device.name if device else "",
          **({"because": because} if because else {}))


def _ended(row: DevicePresence, now):
    """When a tie ended: as recorded, or 30 days after its last sign-in if nothing has recorded that yet."""
    lapsed = utc(row.last_at) + timedelta(days=TIE_DAYS)
    return utc(row.ended_at) if row.ended_at else lapsed if row.kind == "tie" and lapsed <= now else None


def keep(factory, now) -> None:
    """Record keeping, run by the worker and by no page: close the ties whose 30 days ran out, drop the old records.

    Each tie that lapsed gets its ending written down, with one audit record that says whose it
    was. A record that ended 90 days ago, and a conflict last seen 90 days ago, is deleted, with
    the addresses it held. What a tie shows never waits for this: `deps` counts the days itself.
    """
    with factory() as db:
        for tie in db.scalars(select(DevicePresence).where(
                DevicePresence.kind == "tie", DevicePresence.ended_at.is_(None),
                DevicePresence.last_at <= now - timedelta(days=TIE_DAYS))):
            tie.ended_at, tie.ended_by = _ended(tie, now), "expired"
            _said(db, None, tie, "lapsed")
        old = now - timedelta(days=KEPT_DAYS)
        db.execute(delete(DevicePresence).where(or_(
            DevicePresence.ended_at <= old, (DevicePresence.kind == "conflict") & (DevicePresence.last_at <= old))))
        db.commit()


def gone(db: Session, ids: list[str], by: str | None) -> None:
    """Take the ties and conflicts on these devices off record, because the devices are going. The caller commits.

    Each tie still in force is ended on record first, so the audit trail says whose it was.
    """
    for tie in db.scalars(select(DevicePresence).where(*live_ties(), DevicePresence.device_id.in_(ids))):
        _said(db, by, tie, "device_removed")
    db.execute(delete(DevicePresence).where(DevicePresence.device_id.in_(ids)))


def _places(db: Session, address) -> list[tuple[Integration, Resource | None]]:
    """Each source that declares the lookup, and site of it, that collected a network whose range holds this address.

    A source whose integration does not declare `devices.lookup` takes no part: its networks
    neither tie anybody through its stored inventory nor put another source's range in doubt.
    """
    found = set()
    for network in db.scalars(select(Resource).where(Resource.kind == "network")):
        for subnet in network.attributes.get("subnets") or []:
            try:
                if address in ipaddress.ip_network(subnet):
                    found.add((network.integration_id, network.site_id or ""))
            except (TypeError, ValueError):
                continue
    places = []
    for source, site_id in sorted(found):
        site = db.get(Resource, site_id) if site_id else None
        integration = db.get(Integration, source)
        if integration is not None and registry.provides(integration.provider, "devices.lookup"):
            places.append((integration, site))
    return places


async def _ask(provider, integration_id: str, config: dict, secret: str, address: str, site: str | None) -> list:
    """One read of the gateway's client list for one site, with a time limit of its own."""
    async with asyncio.timeout(READ_SECONDS):
        with core.patience(READ_SECONDS):
            return await provider.client_at(integration_id, provider.validate(config), secret, address, site)


def _holders(db: Session, integration: Integration, site: Resource | None, address, now) -> tuple[list | None, str]:
    """Say which clients of that site hold the address now: the gateway's answer, or fresh stored inventory.

    One paced, read-only call with a time limit, remembered for a minute whatever it
    answered. It runs on the server's loop while this thread waits, so the server goes on
    answering. None means nobody can say: the read failed and the inventory is old.
    """
    provider = registry.find(integration.provider)
    secret = os.environ.get(integration.secret_ref) if SECRET_REF.fullmatch(integration.secret_ref or "") else None
    answer = None
    if provider and provider.client_at and secret:
        key = (integration.id, site.source_id if site is not None else None, str(address))
        cached = _answers.get(key)
        if cached and monotonic() - cached[0] < REMEMBER_SECONDS:
            answer = cached[1]
        else:
            try:
                answer = from_thread.run(_ask, provider, integration.id, integration.config, secret, key[2], key[1])
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
            if core.plain_address(row.attributes.get("ip")) == address and not is_missing(row)
            and (site is None or row.site_id == site.id)], "stored"


def _own_from(db: Session, device: Resource, user, now):
    """The latest time Nyctr's own record says the device was, or may have been, someone else's: None if never.

    That is the last time an administrator said whose it is, saved again unchanged or not, and,
    on a device that is not shared, the end of the last tie anyone else held on it. A new tie
    reaches back no further: what was looked up before then was not this person's.
    """
    times = [utc(at) for at in (db.scalar(select(func.max(Audit.created_at)).where(
        Audit.action == "device.assignment_changed", Audit.target_id == device.id)),) if at is not None]
    if device.classification != "shared":
        times += [_ended(tie, now) or now for tie in db.scalars(select(DevicePresence).where(
            DevicePresence.kind == "tie", DevicePresence.device_id == device.id,
            DevicePresence.user_id != user.id))]
    return max(times, default=None)


def _record(db: Session, kind: str, user, device: Resource, holder: dict, basis: str, mark: str, now,
            address) -> DevicePresence:
    """Move the time of this person's open tie or conflict on the device, or put a new one on record."""
    live = live_ties(now) if kind == "tie" else [DevicePresence.kind == "conflict"]
    row = db.scalar(select(DevicePresence).where(
        *live, DevicePresence.user_id == user.id, DevicePresence.device_id == device.id).limit(1))
    if row is None:
        reach = None
        if kind == "tie":
            # Stored inventory may be 15 minutes behind the network, so a tie that rests on it reaches back
            # to nothing: if the address has changed hands since, it shows nothing from before this sign-in.
            reach = now if basis == "stored" else now - timedelta(hours=settings(db).reach_back_hours)
            reach = max(reach, _own_from(db, device, user, now) or reach)
        row = DevicePresence(kind=kind, user_id=user.id, device_id=device.id, first_at=now, reach_from=reach)
        db.add(row)
        if kind == "tie":
            audit(db, user.id, "presence.tied", device.id, device_name=device.name)
        else:
            audit(db, user.id, "presence.conflict", device.id, device_name=device.name)
    mac = holder.get("mac")
    row.last_at, row.session, row.basis = now, mark, basis
    row.address, row.mac = str(address), mac[:64] if isinstance(mac, str) else None
    return row


def _barred(device: Resource, user) -> str | None:
    """Say why this person can never be tied to this device, whoever else is on it: None when they can."""
    if device.classification == "infrastructure":
        return "infrastructure"
    return "other_person" if device.classification == "personal" and device.owner_id != user.id else None


def recognise(db: Session, app_settings, user, session, seen, site: str) -> Found:
    """Find the device this signed-in request came from and tie the person to it, or say why not.

    Each step fails to no tie. A tie this sign-in already made, or was told to
    forget, is answered from the record, so the gateway is read once a sign-in
    and nothing is written after that. A database too busy to write the tie is
    a reason like the others, not an error.
    """
    try:
        return _recognise(db, app_settings, user, session, seen, site)
    except OperationalError:
        db.rollback()
        return Found(why="busy")


def _recognise(db: Session, app_settings, user, session, seen, site: str) -> Found:
    """The steps of `recognise`, in order."""
    if not settings(db).enabled:
        return Found(why="off")
    if app_settings.portal_url and site != PORTAL:
        return Found(why="console")
    now, mark = utcnow(), digest("presence:" + session.token_hash)
    known = db.scalar(select(DevicePresence).where(
        DevicePresence.kind == "tie", DevicePresence.user_id == user.id, DevicePresence.session == mark)
        .order_by(DevicePresence.last_at.desc()).limit(1))
    if known is not None:
        device = db.get(Resource, known.device_id)
        if _ended(known, now) is not None or device is None:
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
    if address is not None and address.version == 6:
        return Found(why="ipv6")  # by rule, whatever a source collects: IPv4 carried inside IPv6 is IPv4 by now
    places = _places(db, address) if address is not None else []
    if len(places) != 1:
        # Two sites, or two sources, that use one range: nothing says which of them the request came from.
        return Found(why="two_networks" if places else "outside")
    integration, where = places[0]
    holders, basis = _holders(db, integration, where, address, now)
    if holders is None:
        return Found(why="not_answering")
    if len(holders) != 1:
        return Found(why="several" if holders else "nobody")
    found = _tie(db, user, integration, holders[0], basis, mark, now, address)
    if found.device is None:
        db.rollback()  # lets the lock go at once where no tie was made; after a commit this does nothing
    return found


def _tie(db: Session, user, integration: Integration, holder: dict, basis: str, mark: str, now, address) -> Found:
    """Under the one lock: look at the device and at who is tied to it, and write the tie or the conflict.

    The lock comes first, before anything the decision rests on is read. From there to the
    commit the switch cannot run, and no other sign-in can read "nobody is tied here" and
    write beside this one. PostgreSQL holds the device's row as well, against an assignment
    saved at the same moment; SQLite has no row to hold, so there the lock is all of it.
    """
    if not _held(db).enabled:
        return Found(why="off")  # switched off since the first check: nothing is written
    device = db.scalar(select(Resource).where(Resource.id == holder["id"]).with_for_update())
    if device is None or device.kind != "client" or device.integration_id != integration.id:
        return Found(why="not_collected")
    barred = _barred(device, user)
    if barred == "infrastructure":
        return Found(why=barred)
    taken = db.scalar(select(DevicePresence.id).where(
        *live_ties(now), DevicePresence.device_id == device.id, DevicePresence.user_id != user.id).limit(1))
    kind = "conflict" if barred or (taken and device.classification != "shared") else "tie"
    row = _record(db, kind, user, device, holder, basis, mark, now, address)
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


def release(db: Session, device: Resource, named: list[str], by: str, now, changed: bool = True) -> int:
    """Bring the ties on a device in line with what an administrator just said about it. The caller commits.

    When the assignment changed whose the device is or who shares it, every tie held by
    anyone it does not name ends at once: their word replaces what sign-ins suggested, so
    the device never stays listed under people it is no longer for. Someone else who does
    use a shared device is tied again the next time they sign in on it. Every tie that
    stays, also after a save that changed nothing, starts again at this moment: an
    assignment does not show what came before it, and a tie made earlier must not either.
    """
    ended = 0
    for tie in db.scalars(select(DevicePresence).where(*live_ties(now), DevicePresence.device_id == device.id)):
        if changed and tie.user_id not in named:
            tie.ended_at, tie.ended_by, ended = now, by, ended + 1
            _said(db, by, tie, "assignment")
        else:
            tie.reach_from = max(utc(tie.reach_from), now)
    return ended


def _end(db: Session, tie: DevicePresence, by: str, now) -> None:
    """End every tie in force of that person on that device, at once."""
    for row in db.scalars(select(DevicePresence).where(
            *live_ties(now), DevicePresence.user_id == tie.user_id, DevicePresence.device_id == tie.device_id)):
        row.ended_at, row.ended_by = now, by
    if tie.ended_at is None:
        tie.ended_at, tie.ended_by = now, by


@router.get("/presence")
def listed(auth=Depends(identity), db: Session = Depends(get_db)):
    """List sign-in ties. A member gets their own ties in force; an administrator every tie and conflict on record.

    Only an administrator is shown the address a person signed in from and the device's hardware address.
    """
    user, now = auth[0], utcnow()
    mine = [] if user.role == "admin" else [*live_ties(now), DevicePresence.user_id == user.id]
    rows = db.scalars(select(DevicePresence).where(*mine).order_by(DevicePresence.last_at.desc()))
    names = {row.id: row.name for row in db.scalars(select(User))}
    items = []
    for row in rows:
        device = db.get(Resource, row.device_id)
        items.append({**columns(row, "id kind user_id device_id basis first_at last_at"), "ended_at": _ended(row, now),
                      **(columns(row, "address mac") if user.role == "admin" else {}),
                      "user_name": names.get(row.user_id, ""), "device_name": device.name if device else ""})
    return {"items": items, **(settings(db).model_dump() if user.role == "admin" else {})}


@router.put("/presence")
def switch(body: Recognition, user=Depends(admin), db: Session = Depends(get_db)):
    """Switch recognition on or off and set how far back a tie reaches.

    Switching it off ends every tie at once, each with its own audit record.
    A shorter reach applies to ties already made; a longer one never widens them.
    """
    now, ended = utcnow(), 0
    if db.get(Setting, KEY) is None:  # the lock below needs a row to hold
        db.add(Setting(key=KEY, value=Recognition().model_dump(), updated_at=now))
        db.flush()
    _held(db)  # a sign-in that is writing a tie finishes first, and none starts until this commits
    for tie in db.scalars(select(DevicePresence).where(*live_ties(now))):
        if not body.enabled:
            tie.ended_at, tie.ended_by, ended = now, user.id, ended + 1
            _said(db, user.id, tie, "switched_off")
        tie.reach_from = max(utc(tie.reach_from), utc(tie.first_at) - timedelta(hours=body.reach_back_hours))
    row = db.get(Setting, KEY)
    row.value, row.updated_at, row.updated_by = body.model_dump(), now, user.id
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
        _said(db, user.id, tie)
        db.commit()
    return {"ok": True}
