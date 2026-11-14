"""Remove a saved source and everything collected from it, without contacting the source.

What goes: the source's inventory, relationships, blocked lookups, sightings, guest
history, passes read from it that are still live, findings that rest only on its
items, and what hangs on those items (assignments to people and DNS label links).
What stays: requests, exceptions, passes Nyctr issued or that have ended, and the
audit history, which keeps the source's name in the removal record. Removal is
refused while Nyctr still has something of its own at the source, because nothing
could end it afterwards.
"""

from collections import Counter, defaultdict

from sqlalchemy import and_, delete, func, or_, select, update

from .collection import parsed_date
from .guests import EFFECTIVE, state_of
from .models import (
    AccessRequest,
    Audit,
    DeviceGrant,
    DeviceLink,
    Finding,
    GuestAction,
    GuestPass,
    Insight,
    Integration,
    Lease,
    Observation,
    Relationship,
    Resource,
    Sighting,
    utc,
    utcnow,
)


def _count(db, model, *where) -> int:
    return db.scalar(select(func.count()).select_from(model).where(*where)) or 0


def _live_read_passes(integration_id: str):
    """Passes read from the source (no issuer) that have not ended: collected data, removed with it."""
    now = utcnow()
    return (GuestPass.integration_id == integration_id, GuestPass.issued_by.is_(None), GuestPass.ended_at.is_(None),
            or_(GuestPass.expires_at.is_(None), GuestPass.expires_at > now))


def _let_on(device: Resource, actions: list[GuestAction], now) -> bool:
    """A guest Nyctr itself let on at the source whose time there has not run out. It does not hold removal
    back, because the grant ends by itself at the source, but after removal Nyctr cannot cut it off."""
    latest = next((a for a in actions if a.execution in EFFECTIVE), None)
    if not latest or latest.action not in ("admit", "restore") or latest.execution != "applied":
        return False
    if state_of(device, actions) != "online":
        return False
    try:
        return parsed_date(device.attributes["guest"]["expires_at"]) > utc(now)
    except (KeyError, TypeError, ValueError, AttributeError):
        return True


def plan(db, integration: Integration, resources: list[Resource]) -> dict:
    """Count what removal deletes, what it keeps, and what of Nyctr's own still holds it back."""
    iid, ids = integration.id, [row.id for row in resources]
    items = select(Resource.id).where(Resource.integration_id == iid)
    kinds = Counter(row.kind for row in resources)
    actions = defaultdict(list)
    for action in db.scalars(select(GuestAction).where(GuestAction.device_id.in_(items))
                             .order_by(GuestAction.created_at.desc())):
        actions[action.device_id].append(action)
    states = Counter(state_of(row, actions[row.id]) for row in resources if row.id in actions)
    now = utcnow()
    held = {
        # With the entries of openings not confirmed yet: Nyctr may have put them there and still removes them.
        "exceptions": _count(db, Lease, Lease.integration_id == iid, Lease.owned.is_(True), or_(
            and_(Lease.status == "active", Lease.execution == "applied"), Lease.status == "unconfirmed")),
        "passes": _count(db, GuestPass, GuestPass.integration_id == iid, GuestPass.issued_by.is_not(None),
                         GuestPass.execution == "applied", GuestPass.ended_at.is_(None),
                         or_(GuestPass.expires_at.is_(None), GuestPass.expires_at > now)),
        "cut_off": states["cut"], "locked_out": states["locked"],
    }
    remove = {
        "devices": kinds["client"], "networks": kinds["network"], "rules": kinds["policy"],
        "other_items": len(ids) - kinds["client"] - kinds["network"] - kinds["policy"],
        "lookups": _count(db, Observation, Observation.integration_id == iid),
        "assignments": _count(db, DeviceGrant, DeviceGrant.device_id.in_(items), DeviceGrant.valid_until.is_(None)),
        "links": _count(db, DeviceLink, or_(DeviceLink.source_id.in_(items), DeviceLink.device_id.in_(items))),
    }
    keep = {
        "requests": _count(db, AccessRequest, AccessRequest.integration_id == iid),
        "exceptions": _count(db, Lease, Lease.integration_id == iid),
        "passes": _count(db, GuestPass, GuestPass.integration_id == iid) - _count(db, GuestPass,
                                                                                  *_live_read_passes(iid)),
    }
    let_on = sum(_let_on(row, actions[row.id], now) for row in resources if row.id in actions)
    return {"id": iid, "name": integration.name, "provider": integration.provider,
            "remove": remove, "keep": keep, "held": held, "let_on": let_on}


def let_on_message(count: int) -> str | None:
    """Tell the administrator, before removing, about guests Nyctr let on that stay on at the source."""
    if not count:
        return None
    one = count == 1
    return (f"{count} guest{'' if one else 's'} Nyctr let on {'stays' if one else 'stay'} let on at this source "
            f"until {'its' if one else 'their'} time ends. After removal, Nyctr can no longer cut "
            f"{'it' if one else 'them'} off.")


def held_message(held: dict) -> str | None:
    """Say in plain words what of Nyctr's own is still at the source and where to end it, or None."""
    parts = [text for count, text in (
        (held["exceptions"], f"{held['exceptions']} open exception{'s' * (held['exceptions'] != 1)} "
                             "(end under Open now)"),
        (held["passes"], f"{held['passes']} guest pass{'es' * (held['passes'] != 1)} it issued (end under Guests)"),
        (held["cut_off"], f"{held['cut_off']} guest{'s' * (held['cut_off'] != 1)} cut off (let back on under Guests)"),
        (held["locked_out"], f"{held['locked_out']} guest{'s' * (held['locked_out'] != 1)} locked out "
                             "(unlock under Guests)"),
    ) if count]
    if not parts:
        return None
    one = sum(held.values()) == 1
    return (f"Not removed. Nyctr still has {', '.join(parts)} at this source. "
            f"End {'it' if one else 'them'} first, then remove the source. "
            "Nothing at the source itself is changed by removing it.")


def remove(db, integration: Integration) -> None:
    """Delete the source and what was collected from it. The caller holds its row and item locks and commits."""
    iid = integration.id
    items = select(Resource.id).where(Resource.integration_id == iid)
    gone = set(db.scalars(select(Resource.id).where(Resource.integration_id == iid)))
    db.execute(delete(DeviceGrant).where(DeviceGrant.device_id.in_(items)))
    db.execute(delete(DeviceLink).where(or_(DeviceLink.source_id.in_(items), DeviceLink.device_id.in_(items))))
    # Another source's lookups tied to one of these devices lose that tie: it rested on this source.
    db.execute(update(Observation).where(Observation.integration_id != iid, Observation.device_id.in_(items))
               .values(device_id=None, attribution="unverified"))
    db.execute(delete(Observation).where(Observation.integration_id == iid))
    db.execute(delete(Relationship).where(Relationship.integration_id == iid))
    db.execute(delete(Sighting).where(Sighting.device_id.in_(items)))
    db.execute(delete(GuestAction).where(GuestAction.device_id.in_(items)))
    db.execute(delete(GuestPass).where(*_live_read_passes(iid)))
    # What remains active is not Nyctr's at the source (refused otherwise), so it ends here with no request.
    db.execute(update(Lease).where(Lease.integration_id == iid, Lease.status == "active").values(
        status="ended", ended_reason="source_removed", ended_at=utcnow()))
    for finding in db.scalars(select(Finding)):
        ids = list(finding.resource_ids or [])
        if not gone.intersection(ids):
            continue
        if gone.issuperset(ids):
            db.execute(delete(Insight).where(Insight.finding_id == finding.id))
            db.delete(finding)
        else:
            finding.resource_ids = [x for x in ids if x not in gone]
    db.execute(delete(Resource).where(Resource.integration_id == iid))
    db.delete(integration)


def removed_names(db) -> dict[str, str]:
    """Map every source id, current or removed, to its name; a removed one keeps the name it had."""
    names = {record.target_id: record.details.get("name") for record in
             db.scalars(select(Audit).where(Audit.action == "integration.removed"))}
    names.update({row.id: row.name for row in db.scalars(select(Integration))})
    return names
