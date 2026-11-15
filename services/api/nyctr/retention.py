"""What becomes of an item its source no longer reports: marked, not counted, dropped after a stated time.

A read that listed a kind of item in full marks what it did not list as missing, once, with
the time. A missing item is dropped when a later whole read of its source, at least
`KEEP_DAYS` after that, still does not list it. A blocked address is kept by its lookups
instead: it goes when no stored lookup from its source names it. Not knowing is not the same
as gone, so nothing is marked or dropped on a read that may have left the kind out, on a
failed collection, or while the source is being collected, edited or removed.
"""

from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import delete, or_, select, update

from .integrations import registry
from .models import AccessRequest, Audit, Integration, Lease, Observation, Resource, utc
from .security import audit

MISSING, SINCE = "missing_from_latest_snapshot", "missing_since"
# How long an item may be missing before it is dropped. The one place this number lives.
KEEP_DAYS = 7
# How often one copy looks for what to drop. Expired lookups are removed at every tick.
DROP_EVERY = timedelta(hours=1)
EVERY_KIND = "*"


def is_missing(row) -> bool:
    """Say whether the item's source left it out of its latest whole read of that kind."""
    return bool((row.attributes or {}).get(MISSING))


def flagged():
    """The same test as a query condition, for counting and for finding what may be dropped."""
    return Resource.attributes[MISSING].as_boolean().is_(True)


def unread(provider: str, snapshot, gaps) -> list[str]:
    """Name the kinds of item this read may have left out, or `EVERY_KIND`.

    The adapter names the kinds it did not list in full. A recorded gap puts every kind in
    doubt unless the integration declared that it leaves every list whole, and so does a read
    cut short whose adapter named no kind.
    """
    definition = registry.find(provider)
    kinds = set(snapshot.unread)
    if set(gaps) - (definition.detail_gaps if definition else frozenset()) or (
            snapshot.partial_rows is not None and not kinds):
        return [EVERY_KIND]
    return sorted(kinds)


def mark_unseen(rows, seen: set[str], doubt: list[str], now: datetime) -> None:
    """Mark what a whole read did not list, once, with the time, among the source's stored `rows`.

    An item listed again loses the mark with its other attributes, and keeps its identifier and
    everything a person attached to it. `seen` is what the read listed; for a read that picked up
    where an earlier one ended it also holds what earlier reads took from the log and is still
    inside the window, so a resumed read marks exactly what a read of the whole window would.
    """
    if EVERY_KIND in doubt:
        return
    for row in rows:
        if row.id not in seen and row.kind not in doubt and SINCE not in row.attributes:
            row.attributes = {**row.attributes, MISSING: True, SINCE: now.isoformat()}


def _held(db, integration_id: str, rows: list[Resource], now: datetime) -> set[str]:
    """Items Nyctr itself still holds something on, which are kept however long they are missing.

    A blocked address with an open exception or a waiting request; a device a stored lookup is
    tied to (a waiting request's lookup among them); a guest Nyctr cut off or locked out, and
    one whose access at the source has not run out.
    """
    from .collection import parsed_date
    from .guests import is_guest, standing_of

    names = set(db.scalars(select(Lease.domain).where(
        Lease.integration_id == integration_id, Lease.status.in_(("active", "unconfirmed")))))
    names |= set(db.scalars(select(AccessRequest.domain).where(
        AccessRequest.integration_id == integration_id, AccessRequest.status == "pending")))
    tied = {id_ for pair in db.execute(select(Observation.device_id, Observation.source_device_id)).all()
            for id_ in pair if id_}
    held = set()
    for row in rows:
        if row.kind == "domain":
            keep = row.source_id in names
        else:
            keep = row.id in tied
        if not keep and is_guest(row):
            grant = row.attributes["guest"]
            try:
                live = grant.get("authorized") is True and parsed_date(grant["expires_at"]) > now
            except (KeyError, TypeError, ValueError, AttributeError):
                live = False
            keep = live or standing_of(db, row)["state"] in ("cut", "locked")
        if keep:
            held.add(row.id)
    return held


def drop_from(db, integration_id: str, now: datetime) -> int:
    """Drop what has left one source, in the caller's transaction, and say how many items went.

    The source's row is locked first and only when its latest collection stored and none is
    going, so a collection, an edit and a removal each wait for this or are waited for. The
    items are then locked in id order, as removal does.
    """
    from .removal import forget

    locked = db.execute(update(Integration).where(
        Integration.id == integration_id, Integration.status.in_(("connected", "partial")),
        Integration.last_error.is_(None), Integration.last_sync.is_not(None),
    ).values(name=Integration.name).execution_options(synchronize_session=False))
    last = db.scalar(select(Audit).where(Audit.action == "integration.collected", Audit.target_id == integration_id)
                     .order_by(Audit.created_at.desc()).limit(1))
    doubt = last.details.get("unread") if last is not None else None
    if locked.rowcount != 1 or not isinstance(doubt, list):
        return 0  # Collecting, failed, never collected, or collected before this was recorded: not known.
    integration = db.get(Integration, integration_id)
    cutoff = utc(integration.last_sync) - timedelta(days=KEEP_DAYS)
    named = set(db.scalars(select(Observation.domain).where(Observation.integration_id == integration_id)))
    gone = []
    for row in db.scalars(select(Resource).where(
            Resource.integration_id == integration_id, or_(Resource.kind == "domain", flagged()),
    ).order_by(Resource.id).with_for_update()):
        if row.kind == "domain":
            if row.source_id not in named:
                gone.append(row)
        elif EVERY_KIND not in doubt and row.kind not in doubt and SINCE in row.attributes \
                and utc(datetime.fromisoformat(row.attributes[SINCE])) <= cutoff:
            gone.append(row)
    held = _held(db, integration_id, gone, now) if gone else set()
    gone = [row for row in gone if row.id not in held]
    if not gone:
        return 0
    kinds = dict(Counter(row.kind for row in gone))
    for row in gone:
        db.expunge(row)
    went = forget(db, [row.id for row in gone])
    audit(db, None, "inventory.dropped", integration_id, name=integration.name, resources=len(gone),
          kinds=kinds, **went)
    return len(gone)


def expire_lookups(factory, now: datetime) -> None:
    """Remove the blocked lookups whose time is up. A request keeps its own copy of what it asked about."""
    with factory() as db:
        db.execute(delete(Observation).where(Observation.expires_at <= now))
        db.commit()


def drop(factory, now: datetime) -> int:
    """One run over every source, each in its own transaction, with one audit record per source that lost items."""
    with factory() as db:
        ids = list(db.scalars(select(Integration.id)))
    total = 0
    for integration_id in ids:
        with factory() as db:
            total += drop_from(db, integration_id, now)
            db.commit()
    return total
