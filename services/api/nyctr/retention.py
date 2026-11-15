"""What becomes of an item its source no longer reports: marked, not counted, dropped after a stated time.

A read that listed a kind of item in full marks what it did not list as missing, with the
time, and notes the day. A missing item is dropped when whole reads of its kind on at least
`KEEP_DAYS` separate days, the last of them `KEEP_DAYS` days after the first, all left it out
and no read in between listed it. So a source that was down, or is collected rarely, drops
nothing until it has been read on that many days. A blocked address is kept by its lookups
instead: it goes when no stored lookup from its source names it. Not knowing is not the same
as gone, so nothing is marked or dropped on a read that may have left the kind out, on a
failed collection, or while the source is being collected, edited or removed. And what a
person attached something to is never dropped here: it stays, marked, until that is removed.
"""

import logging
import time
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import delete, or_, select, update

from .integrations import registry
from .models import (
    AccessRequest,
    Audit,
    DeviceGrant,
    DeviceLink,
    Integration,
    Lease,
    Observation,
    Resource,
    utc,
)

MISSING, SINCE, DAYS = "missing_from_latest_snapshot", "missing_since", "missing_days"
# How many days an item must be missing, and on how many separate days a whole read must have
# left it out, before it is dropped. The one place this number lives.
KEEP_DAYS = 7
# How often one copy goes through each source for what to drop. Expired lookups are removed at every tick.
DROP_EVERY = timedelta(hours=1)
# How many items one transaction looks at. A batch holds the source's row, and on SQLite the
# only write lock, for as long as these take, so whatever waits for either waits for one batch.
BATCH = 500
# Seconds between two batches of one run. SQLite hands its write lock to whoever asks next, not
# to whoever has waited longest, and a waiting writer asks again at most this far apart.
PAUSE = 0.15
BUSY, UNKNOWN = "busy", "unknown"
EVERY_KIND = "*"
log = logging.getLogger("nyctr.retention")


def is_missing(row) -> bool:
    """Say whether the item's source left it out of its latest whole read of that kind."""
    return bool((row.attributes or {}).get(MISSING))


def flagged():
    """The same test as a query condition, for counting and for finding what may be dropped."""
    return Resource.attributes[MISSING].as_boolean().is_(True)


def unread(provider: str, snapshot, gaps) -> list[str]:
    """Name the kinds of item this read may have left out, or `EVERY_KIND`.

    The adapter names the kinds it did not list in full. A recorded gap puts every kind in
    doubt unless the integration declared that it leaves every other list whole, and so does
    a read cut short whose adapter named no kind.
    """
    definition = registry.find(provider)
    kinds = set(snapshot.unread)
    if set(gaps) - (definition.detail_gaps if definition else frozenset()) or (
            snapshot.partial_rows is not None and not kinds):
        return [EVERY_KIND]
    return sorted(kinds)


def standing(db, integration, snapshot, gaps) -> tuple[list[str], str | None]:
    """Say what this read leaves in doubt, counting the reads it stands on, and from when the stored log is whole.

    A read that picked up where an earlier one ended vouches only for the stretch it read. For
    the rest of the window it stands on the reads before it, so while the stored log is not
    whole from the window's start it is in doubt for whatever they were: a read that kept only
    part, hit a gap or followed one that did leaves a hole no later read goes back for. Where
    the latest stored collection did not record how far back it is whole, that is not known and
    every kind is in doubt. The second value is None for a source with no log to pick up.
    """
    from .collection import parsed_date

    own = unread(integration.provider, snapshot, gaps)
    doubt = set(own)
    if not snapshot.log:
        return sorted(doubt), None
    start, since = (parsed_date(snapshot.log[key]) for key in ("window_from", "read_from"))
    if since > start:
        last = db.scalar(select(Audit).where(
            Audit.action == "integration.collected", Audit.target_id == integration.id
        ).order_by(Audit.created_at.desc()).limit(1))
        try:
            before, theirs = parsed_date(last.details["unread_from"]), list(last.details["unread"])
        except (AttributeError, KeyError, TypeError, ValueError):
            before, theirs = since, [EVERY_KIND]
        since = min(since, before)
        if since > start:
            doubt.update(theirs)
    if own:
        # Whole only from the oldest row this read kept, or not at all when that is not what was short.
        kept = [parsed_date(row["observed_at"]) for row in snapshot.blocks] if snapshot.partial_rows is not None else []
        since = min(kept) if kept else parsed_date(snapshot.log["read_to"])
    return ([EVERY_KIND] if EVERY_KIND in doubt else sorted(doubt)), since.isoformat()


def present(rows) -> None:
    """Take the mark, its time and its days off items a read counts as listed without listing them again."""
    for row in rows:
        if MISSING in row.attributes or SINCE in row.attributes:
            row.attributes = {key: value for key, value in row.attributes.items()
                              if key not in (MISSING, SINCE, DAYS)}


def mark_unseen(rows, seen: set[str], doubt: list[str], now: datetime) -> None:
    """Mark what a whole read did not list, with the time it was first missed and the day of this read.

    An item listed again loses the mark with its other attributes, and keeps its identifier and
    everything a person attached to it. `seen` is what the read listed; for a read that picked up
    where an earlier one ended it also holds what earlier reads took from the log and is still
    inside the window, so a resumed read marks exactly what a read of the whole window would.
    The days are those on which a whole read of the kind left the item out, `KEEP_DAYS` at most.
    """
    if EVERY_KIND in doubt:
        return
    day = now.date().isoformat()
    for row in rows:
        if row.id in seen or row.kind in doubt:
            continue
        days = row.attributes.get(DAYS) or []
        if SINCE not in row.attributes or (day not in days and len(days) < KEEP_DAYS):
            row.attributes = {**row.attributes, MISSING: True, SINCE: row.attributes.get(SINCE, now.isoformat()),
                              DAYS: [*days, day]}


def _due(row: Resource, cutoff: datetime) -> bool:
    """Say whether whole reads on enough separate days, over enough time, have left this marked item out."""
    try:
        return (len(row.attributes.get(DAYS) or []) >= KEEP_DAYS
                and utc(datetime.fromisoformat(row.attributes[SINCE])) <= cutoff)
    except (KeyError, TypeError, ValueError):
        return False  # A time nobody can read is not a time that has passed.


def _held(db, integration_id: str, rows: list[Resource], now: datetime) -> set[str]:
    """Items that are kept however long they are missing, because something still rests on them.

    What a person attached: a device assigned to someone or filed by an administrator, and an
    item with a DNS label link on either side. They stay until an administrator removes the
    assignment or the link, or the source. And what Nyctr itself holds: a blocked address with
    an open exception or a waiting request; a device a stored lookup is tied to (a waiting
    request's lookup among them); a guest Nyctr cut off or locked out, and one whose access at
    the source has not run out.
    """
    from .collection import parsed_date
    from .guests import is_guest, standing_of

    ids = [row.id for row in rows]
    held = {row.id for row in rows if row.classification != "unassigned" or row.owner_id}
    held |= set(db.scalars(select(DeviceGrant.device_id).where(
        DeviceGrant.device_id.in_(ids), DeviceGrant.valid_until.is_(None))))
    for link in db.scalars(select(DeviceLink).where(or_(DeviceLink.source_id.in_(ids), DeviceLink.device_id.in_(ids)))):
        held |= {link.source_id, link.device_id}
    names = set(db.scalars(select(Lease.domain).where(
        Lease.integration_id == integration_id, Lease.status.in_(("active", "unconfirmed")))))
    names |= set(db.scalars(select(AccessRequest.domain).where(
        AccessRequest.integration_id == integration_id, AccessRequest.status == "pending")))
    tied = {id_ for pair in db.execute(select(Observation.device_id, Observation.source_device_id).where(
        or_(Observation.device_id.in_(ids), Observation.source_device_id.in_(ids)))).all() for id_ in pair if id_}
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


def _candidates(db, integration_id: str) -> list[str]:
    """Name, in id order, the source's items that may be dropped: read once a run, with no lock held.

    A blocked address is one when no stored lookup of the source names it. Both sides are read
    whole, each by the index on its source, and compared here, so the cost grows with the
    number of addresses plus the number of lookups and not with one times the other. The
    other kinds are the marked items. Each batch looks again at the ones it is given.
    """
    named = set(db.scalars(select(Observation.domain).where(Observation.integration_id == integration_id).distinct()))
    addresses = db.execute(select(Resource.id, Resource.source_id).where(
        Resource.integration_id == integration_id, Resource.kind == "domain")).all()
    marked = db.scalars(select(Resource.id).where(
        Resource.integration_id == integration_id, Resource.kind != "domain", flagged()))
    return sorted([id_ for id_, name in addresses if name not in named] + list(marked))


def _batch(db, integration_id: str, now: datetime, ids: list[str]) -> tuple[list[Resource], str | None]:
    """Drop what has left among these candidates of the source, `BATCH` of them at most.

    Works in the caller's transaction and returns the items that went and why the run must
    stop here, if it must: `BUSY` when a collection has the source, `UNKNOWN` when it may not
    be touched for another reason. The source's row is locked first, as the store step of a
    collection does, and only when its latest collection stored and none is going. So a
    collection, an edit and a removal each wait for this batch or stop the run, and a drop and
    a store of one source never work at once. The candidates are then locked in id order, as
    removal does, and looked at again: every statement under the lock names the items it is
    about, so the lock is held for as long as `BATCH` items take and no longer.
    """
    from .removal import forget

    locked = db.execute(update(Integration).where(
        Integration.id == integration_id, Integration.status.in_(("connected", "partial")),
        Integration.last_error.is_(None), Integration.last_sync.is_not(None),
    ).values(name=Integration.name).execution_options(synchronize_session=False))
    if locked.rowcount != 1:
        going = db.scalar(select(Integration.status).where(Integration.id == integration_id)) == "syncing"
        return [], BUSY if going else UNKNOWN  # Collecting; or failed, edited, never collected, removed.
    last = db.scalar(select(Audit).where(Audit.action == "integration.collected", Audit.target_id == integration_id)
                     .order_by(Audit.created_at.desc()).limit(1))
    doubt = last.details.get("unread") if last is not None else None
    if not isinstance(doubt, list):
        return [], UNKNOWN  # Collected before this was recorded: not known.
    cutoff = utc(db.get(Integration, integration_id).last_sync) - timedelta(days=KEEP_DAYS)
    rows = list(db.scalars(select(Resource).where(
        Resource.integration_id == integration_id, Resource.id.in_(ids),
    ).order_by(Resource.id).with_for_update()))
    names = [row.source_id for row in rows if row.kind == "domain"]
    named = set(db.scalars(select(Observation.domain).where(
        Observation.integration_id == integration_id, Observation.domain.in_(names)))) if names else set()
    gone = [row for row in rows if (row.source_id not in named if row.kind == "domain" else (
        is_missing(row) and EVERY_KIND not in doubt and row.kind not in doubt and _due(row, cutoff)))]
    held = _held(db, integration_id, gone, now) if gone else set()
    gone = [row for row in gone if row.id not in held]
    for row in gone:
        db.expunge(row)
    forget(db, [row.id for row in gone])
    return gone, None


def drop_from(factory, integration_id: str, now: datetime) -> tuple[int, bool]:
    """Drop what has left one source, a batch to a transaction; say how many items went and whether it was busy.

    Busy means a collection had the source, at the start or between two batches, so the rest
    is still to do. One audit record covers the run. Each batch writes into it what has gone
    so far in the same transaction as its deletions, so the record never says more or less
    than was deleted. Between two batches whatever else is waiting to write is let in.
    """
    kinds, record = Counter(), None
    with factory() as db:
        ids = _candidates(db, integration_id)
    for start in range(0, len(ids), BATCH):
        if start:
            time.sleep(PAUSE)
        with factory() as db:
            gone, stop = _batch(db, integration_id, now, ids[start:start + BATCH])
            if gone:
                kinds.update(row.kind for row in gone)
                details = {"name": db.get(Integration, integration_id).name, "resources": kinds.total(),
                           "kinds": dict(kinds)}
                if record is None:
                    entry = Audit(actor_id=None, action="inventory.dropped", target_id=integration_id,
                                  details=details)
                    db.add(entry)
                    db.flush()
                    record = entry.id
                else:
                    db.get(Audit, record).details = details
            db.commit()
        if stop:
            return kinds.total(), stop == BUSY
    return kinds.total(), False


def expire_lookups(factory, now: datetime) -> None:
    """Remove the blocked lookups whose time is up. A request keeps its own copy of what it asked about."""
    with factory() as db:
        db.execute(delete(Observation).where(Observation.expires_at <= now))
        db.commit()


def drop(factory, now: datetime, ran: dict[str, datetime] | None = None) -> int:
    """One run over every source whose hour has come, and say how many items went.

    `ran` holds when each source was last gone through, and is kept by the caller from one run
    to the next; without it every source is gone through. A source a collection had is not
    stamped, so the next run tries it again and no source waits longer than its hour plus the
    collection that held it. A source that fails is logged without its cause text, stamped so
    it is not tried at every tick, and the rest go on.
    """
    with factory() as db:
        ids = list(db.scalars(select(Integration.id).order_by(Integration.id)))
    if ran is not None:
        for gone in set(ran) - set(ids):
            del ran[gone]
    total = 0
    for integration_id in ids:
        if ran is not None and integration_id in ran and now - ran[integration_id] < DROP_EVERY:
            continue
        busy = False
        try:
            count, busy = drop_from(factory, integration_id, now)
            total += count
        except Exception as error:  # noqa: BLE001 - one source's failure must not keep the others uncleared
            log.warning("Dropping what has left a source failed: %s", type(error).__name__)
        if ran is not None and not busy:
            ran[integration_id] = now
    return total
