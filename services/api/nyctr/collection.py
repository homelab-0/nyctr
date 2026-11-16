"""Applying a provider snapshot to the database, and the one collection routine everything shares.

Collection never changes a provider. After a snapshot is stored, deterministic
analysis refreshes findings and the administrator-written guest rule is checked.
"""

import asyncio
import json
import logging
import os
import re
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, delete, func, literal_column, or_, select, text, update
from sqlalchemy.exc import OperationalError

from . import retention
from .models import (
    Audit,
    DeviceLink,
    GuestPass,
    Integration,
    Observation,
    Relationship,
    Resource,
    Sighting,
    utc,
    utcnow,
)
from .schedule import drop_retry
from .security import audit

SECRET_REF = re.compile(r"NYCTR_CONNECTOR_SECRET_[A-Z0-9_]{1,100}")
# The longest a collection may run before it is stopped as failed. A backstop only: reading ends
# at 60 seconds and waiting for a turn at a paced source at 120, so it is never reached in order.
# It must stay above those two together and inside the five-minute lease on the source.
BACKSTOP_SECONDS = 210
# How far before the end of the last stored read a resumed read starts: the five minutes a source's
# clock may differ from ours (the same allowance a future timestamp gets) and five for its log to settle.
RESUME_OVERLAP = timedelta(minutes=10)
# A holder writes this often, from its own thread. A heartbeat older than the bound means that
# holder cannot be shown alive, so the lease is free instead of being honoured for five minutes.
# Five minutes remains the longest a lease is kept even when the heartbeat is fresh. The bound sits
# well above one missed write, so a loop that is busy does not by itself let a second copy collect.
HEARTBEAT_EVERY = 5
HEARTBEAT_BOUND = timedelta(seconds=60)
# Milliseconds a heartbeat or a release waits when SQLite's one writer is busy. The next beat or tick tries
# again. A row someone else holds is a collection that is still running, so waiting it out would stall the rest.
SQLITE_LOCK_WAIT_MS = 50
LEASE_MINUTES = 5
# What a card can say. Restart is only for a start that can see a different holder had the lease.
CUT_SHORT = "The last collection was cut short by a restart."
NO_SIGN = "No sign of life from the copy that was collecting."
STOPPED = "The last collection was stopped."
CAUSE_STATUS = {CUT_SHORT: "interrupted", NO_SIGN: "silent", STOPPED: "stopped"}
LEAVING = {status: sentence for sentence, status in CAUSE_STATUS.items()}
# How many identifiers one lookup statement asks about.
LOOKUP_BATCH = 500
log = logging.getLogger("nyctr.collection")


def parsed_date(value):
    """Parse an ISO source timestamp or datetime and normalize it to timezone-aware UTC."""
    if isinstance(value, datetime):
        return utc(value)
    return utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _owners(db, model, ids) -> dict[str, str]:
    """Say which of these identifiers are stored and for which source, a batch per statement."""
    ids, found = list(dict.fromkeys(ids)), {}
    for at in range(0, len(ids), LOOKUP_BATCH):
        found.update(db.execute(select(model.id, model.integration_id)
                                .where(model.id.in_(ids[at:at + LOOKUP_BATCH]))).all())
    return found


def apply_snapshot(db, integration, snapshot, settings, gaps=()):
    """Stage a complete integration snapshot while preserving local ownership and event expiry.

    Reject cross-integration identities and relationships outside the snapshot.
    What a whole read did not list is marked missing (`retention.mark_unseen`; `gaps` are the
    codes this read recorded, and `retention.standing` says what they and the reads before
    leave in doubt), relationships are replaced, and replayed
    observations keep their original expiry. The caller commits or rolls back
    the full collection transaction; provider infrastructure is never modified.

    What is stored is read in a fixed number of statements plus one per
    `LOOKUP_BATCH` new identifiers, never one per item. Returns how many items
    and how many lookups were new.
    """
    now = utcnow()
    seen = set()
    # A read that picked up where an earlier one ended names only what the newly read rows name.
    window_from = parsed_date(snapshot.log["window_from"]) if snapshot.log else None
    resumed = window_from is not None and parsed_date(snapshot.log["read_from"]) > window_from
    stored = {row.id: row for row in db.scalars(select(Resource).where(Resource.integration_id == integration.id))}
    if _owners(db, Resource, [data["id"] for data in snapshot.resources if data["id"] not in stored]):
        raise ValueError("Resource identity crosses integration boundary")
    new_items = 0
    for data in snapshot.resources:
        row = stored.get(data["id"])
        values = {key: data.get(key) for key in ["name", "kind", "provider", "source_id", "site_id", "evidence_kind"]}
        values.update(observed_at=parsed_date(data.get("observed_at", now)), attributes=data.get("attributes", {}))
        if row:
            for key, value in values.items():
                setattr(row, key, value)
        else:
            # Importing an endpoint never assigns it to a person.
            row = stored[data["id"]] = Resource(id=data["id"], integration_id=integration.id,
                                                classification="unassigned", owner_id=None, **values)
            db.add(row)
            new_items += 1
        seen.add(data["id"])
    db.flush()
    # Relationships may join only what this snapshot itself names.
    named = set(seen)
    if resumed:
        # What earlier reads stored from the log still stands while it is inside the window, exactly
        # as a read of the whole window would find it; older than that, it is missing like anything else.
        carried = [row for row in stored.values()
                   if row.id not in seen and row.evidence_kind == "observed" and utc(row.observed_at) >= window_from]
        retention.present(carried)
        seen |= {row.id for row in carried}
    # Keep previously seen inventory and ownership; mark what this read left out only if it was whole.
    retention.mark_unseen(stored.values(), seen, retention.standing(db, integration, snapshot, gaps)[0], now)
    kept = {}
    if resumed:
        again = {data["id"] for data in snapshot.relationships}
        for row in db.scalars(select(Relationship).where(Relationship.integration_id == integration.id)):
            if row.id in again or (row.evidence_kind == "observed" and utc(row.observed_at) >= window_from):
                kept[row.id] = row
            else:
                db.delete(row)
    else:
        db.execute(delete(Relationship).where(Relationship.integration_id == integration.id))
    for data in snapshot.relationships:
        if data["source"] not in named or data["target"] not in named:
            raise ValueError("Relationship endpoints are outside this snapshot")
        values = {key: data[key] for key in ["id", "source", "target", "kind", "provider", "evidence_kind"]}
        values.update(observed_at=parsed_date(data.get("observed_at", now)), attributes=data.get("attributes", {}))
        if row := kept.get(data["id"]):
            for key, value in values.items():
                setattr(row, key, value)
        else:
            kept[data["id"]] = Relationship(integration_id=integration.id, **values)
            db.add(kept[data["id"]])
    links = {link.source_id: link for link in db.scalars(select(DeviceLink))}
    guests_by_name: dict[str, list[str]] = {}
    for row in db.scalars(select(Resource).where(Resource.kind == "client")):
        if isinstance(row.attributes.get("guest"), dict):
            guests_by_name.setdefault(row.name.casefold(), []).append(row.id)
    fresh = []
    for data in snapshot.blocks:
        when = parsed_date(data["observed_at"])
        expires = min(parsed_date(data.get("expires_at", when + timedelta(hours=settings.block_retention_hours))),
                      when + timedelta(hours=settings.block_retention_hours))
        if expires > now and when <= now + timedelta(minutes=5):
            fresh.append((data, when, expires))
    owners = _owners(db, Observation, [data["id"] for data, _when, _expires in fresh])
    new_lookups = 0
    for data, when, expires in fresh:
        if owner := owners.get(data["id"]):
            if owner != integration.id:
                raise ValueError("Observation identity crosses integration boundary")
            continue  # Do not extend the lifetime of a replayed event.
        owners[data["id"]] = integration.id
        new_lookups += 1
        values = {key: data.get(key) for key in ["id", "device_id", "device_name", "domain", "source", "reason",
                                                "evidence_kind", "attribution", "risk_score", "risk_explanation",
                                                "reason_codes", "source_device_id"]}
        link = links.get(values["source_device_id"]) if values["source_device_id"] else None
        if values["device_id"] is None and link and when >= utc(link.created_at):
            # An administrator stated which device this provider label is. Only later events qualify.
            values.update(device_id=link.device_id, attribution="assigned")
        elif values["device_id"] is None and values["attribution"] == "unverified":
            # A guest device with the same, unique name. Inferred: never shown to members.
            matches = guests_by_name.get(str(values["device_name"]).casefold(), [])
            if len(matches) == 1:
                values.update(device_id=matches[0], attribution="inferred")
        db.add(Observation(integration_id=integration.id, observed_at=when, expires_at=expires, **values))
    _store_passes(db, integration, snapshot, now)
    _record_sightings(db, integration, snapshot, now)
    # A read that stopped at its bound is stored, but never reported as a complete one.
    integration.status = "connected" if snapshot.partial_rows is None else "partial"
    integration.last_sync = now
    integration.last_error = None
    clear_lease(integration)
    integration.capabilities = snapshot.capabilities
    return new_items, new_lookups


def _store_passes(db, integration, snapshot, now):
    """Mirror the source's guest passes, ending passes that disappeared.

    A snapshot without a pass list (`None`) says the source did not report
    passes this time, so nothing stored is touched.
    """
    if snapshot.passes is None:
        return
    seen = set()
    known = {row.voucher_id: row for row in db.scalars(
        select(GuestPass).where(GuestPass.integration_id == integration.id)) if row.voucher_id}
    for data in snapshot.passes:
        seen.add(data["id"])
        row = known.get(data["id"])
        if row is None:
            row = GuestPass(integration_id=integration.id, voucher_id=data["id"], code=str(data["code"])[:64],
                            name=str(data.get("name") or "Guest pass")[:160],
                            minutes=int(data.get("minutes") or 0), execution="applied",
                            created_at=parsed_date(data["created_at"]) if data.get("created_at") else now)
            db.add(row)
        row.guest_limit = data.get("guest_limit")
        row.data_limit_mb = data.get("data_limit_mb")
        row.guest_count = int(data.get("guest_count") or 0)
        row.activated_at = parsed_date(data["activated_at"]) if data.get("activated_at") else None
        row.expires_at = parsed_date(data["expires_at"]) if data.get("expires_at") else None
        if data.get("expired") and row.ended_at is None:
            row.ended_at = row.expires_at or now
    for pass_id, row in known.items():
        if pass_id not in seen and row.ended_at is None:
            row.ended_at = now


def _record_sightings(db, integration, snapshot, now):
    """Extend or start each guest client's attachment record so movement between access points is kept."""
    guests = [data for data in snapshot.resources
              if data["kind"] == "client" and isinstance(data["attributes"].get("guest"), dict)]
    latest: dict[str, Sighting] = {}
    for at in range(0, len(guests), LOOKUP_BATCH):
        newest = (select(Sighting.device_id, func.max(Sighting.last_seen).label("at"))
                  .where(Sighting.device_id.in_([data["id"] for data in guests[at:at + LOOKUP_BATCH]]))
                  .group_by(Sighting.device_id).subquery())
        latest.update((row.device_id, row) for row in db.scalars(select(Sighting).join(newest, and_(
            Sighting.device_id == newest.c.device_id, Sighting.last_seen == newest.c.at))))
    for data in guests:
        uplink, last = data["attributes"].get("uplink"), latest.get(data["id"])
        if last and last.uplink_id == uplink and now - utc(last.last_seen) < timedelta(hours=6):
            last.last_seen = now
        else:
            latest[data["id"]] = Sighting(device_id=data["id"], uplink_id=uplink, first_seen=now, last_seen=now)
            db.add(latest[data["id"]])


# Failures that may pass by waiting: a broken connection, a timeout, a rate limit.
# A server error at the source is marked transient on the error itself.
PASSING = {"transport", "timeout", "rate_limit"}


@dataclass(frozen=True)
class Failure:
    """Why one collection failed, as the scheduled retry needs it: may it pass, and when to come back."""
    message: str
    may_pass: bool
    retry_after: int | None = None


def classify(exc: BaseException, message: str) -> Failure:
    """Sort a collection failure by its typed category, never by its text.

    A refused key, an address that is not allowed, a setting the integration
    rejects, a certificate problem or an unknown fault will not pass by waiting.
    """
    from .integrations import IntegrationError

    if isinstance(exc, IntegrationError):
        may_pass = exc.category in PASSING or exc.transient
        wait = exc.retry_after if exc.category == "rate_limit" else None
        return Failure(message, may_pass, wait)
    return Failure(message, isinstance(exc, TimeoutError))


def after_collection(db, settings):
    """Run deterministic analysis on stored evidence and return guest devices the written rule cuts off."""
    from .analysis import refresh_findings
    from .guests import evaluate_rule

    refresh_findings(db)
    return evaluate_rule(db, settings)


def analyse(factory, settings):
    """Run the analysis in a session and transaction of its own and return who the guest rule cuts off.

    Blocking database work over everything stored: call it through `off_loop`. One analysis runs
    at a time in a process, so two never add the same new finding.
    """
    from .analysis import ONE_AT_A_TIME

    with ONE_AT_A_TIME, factory() as db:
        due = after_collection(db, settings)
        db.commit()
        return due


def last_gaps(db, integration) -> list[dict[str, str]]:
    """Say what the last collection that stored data could not read, in the integration's own words.

    Read from that collection's audit record: the next stored collection replaces
    it and a failed one leaves it alone. Only fixed codes are kept there, so no
    address, secret name or source answer can be repeated here.
    """
    from .integrations import registry
    from .integrations.core import describe_gaps

    last = db.scalar(select(Audit).where(Audit.action == "integration.collected", Audit.target_id == integration.id)
                     .order_by(Audit.created_at.desc()).limit(1))
    codes = last.details.get("gaps") if last is not None else None
    if not isinstance(codes, list):
        return []
    causes = last.details.get("gap_causes")
    causes = causes if isinstance(causes, dict) else {}
    definition = registry.find(integration.provider)
    described = describe_gaps(definition.gap_notes if definition else {},
                              {code: causes.get(code) for code in codes if isinstance(code, str)})
    return [{"id": code, "title": title, "summary": text} for code, title, text in described]


def _resume_from(db, integration) -> tuple[datetime | None, str | None]:
    """Say where the next read of this source's log may start, or None to read its whole window.

    A read picks up when the last stored collection or edit of the source is a stored collection
    that said where its log read ended: not after an edit or a first run. A failed attempt stored
    nothing, so the stored read before it still says where. The read starts `RESUME_OVERLAP` before
    that end, and never later than `RESUME_OVERLAP` before the newest lookup stored for the source,
    whose time is the source's own: a source clock behind ours then loses nothing. With no lookup
    stored the whole window is read. What is read twice is stored once.

    Also returns the time that record says the stored log is whole from.
    """
    last = db.scalar(select(Audit).where(
        Audit.target_id == integration.id, Audit.action.in_(("integration.collected", "integration.updated"))
    ).order_by(Audit.created_at.desc()).limit(1))
    newest = db.scalar(select(func.max(Observation.observed_at)).where(Observation.integration_id == integration.id))
    try:
        return min(parsed_date(last.details["read_to"]), utc(newest)) - RESUME_OVERLAP, last.details.get("whole_from")
    except (AttributeError, KeyError, TypeError, ValueError):
        return None, None


def _whole_from(snapshot, earlier: str | None) -> datetime | None:
    """Say the oldest time the stored log has no hole after, once this snapshot is stored.

    A read that kept only its most recent rows leaves a hole before the oldest row it kept. A
    complete read of the whole window leaves none. A complete read that picked up joins what was
    stored, so the time the last record gave still stands. None when the snapshot read no log.
    """
    if not snapshot.log:
        return None
    window_from, read_from = (parsed_date(snapshot.log[key]) for key in ("window_from", "read_from"))
    if snapshot.partial_rows is not None:
        return min((parsed_date(data["observed_at"]) for data in snapshot.blocks),
                   default=parsed_date(snapshot.log["read_to"]))
    if read_from <= window_from:
        return window_from
    try:
        return parsed_date(earlier)
    except (AttributeError, TypeError, ValueError):
        return read_from


async def off_loop(work):
    """Run blocking database work on a worker thread, so the server goes on answering meanwhile.

    The work is waited for however often the caller is cancelled: it ends as a whole, stored or
    not, before the caller goes on. Work that uses a session opens it itself, on its own thread.
    """
    task = asyncio.ensure_future(asyncio.to_thread(work))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        while not task.done():
            try:
                await asyncio.wait([task])
            except asyncio.CancelledError:
                continue
        raise


def show_log() -> None:
    """Let Nyctr's own log lines through at the level a collection is reported at.

    The server configures only its own loggers, so without this a line about a
    collection would be dropped. Logging an operator set up already is left as it is.
    """
    ours = logging.getLogger("nyctr")
    ours.setLevel(logging.INFO)
    if not ours.handlers and not logging.getLogger().handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s:     %(message)s"))
        ours.addHandler(handler)


def _report(event: str, name: str, **facts) -> None:
    """Write one log line about a collection: counts and times only, the source by its saved name."""
    log.info("Collection %s: source=%s %s", event, json.dumps(name, ensure_ascii=False),
             " ".join(f"{key}={value}" for key, value in facts.items()))


def begin_holder(engine) -> str:
    """Give this start of Nyctr a holder id no earlier start can still be using."""
    engine.nyctr_holder = uuid.uuid4().hex
    return engine.nyctr_holder


def holder_id(source) -> str:
    """The holder id of the start `source` belongs to.

    `source` is the session factory, its engine, or a connection checked out from that engine.
    A collection is sometimes given a function in place of the session factory, so the id is read
    from the engine and not from that function.
    """
    bind = getattr(source, "kw", None)
    if isinstance(bind, dict) and "bind" in bind:
        source = bind["bind"]
    engine = getattr(source, "engine", source)
    return getattr(engine, "nyctr_holder", None) or begin_holder(engine)


def clear_lease(row) -> None:
    """Drop the lease stamps. The caller chooses the status those stamps were holding."""
    row.sync_started_at = row.sync_holder = row.sync_heartbeat = None


def db_now(bind):
    """The database clock, written so a later comparison of the same value matches.

    SQLite's clock has milliseconds. The stored text keeps six fractional digits, which is how a
    datetime is bound again, so the claim's start time still identifies that claim. PostgreSQL
    `now()` already round-trips.
    """
    if bind.dialect.name == "sqlite":
        return func.printf("%s000", func.strftime("%Y-%m-%d %H:%M:%f", "now"))
    return func.now()


def db_ago(bind, seconds: int):
    """A timestamp this many seconds before the database clock, computed in the statement.

    Copies compare this clock and no other, so a process clock set ahead or behind cannot free a
    live lease or keep a dead one.
    """
    seconds = int(seconds)
    if bind.dialect.name == "sqlite":
        return func.datetime("now", f"-{seconds} seconds")
    return func.now() - literal_column(f"interval '{seconds} seconds'")


def abandoned_sql(bind):
    """A syncing row whose holder cannot be shown alive, or whose lease is already five minutes old.

    Both ages are the database clock. A heartbeat exactly at the bound is still held: the comparison
    is older-than, so one write that lands on the bound does not free the lease.
    """
    stale = db_ago(bind, int(HEARTBEAT_BOUND.total_seconds()))
    aged = db_ago(bind, LEASE_MINUTES * 60)
    return or_(
        Integration.sync_holder.is_(None),
        Integration.sync_heartbeat.is_(None),
        Integration.sync_heartbeat < stale,
        Integration.sync_started_at.is_(None),
        Integration.sync_started_at < aged,
    )


def lease_free_sql(bind):
    """A source that is not being collected, or whose collection can no longer be shown to be running."""
    return or_(Integration.status != "syncing", abandoned_sql(bind))


def claim_values(holder, bind):
    """The stamps a claim writes. The database fills both times, so the heartbeat starts as new as the claim."""
    when = db_now(bind)
    return {"status": "syncing", "sync_started_at": when, "sync_holder": holder, "sync_heartbeat": when}


def _cause(row, restart_of: str | None) -> str:
    """Which sentence this abandoned lease gets.

    Restart only when the caller is a start of Nyctr and the lease names some other holder. A missing
    holder is not a known restart. A tick, a claim, an edit, a removal and a diagnostic pass no
    `restart_of`, so a missed beat stays no sign of life.
    """
    if restart_of and row.sync_holder and row.sync_holder != restart_of:
        return CUT_SHORT
    return NO_SIGN


def settle_abandoned(db, row, cause: str) -> bool:
    """Record why this collection ended and leave the source not collecting.

    The caller has already locked the row as abandoned, on the database clock. False when the row is
    no longer that syncing lease. The sentence is not stored as a failure, so the card does not say
    the collection failed.
    """
    if row.status != "syncing" or cause not in CAUSE_STATUS:
        return False
    row.status = CAUSE_STATUS[cause]
    row.last_error = None
    clear_lease(row)
    db.flush()
    audit(db, None, "integration.collection_interrupted", row.id, name=row.name, why=cause)
    db.flush()
    return True


def _busy_timeout(db, milliseconds: int) -> None:
    """How long this SQLite connection waits when the one writer is busy. PostgreSQL has no such wait."""
    if db.get_bind().dialect.name == "sqlite":
        db.execute(text(f"PRAGMA busy_timeout = {int(milliseconds)}"))


def _lock_abandoned(db, integration_id: str) -> bool:
    """Lock this abandoned row without waiting. False when it is no longer abandoned, or someone else holds it.

    A held row is a collection that is still in its store, so it is alive whatever its heartbeat says.
    PostgreSQL skips the row. SQLite has one writer, so a short wait gives up and the next tick tries again.
    The caller sets that short wait for the whole release, including the read of which rows are due.
    """
    bind = db.get_bind()
    where = (Integration.id == integration_id, Integration.status == "syncing", abandoned_sql(bind))
    if bind.dialect.name == "postgresql":
        return db.scalar(select(Integration.id).where(*where).with_for_update(skip_locked=True)) is not None
    locked = db.execute(update(Integration).where(*where).values(name=Integration.name).execution_options(
        synchronize_session="fetch"))
    return locked.rowcount == 1


def release_abandoned(db, *, restart_of: str | None = None, only: str | None = None) -> list[str]:
    """Free every syncing lease whose holder is gone, in id order, and record each once.

    The caller commits. A row this call cannot lock at once is left for the next tick: someone else is
    still using it, or SQLite's writer is busy. `only` limits that to one source, which a collection does
    in its own transaction before it claims. `restart_of` is this start's holder id, and only the
    start-up call passes it. Two copies still cannot collect one source at once: a live holder's
    heartbeat is newer than the bound, so it does not match here, and the claim that follows is one
    conditional update of the row.
    """
    _busy_timeout(db, SQLITE_LOCK_WAIT_MS)
    try:
        where = [Integration.status == "syncing", abandoned_sql(db.get_bind())]
        if only is not None:
            where.append(Integration.id == only)
        ids = list(db.scalars(select(Integration.id).where(*where).order_by(Integration.id)))
        freed = []
        for integration_id in ids:
            if not _lock_abandoned(db, integration_id):
                continue
            row = db.get(Integration, integration_id)
            db.refresh(row)
            if settle_abandoned(db, row, _cause(row, restart_of)):
                freed.append(integration_id)
        return freed
    except OperationalError:
        db.rollback()
        return []
    finally:
        _busy_timeout(db, 5000)


def _record_stopped(factory, integration_id: str, started, holder: str) -> None:
    """Record a collection that was cancelled before it stored.

    The update matches this claim's holder and the start time read back from the database, so a lease
    taken since is left alone. A store that already finished is not passed here.
    """
    with factory() as db:
        locked = db.execute(update(Integration).where(
            Integration.id == integration_id, Integration.status == "syncing",
            Integration.sync_started_at == started, Integration.sync_holder == holder,
        ).values(name=Integration.name).execution_options(synchronize_session="fetch"))
        if locked.rowcount != 1:
            db.rollback()
            return
        row = db.get(Integration, integration_id)
        db.refresh(row)
        row.status = CAUSE_STATUS[STOPPED]
        row.last_error = None
        clear_lease(row)
        db.flush()
        audit(db, None, "integration.collection_interrupted", row.id, name=row.name, why=STOPPED)
        db.commit()


def _beat_one(factory, holder, integration_id: str) -> None:
    """Stamp one lease from the database clock, and do not wait if its row is already held.

    Each source commits on its own, so a store that holds one row cannot keep the others from being stamped.
    A missed row is tried again on the next beat. The store that holds it refreshes that lease itself.
    """
    with factory() as db:
        bind = db.get_bind()
        where = (
            Integration.id == integration_id, Integration.status == "syncing", Integration.sync_holder == holder,
        )
        _busy_timeout(db, SQLITE_LOCK_WAIT_MS)
        try:
            if bind.dialect.name == "postgresql":
                if db.scalar(select(Integration.id).where(*where).with_for_update(skip_locked=True)) is None:
                    db.rollback()
                    return
            db.execute(update(Integration).where(*where).values(
                sync_heartbeat=db_now(bind)).execution_options(synchronize_session=False))
            db.commit()
        except OperationalError:
            db.rollback()
        finally:
            _busy_timeout(db, 5000)


def _beat_once(factory, holder) -> None:
    """Stamp every lease this start holds, from the database clock. A row held by anyone else is left alone."""
    with factory() as db:
        _busy_timeout(db, SQLITE_LOCK_WAIT_MS)
        try:
            ids = list(db.scalars(select(Integration.id).where(
                Integration.status == "syncing", Integration.sync_holder == holder,
            ).order_by(Integration.id)))
        except OperationalError:
            db.rollback()
            return
        finally:
            _busy_timeout(db, 5000)
    for integration_id in ids:
        try:
            _beat_one(factory, holder, integration_id)
        except Exception as error:  # noqa: BLE001 - one source must not stop the others being stamped
            log.warning("Collection heartbeat failed: %s", type(error).__name__)


class Heartbeat:
    """Write this start's heartbeat on a thread that does not use the server's loop.

    The first write waits one interval, so a start that stops at once does not touch a lease.
    One failed write is logged and the loop continues. `stop` wakes the wait and joins the thread.
    """

    def __init__(self, factory):
        self._factory = factory
        self._holder = holder_id(factory)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="nyctr-collection-heartbeat", daemon=True)

    def start(self):
        """Begin the thread. The caller stops it before disposing the engine."""
        self._thread.start()
        return self

    def stop(self) -> None:
        """Wake the thread and wait until it has left the database."""
        self._stop.set()
        self._thread.join(timeout=HEARTBEAT_EVERY + 2)

    def _run(self) -> None:
        while not self._stop.wait(HEARTBEAT_EVERY):
            try:
                _beat_once(self._factory, self._holder)
            except Exception as error:  # noqa: BLE001 - one failed beat must not end the thread
                log.warning("Collection heartbeat failed: %s", type(error).__name__)


def _still_holds(db, integration_id: str, started, holder) -> bool:
    """Lock the source row and say whether the lease taken at `started` by `holder` is still this caller's.

    Refreshing the heartbeat from the database clock keeps a long store from looking abandoned while
    this row is locked. The holder is part of the match: the same start time with a new holder is not ours.
    """
    return db.execute(update(Integration).where(
        Integration.id == integration_id, Integration.status == "syncing",
        Integration.sync_started_at == started, Integration.sync_holder == holder,
    ).values(sync_heartbeat=db_now(db.get_bind())).execution_options(synchronize_session=False)).rowcount == 1


async def collect_integration(factory, settings, integration_id: str, actor: str | None, *,
                              attempt: int | None = None, hold=None):
    """Collect one live integration under a database lease and store its snapshot atomically.

    Returns (snapshot, error message). A second caller during a running
    collection gets ("busy"); a read whose lease was taken over or ended by an
    edit stores nothing and gets ("replaced"). A snapshot that kept only the most recent rows is
    stored and audited as partial, not as an error. Failure rolls back the snapshot, records a
    sanitized error and releases the lease. Never performs a provider change.

    A scheduled collection passes `attempt` (0 for the run, 1-3 for retries) and
    `hold(db, failure)`, which may stage a retry in the same transaction and return
    when it is due. While one is due the source keeps its previous status; the
    error is still recorded and the attempt audited.
    """
    from .integrations import IntegrationError, collect
    from .integrations.core import capture_probe

    with factory() as db:
        integration = db.get(Integration, integration_id)
        if not integration:
            return None, "missing"
        if not SECRET_REF.fullmatch(integration.secret_ref):
            return None, "secret_ref"
        api_key = os.environ.get(integration.secret_ref)
        if not api_key:
            return None, "secret"
        # The name that supplied the secret, and the status to put back if this read fails. An edit can
        # land during the lookup above. The rollback below ends this snapshot, so a later load already
        # includes that edit; comparing against the later load would keep the secret resolved here.
        read_ref = integration.secret_ref
        previous = integration.status
        holder = holder_id(db.get_bind())
        # The read above holds a transaction. End it before freeing a dead holder, or that write waits
        # on this read and this read waits on that write. The record commits on its own, so a busy
        # result or a later rollback cannot erase it. Same session, so a caller counting sessions
        # still sees one for this read and one for the store.
        db.rollback()
        release_abandoned(db, only=integration_id)
        db.commit()
        integration = db.get(Integration, integration_id)
        if integration is None:
            return None, "missing"
        locked = db.execute(update(Integration).where(
            Integration.id == integration.id, lease_free_sql(db.get_bind()),
        ).values(**claim_values(holder, db.get_bind())).execution_options(synchronize_session="fetch"))
        if locked.rowcount != 1:
            db.rollback()
            return None, "busy" if db.get(Integration, integration_id) else "missing"
        db.commit()
        # The start time the store matches is the one the database wrote, not this process's clock.
        # An edit may have been saved after the read above and before the lease. None can be while
        # the lease is held, so read the source again and use only the settings saved now.
        db.refresh(integration)
        started = integration.sync_started_at
        if integration.secret_ref != read_ref:
            api_key = os.environ.get(integration.secret_ref)
            if not api_key:
                # A new secret name always leaves the source "configured"; give the lease back as that.
                integration.status = "configured"
                clear_lease(integration)
                db.commit()
                return None, "secret"
        # Nobody else stores for this source while the lease is held, so its last record is final.
        since, earlier = _resume_from(db, integration)
        name, clock, stored = integration.name, time.monotonic(), []
        provider, config = integration.provider, integration.config
        # The store has a session of its own, so this one holds no transaction open meanwhile.
        db.rollback()
        told = {"by": "schedule" if attempt is not None else "person" if actor else "nudge", "retry": attempt or 0}
        _report("started", name, **told, reading="since_last_read" if since else "whole_window")

        def spent(evidence):
            """What the collection cost, for the closing log line."""
            return {"seconds": round(time.monotonic() - clock, 2), "requests": evidence.requests,
                    "waited_seconds": round(evidence.waited, 2), **told}
        try:
            # The same recorder the connection test opens, so a collection keeps the gaps it hit.
            # The time limit is a backstop only; see BACKSTOP_SECONDS.
            with capture_probe() as evidence:
                snapshot = await asyncio.wait_for(
                    collect(provider, integration_id, config, api_key, **({"since": since} if since else {})),
                    timeout=BACKSTOP_SECONDS)
            # Partial while rows this read set out to read were left unread, and for as long as a
            # hole an earlier read left is still inside the window.
            whole = _whole_from(snapshot, earlier)
            partial = snapshot.partial_rows is not None or (
                whole is not None and whole > parsed_date(snapshot.log["window_from"]))

            def store():
                """Store the snapshot and its record in one transaction; None if the lease is no longer ours.

                The session is opened here, on the thread that uses it, and closed here: nothing
                the caller does, cancelled or not, can close it under the store.
                """
                with factory() as own:
                    # Lock the source row before any other row, and store only while this lease is still ours.
                    # A lease older than five minutes can be taken over, and an edit can then move the source;
                    # either clears or replaces the stamp, so a read that outlived its lease stores nothing.
                    if not _still_holds(own, integration_id, started, holder):
                        return None
                    source = own.get(Integration, integration_id)
                    doubt, sure_from = retention.standing(own, source, snapshot, evidence.gaps)
                    new = apply_snapshot(own, source, snapshot, settings, evidence.gaps)
                    if partial:
                        source.status = "partial"
                    audit(own, actor, "integration.collected", source.id, name=source.name,
                          resources=len(snapshot.resources), observations=len(snapshot.blocks), partial=partial,
                          **({"rows_kept": snapshot.partial_rows} if snapshot.partial_rows is not None else {}),
                          gaps=sorted(evidence.gaps),
                          unread=doubt, **({"unread_from": sure_from} if sure_from else {}),
                          **({"gap_causes": {code: sorted(causes)
                                             for code, causes in sorted(evidence.gap_causes.items())}}
                             if evidence.gap_causes else {}),
                          **({"read_to": snapshot.log["read_to"], "whole_from": whole.isoformat()}
                             if snapshot.log else {}),
                          **({"attempt": attempt} if attempt is not None else {}))
                    own.commit()
                    stored.append(True)
                    return new

            # Off the server's loop: storing is blocking database work and requests go on meanwhile.
            read_at = time.monotonic()
            new = await off_loop(store)
            if new is None:
                _report("ended", name, outcome="replaced", **spent(evidence))
                return None, "replaced"
            _report("ended", name, outcome="partial" if partial else "stored", **spent(evidence),
                    store_seconds=round(time.monotonic() - read_at, 2), items_read=len(snapshot.resources),
                    items_new=new[0], lookups_read=len(snapshot.blocks), lookups_new=new[1])
        except asyncio.CancelledError:
            # Stopped by the server or a dropped request. A store already begun was waited for.
            # A read that stored nothing is recorded now, as stopped, and is not left until the lease ages out.
            if not stored:
                _record_stopped(factory, integration_id, started, holder)
            _report("ended", name, outcome="stopped", **spent(evidence), stored=bool(stored))
            raise
        except Exception as exc:
            db.rollback()
            if not _still_holds(db, integration_id, started, holder):
                db.rollback()
                _report("ended", name, outcome="replaced", **spent(evidence))
                return None, "replaced"
            integration = db.get(Integration, integration_id)
            integration.last_error = (str(exc) if isinstance(exc, IntegrationError)
                                      else "Collection failed. Check that the source can be reached and how it is set up.")
            failure = classify(exc, integration.last_error)
            try:
                retry_at = hold(db, failure) if hold else None
            except Exception:  # noqa: BLE001 - e.g. a copy claimed the next run meanwhile; that run covers it
                db.rollback()
                if not _still_holds(db, integration_id, started, holder):
                    db.rollback()
                    _report("ended", name, outcome="replaced", **spent(evidence))
                    return None, "replaced"
                # The failure is final, so the claimed retry that led here ends with it.
                drop_retry(db, integration_id)
                integration = db.get(Integration, integration_id)
                integration.last_error, retry_at = failure.message, None
            keep = retry_at and previous not in {"syncing", *LEAVING}
            integration.status = previous if keep else "error"
            clear_lease(integration)
            # `why` is the sentence the source's card shows: Nyctr's own words, never the source's answer.
            details = {"why": integration.last_error, **({} if attempt is None else {"attempt": attempt})}
            if retry_at:
                details["retry_at"] = retry_at.isoformat()
            audit(db, actor, "integration.collection_failed", integration.id, name=integration.name, **details)
            db.commit()
            _report("ended", name, outcome="failed", **spent(evidence),
                    cause=getattr(exc, "category", "other"), retry_staged=bool(retry_at))
            return None, integration.last_error
        return snapshot, None
