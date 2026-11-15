"""Applying a provider snapshot to the database, and the one collection routine everything shares.

Collection never changes a provider. After a snapshot is stored, deterministic
analysis refreshes findings and the administrator-written guest rule is checked.
"""

import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import and_, delete, func, or_, select, update

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


def apply_snapshot(db, integration, snapshot, settings):
    """Stage a complete integration snapshot while preserving local ownership and event expiry.

    Reject cross-integration identities and relationships outside the snapshot.
    Missing inventory is marked stale, relationships are replaced, and replayed
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
        seen |= {row.id for row in stored.values()
                 if row.evidence_kind == "observed" and utc(row.observed_at) >= window_from}
    # Keep previously seen inventory and ownership but explicitly flag missing sources.
    for row in db.scalars(select(Resource).where(Resource.integration_id == integration.id)):
        if row.id not in seen:
            row.attributes = {**row.attributes, "missing_from_latest_snapshot": True}
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
    integration.sync_started_at = None
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


def _resume_from(db, integration) -> datetime | None:
    """Say where the next read of this source's log may start, or None to read its whole window.

    A read resumes only from the last thing that happened to the source being a stored collection
    that said where its log read ended: not after a failed attempt, an edit, or a first run. It
    starts `RESUME_OVERLAP` before that end, and what is read twice is stored once.
    """
    if integration.last_error:
        return None
    last = db.scalar(select(Audit).where(
        Audit.target_id == integration.id, Audit.action.in_(("integration.collected", "integration.updated"))
    ).order_by(Audit.created_at.desc()).limit(1))
    try:
        return parsed_date(last.details["read_to"]) - RESUME_OVERLAP
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


async def off_loop(work):
    """Run blocking database work on a worker thread, so the server goes on answering meanwhile.

    If the caller is cancelled the work is still waited for: it ends as a whole,
    stored or not, before the session it uses is closed.
    """
    task = asyncio.ensure_future(asyncio.to_thread(work))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await asyncio.wait([task])
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


def _still_holds(db, integration_id: str, started) -> bool:
    """Lock the source row and say whether the lease taken at `started` is still this caller's."""
    return db.execute(update(Integration).where(
        Integration.id == integration_id, Integration.status == "syncing", Integration.sync_started_at == started
    ).values(name=Integration.name).execution_options(synchronize_session=False)).rowcount == 1


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
        started = utcnow()
        previous = integration.status
        locked = db.execute(update(Integration).where(
            Integration.id == integration.id,
            or_(Integration.status != "syncing", Integration.sync_started_at < started - timedelta(minutes=5))
        ).values(status="syncing", sync_started_at=started).execution_options(synchronize_session="fetch"))
        if locked.rowcount != 1:
            db.rollback()
            return None, "busy" if db.get(Integration, integration_id) else "missing"
        db.commit()
        # An edit may have been saved after the read above and before the lease. None can be while
        # the lease is held, so read the source again and use only the settings saved now.
        read_ref = integration.secret_ref
        db.refresh(integration)
        if integration.secret_ref != read_ref:
            api_key = os.environ.get(integration.secret_ref)
            if not api_key:
                # A new secret name always leaves the source "configured"; give the lease back as that.
                integration.status, integration.sync_started_at = "configured", None
                db.commit()
                return None, "secret"
        # Nobody else stores for this source while the lease is held, so its last record is final.
        since = _resume_from(db, integration)
        name, clock = integration.name, time.monotonic()
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
                    collect(integration.provider, integration.id, integration.config, api_key,
                            **({"since": since} if since else {})),
                    timeout=BACKSTOP_SECONDS)
            partial = snapshot.partial_rows is not None

            def store():
                """Store the snapshot and its record in one transaction; None if the lease is no longer ours."""
                # Lock the source row before any other row, and store only while this lease is still ours.
                # A lease older than five minutes can be taken over, and an edit can then move the source;
                # either clears or replaces the stamp, so a read that outlived its lease stores nothing.
                if not _still_holds(db, integration.id, started):
                    db.rollback()
                    return None
                new = apply_snapshot(db, integration, snapshot, settings)
                audit(db, actor, "integration.collected", integration.id, name=integration.name,
                      resources=len(snapshot.resources), observations=len(snapshot.blocks),
                      partial=partial, **({"rows_kept": snapshot.partial_rows} if partial else {}),
                      gaps=sorted(evidence.gaps),
                      **({"gap_causes": {code: sorted(causes)
                                         for code, causes in sorted(evidence.gap_causes.items())}}
                         if evidence.gap_causes else {}),
                      **({"read_to": snapshot.log["read_to"]} if snapshot.log else {}),
                      **({"attempt": attempt} if attempt is not None else {}))
                db.commit()
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
        except Exception as exc:
            db.rollback()
            if not _still_holds(db, integration_id, started):
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
                if not _still_holds(db, integration_id, started):
                    db.rollback()
                    _report("ended", name, outcome="replaced", **spent(evidence))
                    return None, "replaced"
                # The failure is final, so the claimed retry that led here ends with it.
                drop_retry(db, integration_id)
                integration = db.get(Integration, integration_id)
                integration.last_error, retry_at = failure.message, None
            integration.status = previous if retry_at and previous != "syncing" else "error"
            integration.sync_started_at = None
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
