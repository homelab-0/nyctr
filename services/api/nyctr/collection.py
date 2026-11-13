"""Applying a provider snapshot to the database, and the one collection routine everything shares.

Collection never changes a provider. After a snapshot is stored, deterministic
analysis refreshes findings and the administrator-written guest rule is checked.
"""

import asyncio
import os
import re
from datetime import datetime, timedelta

from sqlalchemy import delete, or_, select, update

from .models import (
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
from .security import audit

SECRET_REF = re.compile(r"NYCTR_CONNECTOR_SECRET_[A-Z0-9_]{1,100}")


def parsed_date(value):
    """Parse an ISO source timestamp or datetime and normalize it to timezone-aware UTC."""
    if isinstance(value, datetime):
        return utc(value)
    return utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def apply_snapshot(db, integration, snapshot, settings):
    """Stage a complete integration snapshot while preserving local ownership and event expiry.

    Reject cross-integration identities and relationships outside the snapshot.
    Missing inventory is marked stale, relationships are replaced, and replayed
    observations keep their original expiry. The caller commits or rolls back
    the full collection transaction; provider infrastructure is never modified.
    """
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
    links = {link.source_id: link for link in db.scalars(select(DeviceLink))}
    guests_by_name: dict[str, list[str]] = {}
    for row in db.scalars(select(Resource).where(Resource.kind == "client")):
        if isinstance(row.attributes.get("guest"), dict):
            guests_by_name.setdefault(row.name.casefold(), []).append(row.id)
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
    for data in snapshot.resources:
        if data["kind"] != "client" or not isinstance(data["attributes"].get("guest"), dict):
            continue
        uplink = data["attributes"].get("uplink")
        last = db.scalar(select(Sighting).where(Sighting.device_id == data["id"])
                         .order_by(Sighting.last_seen.desc()).limit(1))
        if last and last.uplink_id == uplink and now - utc(last.last_seen) < timedelta(hours=6):
            last.last_seen = now
        else:
            db.add(Sighting(device_id=data["id"], uplink_id=uplink, first_seen=now, last_seen=now))


def after_collection(db, settings):
    """Run deterministic analysis on stored evidence and return guest devices the written rule cuts off."""
    from .analysis import refresh_findings
    from .guests import evaluate_rule

    refresh_findings(db)
    return evaluate_rule(db, settings)


def _still_holds(db, integration_id: str, started) -> bool:
    """Lock the source row and say whether the lease taken at `started` is still this caller's."""
    return db.execute(update(Integration).where(
        Integration.id == integration_id, Integration.status == "syncing", Integration.sync_started_at == started
    ).values(name=Integration.name).execution_options(synchronize_session=False)).rowcount == 1


async def collect_integration(factory, settings, integration_id: str, actor: str | None):
    """Collect one live integration under a database lease and store its snapshot atomically.

    Returns (snapshot, error message). A second caller during a running
    collection gets ("busy"); a read whose lease was taken over or ended by an
    edit stores nothing and gets ("replaced"). A snapshot that kept only the most recent rows is
    stored and audited as partial, not as an error. Failure rolls back the snapshot, records a
    sanitized error and releases the lease. Never performs a provider change.
    """
    from .integrations import IntegrationError, collect

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
        locked = db.execute(update(Integration).where(
            Integration.id == integration.id,
            or_(Integration.status != "syncing", Integration.sync_started_at < started - timedelta(minutes=5))
        ).values(status="syncing", sync_started_at=started).execution_options(synchronize_session="fetch"))
        if locked.rowcount != 1:
            db.rollback()
            return None, "busy"
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
        try:
            snapshot = await asyncio.wait_for(
                collect(integration.provider, integration.id, integration.config, api_key), timeout=90)
            # Lock the source row before any other row, and store only while this lease is still ours.
            # A lease older than five minutes can be taken over, and an edit can then move the source;
            # either clears or replaces the stamp, so a read that outlived its lease stores nothing.
            if not _still_holds(db, integration.id, started):
                db.rollback()
                return None, "replaced"
            apply_snapshot(db, integration, snapshot, settings)
            partial = snapshot.partial_rows is not None
            audit(db, actor, "integration.collected", integration.id,
                  resources=len(snapshot.resources), observations=len(snapshot.blocks),
                  partial=partial, **({"rows_kept": snapshot.partial_rows} if partial else {}))
            db.commit()
        except Exception as exc:
            db.rollback()
            if not _still_holds(db, integration_id, started):
                db.rollback()
                return None, "replaced"
            integration = db.get(Integration, integration_id)
            integration.status = "error"
            integration.last_error = (str(exc) if isinstance(exc, IntegrationError)
                                      else "Collection failed. Check provider reachability and configuration.")
            integration.sync_started_at = None
            audit(db, actor, "integration.collection_failed", integration.id)
            db.commit()
            return None, integration.last_error
        return snapshot, None
