"""Deterministic findings computed from stored evidence. No model is involved.

Each rule states a configured or observed fact and what it does not prove.
Findings produced here have identifiers starting `auto:`; they are opened,
updated and resolved by re-running the rules after every collection.
"""

from __future__ import annotations

from sqlalchemy import select

from .integrations import registry
from .models import Finding, GuestAction, Integration, Lease, Resource, utc


def _workload_firewall(resources: list[Resource]) -> list[dict]:
    """A hosted workload whose firewall is switched off for the workload or on every network card."""
    found = []
    for row in resources:
        if row.kind != "workload":
            continue
        nics = [n for n in row.attributes.get("nics") or [] if isinstance(n, dict)]
        guest_off = row.attributes.get("firewall_enabled") is False
        nics_off = bool(nics) and all(n.get("firewall") is False for n in nics)
        if not (guest_off or nics_off):
            continue
        source = registry.name_of(row.provider, "The source")
        where = "for the whole workload" if guest_off else "on its network card" + ("s" if len(nics) != 1 else "")
        found.append({
            "id": f"auto:workload-firewall:{row.id}"[:128], "severity": "medium",
            "title": f"Firewall is off on {row.name}",
            "summary": f"{source} reports the firewall switched off {where}. Anything that can reach this "
                       "workload's network can reach every port it listens on. This is a configuration fact, "
                       "not evidence that something connected.",
            "resource_ids": [row.id],
            "evidence": [f"Configured in {source}: firewall off {where}.",
                         "Firewall rules and upstream filtering were not read."],
        })
    return found


def _dns_logging(resources: list[Resource]) -> list[dict]:
    """A DNS profile that reports logging disabled, so Nyctr cannot see blocks at all."""
    return [{
        "id": f"auto:dns-logging:{row.id}"[:128], "severity": "informational",
        "title": f"DNS logging is off for {row.name}",
        "summary": "With logging off Nyctr sees no blocked lookups from this profile. People will not find "
                   "their blocks here, and guest activity cannot be assessed.",
        "resource_ids": [row.id],
        "evidence": [f"Configured in {registry.name_of(row.provider, 'the source')}: logs disabled."],
    } for row in resources if row.kind == "dns_profile" and row.attributes.get("logs_enabled") is False]


def _guest_events(db) -> list[dict]:
    """Guest devices currently cut off or locked, and rule matches Nyctr was not allowed to act on."""
    found = []
    latest: dict[str, GuestAction] = {}
    for action in db.scalars(select(GuestAction).order_by(GuestAction.created_at)):
        latest[action.device_id] = action
    for device_id, action in latest.items():
        device = db.get(Resource, device_id)
        name = device.name if device else "A guest device"
        source = registry.name_of(device.provider if device else None, "the network source")
        when = utc(action.created_at).strftime("%H:%M UTC")
        if action.action in {"cut", "lock"} and action.execution in {"applied", "simulated"}:
            who = "the cut-off rule" if action.actor == "rule" else "an administrator"
            found.append({
                "id": f"auto:guest-cut:{device_id}"[:128], "severity": "high",
                "title": f"{name} was cut off the guest Wi-Fi",
                "summary": f"At {when} {who} removed this device's guest access. {action.reason}. It stays off "
                           "until someone lets it back on.".replace(". .", "."),
                "resource_ids": [device_id],
                "evidence": [f"Observed: {action.reason or 'administrator action'}.",
                             "Nyctr sees DNS lookups only. Connection attempts are not collected."],
            })
        elif action.actor == "rule" and action.execution in {"not_applied", "failed"}:
            found.append({
                "id": f"auto:guest-unenforced:{device_id}"[:128], "severity": "high",
                "title": f"{name} matched the cut-off rule but is still online",
                "summary": "The rule matched, but Nyctr " + (
                    f"is read-only for {source}" if action.execution == "not_applied"
                    else f"was refused by {source}") + f". Cut this device off in {source} if you agree.",
                "resource_ids": [device_id], "evidence": [f"Observed: {action.reason}."],
            })
    return found


def _stuck_leases(db) -> list[dict]:
    """Access that should have closed but could not be removed at the provider."""
    return [{
        "id": f"auto:lease-stuck:{lease.id}"[:128], "severity": "high",
        "title": f"{lease.domain} is still open after its time ran out",
        "summary": "Nyctr could not remove this exception at the DNS source and will keep trying. "
                   "Remove it by hand if this persists.",
        "resource_ids": [], "evidence": [f"Why it could not be removed: {lease.last_error}"],
    } for lease in db.scalars(select(Lease).where(Lease.status == "active", Lease.last_error.is_not(None)))]


# Every rule above in plain words, with the capability a collected source must offer for it to have
# anything to look at. The Findings page lists these so an empty list is not read as "all checked".
CHECKS = (
    ("compute", "A hosted workload whose firewall is switched off"),
    ("dns.blocks", "A DNS profile with logging switched off"),
    ("guest.devices", "A guest device that was cut off, or that matched the cut-off rule and is still online"),
    ("dns.exceptions", "A temporary exception that could not be closed when its time ran out"),
)
# Kinds of thing sources report that no rule reads, in the words shown to people.
UNCHECKED = {"policy": "Firewall rules", "network": "Networks and VLANs", "client": "Devices that are not guests",
             "gateway": "Network equipment", "switch": "Network equipment", "access_point": "Network equipment",
             "host": "Hosts and bridges", "bridge": "Hosts and bridges", "domain": "Blocked addresses"}


def coverage(db) -> dict:
    """Say what the rules check with the sources connected, and what is collected but never checked.

    A check is active only when a source that has stored a collection offers what it reads.
    """
    collected = select(Integration.provider).where(Integration.last_sync.is_not(None)).distinct()
    offered = {capability for provider in db.scalars(collected)
               for capability in registry.CAPABILITIES if registry.provides(provider, capability)}
    kinds = set(db.scalars(select(Resource.kind).distinct()))
    unchecked = list(dict.fromkeys(text for kind, text in UNCHECKED.items() if kind in kinds))
    return {"checks": [{"text": text, "active": needs in offered} for needs, text in CHECKS],
            "not_checked": unchecked}


def refresh_findings(db) -> None:
    """Re-run every rule, upsert current findings and resolve ones whose cause is gone.

    A finding an administrator already closed is not reopened for the same cause.
    The caller commits.
    """
    resources = list(db.scalars(select(Resource)))
    current = {item["id"]: item for item in
               _workload_firewall(resources) + _dns_logging(resources) + _guest_events(db) + _stuck_leases(db)}
    existing = {row.id: row for row in db.scalars(select(Finding).where(Finding.id.like("auto:%")))}
    for id_, item in current.items():
        row = existing.get(id_)
        if row is None:
            db.add(Finding(id=id_, title=item["title"], severity=item["severity"], summary=item["summary"],
                           resource_ids=item["resource_ids"], relationship_ids=[], evidence=item["evidence"],
                           status="open"))
        else:
            row.title, row.severity, row.summary = item["title"], item["severity"], item["summary"]
            row.resource_ids, row.evidence = item["resource_ids"], item["evidence"]
            if row.status == "resolved":
                row.status = "open"
    for id_, row in existing.items():
        if id_ not in current and row.status == "open":
            row.status = "resolved"
    db.flush()
