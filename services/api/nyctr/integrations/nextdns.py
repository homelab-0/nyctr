"""NextDNS profile and recent blocked-query evidence, without device inference.

NextDNS-reported device metadata is retained as unassigned source evidence. An IP
or DNS profile is never treated as a user. Missing metadata remains unattributed.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from . import core
from .core import IntegrationError, ReadClient, Snapshot, cursor_pages, relationship, resource, source_id

PROVIDER = "nextdns"
API_BASE = "https://api.nextdns.io"


def _timestamp(value: Any) -> datetime:
    """Require a timezone-aware source timestamp and normalize it without refreshing it."""
    if not isinstance(value, str):
        raise IntegrationError("NextDNS returned an observation without a timestamp.")
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise IntegrationError("NextDNS returned an invalid observation timestamp.") from None
    if timestamp.tzinfo is None:
        raise IntegrationError("NextDNS observation timestamp is missing a timezone.")
    return timestamp.astimezone(UTC)


def _domain(value: Any) -> str:
    """Normalize a bounded source DNS name to lowercase ASCII without accepting a URL."""
    if not isinstance(value, str) or len(value) > 253 or not value:
        raise IntegrationError("NextDNS returned a missing or invalid domain.")
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise IntegrationError("NextDNS returned an invalid domain.") from None
    if len(domain) > 253 or any(not label or len(label) > 63 for label in domain.split(".")):
        raise IntegrationError("NextDNS returned an invalid domain.")
    if any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-_." for char in domain):
        raise IntegrationError("NextDNS returned an invalid domain.")
    return domain


async def collect_nextdns(integration_id: str, config: dict[str, Any], api_key: str) -> Snapshot:
    """Collect profile controls and recent blocks without assigning users or risk.

    Preserve source timestamps and reasons, report disabled logging explicitly,
    and keep reported device labels unverified. Every imported block remains
    without a trusted device ID until a separate attribution layer establishes it.
    """
    from . import capabilities_for

    snapshot = Snapshot(capabilities=capabilities_for(PROVIDER))
    now = core.utc_now()
    collected_at = core.iso(now)
    cutoff = now - timedelta(hours=config["lookback_hours"])
    profile_id = config["profile_id"]
    path = f"/profiles/{profile_id}"
    async with core.make_http_client(api_key) as client:
        reader = ReadClient(client, API_BASE)
        payload = await reader.get(path)
        profile = payload.get("data")
        if not isinstance(profile, dict):
            raise IntegrationError("NextDNS returned an invalid profile response.")
        settings = profile.get("settings", {})
        if not isinstance(settings, dict) or not isinstance(settings.get("logs", {}), dict):
            raise IntegrationError("NextDNS returned invalid log settings.")
        log_settings = settings.get("logs", {})
        profile_node = resource(
            integration_id, PROVIDER, "dns_profile", profile_id,
            profile.get("name", f"NextDNS {profile_id}"), collected_at,
            attributes={"scope": "entire_profile", "logs_enabled": log_settings.get("enabled"), "logs_retention_seconds": log_settings.get("retention")},
        )
        snapshot.resources.append(profile_node)
        controls = {
            "security": ("threatIntelligenceFeeds", "aiThreatDetection", "googleSafeBrowsing", "cryptojacking", "dnsRebinding", "dga", "nrd", "ddns", "parking", "csam", "tlds"),
            "privacy": ("blocklists", "natives", "disguisedTrackers", "allowAffiliate"),
            "parentalControl": ("services", "categories", "safeSearch", "youtubeRestrictedMode", "blockBypass"),
        }
        for section in ("security", "privacy", "parentalControl", "allowlist", "denylist"):
            if section not in profile:
                continue
            value = profile[section]
            if section in controls:
                if not isinstance(value, dict):
                    raise IntegrationError("NextDNS returned invalid profile policy configuration.")
                value = core.selected(value, controls[section])
            else:
                if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
                    raise IntegrationError("NextDNS returned invalid domain list configuration.")
                value = [core.selected(x, ("id", "active")) for x in value]
            node = resource(
                integration_id, PROVIDER, "policy", f"{profile_id}.{section}",
                f"{profile_node['name']} · {section}", collected_at,
                attributes={"scope": "entire_profile", "section": section, "configuration": value},
            )
            snapshot.resources.append(node)
            snapshot.relationships.append(relationship(integration_id, PROVIDER, profile_node["id"], node["id"], "governed_by", collected_at))
        if log_settings.get("enabled") is False:
            snapshot.capabilities = [x for x in snapshot.capabilities if x != "blocked_dns_logs:read"]
            snapshot.capabilities.append("blocked_dns_logs:disabled_at_source")
            return snapshot
        logs = await cursor_pages(reader, path + "/logs", {
            "status": "blocked", "from": core.iso(cutoff), "to": collected_at,
            "sort": "desc", "limit": core.PAGE_SIZE,
        })
        for row in logs:
            # Never classify another status as a block just because a query asked
            # for blocked records. Providers may return unexpected records.
            if row.get("status") != "blocked":
                continue
            observed = _timestamp(row.get("timestamp"))
            if observed > now + timedelta(minutes=5):
                raise IntegrationError("NextDNS returned a future observation timestamp.")
            if observed < cutoff:
                continue
            domain = _domain(row.get("domain"))
            device = row.get("device")
            device_node = None
            if device is not None and not isinstance(device, dict):
                raise IntegrationError("NextDNS returned invalid device metadata.")
            if device and device.get("id") and device["id"] != "__UNIDENTIFIED__":
                remote_device_id = source_id(device["id"])
                device_node = resource(
                    integration_id, PROVIDER, "client", remote_device_id,
                    device.get("name", remote_device_id), core.iso(observed), evidence_kind="observed",
                    attributes={"provider_device_id": remote_device_id, "model": device.get("model"), "identity_verified": False},
                )
                snapshot.resources.append(device_node)
                snapshot.relationships.append(relationship(
                    integration_id, PROVIDER, device_node["id"], profile_node["id"], "uses_dns_profile", core.iso(observed),
                    evidence_kind="observed", attributes={"meaning": "Provider-reported device label; no user ownership established."},
                ))
            reasons = row.get("reasons", [])
            if not isinstance(reasons, list) or any(not isinstance(x, dict) for x in reasons):
                raise IntegrationError("NextDNS returned invalid block-reason evidence.")
            reason = "; ".join(str(x.get("name") or x.get("id") or "Unspecified source reason")[:200] for x in reasons[:20])
            if not reason:
                reason = "NextDNS reported a block without a reason."
            fingerprint = hashlib.sha256(json.dumps({
                "timestamp": core.iso(observed), "domain": domain,
                "device": device.get("id") if device else None,
                "client_ip": row.get("clientIp"), "reasons": reasons,
            }, sort_keys=True).encode()).hexdigest()[:40]
            snapshot.blocks.append({
                "id": f"{integration_id}:block:{fingerprint}",
                # A client-supplied NextDNS device label is not authenticated
                # endpoint identity. Correlation must establish ownership before
                # any event can enter a member's inbox.
                "device_id": None,
                "device_name": device_node["name"] if device_node else "Unattributed DNS client",
                "domain": domain,
                "source": PROVIDER,
                "reason": reason,
                "observed_at": core.iso(observed),
                "expires_at": core.iso(observed + timedelta(hours=24)),
                "evidence_kind": "observed",
                "attribution": "unverified" if device_node else "unattributed",
                "risk_score": None,
                "risk_explanation": "The source reports a DNS block. Reputation, user intent, and device ownership have not been independently verified.",
            })
            domain_node = resource(integration_id, PROVIDER, "domain", domain, domain, core.iso(observed), evidence_kind="observed")
            snapshot.resources.append(domain_node)
            snapshot.relationships.append(relationship(
                integration_id, PROVIDER, profile_node["id"], domain_node["id"], "blocked_dns_query", core.iso(observed),
                evidence_kind="observed", attributes={"reason": reason, "meaning": "Observed DNS decision; not a firewall or HTTP result."},
            ))
    # Logs arrive newest-first. Keep the newest evidence for repeated resources.
    snapshot.resources = list({node["id"]: node for node in reversed(snapshot.resources)}.values())
    snapshot.relationships = list({edge["id"]: edge for edge in reversed(snapshot.relationships)}.values())
    snapshot.blocks = list({event["id"]: event for event in snapshot.blocks}.values())
    return snapshot
