"""NextDNS profile and recent blocked-query evidence, without device inference.

NextDNS-reported device metadata is retained as unassigned source evidence. An IP
or DNS profile is never treated as a user. Missing metadata remains unattributed.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from . import actions, core
from .core import IntegrationError, ReadClient, Snapshot, cursor_pages, relationship, resource, source_id
from .registry import ConfigField, Provider

ID = "nextdns"
API_BASE = "https://api.nextdns.io"
READS = (
    ("profile:read", "DNS profile configuration"),
    ("dns_policies:read", "DNS policy sections"),
    ("blocked_dns_logs:read", "Recent blocked DNS queries"),
)

# NextDNS block reasons, matched against reason identifiers and names in order:
# (pattern, category, base score, plain explanation). The core adds name-shape factors.
_REASONS: tuple[tuple[re.Pattern[str], str, int, str], ...] = tuple(
    (re.compile(pattern, re.I), category, score, text) for pattern, category, score, text in (
        (r"threat|safe.?browsing|malware|phish|cryptojack|rebind|homograph|typosquat|\bdga\b|csam",
         "security", 92, "A security feed lists this address as a threat"),
        (r"\bnrd\b|newly.registered", "security", 72, "The address was registered very recently"),
        (r"\bddns\b|dynamic.dns", "security", 58, "It uses a dynamic address service, common for short-lived sites"),
        (r"parked|parking", "security", 52, "The address is parked and has no real site behind it"),
        (r"denylist|deny.list", "policy", 65, "An administrator blocked this address by name"),
        (r"parental|category|service:|safe.?search|bypass", "policy", 60,
         "A content rule set by an administrator blocks this kind of site"),
        (r"disguised", "privacy_list", 24, "It is a tracker hidden behind another site's name"),
        (r"^native|native.tracking", "privacy_list", 14, "It is device telemetry blocked by a tracking list"),
        (r"^blocklist:|blocklist|privacy list|ad.?block|tracker|tracking", "privacy_list", 16,
         "A privacy and ad-blocking list covers it, not a security feed"),
    )
)


def classify(text: str) -> tuple[str, int, str] | None:
    """Explain one NextDNS block reason. Unrecognised reasons return None and stay unknown."""
    for pattern, category, score, label in _REASONS:
        if pattern.search(text):
            return category, score, label
    return None


def validate(config: dict[str, Any]) -> dict[str, Any]:
    """Accept one profile and a bounded log lookback. The destination is fixed."""
    if set(config) - {"profile_id", "lookback_hours"}:
        raise IntegrationError("This source takes a Profile and, if you wish, Hours of blocked lookups to read. Nothing else can be set.")
    profile = config.get("profile_id")
    if not isinstance(profile, str) or not re.fullmatch(r"[a-fA-F0-9]{6}", profile):
        raise IntegrationError("Profile must be the six-character identifier of the profile: digits and the letters a to f.")
    hours = config.get("lookback_hours", 24)
    if type(hours) is not int or not 1 <= hours <= 72:
        raise IntegrationError("Hours of blocked lookups to read must be a whole number between 1 and 72.")
    return {"profile_id": profile.lower(), "lookback_hours": hours}


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
    snapshot = Snapshot(capabilities=[read for read, _label in READS])
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
            integration_id, ID, "dns_profile", profile_id,
            profile.get("name", f"NextDNS {profile_id}"), collected_at,
            attributes={"scope": "entire_profile", "logs_enabled": log_settings.get("enabled"), "logs_retention_seconds": log_settings.get("retention")},
        )
        snapshot.resources.append(profile_node)
        core.record_capability("profile:read")
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
                integration_id, ID, "policy", f"{profile_id}.{section}",
                f"{profile_node['name']} · {section}", collected_at,
                attributes={"scope": "entire_profile", "section": section, "configuration": value},
            )
            snapshot.resources.append(node)
            snapshot.relationships.append(relationship(integration_id, ID, profile_node["id"], node["id"], "governed_by", collected_at))
        if all(section in profile for section in ("security", "privacy", "parentalControl", "allowlist", "denylist")):
            core.record_capability("dns_policies:read")
        else:
            core.record_gap("nextdns_policy_fields_missing")
        if type(log_settings.get("enabled")) is not bool:
            core.record_gap("nextdns_log_settings_unknown")
        if log_settings.get("enabled") is False:
            core.record_capability("blocked_dns_logs:read", unavailable=True)
            snapshot.capabilities = [x for x in snapshot.capabilities if x != "blocked_dns_logs:read"]
            snapshot.capabilities.append("blocked_dns_logs:disabled_at_source")
            return snapshot
        # The published API returns logs "from newest to oldest" under sort=desc, so when the
        # window holds more than one collection may read, the rows kept are the most recent.
        logs, more = await cursor_pages(reader, path + "/logs", {
            "status": "blocked", "from": core.iso(cutoff), "to": collected_at,
            "sort": "desc", "limit": core.PAGE_SIZE,
        })
        if more:
            snapshot.partial_rows = len(logs)
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
                    integration_id, ID, "client", remote_device_id,
                    device.get("name", remote_device_id), core.iso(observed), evidence_kind="observed",
                    attributes={"provider_device_id": remote_device_id, "model": device.get("model"), "identity_verified": False},
                )
                snapshot.resources.append(device_node)
                snapshot.relationships.append(relationship(
                    integration_id, ID, device_node["id"], profile_node["id"], "uses_dns_profile", core.iso(observed),
                    evidence_kind="observed", attributes={"meaning": "Device label reported by the source; no user ownership established."},
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
                # The provider label's own resource, so an administrator can link it to a device.
                "source_device_id": device_node["id"] if device_node else None,
                "reason_codes": [str(x["id"])[:120] for x in reasons[:20] if isinstance(x.get("id"), str)],
                "device_name": device_node["name"] if device_node else "Unattributed DNS client",
                "domain": domain,
                "source": ID,
                "reason": reason,
                "observed_at": core.iso(observed),
                "expires_at": core.iso(observed + timedelta(hours=24)),
                "evidence_kind": "observed",
                "attribution": "unverified" if device_node else "unattributed",
                "risk_score": None,
                "risk_explanation": "The source reports a DNS block. Reputation, user intent, and device ownership have not been independently verified.",
            })
            domain_node = resource(integration_id, ID, "domain", domain, domain, core.iso(observed), evidence_kind="observed")
            snapshot.resources.append(domain_node)
            snapshot.relationships.append(relationship(
                integration_id, ID, profile_node["id"], domain_node["id"], "blocked_dns_query", core.iso(observed),
                evidence_kind="observed", attributes={"reason": reason, "meaning": "Observed DNS decision; not a firewall or HTTP result."},
            ))
    # Logs arrive newest-first. Keep the newest evidence for repeated resources.
    snapshot.resources = list({node["id"]: node for node in reversed(snapshot.resources)}.values())
    snapshot.relationships = list({edge["id"]: edge for edge in reversed(snapshot.relationships)}.values())
    snapshot.blocks = list({event["id"]: event for event in snapshot.blocks}.values())
    core.record_capability("blocked_dns_logs:read")
    return snapshot


PROVIDER = Provider(
    id=ID, name="NextDNS", letter="N", tone="teal", logo="nextdns.png",
    summary="One DNS profile: its filtering settings and the lookups it blocked recently.",
    secret_hint="A NextDNS API key from your account page.",
    fields=(
        ConfigField("profile_id", "Profile", "The six-character identifier of the profile.", "abc123"),
        ConfigField("lookback_hours", "Hours of blocked lookups to read", "Between 1 and 72.", "24", "number",
                    False),
    ),
    reads=READS,
    provides=frozenset({"dns.blocks", "dns.exceptions"}),
    gaps=(
        ("upstream_identity", "Upstream DNS is not user identity",
         "A shared DNS profile or a device label from the source cannot identify the person who made a query. Blocks remain unassigned until trusted attribution exists."),
        ("dns_scope", "DNS decisions cover one enforcement layer",
         "A DNS block does not establish a firewall decision, HTTPS result, or destination risk. Unknown risk remains unknown."),
    ),
    not_collected=("DNS lookups that were allowed",),
    gap_notes={
        "nextdns_policy_fields_missing": (
            "Some DNS policy sections were absent",
            "The profile did not list every policy section this integration reads. DNS policy coverage remains unverified."),
        "nextdns_log_settings_unknown": (
            "The source logging setting is unknown",
            "The profile did not explicitly report whether logging is enabled. Any successful log read describes only the requested window."),
    },
    validate=validate, collect=collect_nextdns, classify=classify,
    allow_domain=actions.nextdns_allow, disallow_domain=actions.nextdns_disallow,
    domain_listed=actions.nextdns_listed,
)
