"""Pi-hole v6 blocked-query reader. Experimental.

Pi-hole has no API keys: a client signs in with the web or an application
password and receives a short-lived session id. Collection therefore makes one
POST to `/api/auth` to sign in and one DELETE to `/api/auth` to sign out. Those
two requests manage only this collection's own session; every read between them
is a GET and nothing on the Pi-hole is changed.

Sign-in follows the published authentication contract. The query-log fields
(`time`, `domain`, `status`, `client.ip`, `client.name`) follow the published
API description and have not been run against a live Pi-hole by this project.

This adapter reports blocks. It does not open them: it declares no
`dns.exceptions` capability, so a request about a Pi-hole block always waits
for a person. That is the contract working as intended, not a missing check.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from . import core
from .core import IntegrationError, ReadClient, Snapshot, exchange, relationship, resource
from .registry import ConfigField, Provider

ID = "pihole"
PAGE = 500
MAX_QUERY_PAGES = 4
READS = (
    ("session:read", "Sign-in with the configured password"),
    ("blocked_dns_logs:read", "Recent blocked DNS queries"),
)
_SID = re.compile(r"[A-Za-z0-9+/=_-]{8,256}")
_NAME = re.compile(r"[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?")

# Query statuses that mean the lookup was blocked, with the words shown to people.
_BLOCKED = {
    "GRAVITY": "On a subscribed blocklist",
    "GRAVITY_CNAME": "Points at a name on a subscribed blocklist",
    "DENYLIST": "Blocked by name on the deny list",
    "DENYLIST_CNAME": "Points at a name on the deny list",
    "REGEX": "Matched a deny pattern",
    "REGEX_CNAME": "Points at a name that matched a deny pattern",
    "EXTERNAL_BLOCKED_IP": "Refused by the upstream DNS server",
    "EXTERNAL_BLOCKED_NULL": "Refused by the upstream DNS server",
    "EXTERNAL_BLOCKED_NXRA": "Refused by the upstream DNS server",
    "EXTERNAL_BLOCKED_EDE15": "Refused by the upstream DNS server",
}


def classify(text: str) -> tuple[str, int | None, str] | None:
    """Explain one Pi-hole block status.

    A subscribed list can hold adverts or threats and Pi-hole does not say
    which, so those blocks are explicitly unknown rather than scored low.
    """
    code = text.strip().upper()
    if code.startswith(("DENYLIST", "REGEX")):
        return "policy", 65, "An administrator blocked this address by name"
    if code.startswith("GRAVITY"):
        return "unknown", None, ("A subscribed blocklist covers this address. The source does not say whether "
                                 "that list is about adverts or about threats, so Nyctr cannot score it")
    if code.startswith("EXTERNAL_BLOCKED"):
        return "unknown", None, "The upstream DNS server refused this address and gave no reason"
    return None


def validate(config: dict[str, Any]) -> dict[str, Any]:
    """Require an allowed HTTPS host, normalise to the `/api` root and bound the lookback."""
    if set(config) - {"base_url", "lookback_hours"}:
        raise IntegrationError("Pi-hole supports base_url and optional lookback_hours configuration only.")
    parsed, _host = core.validated_host(config.get("base_url"), "Pi-hole")
    if parsed.path.rstrip("/") not in ("", "/api"):
        raise IntegrationError("Use the Pi-hole address, optionally ending in /api.")
    hours = config.get("lookback_hours", 24)
    if type(hours) is not int or not 1 <= hours <= 72:
        raise IntegrationError("Pi-hole lookback_hours must be an integer between 1 and 72.")
    return {"base_url": f"https://{parsed.netloc}/api", "lookback_hours": hours}


def _domain(value: Any) -> str | None:
    """Return a plain lowercase DNS name, or None for anything that is not one."""
    if not isinstance(value, str) or not 0 < len(value) <= 253:
        return None
    name = value.rstrip(".").lower()
    labels = name.split(".")
    return name if len(labels) >= 2 and all(_NAME.fullmatch(label) for label in labels) else None


def _client(value: Any) -> tuple[str, str] | None:
    """Return (address, label) for a query's client when the address is a real IP address."""
    if not isinstance(value, dict) or not isinstance(value.get("ip"), str):
        return None
    try:
        address = str(ipaddress.ip_address(value["ip"]))
    except ValueError:
        return None
    name = value.get("name")
    return address, (name.strip()[:120] if isinstance(name, str) and name.strip() else address)


async def _sign_in(reader: ReadClient, password: str) -> str:
    """Start a session and return its id. A wrong password is an authentication failure."""
    payload = await exchange(reader, "POST", "/auth", body={"password": password})
    session = payload.get("session")
    sid = session.get("sid") if isinstance(session, dict) else None
    if not isinstance(session, dict) or session.get("valid") is not True or not isinstance(sid, str):
        raise IntegrationError("Pi-hole did not accept the password.", category="authentication")
    if not _SID.fullmatch(sid):
        raise IntegrationError("Pi-hole returned an invalid session.")
    return sid


async def collect_pihole(integration_id: str, config: dict[str, Any], api_key: str) -> Snapshot:
    """Read recently blocked lookups and the client label Pi-hole reports for each.

    Client names come from the Pi-hole's own network table and are not proof of
    who made a lookup, so every block stays unassigned until an administrator
    links the label to a device.
    """
    snapshot = Snapshot(capabilities=[read for read, _label in READS])
    now = core.utc_now()
    collected_at = core.iso(now)
    cutoff = now - timedelta(hours=config["lookback_hours"])
    async with core.make_http_client(api_key, send_key=False) as client:
        reader = ReadClient(client, config["base_url"])
        client.headers["X-FTL-SID"] = await _sign_in(reader, api_key)
        core.record_capability("session:read")
        try:
            resolver = resource(integration_id, ID, "dns_profile", "resolver", "Pi-hole", collected_at,
                                attributes={"scope": "entire_resolver"})
            snapshot.resources.append(resolver)
            seen: set[str] = set()
            for page in range(MAX_QUERY_PAGES):
                payload = await reader.get("/queries", {
                    "from": int(cutoff.timestamp()), "until": int(now.timestamp()),
                    "length": PAGE, "start": page * PAGE})
                rows = payload.get("queries")
                if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
                    raise IntegrationError("Pi-hole returned an invalid query log.")
                if len(rows) > PAGE * 2:
                    raise IntegrationError("Pi-hole ignored the requested page size.")
                reader.count_records(len(rows))
                fresh = 0
                for row in rows:
                    status = row.get("status")
                    stamp, domain = row.get("time"), _domain(row.get("domain"))
                    if status not in _BLOCKED or domain is None or isinstance(stamp, bool) \
                            or not isinstance(stamp, (int, float)):
                        continue
                    try:
                        observed = datetime.fromtimestamp(stamp, UTC)
                    except (OverflowError, OSError, ValueError):
                        continue
                    if observed > now + timedelta(minutes=5):
                        raise IntegrationError("Pi-hole returned a future observation timestamp.")
                    if observed < cutoff:
                        continue
                    who = _client(row.get("client"))
                    fingerprint = hashlib.sha256(
                        f"{stamp}|{domain}|{status}|{who[0] if who else ''}".encode()).hexdigest()[:40]
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
                    fresh += 1
                    label = None
                    if who:
                        label = resource(integration_id, ID, "client", who[0], who[1], core.iso(observed),
                                         evidence_kind="observed",
                                         attributes={"ip": who[0], "identity_verified": False})
                        snapshot.resources.append(label)
                        snapshot.relationships.append(relationship(
                            integration_id, ID, label["id"], resolver["id"], "uses_dns_profile",
                            core.iso(observed), evidence_kind="observed",
                            attributes={"meaning": "Client label reported by the resolver; no user ownership established."}))
                    snapshot.blocks.append({
                        "id": f"{integration_id}:block:{fingerprint}", "device_id": None,
                        "source_device_id": label["id"] if label else None,
                        "reason_codes": [status.lower()],
                        "device_name": label["name"] if label else "Unattributed DNS client",
                        "domain": domain, "source": ID, "reason": _BLOCKED[status],
                        "observed_at": core.iso(observed),
                        "expires_at": core.iso(observed + timedelta(hours=24)),
                        "evidence_kind": "observed", "attribution": "unverified" if label else "unattributed",
                        "risk_score": None,
                        "risk_explanation": "The source reports a DNS block. Reputation, user intent, and device ownership have not been independently verified.",
                    })
                if len(rows) < PAGE or not fresh:
                    break
            else:
                core.record_gap("pihole_query_limit")
            core.record_capability("blocked_dns_logs:read")
        finally:
            try:
                await exchange(reader, "DELETE", "/auth")
            except IntegrationError:
                # The session expires on its own; a failed sign-out must not hide the real result.
                core.record_gap("pihole_sign_out_failed")
    snapshot.resources = list({node["id"]: node for node in reversed(snapshot.resources)}.values())
    snapshot.relationships = list({edge["id"]: edge for edge in reversed(snapshot.relationships)}.values())
    return snapshot


PROVIDER = Provider(
    id=ID, name="Pi-hole", letter="H", tone="rose", status="experimental",
    summary="A Pi-hole v6 resolver: the lookups it blocked recently and the client each came from.",
    secret_hint="The Pi-hole web password, or better an application password made for Nyctr.",
    fields=(
        ConfigField("base_url", "Pi-hole address", "Over HTTPS. Add its certificate to the connector CA bundle.",
                    "https://pihole.example.net", "url"),
        ConfigField("lookback_hours", "Hours of blocked lookups to read", "Between 1 and 72.", "24", "number",
                    False),
    ),
    reads=READS,
    provides=frozenset({"dns.blocks"}),
    limitations=(
        ("dns_exceptions:write", "Opening a blocked address",
         "Not implemented for Pi-hole. Requests about its blocks always wait for a person, who changes Pi-hole by hand."),
    ),
    gaps=(
        ("experimental", "This adapter has not been run against a real Pi-hole",
         "Sign-in follows the published contract. The query-log fields are unverified; treat first results with care and report differences."),
        ("upstream_identity", "A client name is not user identity",
         "Pi-hole names clients from its own network table. That cannot identify the person who made a lookup. Blocks remain unassigned until an administrator links the label to a device."),
        ("list_kind", "Pi-hole does not say what kind of list blocked a name",
         "A subscribed list may hold adverts or threats. Nyctr leaves those blocks unscored instead of guessing."),
    ),
    gap_notes={
        "pihole_query_limit": (
            "More lookups than one collection reads",
            "Only the newest 2,000 queries in the window were read. Older blocks in the window are missing."),
        "pihole_sign_out_failed": (
            "The session could not be closed",
            "Nyctr could not sign out. The session expires on its own after a few minutes."),
    },
    validate=validate, collect=collect_pihole, classify=classify,
)
