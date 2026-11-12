"""Bounded, credential-safe transport shared by provider adapters.

`ReadClient` deliberately has no write method; collection can never change a
provider. Changes go through `nyctr.integrations.actions`, which is the only
caller of the non-GET exchange below and is gated by explicit configuration.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import ssl
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

MAX_PAGES = 20
MAX_REQUESTS = 128
MAX_RECORDS = 10_000
MAX_BODY_BYTES = 2 * 1024 * 1024
PAGE_SIZE = 200


class IntegrationError(Exception):
    """A safe error with a fixed diagnostic category and no provider response content."""

    def __init__(self, message: str, *, category: str = "provider_contract"):
        """Retain a sanitized collector message and classify failure without parsing its text."""
        super().__init__(message)
        self.category = category


@dataclass
class ProbeEvidence:
    """Track only bounded transport facts and normalized capabilities for one diagnostic task.

    No request URLs, headers, payloads, names, or source identifiers are retained.
    A received response establishes an HTTPS exchange, not accepted credentials.
    """
    responses_received: int = 0
    verified_capabilities: set[str] = field(default_factory=set)
    unavailable_capabilities: set[str] = field(default_factory=set)
    gaps: set[str] = field(default_factory=set)


_probe_evidence: ContextVar[ProbeEvidence | None] = ContextVar("nyctr_probe_evidence", default=None)


@contextmanager
def capture_probe():
    """Isolate diagnostic evidence to the current async context and reset it even after failure."""
    evidence = ProbeEvidence()
    token = _probe_evidence.set(evidence)
    try:
        yield evidence
    finally:
        _probe_evidence.reset(token)


def record_capability(capability: str, *, unavailable: bool = False):
    """Record a capability only after its source data was normalized or explicitly disabled."""
    if (evidence := _probe_evidence.get()) is not None:
        target = evidence.unavailable_capabilities if unavailable else evidence.verified_capabilities
        target.add(capability)


def record_gap(gap: str):
    """Record a fixed code for source coverage that the diagnostic cannot verify."""
    if (evidence := _probe_evidence.get()) is not None:
        evidence.gaps.add(gap)


def _transport_category(error: Exception) -> str:
    """Classify typed timeout and TLS causes without inspecting potentially secret-bearing messages."""
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen and len(seen) < 12:
        seen.add(id(current))
        if isinstance(current, ssl.SSLError):
            return "tls"
        current = current.__cause__ or current.__context__
    return "timeout" if isinstance(error, httpx.TimeoutException) else "transport"


@dataclass
class Snapshot:
    """Normalized evidence returned only after a provider collection succeeds."""
    resources: list[dict[str, Any]] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    blocks: list[dict[str, Any]] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    # Guest passes as {id, code, name, minutes, guest_limit, data_limit_mb, guest_count, created_at,
    # activated_at, expires_at, expired}. None means the source did not report passes this time,
    # so stored passes are left alone; a list is the complete current set.
    passes: list[dict[str, Any]] | None = None
    # Set when the source held more log rows than one collection may read: the number of
    # most recent rows kept. None means the whole requested window was read.
    partial_rows: int | None = None


def utc_now() -> datetime:
    """Return an aware UTC collection time, replaceable in deterministic tests."""
    return datetime.now(UTC)


def iso(value: datetime) -> str:
    """Serialize a timestamp in UTC for the adapter snapshot contract."""
    return value.astimezone(UTC).isoformat()


def source_id(value: Any) -> str:
    """Validate a bounded source identifier without altering its original value."""
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", value):
        raise IntegrationError("The provider returned an invalid resource identifier.")
    return value


def object_id(integration_id: str, kind: str, value: Any) -> str:
    """Namespace a source ID while remaining within the database identifier limit.

    Hash overlong source IDs in a disjoint format so shared prefixes remain
    distinguishable; the original identifier is retained separately as evidence.
    """
    namespace = source_id(integration_id)
    remote_id = source_id(value)
    if len(namespace) > 128 or not re.fullmatch(r"[a-z_]{1,40}", kind):
        raise IntegrationError("Invalid integration resource namespace.")
    prefix = f"{namespace}:{kind}:"
    if len(prefix) + len(remote_id) <= 255:
        return prefix + remote_id
    # PostgreSQL enforces the model's VARCHAR(255) unlike SQLite. Preserve the
    # complete source identifier on Resource.source_id, but bound its primary ID.
    # Hash the whole source ID so common long prefixes cannot cause collisions.
    # '~' cannot occur in accepted source IDs, keeping hashed and literal IDs
    # disjoint even if a provider supplies a hash-looking short identifier.
    return prefix + "~sha256-" + hashlib.sha256(remote_id.encode()).hexdigest()


def resource(
    integration_id: str,
    provider: str,
    kind: str,
    remote_id: str,
    name: str,
    collected_at: str,
    *,
    site_id: str | None = None,
    evidence_kind: str = "configured",
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an unowned resource with bounded identity and explicit source evidence."""
    return {
        "id": object_id(integration_id, kind, remote_id),
        "name": str(name)[:255],
        "kind": kind,
        "provider": provider,
        "source_id": remote_id,
        "site_id": site_id,
        "observed_at": collected_at,
        "evidence_kind": evidence_kind,
        "classification": "unassigned" if kind == "client" else "infrastructure",
        "owner_id": None,
        "attributes": {"integration_id": integration_id, **(attributes or {})},
    }


def relationship(
    integration_id: str,
    provider: str,
    source: str,
    target: str,
    kind: str,
    collected_at: str,
    *,
    evidence_kind: str = "configured",
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a stable typed evidence link without asserting network reachability."""
    fingerprint = hashlib.sha256(f"{source}|{kind}|{target}".encode()).hexdigest()[:32]
    return {
        "id": f"{integration_id}:relation:{fingerprint}",
        "source": source,
        "target": target,
        "kind": kind,
        "provider": provider,
        "observed_at": collected_at,
        "evidence_kind": evidence_kind,
        "attributes": {"integration_id": integration_id, **(attributes or {})},
    }


def selected(row: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """Keep only documented, relevant source fields, never arbitrary raw objects."""
    return {key: row[key] for key in keys if key in row}


def _validated_host(value: Any, label: str):
    """Parse an HTTPS connector URL and require an explicitly allowed, non-reserved host.

    Reject credential-bearing URLs and forbidden literal addresses before any
    API key can be sent to the destination. Returns the parsed URL and host.
    """
    if not isinstance(value, str) or len(value) > 2048:
        raise IntegrationError(f"{label} requires an HTTPS integration base URL.")
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        raise IntegrationError(f"Invalid {label} integration base URL.") from None
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or "\\" in value
        or any(char.isspace() for char in value)
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise IntegrationError(f"{label} requires HTTPS without URL credentials, query, or fragment.")
    if host in {"localhost", "metadata.google.internal", "metadata.azure.internal"} or host.endswith(".localhost"):
        raise IntegrationError("Loopback and metadata endpoints cannot be connector destinations.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address and (
        address.is_loopback or address.is_link_local or address.is_multicast
        or address.is_unspecified or address.is_reserved
        or (getattr(address, "ipv4_mapped", None) is not None)
    ):
        raise IntegrationError("Loopback, link-local, metadata, and reserved endpoints are not allowed.")
    allowed = {
        entry.strip().lower()
        for entry in os.getenv("NYCTR_CONNECTOR_HOSTS", "").split(",")
        if entry.strip()
    }
    if host not in allowed:
        raise IntegrationError(f"{label} hostname is not in the server's NYCTR_CONNECTOR_HOSTS allowlist.")
    return parsed, host


def validated_host(value: Any, label: str):
    """Public name for the destination check every adapter must pass before a credential is sent."""
    return _validated_host(value, label)


def make_http_client(api_key: str, *, authorization_scheme: str = "", send_key: bool = True) -> httpx.AsyncClient:
    """Create a verified-TLS client that never redirects or inherits proxy settings.

    Providers that expect an Authorization header pass its scheme; the default
    sends the key as X-Api-Key. A provider that signs in for a session passes
    `send_key=False` and sets its own session header once it has one.
    """
    if not isinstance(api_key, str) or not api_key or any(c in api_key for c in "\r\n"):
        raise IntegrationError("The configured API key is missing or invalid.", category="secret")
    credential = ({} if not send_key else {"Authorization": f"{authorization_scheme}={api_key}"}
                  if authorization_scheme else {"X-Api-Key": api_key})
    ca_bundle = os.getenv("NYCTR_CONNECTOR_CA_BUNDLE")
    try:
        verify = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else True
    except (OSError, ssl.SSLError):
        raise IntegrationError("The server's connector CA bundle could not be loaded.", category="tls") from None
    return httpx.AsyncClient(
        headers={**credential, "Accept": "application/json"},
        follow_redirects=False,
        timeout=httpx.Timeout(20.0, connect=10.0),
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        verify=verify,
        trust_env=False,
    )


class BudgetExceeded(IntegrationError):
    """A collection used up its request or record budget.

    Raised as its own type so an optional read never mistakes "Nyctr stopped
    asking" for "the provider does not offer this".
    """


def must_stop(error: IntegrationError) -> bool:
    """Say whether an error on an optional read must fail the collection instead of becoming a gap.

    A missing optional feature is a gap. A broken connection, a rate limit or a
    spent budget is not: continuing would return an incomplete snapshot labelled
    with the wrong cause.
    """
    return isinstance(error, BudgetExceeded) or error.category in {"tls", "transport", "timeout", "rate_limit"}


class ReadClient:
    """GET-only, same-origin requests; external pagination URLs are never followed."""

    def __init__(self, client: httpx.AsyncClient, base_url: str):
        """Bind a validated provider origin to per-collection request and record budgets."""
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.requests = 0
        self.records = 0

    def count_records(self, count: int) -> None:
        """Charge returned rows against the shared collection budget or fail closed."""
        self.records += count
        if self.records > MAX_RECORDS:
            raise BudgetExceeded("Collection exceeded its record budget; narrow the integration scope.")

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Read a local provider path with bounded size and sanitized failures.

        Reject redirects and provider-level errors even when HTTP reports success;
        never include response contents or credentials in public exceptions.
        """
        return await exchange(self, "GET", path, params)


async def exchange(reader: ReadClient, method: str, path: str, params: dict[str, Any] | None = None,
                   body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Perform one bounded same-origin request and return its JSON object.

    Shared by collection (GET) and by the separately gated action client. An
    empty successful body is returned as an empty object.
    """
    self = reader
    if not path.startswith("/") or path.startswith("//") or any(x in path for x in ("?", "#", "\\", "..")):
        raise IntegrationError("Invalid connector request path.")
    self.requests += 1
    if self.requests > MAX_REQUESTS:
        raise BudgetExceeded("Collection exceeded its request budget; narrow the site scope.")
    try:
        async with self.client.stream(method, self.base_url + path, params=params, json=body) as response:
            if (evidence := _probe_evidence.get()) is not None:
                evidence.responses_received += 1
            if response.is_redirect:
                raise IntegrationError("Provider redirected the request; redirects are never followed.")
            if response.status_code in {401, 403}:
                raise IntegrationError("Provider denied access. Check the configured key and its read permissions.",
                                       category="authentication")
            if response.status_code == 429:
                raise IntegrationError("Provider rate limit reached. Try syncing later.", category="rate_limit")
            if response.status_code >= 400:
                raise IntegrationError(f"Provider returned HTTP {response.status_code}.")
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > MAX_BODY_BYTES:
                    raise IntegrationError("Provider response exceeded the collection size limit.")
                chunks.append(chunk)
            raw = b"".join(chunks)
            payload = {} if method != "GET" and not raw.strip() else json.loads(raw)
    except (httpx.HTTPError, OSError) as exc:
        raise IntegrationError("Could not securely connect to the provider. Check its address, certificate, and availability.",
                               category=_transport_category(exc)) from None
    except (ValueError, UnicodeError):
        raise IntegrationError("Provider returned invalid JSON.") from None
    if not isinstance(payload, dict):
        raise IntegrationError("Provider response must be a JSON object.")
    if payload.get("errors"):
        # NextDNS can report failures with HTTP 200. Never expose error bodies,
        # which may contain reflected credentials, addresses, or request inputs.
        raise IntegrationError("Provider reported an API error. Check the configuration and read permissions.")
    return payload


def _rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Require a bounded list of JSON objects before pagination imports any rows."""
    rows = payload.get("data")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise IntegrationError("Provider returned an invalid list response.")
    if len(rows) > 1000:
        raise IntegrationError("Provider ignored the requested page size.")
    return rows


async def offset_pages(client: ReadClient, path: str) -> list[dict[str, Any]]:
    """Read bounded UniFi pages, rejecting repeats or inconsistent source totals."""
    results: list[dict[str, Any]] = []
    offset = 0
    seen: set[str] = set()
    for _ in range(MAX_PAGES):
        payload = await client.get(path, {"offset": offset, "limit": PAGE_SIZE})
        rows = _rows(payload)
        client.count_records(len(rows))
        for metadata_key in ("offset", "count", "totalCount"):
            value = payload.get(metadata_key)
            if value is not None and (type(value) is not int or value < 0):
                raise IntegrationError("Provider returned invalid pagination metadata.")
        if payload.get("offset", offset) != offset or payload.get("count", len(rows)) != len(rows):
            raise IntegrationError("Provider returned inconsistent pagination metadata.")
        fingerprint = hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()
        if rows and fingerprint in seen:
            raise IntegrationError("Provider repeated a page; incomplete inventory was not imported.")
        seen.add(fingerprint)
        results.extend(rows)
        total = payload.get("totalCount")
        if total is not None:
            if offset + len(rows) >= total:
                return results
            if not rows:
                raise IntegrationError("Provider ended pagination before its advertised total.")
        elif len(rows) < PAGE_SIZE:
            return results
        offset += len(rows)
    raise IntegrationError("Provider inventory exceeded the page limit; narrow the site scope.")


async def cursor_pages(client: ReadClient, path: str, params: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    """Read bounded cursor pages, using each cursor only as a query value.

    Returns the rows and whether the source still had more after the last page
    this collection may read. Stopping at that bound is not a failure: the
    caller keeps what was read and must report the read as partial. The rows are
    the most recent ones only if the caller asked the source for newest first.
    Every other fault, on any page, still raises and nothing is returned.
    """
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    query = dict(params)
    for _ in range(MAX_PAGES):
        payload = await client.get(path, query)
        rows = _rows(payload)
        client.count_records(len(rows))
        results.extend(rows)
        meta = payload.get("meta", {})
        if not isinstance(meta, dict) or not isinstance(meta.get("pagination", {}), dict):
            raise IntegrationError("Provider returned invalid cursor pagination metadata.")
        cursor = meta.get("pagination", {}).get("cursor")
        if cursor is None:
            return results, False
        if not isinstance(cursor, str) or not cursor or len(cursor) > 2048 or cursor in seen:
            raise IntegrationError("Provider returned an invalid or repeated pagination cursor.")
        seen.add(cursor)
        query["cursor"] = cursor
    return results, True
