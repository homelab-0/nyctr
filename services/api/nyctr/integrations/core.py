"""Bounded, credential-safe transport shared by provider adapters.

`ReadClient` deliberately has no write method; collection can never change a
provider. Changes go through `nyctr.integrations.actions`, which is the only
caller of the non-GET exchange below and is gated by explicit configuration.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import math
import os
import re
import ssl
import time
from collections.abc import Callable
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
# The longest one collection may spend waiting for its turn at a source that declares a request
# limit: two full windows of a limit counted by the minute. A longer wait ends as a rate limit.
LONGEST_WAIT = 120.0


class IntegrationError(Exception):
    """A safe error with a fixed diagnostic category and no provider response content."""

    def __init__(self, message: str, *, category: str = "provider_contract", transient: bool = False,
                 retry_after: int | None = None):
        """Retain a sanitized collector message and classify failure without parsing its text.

        `transient` marks a server error or a request timeout (408) at the source, which may pass by waiting; its
        category is unchanged, so optional reads and diagnostics treat it as before.
        `retry_after` is the wait in seconds a rate-limited source asked for, if it said.
        """
        super().__init__(message)
        self.category = category
        self.transient = transient
        self.retry_after = retry_after


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
    # Why a gap happened, where the source's last answer said so: code -> causes from GAP_CAUSES.
    gap_causes: dict[str, set[str]] = field(default_factory=dict)
    # How the latest request was turned away, until the next request or the gap that records it.
    last_fault: str | None = None


_probe_evidence: ContextVar[ProbeEvidence | None] = ContextVar("nyctr_probe_evidence", default=None)


@contextmanager
def capture_probe():
    """Isolate one task's evidence to the current async context and reset it even after failure.

    Opened by the connection test and by every collection, so both record the same gaps.
    """
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
    """Record a fixed code for something this collection or connection test could not read.

    A gap recorded straight after the source refused a read or answered with an error
    of its own keeps that cause, so the two are never told as one.
    """
    if (evidence := _probe_evidence.get()) is not None:
        evidence.gaps.add(gap)
        if evidence.last_fault:
            evidence.gap_causes.setdefault(gap, set()).add(evidence.last_fault)
            evidence.last_fault = None


def _fault(cause: str | None):
    """Note how the request in hand was turned away; None at the start of each request."""
    if (evidence := _probe_evidence.get()) is not None:
        evidence.last_fault = cause


# Plain words for why a read was not made. Fixed text: nothing from a response is repeated.
GAP_CAUSES = {
    "refused": "This time the source refused the read: this key may not read it.",
    "source_error": "This time the source had an error of its own, so the next collection may read it.",
}
UNDESCRIBED_GAP = ("Part of this source could not be read",
                   "This release has no description for what was missed.")


def describe_gaps(notes: dict[str, tuple[str, str]], gaps: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Turn recorded gap codes, each with its causes, into (code, title, text) in the integration's words."""
    entries = []
    for code in sorted(gaps):
        title, text = notes.get(code, UNDESCRIBED_GAP)
        causes = [GAP_CAUSES[cause] for cause in sorted(GAP_CAUSES) if cause in (gaps[code] or ())]
        entries.append((code, title, " ".join([text, *causes])))
    return entries


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
        raise IntegrationError(f"{label} must be an address that starts with https://.")
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        raise IntegrationError(f"{label} is not an address Nyctr can read. Check it for a typing mistake.") from None
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
        raise IntegrationError(f"{label} must start with https:// and hold no sign-in name, password, question mark, # or space.")
    if host in {"localhost", "metadata.google.internal", "metadata.azure.internal"} or host.endswith(".localhost"):
        raise IntegrationError(f"{label} cannot be the Nyctr server itself or a cloud metadata address.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address and (
        address.is_loopback or address.is_link_local or address.is_multicast
        or address.is_unspecified or address.is_reserved
        or (getattr(address, "ipv4_mapped", None) is not None)
    ):
        raise IntegrationError(f"{label} cannot be a loopback, link-local, multicast or reserved address.")
    allowed = {
        entry.strip().lower()
        for entry in os.getenv("NYCTR_CONNECTOR_HOSTS", "").split(",")
        if entry.strip()
    }
    if host not in allowed:
        raise IntegrationError(f"{label} names a server Nyctr is not yet allowed to connect to. Only whoever runs the Nyctr server "
                               "can change that: ask them to add this server's name to the sources Nyctr may reach.")
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


MAX_RETRY_AFTER = 3600
RETRY_AFTER_SECONDS = re.compile(r"[0-9]{1,9}")


def _retry_after(value: str | None) -> int | None:
    """Read a Retry-After wait given in seconds, capped at an hour.

    Never raises: a 429 is a rate limit whatever its header says, and a date,
    a non-ASCII digit or an overlong number only means no wait is known.
    """
    seconds = value.strip() if value is not None else ""
    return min(int(seconds), MAX_RETRY_AFTER) if RETRY_AFTER_SECONDS.fullmatch(seconds) else None


@dataclass(frozen=True)
class Pace:
    """A request limit an integration declares for one destination.

    At most `requests` are sent in any `seconds`. Every reader given a pace with
    the same `key` shares one count, whatever it is reading for. The count lives
    in this process: two copies of Nyctr each keep their own.
    """
    key: str
    requests: int
    seconds: float = 60.0


@dataclass
class _Patience:
    """How long the work in this context may still wait for a turn, and who to tell when it waits."""
    left: float
    waited: Callable[[float], None] | None = None


# When each paced request was answered, by pace key. A request still in flight holds infinity.
_turns: dict[str, list[list[float]]] = {}
_patience: ContextVar[_Patience | None] = ContextVar("nyctr_pace_patience", default=None)
monotonic = time.monotonic
pause = asyncio.sleep


@contextmanager
def patience(seconds: float | None = None, waited: Callable[[float], None] | None = None):
    """Bound the total time requests in this context may wait for a turn at a paced source.

    Without `seconds` the bound already in force is kept, or `LONGEST_WAIT`.
    `waited` is called with each wait just before it starts, so a caller that
    limits reading time can leave waiting out of it.
    """
    outer = _patience.get()
    token = _patience.set(_Patience(
        seconds if seconds is not None else outer.left if outer else LONGEST_WAIT, waited))
    try:
        yield
    finally:
        _patience.reset(token)


async def _take_turn(pace: Pace) -> list[float]:
    """Wait until one more request fits the declared limit, and claim its place.

    A wait longer than this context may still spend is not started: the request
    fails as a rate limit carrying that wait, so a retry comes back when it fits.
    """
    turns = _turns.setdefault(pace.key, [])
    while True:
        now = monotonic()
        turns[:] = [turn for turn in turns if now - turn[0] < pace.seconds]
        if len(turns) < pace.requests:
            turn = [math.inf]
            turns.append(turn)
            return turn
        # Only a limit smaller than the requests in flight leaves nothing answered to wait for.
        # The floor keeps a wait that rounding made too short from being repeated without end.
        wait = max(min(min(turn[0] for turn in turns) + pace.seconds - now, pace.seconds), 0.001)
        allowed = _patience.get() or _Patience(LONGEST_WAIT)
        if wait > allowed.left:
            raise IntegrationError("The source's request limit is in use. Try again shortly.",
                                   category="rate_limit", retry_after=math.ceil(wait))
        allowed.left -= wait
        if allowed.waited:
            allowed.waited(wait)
        await pause(wait)


def must_stop(error: IntegrationError) -> bool:
    """Say whether an error on an optional read must fail the collection instead of becoming a gap.

    A missing optional feature is a gap. A broken connection, a rate limit or a
    spent budget is not: continuing would return an incomplete snapshot labelled
    with the wrong cause.
    """
    return isinstance(error, BudgetExceeded) or error.category in {"tls", "transport", "timeout", "rate_limit"}


class ReadClient:
    """GET-only, same-origin requests; external pagination URLs are never followed."""

    def __init__(self, client: httpx.AsyncClient, base_url: str, pace: Pace | None = None):
        """Bind a validated provider origin to per-collection request and record budgets.

        With `pace`, each request first waits for its turn under that declared limit.
        """
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.pace = pace
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
    _fault(None)
    turn = await _take_turn(self.pace) if self.pace else None
    try:
        async with self.client.stream(method, self.base_url + path, params=params, json=body) as response:
            if (evidence := _probe_evidence.get()) is not None:
                evidence.responses_received += 1
            if response.is_redirect:
                raise IntegrationError("Provider redirected the request; redirects are never followed.")
            if response.status_code in {401, 403}:
                _fault("refused")
                raise IntegrationError("Provider denied access. Check the configured key and its read permissions.",
                                       category="authentication")
            if response.status_code == 429:
                raise IntegrationError("The source's request limit was reached. Try collecting again later.", category="rate_limit",
                                       retry_after=_retry_after(response.headers.get("retry-after")))
            if response.status_code >= 400:
                # A 408 is the source giving up on a read it could not finish: like a 5xx, it may pass.
                passing = response.status_code >= 500 or response.status_code == 408
                _fault("source_error" if passing else None)
                raise IntegrationError(f"Provider returned HTTP {response.status_code}.", transient=passing)
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
    finally:
        if turn is not None:
            # Counted from the answer, so the limit holds by the source's clock as well as ours.
            turn[0] = monotonic()
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
