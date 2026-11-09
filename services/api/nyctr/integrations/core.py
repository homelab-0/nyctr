"""Bounded, credential-safe read transport shared by provider adapters.

This module deliberately has no write method. Imported metadata is evidence,
not authority to make an infrastructure change.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import ssl
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
    """A safe public error; never include a request, response body, or API key."""


@dataclass
class Snapshot:
    resources: list[dict[str, Any]] = field(default_factory=list)
    relationships: list[dict[str, Any]] = field(default_factory=list)
    blocks: list[dict[str, Any]] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


def source_id(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", value):
        raise IntegrationError("The provider returned an invalid resource identifier.")
    return value


def object_id(integration_id: str, kind: str, value: Any) -> str:
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


def validate_unifi_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise IntegrationError("UniFi requires an HTTPS integration base URL.")
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        raise IntegrationError("Invalid UniFi integration base URL.") from None
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
        raise IntegrationError("UniFi requires HTTPS without URL credentials, query, or fragment.")
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
        raise IntegrationError("UniFi hostname is not in the server's NYCTR_CONNECTOR_HOSTS allowlist.")
    path = parsed.path.rstrip("/")
    local = path == "/proxy/network/integration"
    cloud = bool(re.fullmatch(r"/v1/connector/consoles/[A-Za-z0-9:_-]+/proxy/network/integration", path))
    if not local and not (host == "api.ui.com" and cloud):
        raise IntegrationError("Use the documented UniFi Network integration base path.")
    return value.rstrip("/")


def make_http_client(api_key: str) -> httpx.AsyncClient:
    if not isinstance(api_key, str) or not api_key or any(c in api_key for c in "\r\n"):
        raise IntegrationError("The configured API key is missing or invalid.")
    ca_bundle = os.getenv("NYCTR_CONNECTOR_CA_BUNDLE")
    try:
        verify = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else True
    except (OSError, ssl.SSLError):
        raise IntegrationError("The server's connector CA bundle could not be loaded.") from None
    return httpx.AsyncClient(
        headers={"X-Api-Key": api_key, "Accept": "application/json"},
        follow_redirects=False,
        timeout=httpx.Timeout(20.0, connect=10.0),
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
        verify=verify,
        trust_env=False,
    )


class ReadClient:
    """GET-only, same-origin requests; external pagination URLs are never followed."""

    def __init__(self, client: httpx.AsyncClient, base_url: str):
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.requests = 0
        self.records = 0

    def count_records(self, count: int) -> None:
        self.records += count
        if self.records > MAX_RECORDS:
            raise IntegrationError("Collection exceeded its record budget; narrow the integration scope.")

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if not path.startswith("/") or path.startswith("//") or any(x in path for x in ("?", "#", "\\", "..")):
            raise IntegrationError("Invalid connector request path.")
        self.requests += 1
        if self.requests > MAX_REQUESTS:
            raise IntegrationError("Collection exceeded its request budget; narrow the site scope.")
        try:
            async with self.client.stream("GET", self.base_url + path, params=params) as response:
                if response.is_redirect:
                    raise IntegrationError("Provider redirected the request; redirects are never followed.")
                if response.status_code in {401, 403}:
                    raise IntegrationError("Provider denied access. Check the configured key and its read permissions.")
                if response.status_code == 429:
                    raise IntegrationError("Provider rate limit reached. Try syncing later.")
                if response.status_code >= 400:
                    raise IntegrationError(f"Provider returned HTTP {response.status_code}.")
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_BODY_BYTES:
                        raise IntegrationError("Provider response exceeded the collection size limit.")
                    chunks.append(chunk)
                payload = json.loads(b"".join(chunks))
        except (httpx.HTTPError, OSError):
            raise IntegrationError("Could not securely connect to the provider. Check its address, certificate, and availability.") from None
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
    rows = payload.get("data")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise IntegrationError("Provider returned an invalid list response.")
    if len(rows) > 1000:
        raise IntegrationError("Provider ignored the requested page size.")
    return rows


async def offset_pages(client: ReadClient, path: str) -> list[dict[str, Any]]:
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


async def cursor_pages(client: ReadClient, path: str, params: dict[str, Any]) -> list[dict[str, Any]]:
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
            return results
        if not isinstance(cursor, str) or not cursor or len(cursor) > 2048 or cursor in seen:
            raise IntegrationError("Provider returned an invalid or repeated pagination cursor.")
        seen.add(cursor)
        query["cursor"] = cursor
    raise IntegrationError("Provider logs exceeded the page limit; reduce the lookback period.")
