"""The only code path that changes a provider. Off unless an operator enables it.

Every function here performs one narrowly scoped, documented provider call and
then reads back enough to say what actually happened. Two functions do not yet
read back: creating a voucher trusts the voucher the provider returns, and
deleting one trusts the accepted request; collection mirrors the list afterwards.
Callers decide whether an action is allowed; this module refuses to run unless
the caller passes the operator's explicit write permission for the provider.

The core never imports these by name. Each provider lists the actions it
supports in its `PROVIDER` declaration (see `registry.py`), and a feature calls
whatever the source of the evidence declares.

Contracts:
- UniFi Network integration API 11.0.97: hotspot vouchers and the two guest
  client actions, AUTHORIZE_GUEST_ACCESS and UNAUTHORIZE_GUEST_ACCESS.
- NextDNS API: the profile `allowlist` array endpoint. Its POST and item DELETE
  follow the documented rule for nested arrays; they have not been exercised
  against the live service by this project.
"""

from __future__ import annotations

import re
from typing import Any

from . import core
from .core import IntegrationError, ReadClient, exchange, offset_pages

NEXTDNS_BASE = "https://api.nextdns.io"
_DOMAIN = re.compile(r"(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}")
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,255}")


class WritesDisabled(IntegrationError):
    """Raised before any network call when the operator has not allowed changes to a provider."""

    def __init__(self, provider: str):
        """Name the provider so the caller can show a precise, credential-free explanation."""
        super().__init__(f"Nyctr is read-only for {provider}. An operator must allow changes first.",
                         category="configuration")


def _require(allowed: bool, provider: str) -> None:
    """Fail closed unless the caller holds explicit permission to change this provider."""
    if allowed is not True:
        raise WritesDisabled(provider)


def _domain(value: str) -> str:
    """Accept only a plain lowercase DNS name; never a URL, wildcard or address."""
    domain = value.strip().rstrip(".").lower()
    if not _DOMAIN.fullmatch(domain):
        raise IntegrationError("That is not a valid domain name.")
    return domain


def _path_id(value: str) -> str:
    """Validate an identifier before it becomes a URL path segment."""
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise IntegrationError("Invalid provider identifier.")
    return value


async def _allowlist(reader: ReadClient, profile: str) -> dict[str, bool]:
    """Read the profile allowlist as {domain: active}."""
    payload = await reader.get(f"/profiles/{profile}/allowlist")
    rows = payload.get("data")
    if not isinstance(rows, list) or any(not isinstance(x, dict) for x in rows):
        raise IntegrationError("NextDNS returned an invalid allowlist.")
    return {str(x.get("id", "")).lower(): bool(x.get("active", True)) for x in rows}


async def nextdns_allow(config: dict[str, Any], api_key: str, domain: str, *, allowed: bool) -> dict[str, Any]:
    """Allow a domain on the whole profile and verify it. Reports whether Nyctr created the entry.

    An entry that already exists is left exactly as it was and reported as not
    owned, so a later expiry will not remove a rule someone else wrote.
    """
    _require(allowed, "NextDNS")
    name, profile = _domain(domain), _path_id(config["profile_id"])
    async with core.make_http_client(api_key) as client:
        reader = ReadClient(client, NEXTDNS_BASE)
        before = await _allowlist(reader, profile)
        if before.get(name) is True:
            return {"owned": False, "verified": True}
        if name in before:
            raise IntegrationError("That domain is on the allowlist but switched off. Nyctr will not change it.")
        await exchange(reader, "POST", f"/profiles/{profile}/allowlist", body={"id": name, "active": True})
        after = await _allowlist(reader, profile)
        if after.get(name) is not True:
            raise IntegrationError("NextDNS accepted the request but the domain is not on the allowlist.")
        return {"owned": True, "verified": True}


async def nextdns_disallow(config: dict[str, Any], api_key: str, domain: str, *, allowed: bool) -> dict[str, Any]:
    """Remove an allowlist entry Nyctr created and verify it is gone.

    A missing entry counts as done: someone already removed it.
    """
    _require(allowed, "NextDNS")
    name, profile = _domain(domain), _path_id(config["profile_id"])
    async with core.make_http_client(api_key) as client:
        reader = ReadClient(client, NEXTDNS_BASE)
        if name not in await _allowlist(reader, profile):
            return {"removed": False, "verified": True}
        await exchange(reader, "DELETE", f"/profiles/{profile}/allowlist/{name}")
        if name in await _allowlist(reader, profile):
            raise IntegrationError("NextDNS accepted the request but the domain is still on the allowlist.")
        return {"removed": True, "verified": True}


def _voucher(row: dict[str, Any]) -> dict[str, Any]:
    """Turn one documented UniFi voucher into the neutral guest-pass shape the core stores."""
    if not isinstance(row.get("id"), str) or not isinstance(row.get("code"), str):
        raise IntegrationError("UniFi returned an invalid voucher.")
    return {"id": row["id"], "code": row["code"], "name": row.get("name"),
            "minutes": row.get("timeLimitMinutes"), "guest_limit": row.get("authorizedGuestLimit"),
            "data_limit_mb": row.get("dataUsageLimitMBytes"), "guest_count": row.get("authorizedGuestCount"),
            "created_at": row.get("createdAt"), "activated_at": row.get("activatedAt"),
            "expires_at": row.get("expiresAt"), "expired": row.get("expired") is True}


async def unifi_create_voucher(config: dict[str, Any], api_key: str, site: str, *, name: str, minutes: int,
                               guest_limit: int | None, data_limit_mb: int | None,
                               allowed: bool) -> dict[str, Any]:
    """Create one hotspot voucher and return its details, including the code."""
    _require(allowed, "UniFi")
    body: dict[str, Any] = {"count": 1, "name": name[:120], "timeLimitMinutes": minutes}
    if guest_limit:
        body["authorizedGuestLimit"] = guest_limit
    if data_limit_mb:
        body["dataUsageLimitMBytes"] = data_limit_mb
    async with core.make_http_client(api_key) as client:
        reader = ReadClient(client, config["base_url"])
        payload = await exchange(reader, "POST", f"/v1/sites/{_path_id(site)}/hotspot/vouchers", body=body)
    vouchers = payload.get("vouchers")
    if not isinstance(vouchers, list) or len(vouchers) != 1 or not isinstance(vouchers[0], dict):
        raise IntegrationError("UniFi did not return the created voucher.")
    return _voucher(vouchers[0])


async def unifi_delete_voucher(config: dict[str, Any], api_key: str, site: str, voucher: str, *,
                               allowed: bool) -> None:
    """Delete one voucher by its identifier."""
    _require(allowed, "UniFi")
    async with core.make_http_client(api_key) as client:
        reader = ReadClient(client, config["base_url"])
        await exchange(reader, "DELETE", f"/v1/sites/{_path_id(site)}/hotspot/vouchers/{_path_id(voucher)}")


async def unifi_list_vouchers(reader: ReadClient, site: str) -> list[dict[str, Any]]:
    """Read every voucher of a site. A read; shared with collection."""
    return [_voucher(row) for row in await offset_pages(reader, f"/v1/sites/{_path_id(site)}/hotspot/vouchers")]


async def unifi_guest_action(config: dict[str, Any], api_key: str, site: str, client_id: str, action: str, *,
                             minutes: int | None = None, allowed: bool) -> dict[str, Any]:
    """Authorize or unauthorize one guest client and read back its resulting access state."""
    _require(allowed, "UniFi")
    if action not in {"AUTHORIZE_GUEST_ACCESS", "UNAUTHORIZE_GUEST_ACCESS"}:
        raise IntegrationError("Unsupported guest action.")
    body: dict[str, Any] = {"action": action}
    if action == "AUTHORIZE_GUEST_ACCESS" and minutes:
        body["timeLimitMinutes"] = minutes
    path = f"/v1/sites/{_path_id(site)}/clients/{_path_id(client_id)}"
    async with core.make_http_client(api_key) as client:
        reader = ReadClient(client, config["base_url"])
        await exchange(reader, "POST", path + "/actions", body=body)
        try:
            detail = await reader.get(path)
        except IntegrationError:
            # A cut-off client may no longer be listed; the action itself succeeded.
            return {"authorized": None, "verified": False}
    access = detail.get("access") if isinstance(detail.get("access"), dict) else {}
    authorized = access.get("authorized")
    expected = action == "AUTHORIZE_GUEST_ACCESS"
    if isinstance(authorized, bool) and authorized != expected:
        raise IntegrationError("UniFi accepted the request but the device's access did not change.")
    return {"authorized": authorized if isinstance(authorized, bool) else None,
            "verified": isinstance(authorized, bool)}



async def unifi_set_guest_access(config: dict[str, Any], api_key: str, site: str, client_id: str, allow: bool, *,
                                 minutes: int | None = None, allowed: bool) -> dict[str, Any]:
    """Let one guest client on, or take its access away. The neutral form the core calls."""
    return await unifi_guest_action(config, api_key, site, client_id,
                                    "AUTHORIZE_GUEST_ACCESS" if allow else "UNAUTHORIZE_GUEST_ACCESS",
                                    minutes=minutes, allowed=allowed)
