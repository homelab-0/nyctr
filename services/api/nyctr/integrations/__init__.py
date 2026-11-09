"""Vendor adapters with an intentionally read-only capability boundary."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from .core import IntegrationError, Snapshot, validate_unifi_url

_CAPABILITIES = {
    "unifi_network": ["sites:read", "devices:read", "clients:read", "networks:read", "firewall_policies:read"],
    "nextdns": ["profile:read", "dns_policies:read", "blocked_dns_logs:read"],
}


def capabilities_for(provider: str) -> list[str]:
    """Return a fresh list of implemented read capabilities for a provider."""
    return list(_CAPABILITIES.get(provider, []))


def validate_config(provider: str, config: dict[str, Any]) -> dict[str, Any]:
    """Validate supported keys and normalize configuration before credentials are used.

    Reject unsupported providers, unapproved UniFi destinations, and unbounded
    NextDNS lookbacks with errors safe to return to an administrator.
    """
    if not isinstance(config, dict):
        raise IntegrationError("Integration configuration must be an object.")
    if provider == "unifi_network":
        if set(config) - {"base_url", "site_id"}:
            raise IntegrationError("UniFi supports base_url and optional site_id configuration only.")
        clean = {"base_url": validate_unifi_url(config.get("base_url"))}
        if config.get("site_id"):
            site = config["site_id"]
            if not isinstance(site, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", site):
                raise IntegrationError("Invalid UniFi site identifier.")
            clean["site_id"] = site
        return clean
    if provider == "nextdns":
        if set(config) - {"profile_id", "lookback_hours"}:
            raise IntegrationError("NextDNS supports profile_id and optional lookback_hours configuration only.")
        profile = config.get("profile_id")
        if not isinstance(profile, str) or not re.fullmatch(r"[a-fA-F0-9]{6}", profile):
            raise IntegrationError("NextDNS profile_id must contain six hexadecimal characters.")
        hours = config.get("lookback_hours", 24)
        if type(hours) is not int or not 1 <= hours <= 72:
            raise IntegrationError("NextDNS lookback_hours must be an integer between 1 and 72.")
        return {"profile_id": profile.lower(), "lookback_hours": hours}
    raise IntegrationError("This provider is not implemented in this release.")


async def collect(provider: str, integration_id: str, config: dict[str, Any], api_key: str) -> Snapshot:
    """Collect a complete read-only snapshot within one bounded operation.

    Validate configuration before dispatch and convert the overall timeout into
    a sanitized provider error; callers must discard failed partial collections.
    """
    clean = validate_config(provider, config)
    try:
        async with asyncio.timeout(60):
            if provider == "unifi_network":
                from .unifi import collect_unifi

                return await collect_unifi(integration_id, clean, api_key)
            from .nextdns import collect_nextdns

            return await collect_nextdns(integration_id, clean, api_key)
    except TimeoutError:
        raise IntegrationError("Collection timed out; narrow its site scope or log lookback.") from None


__all__ = ["IntegrationError", "Snapshot", "capabilities_for", "collect", "validate_config"]
