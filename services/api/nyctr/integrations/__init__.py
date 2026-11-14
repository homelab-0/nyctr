"""Integrations. Each provider is one module registered in `registry.py`; the core never names one."""

from __future__ import annotations

import asyncio
from typing import Any

from . import core, registry
from .core import IntegrationError, Snapshot

# The longest one collection may spend reading, whatever the source. Time spent waiting for a
# turn at a source that declares a request limit is not reading and is bounded separately.
READING_SECONDS = 60


def capabilities_for(provider: str) -> list[str]:
    """Return a fresh list of the read-capability identifiers an integration implements."""
    found = registry.find(provider)
    return [read for read, _label in found.reads] if found else []


def validate_config(provider: str, config: dict[str, Any]) -> dict[str, Any]:
    """Validate supported keys and normalize configuration before credentials are used.

    The provider's own validator rejects unapproved destinations and unbounded
    settings with errors safe to return to an administrator.
    """
    if not isinstance(config, dict):
        raise IntegrationError("Integration configuration must be an object.")
    return registry.get(provider).validate(config)


async def collect(provider: str, integration_id: str, config: dict[str, Any], api_key: str) -> Snapshot:
    """Collect a complete read-only snapshot within one bounded operation.

    Validate configuration before dispatch and convert the overall timeout into
    a sanitized provider error; callers must discard failed partial collections.
    Each wait for a turn at a paced source moves the deadline back by that wait,
    so reading is limited to the same time for every source.
    """
    definition = registry.get(provider)
    clean = definition.validate(config) if isinstance(config, dict) else validate_config(provider, config)
    try:
        async with asyncio.timeout(READING_SECONDS) as limit:
            with core.patience(waited=lambda wait: limit.reschedule(limit.when() + wait)):
                return await definition.collect(integration_id, clean, api_key)
    except TimeoutError:
        raise IntegrationError("Collection timed out; narrow its site scope or log lookback.",
                               category="timeout") from None


__all__ = ["IntegrationError", "Snapshot", "capabilities_for", "collect", "registry", "validate_config"]
