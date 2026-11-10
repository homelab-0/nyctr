"""Background upkeep: close expired access, and optionally collect on a schedule.

Runs inside the single API process. Closing leases is always on so temporary
access ends even if nobody opens the console. Scheduled collection is off
unless an operator sets an interval, and it never runs in demo mode.
"""

from __future__ import annotations

import asyncio
import logging
import time

from sqlalchemy import select

from .access import reconcile
from .collection import after_collection, collect_integration
from .guests import enforce
from .models import Integration

log = logging.getLogger("nyctr.worker")
TICK_SECONDS = 30


async def collect_all(factory, settings, actor: str | None = None) -> None:
    """Collect every configured source, then run analysis and the guest rule once."""
    with factory() as db:
        ids = list(db.scalars(select(Integration.id)))
    for integration_id in ids:
        await collect_integration(factory, settings, integration_id, actor)
    with factory() as db:
        due = after_collection(db, settings)
        db.commit()
        await enforce(db, settings, due)


async def run(app) -> None:
    """Loop until cancelled. One failed pass is logged without its cause text and retried next tick."""
    settings, factory = app.state.settings, app.state.session_factory
    last_collection = time.monotonic()
    while True:
        await asyncio.sleep(TICK_SECONDS)
        try:
            with factory() as db:
                await reconcile(db, settings)
            interval = settings.collect_interval_seconds
            if settings.mode == "live" and interval and time.monotonic() - last_collection >= interval:
                last_collection = time.monotonic()
                await collect_all(factory, settings)
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001 - upkeep must survive any single failure
            log.warning("Background upkeep failed: %s", type(error).__name__)
