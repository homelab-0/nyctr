"""Background upkeep: close expired access, and collect on the schedule in force.

Runs inside each API process. Closing leases is always on so temporary access
ends even if nobody opens the console. The collection schedule is read from the
database at every pass, so a change made in the Console applies within one tick
on every running copy, and it never runs in demo mode.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from . import schedule
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


async def tick(factory, settings, now=None) -> bool:
    """Run one upkeep pass and say whether it performed a scheduled collection.

    The run is claimed in the database before any source is contacted, so a
    second copy of Nyctr on the same database skips it, and a source that fails
    is not tried again until the next scheduled time.
    """
    with factory() as db:
        await reconcile(db, settings)
        due = schedule.claim_run(db, schedule.in_force(db, settings), now)
    if due:
        await collect_all(factory, settings)
    return due


async def run(app) -> None:
    """Loop until cancelled. One failed pass is logged without its cause text and retried next tick."""
    settings, factory = app.state.settings, app.state.session_factory
    while True:
        await asyncio.sleep(TICK_SECONDS)
        try:
            await tick(factory, settings)
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001 - upkeep must survive any single failure
            log.warning("Background upkeep failed: %s", type(error).__name__)
