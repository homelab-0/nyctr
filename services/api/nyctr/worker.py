"""Background upkeep: close expired access, and collect on the schedule in force.

Runs inside each API process. Closing leases is always on so temporary access
ends even if nobody opens the console. The collection schedule is read from the
database at every pass, so a change an administrator saves applies within one tick
on every running copy, and it never runs in demo mode.

A scheduled collection that fails for a reason that may pass is retried up to
three times before the source is shown as failed (see `schedule.plan_retry`).
A Collect pressed by a person and a connection test are never retried.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from . import schedule
from .access import reconcile
from .collection import after_collection, collect_integration
from .guests import enforce
from .models import Integration, utcnow

log = logging.getLogger("nyctr.worker")
TICK_SECONDS = 30


def _hold(plan, integration_id: str, attempt: int, now):
    """Build the failure step of one scheduled attempt: stage the next retry if the failure may pass."""
    def hold(db, failure):
        if not failure.may_pass:
            schedule.drop_retry(db, integration_id)
            return None
        return schedule.plan_retry(db, plan, integration_id, attempt, now, failure.retry_after)
    return hold


async def collect_all(factory, settings, actor: str | None = None, *, plan=None, now=None) -> None:
    """Collect every configured source, then run analysis and the guest rule once.

    With `plan` (the schedule in force) this is a scheduled run, and a source
    that fails for a reason that may pass gets a retry.
    """
    with factory() as db:
        ids = list(db.scalars(select(Integration.id)))
    for integration_id in ids:
        if plan is None:
            await collect_integration(factory, settings, integration_id, actor)
        else:
            await collect_integration(factory, settings, integration_id, actor, attempt=0,
                                      hold=_hold(plan, integration_id, 0, now or utcnow()))
    await _analyse(factory, settings)


async def _analyse(factory, settings) -> None:
    """Run analysis on the stored evidence and apply the guest rule once."""
    with factory() as db:
        due = after_collection(db, settings)
        db.commit()
        await enforce(db, settings, due)


async def retry_due(factory, settings, plan, now) -> None:
    """Run the retries that are due and this copy claimed.

    A source already being collected is put back a minute later rather than
    run alongside; a source that no longer exists or has no secret is dropped.
    """
    with factory() as db:
        taken = schedule.claim_retries(db, plan, now)
    collected = False
    for integration_id, attempt in taken:
        snapshot, error = await collect_integration(factory, settings, integration_id, None, attempt=attempt,
                                                    hold=_hold(plan, integration_id, attempt, now))
        with factory() as db:
            if error == "busy":
                schedule.defer_retry(db, plan, integration_id, attempt, now)
            elif snapshot is not None or error in {"missing", "secret", "secret_ref"}:
                schedule.drop_retry(db, integration_id)
            db.commit()
        collected = collected or snapshot is not None
    if collected:
        await _analyse(factory, settings)


async def tick(factory, settings, now=None) -> bool:
    """Run one upkeep pass and say whether it performed a scheduled collection.

    The run is claimed in the database before any source is contacted, so a
    second copy of Nyctr on the same database skips it. Retries that are due
    are claimed the same way and run after it.
    """
    now = now or utcnow()
    with factory() as db:
        await reconcile(db, settings)
        plan = schedule.in_force(db, settings)
        due = schedule.claim_run(db, plan, now)
    if due:
        await collect_all(factory, settings, plan=plan, now=now)
    await retry_due(factory, settings, plan, now)
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
