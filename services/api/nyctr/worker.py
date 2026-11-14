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

from sqlalchemy import select, update

from . import schedule
from .access import reconcile
from .collection import after_collection, collect_integration
from .guests import enforce
from .models import Integration, utcnow
from .security import audit

log = logging.getLogger("nyctr.worker")
TICK_SECONDS = 30


# Why a scheduled collection returned without contacting the source: it cannot be retried.
ENDED = {"missing", "secret", "secret_ref"}


def _hold(plan, integration_id: str, attempt: int, clock):
    """Build the failure step of one scheduled attempt: stage the next retry if the failure may pass.

    The wait is counted from when the attempt failed, not from the start of the pass.
    """
    def hold(db, failure):
        if not failure.may_pass:
            schedule.drop_retry(db, integration_id)
            return None
        return schedule.plan_retry(db, plan, integration_id, attempt, clock(), failure.retry_after)
    return hold


def _stop_retries(db, integration_id: str, reason: str) -> None:
    """End a source's pending retries without a collection, so it is not left looking healthy.

    A source kept at its previous status for a retry is shown as failed with
    its last error, and the audit says why the retries stopped. A source that
    was not waiting on a retry, or is being collected now, is left alone.
    """
    schedule.drop_retry(db, integration_id)
    shown = db.execute(update(Integration).where(
        Integration.id == integration_id, Integration.status.not_in(("error", "syncing")),
        Integration.last_error.is_not(None)).values(status="error").execution_options(synchronize_session=False))
    if shown.rowcount == 1:
        audit(db, None, "integration.retries_stopped", integration_id,
              name=db.get(Integration, integration_id).name, reason=reason)


async def collect_all(factory, settings, actor: str | None = None, *, plan=None, clock=None) -> None:
    """Collect every configured source, then run analysis and the guest rule once.

    With `plan` (the schedule in force) this is a scheduled run, and a source
    that fails for a reason that may pass gets a retry.
    """
    with factory() as db:
        ids = list(db.scalars(select(Integration.id)))
    for integration_id in ids:
        if plan is None:
            await collect_integration(factory, settings, integration_id, actor)
            continue
        snapshot, error = await collect_integration(factory, settings, integration_id, actor, attempt=0,
                                                    hold=_hold(plan, integration_id, 0, clock or utcnow))
        if error in ENDED or snapshot is not None:
            with factory() as db:
                # A retry staged by a copy that failed just as this run was claimed outlives
                # the run's clear-out; this run's verdict replaces it.
                if error:
                    _stop_retries(db, integration_id, error)
                else:
                    schedule.drop_retry(db, integration_id)
                db.commit()
    await _analyse(factory, settings)


async def _analyse(factory, settings) -> None:
    """Run analysis on the stored evidence and apply the guest rule once."""
    with factory() as db:
        due = after_collection(db, settings)
        db.commit()
        await enforce(db, settings, due)


async def retry_due(factory, settings, plan, clock) -> None:
    """Run the retries that are due and this copy claimed, or end them all if the schedule is off.

    Each retry is claimed just before it runs, and none runs once the next run
    is due. A source already being collected is put back a minute later rather
    than run alongside; a source that no longer exists or has no secret is shown
    as failed and its retries end; an attempt whose lease was replaced ends the
    retries and leaves the source to whoever holds it now.
    """
    with factory() as db:
        if not plan["enabled"]:
            for integration_id in schedule.pending_retries(db):
                _stop_retries(db, integration_id, "schedule_off")
            db.commit()
            return
        due = schedule.due_retries(db, plan, clock())
    collected = False
    for integration_id in due:
        with factory() as db:
            upcoming = schedule.next_run(db, plan, clock())
            if upcoming is None or clock() >= upcoming:
                break  # The pass ran long and the next run is due; it collects every source and clears retries.
            attempt = schedule.claim_retry(db, integration_id, clock())
        if attempt is None:
            continue  # Another copy took it, ran it or cleared it meanwhile.
        snapshot, error = await collect_integration(factory, settings, integration_id, None, attempt=attempt,
                                                    hold=_hold(plan, integration_id, attempt, clock))
        with factory() as db:
            if error == "busy":
                schedule.defer_retry(db, plan, integration_id, attempt, clock())
            elif error in ENDED:
                _stop_retries(db, integration_id, error)
            elif snapshot is not None or error == "replaced":
                # A replaced attempt stored nothing and staged nothing: whoever holds the
                # source now gives its verdict, so this chain of retries ends here.
                schedule.drop_retry(db, integration_id)
            db.commit()
        collected = collected or snapshot is not None
    if collected:
        await _analyse(factory, settings)


async def tick(factory, settings, now=None, *, clock=None) -> bool:
    """Run one upkeep pass and say whether it performed a scheduled collection.

    The run is claimed in the database before any source is contacted, so a
    second copy of Nyctr on the same database skips it. Retries that are due
    are claimed the same way and run after it. `now` fixes the time of the
    whole pass; `clock` is read again whenever a time is needed.
    """
    clock = clock or ((lambda: now) if now else utcnow)
    with factory() as db:
        await reconcile(db, settings)
        plan = schedule.in_force(db, settings)
        due = schedule.claim_run(db, plan, clock())
    if due:
        await collect_all(factory, settings, plan=plan, clock=clock)
    await retry_due(factory, settings, plan, clock)
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
