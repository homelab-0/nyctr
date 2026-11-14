"""Background upkeep: close expired access, and collect on the schedule in force.

Runs inside each API process. Every 30 seconds a tick does two separate things,
and neither waits for the other. It ends the exceptions whose time is up, so
temporary access ends even if nobody opens the console and however long a
collection takes. And it starts a collection pass unless this copy's previous
pass is still going: the pass claims the scheduled run if one is due, collects
each source in turn, then runs the retries that are due. The schedule is read
from the database at every pass, so a change an administrator saves applies at
the next pass on every running copy, and it never runs in demo mode.

A scheduled collection that fails for a reason that may pass is retried up to
three times before the source is shown as failed (see `schedule.plan_retry`).
A Collect pressed by a person and a connection test are never retried.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select, update

from . import schedule
from .access import end_lease
from .collection import after_collection, collect_integration
from .guests import enforce
from .models import Integration, Lease, utcnow
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


async def collection_pass(factory, settings, now=None, *, clock=None) -> bool:
    """Run one collection pass and say whether it performed a scheduled collection.

    The run is claimed in the database before any source is contacted, so a
    second copy of Nyctr on the same database skips it. Retries that are due
    are claimed the same way and run after it. `now` fixes the time of the
    whole pass; `clock` is read again whenever a time is needed.
    """
    clock = clock or ((lambda: now) if now else utcnow)
    with factory() as db:
        plan = schedule.in_force(db, settings)
        due = schedule.claim_run(db, plan, clock())
    if due:
        await collect_all(factory, settings, plan=plan, clock=clock)
    await retry_due(factory, settings, plan, clock)
    return due


async def end_at_source(factory, settings, lease_ids: list[str]) -> None:
    """End one source's expired exceptions in turn, each in its own transaction.

    In turn, because two exceptions for one address share one entry at the source
    and the entry goes only with the last of them. No row is locked during the
    provider call. After it the exception's row is locked and read again, and the
    outcome is recorded only if it is still open: another copy of Nyctr, or
    someone reading the list, may have ended it meanwhile, and then nothing is
    written here. A failure is logged without its cause text and the rest go on;
    an exception that could not be ended stays open and is tried again next tick.
    """
    for lease_id in lease_ids:
        try:
            with factory() as db:
                lease = db.get(Lease, lease_id)
                if lease is None or lease.status != "active":
                    continue
                await end_lease(db, settings, lease, "expired")
                with db.no_autoflush:  # Read what is stored, not what this session is about to write.
                    stored = db.scalar(select(Lease.status).where(Lease.id == lease_id).with_for_update())
                if stored != "active":
                    db.rollback()
                    continue
                db.commit()
        except Exception as error:  # noqa: BLE001 - one exception's failure must not keep the others open
            log.warning("Ending an expired exception failed: %s", type(error).__name__)


class Upkeep:
    """One copy's upkeep: what a tick starts, and what is still going from earlier ticks.

    A tick never waits for a provider. It starts at most one collection pass, and
    at most one run of endings per source, so a slow collection or a source that
    does not answer holds up neither the next tick nor the other sources.
    """

    def __init__(self, factory, settings, clock=utcnow):
        self.factory, self.settings, self.clock = factory, settings, clock
        self.collecting: asyncio.Task | None = None
        self.ending: dict[str | None, asyncio.Task] = {}

    def tick(self) -> None:
        """Start a collection pass if none is going, then the endings that are due.

        A run or retry that comes due during a pass is not claimed until the pass
        ends, so it stays due in the database for the next tick, or for another copy.
        """
        if self.collecting is None or self.collecting.done():
            self.collecting = asyncio.create_task(self._collect())
        with self.factory() as db:
            due = db.execute(select(Lease.id, Lease.integration_id).where(
                Lease.status == "active", Lease.expires_at.is_not(None), Lease.expires_at <= self.clock()
            ).order_by(Lease.expires_at)).all()
        by_source: dict[str | None, list[str]] = {}
        for lease_id, source in due:
            by_source.setdefault(source, []).append(lease_id)
        for source, lease_ids in by_source.items():
            # Endings still going at this source cover it; what they miss is due again next tick.
            if source not in self.ending or self.ending[source].done():
                self.ending[source] = asyncio.create_task(end_at_source(self.factory, self.settings, lease_ids))

    async def _collect(self) -> None:
        """Run one collection pass. A failure is logged without its cause text; the next tick starts another."""
        try:
            await collection_pass(self.factory, self.settings, clock=self.clock)
        except Exception as error:  # noqa: BLE001 - upkeep must survive any single failure
            log.warning("Background upkeep failed: %s", type(error).__name__)

    async def stop(self) -> None:
        """Cancel whatever is still going and wait until it has stopped."""
        tasks = [task for task in (self.collecting, *self.ending.values()) if task]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def run(app) -> None:
    """Tick until cancelled, then stop what is in progress. A failed tick is logged without its cause text."""
    upkeep = Upkeep(app.state.session_factory, app.state.settings)
    try:
        while True:
            await asyncio.sleep(TICK_SECONDS)
            try:
                upkeep.tick()
            except Exception as error:  # noqa: BLE001 - upkeep must survive any single failure
                log.warning("Background upkeep failed: %s", type(error).__name__)
    finally:
        await upkeep.stop()
