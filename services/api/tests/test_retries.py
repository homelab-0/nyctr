"""A failed scheduled collection is retried after 1, 2 and 4 minutes before the source is shown as failed."""

import asyncio
from datetime import datetime, timedelta

import pytest
from conftest import live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import select

from nyctr import schedule, worker
from nyctr.integrations import IntegrationError, Snapshot
from nyctr.models import Audit, Integration, Setting, utc, utcnow

PASSING = {
    "broken connection": lambda: IntegrationError("Could not connect.", category="transport"),
    "timeout": lambda: IntegrationError("Collection timed out.", category="timeout"),
    "overall timeout": lambda: TimeoutError(),
    "rate limit": lambda: IntegrationError("Rate limit.", category="rate_limit"),
    "server error": lambda: IntegrationError("Provider returned HTTP 503.", transient=True),
}
LASTING = {
    "refused key": lambda: IntegrationError("Denied.", category="authentication"),
    "missing key": lambda: IntegrationError("Key invalid.", category="secret"),
    "address not allowed": lambda: IntegrationError("Not in the allowlist."),
    "client error": lambda: IntegrationError("Provider returned HTTP 404."),
    "certificate": lambda: IntegrationError("Bad certificate.", category="tls"),
    "unknown fault": lambda: RuntimeError("fabricated"),
}


def fail_dns(monkeypatch, errors):
    """Fail the DNS source with each error in turn (then succeed); the other source always succeeds."""
    asked = []

    async def collect(provider, integration_id, config, api_key):
        if integration_id == "dns":
            asked.append(integration_id)
            if errors:
                raise errors.pop(0)()
        return Snapshot()

    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "fabricated-key")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "fabricated-key")
    monkeypatch.setattr("nyctr.integrations.collect", collect)
    return asked


def tick(app, now):
    """Run one upkeep pass of this copy of Nyctr at a chosen time."""
    return asyncio.run(worker.tick(app.state.session_factory, app.state.settings, now))


def dns(app):
    """Read the DNS source's status and error, and the attempts its audit records."""
    with app.state.session_factory() as db:
        row = db.get(Integration, "dns")
        audits = db.scalars(select(Audit).where(Audit.target_id == "dns").order_by(Audit.created_at))
        return row.status, row.last_error, [(a.action.split(".")[1], a.details.get("attempt")) for a in audits]


@pytest.mark.parametrize("cause", PASSING)
def test_a_failure_that_may_pass_is_retried_after_1_2_and_4_minutes_then_shown_failed(tmp_path, monkeypatch, cause):
    """The source keeps its status while retries are pending; after the third failed retry it is failed."""
    asked = fail_dns(monkeypatch, [PASSING[cause]] * 4)
    app, start = live_app(tmp_path), utcnow()
    with TestClient(app):
        seed_live_member(app)
        assert tick(app, start) is True and len(asked) == 1
        status, error, _ = dns(app)
        assert status == "connected" and error
        for at, count, status in ((59, 1, "connected"), (60, 2, "connected"), (179, 2, "connected"),
                                  (180, 3, "connected"), (419, 3, "connected"), (420, 4, "error"),
                                  (840, 4, "error")):
            assert tick(app, start + timedelta(seconds=at)) is False
            assert (len(asked), dns(app)[0]) == (count, status), at
        assert dns(app)[2] == [("collection_failed", n) for n in range(4)]
        with app.state.session_factory() as db:
            audits = db.scalars(select(Audit).where(Audit.target_id == "dns").order_by(Audit.created_at))
            assert [utc(datetime.fromisoformat(a.details["retry_at"])) - start if "retry_at" in a.details else None
                    for a in audits] == [timedelta(minutes=m) for m in (1, 3, 7)] + [None]


@pytest.mark.parametrize("cause", LASTING)
def test_a_failure_that_will_not_pass_by_waiting_is_shown_at_once_and_not_retried(tmp_path, monkeypatch, cause):
    """A refused key, a rejected setting or an unknown fault fails the source straight away."""
    asked = fail_dns(monkeypatch, [LASTING[cause]] * 4)
    app, start = live_app(tmp_path), utcnow()
    with TestClient(app):
        seed_live_member(app)
        tick(app, start)
        assert dns(app)[0] == "error" and dns(app)[1]
        for minutes in (1, 3, 7):
            tick(app, start + timedelta(minutes=minutes))
        assert len(asked) == 1 and dns(app)[2] == [("collection_failed", 0)]


def test_a_success_on_the_second_try_clears_the_error_and_ends_the_retries(tmp_path, monkeypatch):
    """The retry that works is audited as a collection and leaves nothing pending."""
    asked = fail_dns(monkeypatch, [PASSING["broken connection"]])
    app, start = live_app(tmp_path), utcnow()
    with TestClient(app):
        seed_live_member(app)
        tick(app, start)
        tick(app, start + timedelta(minutes=1))
        assert dns(app) == ("connected", None, [("collection_failed", 0), ("collected", 1)])
        tick(app, start + timedelta(minutes=3))
        assert len(asked) == 2


def test_no_retry_is_due_at_or_past_the_next_scheduled_run(tmp_path, monkeypatch):
    """Every five minutes the third retry would land after the next run, so the second failure is final."""
    asked = fail_dns(monkeypatch, [PASSING["timeout"]] * 4)
    app, start = live_app(tmp_path), utcnow()
    with TestClient(app) as client:
        seed_live_member(app)
        client.put("/api/collection", headers=live_signin(client), json={"enabled": True, "minutes": 5})
        tick(app, start)
        tick(app, start + timedelta(minutes=1))
        assert dns(app)[0] == "connected"
        tick(app, start + timedelta(minutes=3))
        assert (len(asked), dns(app)[0]) == (3, "error")
        assert tick(app, start + timedelta(minutes=4, seconds=59)) is False and len(asked) == 3
        assert tick(app, start + timedelta(minutes=5)) is True and len(asked) == 4


@pytest.mark.parametrize("wait, retried_at", [(600, 10), (900, None), (5, 1)])
def test_a_rate_limit_that_says_when_to_come_back_is_honoured_before_the_next_run(
        tmp_path, monkeypatch, wait, retried_at):
    """The source's own wait is kept when longer than a minute, and dropped when it reaches the next run."""
    asked = fail_dns(monkeypatch, [lambda: IntegrationError("Rate limit.", category="rate_limit", retry_after=wait)])
    app, start = live_app(tmp_path), utcnow()
    with TestClient(app):
        seed_live_member(app)
        tick(app, start)
        assert dns(app)[0] == ("error" if retried_at is None else "connected")
        for minutes in range(1, 15):
            tick(app, start + timedelta(minutes=minutes))
            if minutes == retried_at:
                assert len(asked) == 2
                break
            assert len(asked) == 1, minutes


def test_two_copies_on_one_database_run_a_retry_once(tmp_path, monkeypatch):
    """Both copies see the retry as due at the same moment; one claims it."""
    asked = fail_dns(monkeypatch, [PASSING["broken connection"]] * 2)
    one, two = live_app(tmp_path), live_app(tmp_path)
    start = utcnow()
    with TestClient(one), TestClient(two):
        seed_live_member(one)

        async def both(now):
            return await asyncio.gather(*(worker.tick(copy.state.session_factory, copy.state.settings, now)
                                          for copy in (one, two)))

        asyncio.run(both(start))
        assert len(asked) == 1
        asyncio.run(both(start + timedelta(minutes=1)))
        assert len(asked) == 2 and dns(one)[2] == [("collection_failed", 0), ("collection_failed", 1)]


def test_a_retry_waits_while_the_source_is_being_collected_and_never_runs_in_demo(tmp_path, monkeypatch, app, client):
    """The collection lease puts the retry back a minute without using it up; demo has no retries."""
    asked = fail_dns(monkeypatch, [PASSING["broken connection"]])
    live, start = live_app(tmp_path), utcnow()
    with TestClient(live):
        seed_live_member(live)
        tick(live, start)
        with live.state.session_factory() as db:
            db.get(Integration, "dns").status, db.get(Integration, "dns").sync_started_at = "syncing", utcnow()
            db.commit()
        tick(live, start + timedelta(minutes=1))
        assert len(asked) == 1
        with live.state.session_factory() as db:
            db.get(Integration, "dns").status = "connected"
            db.commit()
        tick(live, start + timedelta(minutes=2))
        assert dns(live) == ("connected", None, [("collection_failed", 0), ("collected", 1)])
    with app.state.session_factory() as db:
        db.add(Setting(key=schedule.RETRY_PREFIX + "demo", value={"integration_id": "dns", "attempt": 1},
                       updated_at=start))
        db.commit()
        assert schedule.due_retries(db, schedule.in_force(db, app.state.settings), start + timedelta(hours=1)) == []
        assert utc(db.get(Setting, schedule.RETRY_PREFIX + "demo").updated_at) == start


def stopped(app):
    """Read why the DNS source's retries stopped, from the audit."""
    with app.state.session_factory() as db:
        return [a.details["reason"] for a in db.scalars(
            select(Audit).where(Audit.action == "integration.retries_stopped", Audit.target_id == "dns"))]


def pending(app):
    """List the sources with a retry pending."""
    with app.state.session_factory() as db:
        return schedule.pending_retries(db)


def test_switching_the_schedule_off_ends_pending_retries_and_shows_the_source_failed(tmp_path, monkeypatch):
    """With nothing left to retry the source, it is not left looking healthy; the audit says why."""
    fail_dns(monkeypatch, [PASSING["server error"]])
    app, start = live_app(tmp_path), utcnow()
    with TestClient(app) as client:
        seed_live_member(app)
        tick(app, start)
        assert dns(app)[0] == "connected" and pending(app) == ["dns"]
        client.put("/api/collection", headers=live_signin(client), json={"enabled": False, "minutes": 15})
        tick(app, start + timedelta(seconds=30))
        assert dns(app)[:2] == ("error", "Provider returned HTTP 503.")
        assert stopped(app) == ["schedule_off"] and pending(app) == []
        tick(app, start + timedelta(seconds=60))
        assert stopped(app) == ["schedule_off"]


def test_a_retry_whose_secret_is_gone_or_source_is_missing_ends_and_shows_the_source_failed(tmp_path, monkeypatch):
    """The retry is not left pending, and a source kept at its old status is shown failed with why."""
    asked = fail_dns(monkeypatch, [PASSING["broken connection"]])
    app, start = live_app(tmp_path), utcnow()
    with TestClient(app):
        seed_live_member(app)
        tick(app, start)
        with app.state.session_factory() as db:
            schedule.plan_retry(db, schedule.in_force(db, app.state.settings), "gone", 0, start)
            db.commit()
        monkeypatch.delenv("NYCTR_CONNECTOR_SECRET_DNS")
        tick(app, start + timedelta(minutes=1))
        assert len(asked) == 1 and dns(app)[:2] == ("error", "Could not connect.")
        assert stopped(app) == ["secret"] and pending(app) == []


@pytest.mark.parametrize("error, wait", [(PASSING["broken connection"], 60),
                                         (lambda: IntegrationError("Rate limit.", category="rate_limit",
                                                                   retry_after=61), 61)])
def test_the_wait_is_counted_from_when_the_attempt_failed(tmp_path, monkeypatch, error, wait):
    """A collection that fails 50 seconds into the pass still waits its full minute or the source's own wait."""
    clock = [utcnow()]
    start = clock[0]

    async def slow(provider, integration_id, config, api_key):
        if integration_id == "dns":
            clock[0] += timedelta(seconds=50)
            raise error()
        return Snapshot()

    fail_dns(monkeypatch, [])
    monkeypatch.setattr("nyctr.integrations.collect", slow)
    app = live_app(tmp_path)
    with TestClient(app):
        seed_live_member(app)
        asyncio.run(worker.tick(app.state.session_factory, app.state.settings, clock=lambda: clock[0]))
        with app.state.session_factory() as db:
            failed = db.scalar(select(Audit).where(Audit.action == "integration.collection_failed"))
            assert utc(datetime.fromisoformat(failed.details["retry_at"])) == start + timedelta(seconds=50 + wait)


def test_a_failed_attempt_whose_retry_cannot_be_staged_releases_the_source(tmp_path, monkeypatch):
    """If staging the retry fails (a copy claimed the next run meanwhile), the source is not left syncing."""
    from sqlalchemy.orm.exc import StaleDataError

    def stale(*args, **kwargs):
        raise StaleDataError("expected to update 1 row(s); 0 were matched")

    fail_dns(monkeypatch, [PASSING["broken connection"]])
    monkeypatch.setattr(schedule, "plan_retry", stale)
    app, start = live_app(tmp_path), utcnow()
    with TestClient(app):
        seed_live_member(app)
        tick(app, start)
        assert dns(app) == ("error", "Could not connect.", [("collection_failed", 0)])
        with app.state.session_factory() as db:
            assert db.get(Integration, "dns").sync_started_at is None


def test_a_scheduled_run_that_finds_the_secret_gone_ends_the_retries_it_replaced(tmp_path, monkeypatch):
    """The new run clears the old retries; if it cannot contact the source, the source is shown failed."""
    fail_dns(monkeypatch, [PASSING["timeout"]])
    app, start = live_app(tmp_path), utcnow()
    with TestClient(app):
        seed_live_member(app)
        tick(app, start)
        monkeypatch.delenv("NYCTR_CONNECTOR_SECRET_DNS")
        assert tick(app, start + timedelta(minutes=15)) is True
        assert dns(app)[:2] == ("error", "Collection timed out.") and stopped(app) == ["secret"]


def test_a_retry_whose_staging_fails_ends_its_claimed_retry_with_the_failure(tmp_path, monkeypatch):
    """The source is shown failed once; the claimed retry is not run again after its hold runs out."""
    asked = fail_dns(monkeypatch, [PASSING["broken connection"]] * 3)
    app, start = live_app(tmp_path), utcnow()
    with TestClient(app):
        seed_live_member(app)
        tick(app, start)
        monkeypatch.setattr(schedule, "plan_retry", lambda *args, **kwargs: 1 / 0)
        tick(app, start + timedelta(minutes=1))
        assert dns(app)[0] == "error" and pending(app) == []
        tick(app, start + timedelta(minutes=7))
        assert len(asked) == 2


@pytest.mark.parametrize("then", ["succeeds", "fails"])
def test_a_retry_whose_lease_was_replaced_ends_and_leaves_the_source_to_its_holder(tmp_path, monkeypatch, then):
    """A replaced attempt stores nothing, stages nothing and ends the retries; the new holder is not disturbed."""
    asked = fail_dns(monkeypatch, [PASSING["broken connection"]])
    app, start = live_app(tmp_path), utcnow()
    other = utcnow() + timedelta(seconds=1)

    async def replaced(provider, integration_id, config, api_key):
        if integration_id == "dns":
            asked.append(integration_id)
            with app.state.session_factory() as db:
                db.get(Integration, "dns").sync_started_at = other  # Another collection took the lease.
                db.commit()
            if then == "fails":
                raise PASSING["timeout"]()
        return Snapshot()

    with TestClient(app):
        seed_live_member(app)
        tick(app, start)
        monkeypatch.setattr("nyctr.integrations.collect", replaced)
        tick(app, start + timedelta(minutes=1))
        status, error, audits = dns(app)
        assert (status, error, audits) == ("syncing", "Could not connect.", [("collection_failed", 0)])
        assert pending(app) == [] and stopped(app) == []
        with app.state.session_factory() as db:
            assert utc(db.get(Integration, "dns").sync_started_at) == other
        tick(app, start + timedelta(minutes=7))
        assert len(asked) == 2


def test_a_copy_claims_each_retry_just_before_running_it(tmp_path, monkeypatch):
    """A retry another copy ran while this copy was busy with a slow one is not run a second time."""
    one, two = live_app(tmp_path), live_app(tmp_path)
    clock = [utcnow()]
    start, asked = clock[0], []

    async def collect(provider, integration_id, config, api_key):
        asked.append(integration_id)
        if clock[0] == start:
            raise PASSING["broken connection"]()
        if len(asked) == 3:  # Copy one's first retry is slow; copy two works meanwhile.
            clock[0] += timedelta(minutes=6)
            await worker.tick(two.state.session_factory, two.state.settings, clock=lambda: clock[0])
        return Snapshot()

    fail_dns(monkeypatch, [])
    monkeypatch.setattr("nyctr.integrations.collect", collect)
    with TestClient(one), TestClient(two):
        seed_live_member(one)
        asyncio.run(worker.tick(one.state.session_factory, one.state.settings, clock=lambda: clock[0]))
        clock[0] = start + timedelta(minutes=1)
        asyncio.run(worker.tick(one.state.session_factory, one.state.settings, clock=lambda: clock[0]))
        assert sorted(asked) == ["dns", "dns", "unifi", "unifi"]


def test_no_retry_runs_once_the_next_scheduled_run_is_due_even_in_a_long_pass(tmp_path, monkeypatch):
    """A retry staged early in a pass that then runs past the next run time is left to that run."""
    clock = [utcnow()]
    start, asked = clock[0], []

    async def collect(provider, integration_id, config, api_key):
        asked.append(integration_id)
        if len(asked) == 1:
            raise PASSING["broken connection"]()
        clock[0] += timedelta(minutes=15)  # The other source is very slow.
        return Snapshot()

    fail_dns(monkeypatch, [])
    monkeypatch.setattr("nyctr.integrations.collect", collect)
    app = live_app(tmp_path)
    with TestClient(app):
        seed_live_member(app)
        asyncio.run(worker.tick(app.state.session_factory, app.state.settings, clock=lambda: clock[0]))
        assert len(asked) == 2 and clock[0] == start + timedelta(minutes=15)
        assert tick(app, clock[0]) is True and len(asked) == 4
