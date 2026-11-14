"""Access that has run out is ended on time, whatever a collection pass is doing.

Every case runs on a passed-in clock against stand-in sources whose reads pause until the test lets them go.
"""

import asyncio
from datetime import timedelta

import httpx
import pytest
from conftest import live_app, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import select

from nyctr import schedule, worker
from nyctr.integrations import IntegrationError, Snapshot, core
from nyctr.models import Audit, Integration, Lease, utcnow


class Sources:
    """Stand-in sources: record who was asked; chosen reads (by order asked) fail once or pause until released."""

    def __init__(self, monkeypatch, pause=(), fail=()):
        self.asked, self.pause, self.fail, self.cancelled = [], set(pause), set(fail), False
        self.reading, self.go = asyncio.Event(), asyncio.Event()
        monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "dns-secret")
        monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "fabricated-key")
        monkeypatch.setattr("nyctr.integrations.collect", self.collect)

    async def collect(self, provider, integration_id, config, api_key):
        call = len(self.asked)
        self.asked.append(integration_id)
        if call in self.fail:
            raise IntegrationError("Could not connect.", category="transport")
        if call in self.pause:
            self.reading.set()
            try:
                await self.go.wait()
            except asyncio.CancelledError:
                self.cancelled = True
                raise
            self.go.clear()
        return Snapshot()

    async def paused(self):
        """Wait until a read is paused mid-collection."""
        await asyncio.wait_for(self.reading.wait(), 5)

    def release(self):
        self.reading.clear()
        self.go.set()


def allowlist(monkeypatch, listed, broken=()):
    """Serve a fabricated DNS allowlist. Each call yields mid-way; removing a name in `broken` fails oddly."""
    async def handler(request):
        await asyncio.sleep(0)  # Another task, or another copy, gets to run in the middle of the call.
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": name, "active": True} for name in listed]})
        name = request.url.path.rsplit("/", 1)[1]
        if name in broken:
            raise RuntimeError("fabricated cause text")
        if name in listed:
            listed.remove(name)
        return httpx.Response(204)

    monkeypatch.setattr(core, "make_http_client", lambda key, **_: httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"X-Api-Key": key}, follow_redirects=False,
        trust_env=False))


def opened(app, listed, domain, expires):
    """Store an exception Nyctr opened at the DNS source, with its entry on the allowlist."""
    listed.append(domain)
    with app.state.session_factory() as db:
        row = Lease(integration_id="dns", domain=domain, execution="applied", owned=True, expires_at=expires)
        db.add(row)
        db.commit()
        return row.id


def stored(app, model, key):
    with app.state.session_factory() as db:
        return db.get(model, key).status


def upkeep(app, now):
    """This copy's upkeep on the test's clock."""
    return worker.Upkeep(app.state.session_factory, app.state.settings, clock=lambda: now[0])


def test_an_exception_that_runs_out_during_a_long_collection_is_ended_at_the_next_tick(tmp_path, monkeypatch):
    """Two sources are read in turn, each for a minute; an exception expiring under each is ended within a tick."""
    listed: list[str] = []
    allowlist(monkeypatch, listed)
    app = live_app(tmp_path, provider_writes="nextdns")
    start = utcnow()
    now = [start]

    async def scenario():
        sources, up = Sources(monkeypatch, pause={0, 1}), upkeep(app, now)
        for read in range(2):
            began = now[0]
            up.tick() if read == 0 else sources.release()
            await sources.paused()
            lease = opened(app, listed, f"{read}.example", began + timedelta(seconds=10))
            up.tick()  # Not yet due: nothing is ended early.
            assert up.ending == {} or up.ending["dns"].done()
            assert stored(app, Lease, lease) == "active"
            now[0] = began + timedelta(seconds=30)
            running = up.collecting
            up.tick()
            await up.ending["dns"]
            assert stored(app, Lease, lease) == "ended" and listed == []
            assert up.collecting is running and not running.done() and len(sources.asked) == read + 1
            now[0] = began + timedelta(seconds=60)
        sources.release()
        await up.collecting
        assert sorted(sources.asked) == ["dns", "unifi"]

    with TestClient(app):
        seed_live_member(app)
        asyncio.run(scenario())
        assert stored(app, Integration, "dns") == stored(app, Integration, "unifi") == "connected"
        with app.state.session_factory() as db:
            closed = db.scalars(select(Audit).where(Audit.action == "access.closed")).all()
        assert [audit.details["reason"] for audit in closed] == ["expired", "expired"]


def test_a_run_that_comes_due_during_a_long_pass_waits_for_the_pass_to_end(tmp_path, monkeypatch):
    """No second pass starts alongside the first; the next tick after it claims the run and reads each source once."""
    app = live_app(tmp_path)
    start = utcnow()
    now = [start]

    async def scenario():
        sources, up = Sources(monkeypatch, pause={0}), upkeep(app, now)
        up.tick()
        await sources.paused()
        first = up.collecting
        for late in (15, 16):
            now[0] = start + timedelta(minutes=late)
            up.tick()
            await asyncio.sleep(0)
            assert up.collecting is first and len(sources.asked) == 1
        sources.release()
        await first
        assert sorted(sources.asked) == ["dns", "unifi"]
        now[0] = start + timedelta(minutes=16, seconds=30)
        up.tick()
        await up.collecting
        assert up.collecting is not first and sorted(sources.asked) == ["dns", "dns", "unifi", "unifi"]
        up.tick()  # That run was claimed at 16:30, so nothing is due again yet.
        await up.collecting
        assert len(sources.asked) == 4

    with TestClient(app):
        seed_live_member(app)
        asyncio.run(scenario())


def test_a_retry_that_comes_due_during_a_pass_is_run_once_by_that_pass(tmp_path, monkeypatch):
    """The first source fails and its retry falls due while the second is still read; no tick runs it alongside."""
    app = live_app(tmp_path)
    start = utcnow()
    now = [start]

    async def scenario():
        sources, up = Sources(monkeypatch, pause={1}, fail={0}), upkeep(app, now)
        enforce, acted = worker.enforce, []

        async def rule(db, settings, due):
            acted.append(len(sources.asked))
            return await enforce(db, settings, due)

        monkeypatch.setattr(worker, "enforce", rule)
        up.tick()
        await sources.paused()
        failed, slow = sources.asked
        for seconds in (60, 90):
            now[0] = start + timedelta(seconds=seconds)
            up.tick()
            await asyncio.sleep(0)
            assert sources.asked == [failed, slow]
        with app.state.session_factory() as db:
            assert schedule.due_retries(db, schedule.in_force(db, app.state.settings), now[0]) == [failed]
        sources.release()
        await up.collecting
        assert sources.asked == [failed, slow, failed]
        assert acted == [2, 3]  # The cut-off rule acted after the run's collections, and again after the retry's.
        now[0] = start + timedelta(seconds=120)
        up.tick()
        await up.collecting
        assert len(sources.asked) == 3
        with app.state.session_factory() as db:
            audits = db.scalars(select(Audit).where(Audit.target_id == failed).order_by(Audit.created_at))
            assert [(a.action.split(".")[1], a.details["attempt"]) for a in audits] == [
                ("collection_failed", 0), ("collected", 1)]
            assert schedule.pending_retries(db) == []

    with TestClient(app):
        seed_live_member(app)
        asyncio.run(scenario())


def test_stopping_during_a_pass_cancels_it_and_the_source_is_collected_again_later(tmp_path, monkeypatch):
    """The read in progress is cancelled with the loop; its lease is left to age out and a later run takes it over."""
    app = live_app(tmp_path)
    monkeypatch.setattr(worker, "TICK_SECONDS", 0.01)

    async def scenario():
        sources = Sources(monkeypatch, pause={0})
        loop = asyncio.create_task(worker.run(app))
        await sources.paused()
        loop.cancel()
        with pytest.raises(asyncio.CancelledError):
            await loop
        assert sources.cancelled and len(sources.asked) == 1
        return sources

    with TestClient(app):
        seed_live_member(app)
        sources = asyncio.run(scenario())
        with app.state.session_factory() as db:
            held = db.get(Integration, sources.asked[0])
            assert held.status == "syncing" and held.sync_started_at is not None
            assert schedule.pending_retries(db) == []
            held.sync_started_at -= timedelta(minutes=6)  # A lease can be taken over after five minutes.
            db.commit()
        later = utcnow() + timedelta(minutes=15)
        assert asyncio.run(worker.collection_pass(app.state.session_factory, app.state.settings, later)) is True
        assert stored(app, Integration, "dns") == stored(app, Integration, "unifi") == "connected"


def test_one_failure_stops_neither_the_other_endings_nor_the_collections(tmp_path, monkeypatch, caplog):
    """An exception that cannot be ended stays open; the next one is ended; a failed pass is followed by another."""
    listed: list[str] = []
    allowlist(monkeypatch, listed, broken={"bad.example"})
    app = live_app(tmp_path, provider_writes="nextdns")
    now = [utcnow()]
    claim_run, failing = schedule.claim_run, [True]

    def claim(db, plan, when):
        if failing and failing.pop():
            raise RuntimeError("fabricated cause text")
        return claim_run(db, plan, when)

    monkeypatch.setattr(schedule, "claim_run", claim)

    async def scenario():
        sources, up = Sources(monkeypatch), upkeep(app, now)
        bad = opened(app, listed, "bad.example", now[0] - timedelta(seconds=2))
        good = opened(app, listed, "good.example", now[0] - timedelta(seconds=1))
        up.tick()
        await asyncio.gather(up.collecting, up.ending["dns"])
        assert (stored(app, Lease, bad), stored(app, Lease, good)) == ("active", "ended")
        assert listed == ["bad.example"] and sources.asked == []
        up.tick()
        await up.collecting
        assert sorted(sources.asked) == ["dns", "unifi"]

    with TestClient(app):
        seed_live_member(app)
        asyncio.run(scenario())
    said = [record.getMessage() for record in caplog.records if record.name == "nyctr.worker"]
    assert "Background upkeep failed: RuntimeError" in said
    assert "Ending an expired exception failed: RuntimeError" in said
    assert "fabricated cause text" not in caplog.text


def test_two_copies_end_an_expired_exception_once_and_collect_each_source_once(tmp_path, monkeypatch):
    """Both copies find it expired and are mid-call together; one records the end, the other writes nothing."""
    listed: list[str] = []
    allowlist(monkeypatch, listed)
    one, two = (live_app(tmp_path, provider_writes="nextdns") for _ in range(2))
    now = [utcnow()]

    async def scenario():
        sources, copies = Sources(monkeypatch), [upkeep(one, now), upkeep(two, now)]
        lease = opened(one, listed, "shared.example", now[0] - timedelta(seconds=1))
        for copy in copies:
            copy.tick()
        await asyncio.gather(*(task for copy in copies for task in (copy.collecting, copy.ending["dns"])))
        assert stored(two, Lease, lease) == "ended" and listed == []
        assert sorted(sources.asked) == ["dns", "unifi"]

    with TestClient(one), TestClient(two):
        seed_live_member(one)
        asyncio.run(scenario())
        with one.state.session_factory() as db:
            assert len(db.scalars(select(Audit).where(Audit.action == "access.closed")).all()) == 1
