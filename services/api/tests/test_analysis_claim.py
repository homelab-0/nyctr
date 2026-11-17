"""A check that is still running keeps the claim it took.

The hold stays two minutes. A claim that is idle can be taken after that, and a fresh claim held
by another process is left alone. Queue time does not make a running check look finished.
"""

import asyncio
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select
from test_analysis_counts import database_url, demo, plant, rule_body, store_analysis
from test_tiers import BOTH

from nyctr import access, assistant, block_analysis
from nyctr.collection import holder_id
from nyctr.models import AccessRequest, Lease, Notice


async def eventually(predicate):
    """Poll until the predicate holds. Ten seconds is a watchdog, not the claim's hold."""
    async with asyncio.timeout(10):
        while not predicate():
            await asyncio.sleep(0.01)


async def login(client, member=False):
    """Sign in as the seeded administrator or member and return the CSRF header."""
    response = await client.post("/api/auth/login", json={
        "email": "jamie@nyctr.demo" if member else "admin@nyctr.demo", "password": "nyctr-demo"})
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def frozen(monkeypatch):
    """Freeze the claim clock at the real current time. A past clock would count every seeded opening."""
    clock = {"now": datetime.now(UTC)}
    monkeypatch.setattr(access, "utcnow", lambda: clock["now"])
    return clock


def watch(monkeypatch):
    """Record each recovery delay the running app asks for, without replacing the calculation."""
    real = access.recovery_delay
    seen = []

    def delay(*args, **kwargs):
        result = real(*args, **kwargs)
        seen.append(result)
        return result

    monkeypatch.setattr(access, "recovery_delay", delay)
    return seen


def add_request(db, key, **values):
    """One analysing request on a copy of the gallery block."""
    plant(db, key)
    db.add(AccessRequest(
        id=key, block_id=key, domain="shop.example", device_name="Jamie's MacBook", requester_id="user-jamie",
        reason="Fabricated probe", duration_minutes=30, status="analysing", **values))


def stand_in(monkeypatch):
    """Store a fabricated analysis and do not call a model."""
    async def analyse(db, domain, block_id=None, *, settings):
        return store_analysis(db, domain, block_id, "missing", None, None)

    monkeypatch.setattr(block_analysis, "analyse", analyse)


@BOTH
@pytest.mark.parametrize("elapsed", [0, 121])
def test_a_queued_check_keeps_its_decision_when_the_same_process_passes_again(
        tmp_path, database, request, monkeypatch, elapsed):
    """Queue time, including past the two-minute hold, does not let a later pass decide the request.

    The first check uses the real claim, the shared limiter and the real opening. The later pass is
    the real due pass. Zero seconds is the same sequence with the claim still inside its hold.
    """
    assert access.ANALYSIS_HOLD == timedelta(minutes=2)
    app = demo(tmp_path, database_url(database, tmp_path, request))
    clock, seen = frozen(monkeypatch), watch(monkeypatch)
    monkeypatch.setattr(assistant, "MODEL_CALLS", 1)
    monkeypatch.setattr(assistant, "_room", None)
    stand_in(monkeypatch)

    async def scenario():
        async with app.router.lifespan_context(app):
            await eventually(lambda: seen == [None])
            factory = app.state.session_factory
            with factory() as db:
                add_request(db, "queued")
                db.commit()
            real_open = access.open_lease
            opening, release = asyncio.Event(), asyncio.Event()

            async def held_open(*args, **kwargs):
                opening.set()
                await release.wait()
                return await real_open(*args, **kwargs)

            monkeypatch.setattr(access, "open_lease", held_open)
            room = assistant._room_for()
            await room.acquire()
            holder = holder_id(app.state.engine)
            first = asyncio.create_task(access.finish_one(factory, app.state.settings, "queued", holder))
            try:
                await eventually(lambda: bool(room._waiters))
                clock["now"] += timedelta(seconds=elapsed)
                # Still queued: the claim was stamped before the wait, so 121 seconds has aged it out.
                await access.finish_due(factory, app.state.settings)
                with factory() as db:
                    row = db.get(AccessRequest, "queued")
                    assert (row.status, row.analysis_holder, row.analysis_id) == ("analysing", holder, None)
                room.release()
                await asyncio.wait_for(opening.wait(), 10)
                with factory() as db:
                    row = db.get(AccessRequest, "queued")
                    # A different process sees only this stamp. It has to be inside the hold at the jumped clock.
                    assert access.utc(row.analysis_claimed_at) == clock["now"]
                    assert access._analysis_free(row, clock["now"], None) is False
                await access.finish_due(factory, app.state.settings)
                with factory() as db:
                    assert db.get(AccessRequest, "queued").status == "analysing"
            finally:
                release.set()
                await asyncio.wait_for(first, 10)
            with factory() as db:
                row = db.get(AccessRequest, "queued")
                leases = db.scalars(select(Lease).where(Lease.request_id == "queued")).all()
                assert row.status == "auto_approved", (row.status, row.decision_note, len(leases))
                assert len(leases) == 1
                assert not access._LIVE

    asyncio.run(scenario())


@BOTH
def test_a_running_check_stamps_its_claim_again(tmp_path, database, request, monkeypatch):
    """While an opening is still in progress, the stamp moves forward. The hold stays two minutes."""
    assert access.ANALYSIS_HOLD == timedelta(minutes=2)
    app = demo(tmp_path, database_url(database, tmp_path, request))
    clock, seen = frozen(monkeypatch), watch(monkeypatch)
    monkeypatch.setattr(access, "CLAIM_PULSE", 0.05)
    monkeypatch.setattr(assistant, "MODEL_CALLS", 1)
    monkeypatch.setattr(assistant, "_room", None)
    stand_in(monkeypatch)

    async def scenario():
        async with app.router.lifespan_context(app):
            await eventually(lambda: seen == [None])
            factory = app.state.session_factory
            with factory() as db:
                add_request(db, "opening")
                db.commit()
            real_open = access.open_lease
            opening, release = asyncio.Event(), asyncio.Event()

            async def held_open(*args, **kwargs):
                opening.set()
                await release.wait()
                return await real_open(*args, **kwargs)

            monkeypatch.setattr(access, "open_lease", held_open)
            first = asyncio.create_task(access.finish_one(
                factory, app.state.settings, "opening", holder_id(app.state.engine)))
            try:
                await asyncio.wait_for(opening.wait(), 10)
                clock["now"] += timedelta(seconds=40)
                def stamped():
                    with factory() as db:
                        row = db.get(AccessRequest, "opening")
                        return access.utc(row.analysis_claimed_at) == clock["now"]

                await eventually(stamped)
                with factory() as db:
                    row = db.get(AccessRequest, "opening")
                    assert row.status == "analysing"
                    assert access._analysis_free(row, clock["now"], None) is False
            finally:
                release.set()
                await asyncio.wait_for(first, 10)
            with factory() as db:
                assert db.get(AccessRequest, "opening").status == "auto_approved"
            assert access.ANALYSIS_HOLD == timedelta(minutes=2)

    asyncio.run(scenario())


@BOTH
def test_a_failed_check_is_finished_after_the_real_hold(tmp_path, database, request, monkeypatch):
    """A failure after the claim waits out the real two-minute hold, then recovery finishes it once.

    A fresh claim held by another process is left alone until that hold. The real wait is interrupted
    when the clock says the hold is over. One always-failing request does not stop the others.
    """
    app = demo(tmp_path, database_url(database, tmp_path, request))
    clock, seen, calls = frozen(monkeypatch), watch(monkeypatch), []
    monkeypatch.setattr(assistant, "MODEL_CALLS", 1)
    monkeypatch.setattr(assistant, "_room", None)

    async def analyse(db, domain, block_id=None, *, settings):
        calls.append(block_id)
        if block_id == "always-fails" or (block_id == "block-gallery" and calls.count(block_id) == 1):
            raise RuntimeError("fabricated after-claim failure")
        return store_analysis(db, domain, block_id, "missing", None, None)

    monkeypatch.setattr(block_analysis, "analyse", analyse)

    async def scenario():
        tasks = asyncio.all_tasks()
        async with app.router.lifespan_context(app):
            await eventually(lambda: seen == [None])
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                for _ in range(10):
                    assert (await client.get("/api/health")).status_code == 200
                assert seen == [None]
                admin = await login(client)
                assert (await client.put("/api/rules/access", headers=admin, json=rule_body())).status_code == 200
                member = await login(client, True)
                with app.state.session_factory() as db:
                    add_request(db, "foreign", analysis_holder="other-live-process",
                                analysis_claimed_at=clock["now"])
                    add_request(db, "always-fails")
                    db.commit()
                with pytest.raises(RuntimeError, match="fabricated after-claim failure"):
                    await client.post("/api/requests", headers=member, json={
                        "block_id": "block-gallery", "reason": "Fabricated later submission",
                        "duration_minutes": 30})
                await eventually(lambda: len(seen) >= 2)
                with app.state.session_factory() as db:
                    own = db.scalar(select(AccessRequest).where(AccessRequest.block_id == "block-gallery"))
                    own_id = own.id
                    assert own.status == "analysing" and own.analysis_holder
                    assert db.get(AccessRequest, "foreign").analysis_holder == "other-live-process"
                assert calls.count("block-gallery") == 1 and "foreign" not in calls
                assert seen[-1] == 120.0
                assert assistant._room_for()._value == 1
                before = len(seen)
                for _ in range(10):
                    assert (await client.get("/api/health")).status_code == 200
                assert len(seen) == before
                clock["now"] += timedelta(seconds=121)
                app.state.analysis_again.set()

                def finished():
                    with app.state.session_factory() as db:
                        return all(db.get(AccessRequest, key).status == "auto_approved"
                                   for key in (own_id, "foreign"))

                await eventually(finished)
                assert calls.count("block-gallery") == 2 and calls.count("always-fails") == 2
                with app.state.session_factory() as db:
                    assert db.get(AccessRequest, "always-fails").status == "analysing"
                    assert len(db.scalars(select(Notice).where(Notice.subject == own_id)).all()) == 1
                assert (await client.get("/api/health")).json()["status"] == "ok"
        await asyncio.sleep(0)
        assert not (asyncio.all_tasks() - tasks)
        assert assistant._room_for()._value == 1

    asyncio.run(scenario())


@BOTH
@pytest.mark.parametrize("where", ["idle", "hold", "inside_model", "waiting_for_slot"])
def test_shutdown_cancels_a_check_that_is_waiting(tmp_path, database, request, monkeypatch, where):
    """Stopping the app ends a check that is idle, waiting out a claim, inside the model, or queued.

    The real wait is cancelled. The shared slot is free afterwards, and the heartbeat thread is gone.
    """
    app = demo(tmp_path, database_url(database, tmp_path, request))
    seen = watch(monkeypatch)
    frozen(monkeypatch)
    monkeypatch.setattr(assistant, "MODEL_CALLS", 1)
    monkeypatch.setattr(assistant, "_room", None)

    async def scenario():
        tasks, threads = asyncio.all_tasks(), set(threading.enumerate())
        entered = asyncio.Event()

        async def analyse(*args, **kwargs):
            entered.set()
            await asyncio.Event().wait()

        monkeypatch.setattr(block_analysis, "analyse", analyse)
        context = app.router.lifespan_context(app)
        await context.__aenter__()
        room = assistant._room_for()
        acquired = False
        try:
            await eventually(lambda: seen == [None])
            if where != "idle":
                if where == "waiting_for_slot":
                    await room.acquire()
                    acquired = True
                with app.state.session_factory() as db:
                    claimed = {"analysis_holder": "fresh-foreign", "analysis_claimed_at": datetime.now(UTC)}
                    add_request(db, "cancel-me", **(claimed if where == "hold" else {}))
                    db.commit()
                app.state.analysis_again.set()
                if where == "hold":
                    await eventually(lambda: len(seen) == 2)
                elif where == "inside_model":
                    await asyncio.wait_for(entered.wait(), 10)
                else:
                    await eventually(lambda: bool(room._waiters))
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
                assert (await client.get("/api/health")).status_code == 200
        finally:
            await asyncio.wait_for(context.__aexit__(None, None, None), 10)
            if acquired:
                room.release()
        await asyncio.sleep(0)
        assert not (asyncio.all_tasks() - tasks)
        assert room._value == 1 and not room._waiters
        assert not [item for item in set(threading.enumerate()) - threads
                    if item.name == "nyctr-collection-heartbeat"]
        assert not access._LIVE

    asyncio.run(scenario())
