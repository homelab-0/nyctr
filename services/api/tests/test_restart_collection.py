"""A restart during a collection must not leave the source looking as if it were still being collected."""

import asyncio
import threading
import time
from contextlib import contextmanager
from datetime import timedelta

import pytest
from conftest import live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select, update
from test_collection_store import POSTGRES
from test_presence import WAIT, on, others_finish

from nyctr import collection
from nyctr.collection import (
    CUT_SHORT,
    HEARTBEAT_BOUND,
    HEARTBEAT_EVERY,
    NO_SIGN,
    STOPPED,
    _beat_once,
    begin_holder,
    collect_integration,
    db_ago,
    release_abandoned,
)
from nyctr.database import migrate
from nyctr.integrations import Snapshot
from nyctr.models import Audit, Integration, utc, utcnow

# The PostgreSQL case needs a server named in NYCTR_TEST_POSTGRES and makes a database of its own.
BOTH = pytest.mark.parametrize("engine", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])


def home(engine, tmp_path, request):
    """The database this case uses. PostgreSQL is skipped when no server is named."""
    if engine == "sqlite":
        return {}
    place = on(engine, request)
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    return place


def prepare(tmp_path, monkeypatch, request, engine):
    """A migrated live database with the two fabricated sources, and no heartbeat task running."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "fabricated-key")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "fabricated-key")
    app = live_app(tmp_path, **home(engine, tmp_path, request))
    migrate(app.state.engine)
    begin_holder(app.state.engine)
    seed_live_member(app)
    return app


def audits(app):
    """How many times a cut-short collection has been recorded."""
    with app.state.session_factory() as db:
        return db.scalar(select(func.count()).select_from(Audit).where(
            Audit.action == "integration.collection_interrupted"))


def saw_lock(engine) -> bool:
    """Whether some other connection is waiting on a lock in this database. Waits until one is, or gives up."""
    watch = create_engine(engine.url)
    try:
        with watch.connect() as connection:
            for _ in range(1000):  # Up to about ten seconds, however long the waiter takes to arrive.
                connection.rollback()
                waiting = connection.exec_driver_sql(
                    "select count(*) from pg_stat_activity where wait_event_type = 'Lock' "
                    "and datname = current_database()").scalar()
                if waiting:
                    return True
                threading.Event().wait(0.01)
    finally:
        watch.dispose()
    return False


@contextmanager
def hold_the_lock(app, match, second):
    """Run `second` while `match` sees the writer's statement, and keep the proof that it was still waiting."""
    kind = app.state.engine.dialect.name
    seen = {"spawned": False, "waiting": False, "locked": False, "raised": [], "sql": []}

    def run():
        try:
            second()
        except Exception as error:  # noqa: BLE001 - the assertion below reports it
            seen["raised"].append(f"{type(error).__name__}: {error}")

    def after(_conn, _cursor, statement, _parameters, _context, _executemany):
        seen["sql"].append(str(statement))
        if seen["spawned"] or not match(str(statement)):
            return
        seen["spawned"] = True
        other = threading.Thread(target=run, daemon=True)
        seen["started"].append(other)
        other.start()
        if kind == "postgresql":
            seen["locked"] = saw_lock(app.state.engine)
            seen["waiting"] = other.is_alive()
        else:
            other.join(WAIT["sqlite"])
            seen["waiting"] = other.is_alive()

    event.listen(app.state.engine, "after_cursor_execute", after)
    try:
        with others_finish() as started:
            seen["started"] = started
            yield seen
    finally:
        event.remove(app.state.engine, "after_cursor_execute", after)
    assert seen["spawned"], seen["sql"]
    assert seen["waiting"] and seen["raised"] == [], seen["raised"]
    if kind == "postgresql":
        assert seen["locked"]


def stamp(app, ids, holder, heartbeat_age, started_age):
    """Leave these sources collecting. Ages are seconds before the database clock. None leaves that stamp empty."""
    with app.state.session_factory() as db:
        bind = db.get_bind()
        db.execute(update(Integration).where(Integration.id.in_(ids)).values(
            status="syncing", sync_holder=holder,
            sync_heartbeat=None if heartbeat_age is None else db_ago(bind, heartbeat_age),
            sync_started_at=None if started_age is None else db_ago(bind, started_age),
        ))
        db.commit()


def whys(app):
    """The sentences recorded for collections that ended without storing, oldest first."""
    with app.state.session_factory() as db:
        rows = db.scalars(select(Audit).where(Audit.action == "integration.collection_interrupted")
                          .order_by(Audit.created_at))
        return [row.details.get("why") for row in rows]


async def fake_collect(*_args, **_kwargs):
    """A collection that stores nothing and never calls a source."""
    return Snapshot()


def test_the_heartbeat_bound_is_sixty_seconds():
    """The bound is part of the behaviour: a holder is treated as gone after sixty seconds, not five minutes."""
    assert HEARTBEAT_BOUND == timedelta(seconds=60) and HEARTBEAT_EVERY == 5


@BOTH
def test_a_restart_frees_the_collection_and_collect_and_remove_are_accepted(tmp_path, monkeypatch, request, engine):
    """Right after the next start, nothing is left collecting. Collect and Remove are accepted."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "fabricated-key")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "fabricated-key")
    monkeypatch.setattr("nyctr.integrations.collect", fake_collect)
    place = home(engine, tmp_path, request)
    first = live_app(tmp_path, **place)
    with TestClient(first):
        seed_live_member(first)
        stamp(first, ["dns", "unifi"], "previous-start", 61, 0)
    again = live_app(tmp_path, **place)
    with TestClient(again) as client:
        headers = live_signin(client)
        listed = {row["id"]: row["status"] for row in client.get("/api/integrations").json()}
        assert listed == {"dns": "interrupted", "unifi": "interrupted"}
        assert audits(again) == 2 and set(whys(again)) == {CUT_SHORT}
        attention = client.get("/api/attention").json()
        assert [item["detail"] for item in attention if item["detail"] == CUT_SHORT] == [CUT_SHORT, CUT_SHORT]
        third = live_app(tmp_path, **place)
        with TestClient(third):
            assert audits(third) == 2
            with third.state.session_factory() as db:
                assert {row.status for row in db.scalars(select(Integration))} == {"interrupted"}
        collected = client.post("/api/integrations/dns/sync", headers=headers)
        assert collected.status_code == 200, collected.text
        with again.state.session_factory() as db:
            assert db.get(Integration, "dns").status == "connected"
        assert audits(again) == 2
        remaining = [item for item in client.get("/api/attention").json() if item["detail"] == CUT_SHORT]
        assert len(remaining) == 1 and remaining[0]["title"].startswith("The last collection from UniFi")
        removed = client.request("DELETE", "/api/integrations/unifi", headers=headers, json={"name": "UniFi"})
        assert removed.status_code == 200, removed.text


@BOTH
def test_a_live_holder_is_still_busy_after_another_copy_starts(tmp_path, monkeypatch, request, engine):
    """A heartbeat one second old is a live holder. The other copy must not collect that source."""
    place = home(engine, tmp_path, request)
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "fabricated-key")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "fabricated-key")
    monkeypatch.setattr("nyctr.integrations.collect", fake_collect)
    first = live_app(tmp_path, **place)
    with TestClient(first):
        seed_live_member(first)
        stamp(first, ["dns"], "other-copy", 1, 0)
    again = live_app(tmp_path, **place)
    with TestClient(again) as client:
        headers = live_signin(client)
        with again.state.session_factory() as db:
            row = db.get(Integration, "dns")
            assert row.status == "syncing" and row.sync_holder == "other-copy"
        response = client.post("/api/integrations/dns/sync", headers=headers)
        assert response.status_code == 409 and response.json()["detail"] == "A collection is already running"
        assert audits(again) == 0


@BOTH
def test_what_makes_a_lease_free(tmp_path, monkeypatch, request, engine):
    """No holder, no heartbeat, a heartbeat past the bound, or a start past five minutes: free. One second: held."""
    app = prepare(tmp_path, monkeypatch, request, engine)
    # heartbeat age, holder, start age. None leaves that stamp empty. Ages are the database clock.
    cases = {
        "stale": (61, "other", 0),
        "recent": (1, "other", 0),
        "aged": (0, "other", 6 * 60),
        "no-beat": (None, "other", 0),
        "no-holder": (0, None, 0),
    }

    def release(names):
        for name, source in zip(names, ("dns", "unifi"), strict=True):
            heartbeat_age, holder, started_age = cases[name]
            stamp(app, [source], holder, heartbeat_age, started_age)
        with app.state.session_factory() as db:
            release_abandoned(db)
            db.commit()
            return {row.id: row.status for row in db.scalars(select(Integration))}

    try:
        assert release(("stale", "recent")) == {"dns": "silent", "unifi": "syncing"}
        assert release(("aged", "no-beat")) == {"dns": "silent", "unifi": "silent"}
        assert release(("no-holder", "no-holder")) == {"dns": "silent", "unifi": "silent"}
        assert set(whys(app)) == {NO_SIGN}
    finally:
        app.state.engine.dispose()


@BOTH
def test_the_beat_refreshes_only_this_start(tmp_path, monkeypatch, request, engine):
    """A live start keeps its own leases fresh and does not refresh a lease another start holds."""
    app = prepare(tmp_path, monkeypatch, request, engine)
    holder = app.state.engine.nyctr_holder
    old = utcnow() - timedelta(minutes=1)
    try:
        with app.state.session_factory() as db:
            dns, unifi = db.get(Integration, "dns"), db.get(Integration, "unifi")
            for row, who in ((dns, holder), (unifi, "other-copy")):
                row.status, row.sync_started_at = "syncing", old
                row.sync_holder, row.sync_heartbeat = who, old
            db.commit()
        _beat_once(app.state.session_factory, holder)
        with app.state.session_factory() as db:
            assert utc(db.get(Integration, "dns").sync_heartbeat) > utc(old)
            assert utc(db.get(Integration, "unifi").sync_heartbeat) == utc(old)
    finally:
        app.state.engine.dispose()


@BOTH
@pytest.mark.parametrize("at", (1, 2, 3))
def test_a_second_release_waits_at_each_write_and_records_the_collection_once(
        tmp_path, monkeypatch, request, engine, at):
    """Whichever of the three writes the first release is in, the other waits, and one record is stored."""
    app = prepare(tmp_path, monkeypatch, request, engine)
    writes = {"n": 0}

    def is_the_write(statement):
        sql = statement.lower().lstrip()
        if sql.startswith("update") or sql.startswith("insert"):
            writes["n"] += 1
            return writes["n"] == at
        return False

    def second():
        with app.state.session_factory() as db:
            release_abandoned(db)
            db.commit()

    try:
        stamp(app, ["dns", "unifi"], "previous-start", 61, 0)
        with hold_the_lock(app, is_the_write, second):
            with app.state.session_factory() as db:
                assert release_abandoned(db) == ["dns", "unifi"]
                db.commit()
        assert audits(app) == 2 and set(whys(app)) == {NO_SIGN}
        with app.state.session_factory() as db:
            assert {row.status for row in db.scalars(select(Integration))} == {"silent"}
    finally:
        app.state.engine.dispose()


@BOTH
def test_a_second_claim_waits_until_the_first_commits_and_is_then_busy(tmp_path, monkeypatch, request, engine):
    """Two copies cannot collect one source at once: the second waits on the claim, then is told it is busy."""
    one = prepare(tmp_path, monkeypatch, request, engine)
    two = live_app(tmp_path, database_url=one.state.settings.database_url)
    begin_holder(two.state.engine)
    # The read waits until the other copy has answered. The lease stays held, so the answer does not
    # depend on the other copy reaching its claim before this copy finishes and gives the lease back.
    answered = threading.Event()

    async def wait_for_the_other_copy(*_args, **_kwargs):
        await asyncio.to_thread(answered.wait, 30)
        return Snapshot()

    monkeypatch.setattr("nyctr.integrations.collect", wait_for_the_other_copy)
    outcome = {}

    def second():
        try:
            outcome["second"] = asyncio.run(collect_integration(
                two.state.session_factory, two.state.settings, "dns", None))
        finally:
            answered.set()

    def is_claim(statement):
        # The claim writes the holder. The later lock only refreshes the heartbeat, so it is not this write.
        set_clause = statement.lower().split("where", 1)[0]
        return set_clause.lstrip().startswith("update") and "sync_holder" in set_clause

    try:
        with hold_the_lock(one, is_claim, second):
            outcome["first"] = asyncio.run(collect_integration(
                one.state.session_factory, one.state.settings, "dns", None))
        assert outcome["second"] == (None, "busy")
        assert outcome["first"][1] is None and outcome["first"][0] is not None
        with one.state.session_factory() as db:
            assert db.get(Integration, "dns").status == "connected"
            assert db.get(Integration, "dns").sync_holder is None
    finally:
        one.state.engine.dispose()
        two.state.engine.dispose()


def _collect(app, source="dns"):
    """Run one collection against the stand-in the test installed. Nothing here calls a real source."""
    return asyncio.run(collect_integration(app.state.session_factory, app.state.settings, source, None))


@BOTH
def test_clock_skew_cannot_free_or_pin_a_lease(tmp_path, monkeypatch, request, engine):
    """A process clock an hour off does not decide the lease. The database clock does, with no wait."""
    app = prepare(tmp_path, monkeypatch, request, engine)
    real = utcnow()
    try:
        stamp(app, ["dns"], "other", 0, 0)
        monkeypatch.setattr("nyctr.collection.utcnow", lambda: real + timedelta(hours=1))
        with app.state.session_factory() as db:
            assert release_abandoned(db) == []
            db.rollback()
            assert db.get(Integration, "dns").status == "syncing"
        stamp(app, ["dns"], "other", 61, 0)
        monkeypatch.setattr("nyctr.collection.utcnow", lambda: real - timedelta(hours=2))
        with app.state.session_factory() as db:
            assert release_abandoned(db) == ["dns"]
            db.commit()
        assert whys(app) == [NO_SIGN]
        with app.state.session_factory() as db:
            assert db.get(Integration, "dns").status == "silent"
    finally:
        app.state.engine.dispose()


@BOTH
def test_a_restart_is_recorded_only_when_another_holder_is_known(tmp_path, monkeypatch, request, engine):
    """Restart needs a holder id on the lease that is not this start. Anything else is no sign of life."""
    app = prepare(tmp_path, monkeypatch, request, engine)
    me = app.state.engine.nyctr_holder

    def once(holder, restart_of):
        stamp(app, ["dns"], holder, 61, 0)
        with app.state.session_factory() as db:
            release_abandoned(db, restart_of=restart_of)
            db.commit()
            status = db.get(Integration, "dns").status
        return status, whys(app)[-1]

    try:
        assert once("previous-start", me) == ("interrupted", CUT_SHORT)
        assert once(None, me) == ("silent", NO_SIGN)
        assert once(me, me) == ("silent", NO_SIGN)
        assert once("previous-start", None) == ("silent", NO_SIGN)
    finally:
        app.state.engine.dispose()


@BOTH
def test_a_store_stops_when_only_the_holder_changed(tmp_path, monkeypatch, request, engine):
    """The same start time with a new holder is not this collection's lease, so the store writes nothing."""
    app = prepare(tmp_path, monkeypatch, request, engine)

    async def steal(*_args, **_kwargs):
        with app.state.session_factory() as db:
            db.execute(update(Integration).where(Integration.id == "dns").values(sync_holder="other-holder"))
            db.commit()
        return Snapshot()

    monkeypatch.setattr("nyctr.integrations.collect", steal)
    try:
        assert _collect(app) == (None, "replaced")
        with app.state.session_factory() as db:
            row = db.get(Integration, "dns")
            assert (row.status, row.sync_holder) == ("syncing", "other-holder")
            assert db.scalar(select(func.count()).select_from(Audit).where(
                Audit.action == "integration.collected")) == 0
    finally:
        app.state.engine.dispose()


@BOTH
def test_a_claim_takes_an_abandoned_lease_without_a_release_first(tmp_path, monkeypatch, request, engine):
    """The claim itself accepts a stale syncing row. Settling it first would hide a claim that only checks status."""
    app = prepare(tmp_path, monkeypatch, request, engine)
    monkeypatch.setattr("nyctr.collection.release_abandoned", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("nyctr.integrations.collect", fake_collect)
    try:
        stamp(app, ["dns"], "other", 61, 0)
        assert _collect(app)[1] is None
        with app.state.session_factory() as db:
            assert db.get(Integration, "dns").status == "connected"
    finally:
        app.state.engine.dispose()


@BOTH
def test_a_collection_records_an_abandoned_lease_before_it_claims(tmp_path, monkeypatch, request, engine):
    """Collecting over a missed beat records that beat, then stores the new read."""
    app = prepare(tmp_path, monkeypatch, request, engine)
    monkeypatch.setattr("nyctr.integrations.collect", fake_collect)
    try:
        stamp(app, ["dns"], "previous-start", 61, 0)
        assert _collect(app)[1] is None
        assert whys(app) == [NO_SIGN]
        with app.state.session_factory() as db:
            assert db.get(Integration, "dns").status == "connected"
    finally:
        app.state.engine.dispose()


@BOTH
def test_a_cancelled_collection_is_recorded_as_stopped(tmp_path, monkeypatch, request, engine):
    """Cancelling the read records stopped at once. It does not wait, and it does not say Nyctr restarted."""
    app = prepare(tmp_path, monkeypatch, request, engine)
    gate = threading.Event()

    async def block(*_args, **_kwargs):
        await asyncio.to_thread(gate.wait, 30)
        return Snapshot()

    monkeypatch.setattr("nyctr.integrations.collect", block)

    async def scenario():
        task = asyncio.create_task(collect_integration(app.state.session_factory, app.state.settings, "dns", None))
        for _ in range(100):
            with app.state.session_factory() as db:
                if db.get(Integration, "dns").status == "syncing":
                    break
            await asyncio.sleep(0.02)
        else:
            raise AssertionError("the collection never took the lease")
        task.cancel()
        # The stand-in blocks in a thread. This run joins that thread on the way out,
        # so open the wait here and the shutdown does not sit out the whole wait.
        gate.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    try:
        asyncio.run(scenario())
        with app.state.session_factory() as db:
            row = db.get(Integration, "dns")
            assert row.status == "stopped" and row.sync_holder is None and row.last_error is None
        assert whys(app) == [STOPPED]
    finally:
        gate.set()
        app.state.engine.dispose()


@BOTH
def test_a_cancelled_collection_does_not_clear_a_replacement_lease(tmp_path, monkeypatch, request, engine):
    """The stop matches this claim's holder and start time, so a lease taken since stays."""
    app = prepare(tmp_path, monkeypatch, request, engine)
    seen = threading.Event()

    async def steal(*_args, **_kwargs):
        with app.state.session_factory() as db:
            db.execute(update(Integration).where(Integration.id == "dns").values(sync_holder="other-holder"))
            db.commit()
        seen.set()
        await asyncio.sleep(30)
        return Snapshot()

    monkeypatch.setattr("nyctr.integrations.collect", steal)

    async def scenario():
        task = asyncio.create_task(collect_integration(app.state.session_factory, app.state.settings, "dns", None))
        assert await asyncio.to_thread(seen.wait, 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    try:
        asyncio.run(scenario())
        with app.state.session_factory() as db:
            row = db.get(Integration, "dns")
            assert (row.status, row.sync_holder) == ("syncing", "other-holder")
        assert whys(app) == []
    finally:
        app.state.engine.dispose()


def beating_past_the_bound(app, source_id) -> bool:
    """Whether the database clock is past the claim by the bound and a later heartbeat has been written."""
    with app.state.session_factory() as db:
        row = db.get(Integration, source_id)
        if row is None or row.status != "syncing" or row.sync_heartbeat is None or row.sync_started_at is None:
            return False
        if utc(row.sync_heartbeat) <= utc(row.sync_started_at):
            return False
        # Read at call time, so a test can shorten the bound without changing the production value.
        bound = int(collection.HEARTBEAT_BOUND.total_seconds())
        return db.scalar(select(Integration.id).where(
            Integration.id == source_id,
            Integration.sync_started_at <= db_ago(db.get_bind(), bound),
        )) is not None


@BOTH
def test_the_running_app_writes_the_heartbeat_while_a_collection_stalls(tmp_path, monkeypatch, request, engine):
    """A real start keeps the lease while a collection blocks the server loop for longer than the bound.

    The stand-in never yields, so a heartbeat running on that loop cannot write. Dropping the heartbeat
    thread leaves the lease free once the bound passes, and this fails. The bound and the interval are
    shortened here; the production values stay 60 seconds and 5 seconds. The stand-in stores nothing
    of its own and calls no source.
    """
    # Long enough that the first beat (one interval in) has happened, short enough not to sit out a minute.
    monkeypatch.setattr(collection, "HEARTBEAT_BOUND", timedelta(seconds=3))
    monkeypatch.setattr(collection, "HEARTBEAT_EVERY", 0.5)
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "fabricated-key")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "fabricated-key")
    held, started = threading.Event(), threading.Event()

    async def stall(*_args, **_kwargs):
        started.set()
        while not held.is_set():
            time.sleep(0.2)
        return Snapshot()

    monkeypatch.setattr("nyctr.integrations.collect", stall)
    app = live_app(tmp_path, **home(engine, tmp_path, request))
    outcome = {}

    def post(client, headers):
        outcome["response"] = client.post("/api/integrations/dns/sync", headers=headers)

    try:
        with TestClient(app) as client:
            seed_live_member(app)
            headers = live_signin(client)
            poster = threading.Thread(target=post, args=(client, headers))
            poster.start()
            try:
                assert started.wait(10), "the collection did not start"
                deadline = time.monotonic() + collection.HEARTBEAT_BOUND.total_seconds() + 6
                while time.monotonic() < deadline and not beating_past_the_bound(app, "dns"):
                    threading.Event().wait(0.5)
                assert beating_past_the_bound(app, "dns"), "the heartbeat did not move before the bound"
                with app.state.session_factory() as db:
                    assert db.get(Integration, "dns").status == "syncing"
                    assert release_abandoned(db) == []
                    db.rollback()
            finally:
                held.set()
                poster.join(30)
        assert outcome["response"].status_code == 200, getattr(outcome.get("response"), "text", outcome)
    finally:
        held.set()
        app.state.engine.dispose()


@BOTH
def test_removing_an_abandoned_source_records_the_collection(tmp_path, monkeypatch, request, engine):
    """Remove records a missed beat before it deletes the source. Skipping that leaves no such record."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "fabricated-key")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "fabricated-key")
    app = live_app(tmp_path, **home(engine, tmp_path, request))
    try:
        with TestClient(app) as client:
            seed_live_member(app)
            stamp(app, ["unifi"], "previous-start", 61, 0)
            headers = live_signin(client)
            removed = client.request("DELETE", "/api/integrations/unifi", headers=headers, json={"name": "UniFi"})
            assert removed.status_code == 200, removed.text
            assert whys(app) == [NO_SIGN]
            with app.state.session_factory() as db:
                assert db.get(Integration, "unifi") is None
    finally:
        app.state.engine.dispose()
