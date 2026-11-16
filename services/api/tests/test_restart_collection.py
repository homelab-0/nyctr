"""A restart during a collection must not leave the source looking as if it were still being collected."""

import asyncio
import threading
from contextlib import contextmanager
from datetime import timedelta

import pytest
from conftest import live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select
from test_collection_store import POSTGRES
from test_presence import WAIT, on, others_finish

from nyctr.collection import (
    CUT_SHORT,
    HEARTBEAT_BOUND,
    HEARTBEAT_EVERY,
    _beat_once,
    begin_holder,
    collect_integration,
    release_abandoned,
)
from nyctr.database import migrate
from nyctr.integrations import Snapshot
from nyctr.models import Audit, Integration, utc, utcnow

BOTH = pytest.mark.parametrize("engine", ["sqlite", "postgresql"])


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


def leave_collecting(app, holder, heartbeat, started):
    """Leave both fabricated sources looking mid-collection, held by `holder`."""
    with app.state.session_factory() as db:
        for row in db.scalars(select(Integration)):
            row.status = "syncing"
            row.sync_started_at = started
            row.sync_holder = holder
            row.sync_heartbeat = heartbeat
        db.commit()


async def fake_collect(*_args, **_kwargs):
    """A collection that stores nothing and never calls a source."""
    return Snapshot()


def test_the_heartbeat_bound_is_fifteen_seconds():
    """The bound is part of the behaviour: a holder is treated as gone after fifteen seconds, not five minutes."""
    assert HEARTBEAT_BOUND == timedelta(seconds=15) and HEARTBEAT_EVERY == 5


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
        leave_collecting(first, "previous-start", utcnow() - HEARTBEAT_BOUND - timedelta(seconds=1), utcnow())
    again = live_app(tmp_path, **place)
    with TestClient(again) as client:
        headers = live_signin(client)
        listed = {row["id"]: row["status"] for row in client.get("/api/integrations").json()}
        assert listed == {"dns": "interrupted", "unifi": "interrupted"}
        assert audits(again) == 2
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
        now = utcnow()
        with first.state.session_factory() as db:
            row = db.get(Integration, "dns")
            row.status, row.sync_started_at = "syncing", now
            row.sync_holder, row.sync_heartbeat = "other-copy", now - timedelta(seconds=1)
            db.commit()
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
    now = utcnow()
    cases = {
        "stale": (now, "other", now - HEARTBEAT_BOUND - timedelta(seconds=1)),
        "recent": (now, "other", now - timedelta(seconds=1)),
        "aged": (now - timedelta(minutes=6), "other", now),
        "no-beat": (now, "other", None),
        "no-holder": (now, None, now),
    }

    def release(names):
        with app.state.session_factory() as db:
            rows = list(db.scalars(select(Integration).order_by(Integration.id)))
            for row, name in zip(rows, names, strict=True):
                started, holder, heartbeat = cases[name]
                row.status, row.sync_started_at = "syncing", started
                row.sync_holder, row.sync_heartbeat = holder, heartbeat
            db.commit()
        with app.state.session_factory() as db:
            release_abandoned(db, now)
            db.commit()
            return {row.id: row.status for row in db.scalars(select(Integration))}

    try:
        assert release(("stale", "recent")) == {"dns": "interrupted", "unifi": "syncing"}
        assert release(("aged", "no-beat")) == {"dns": "interrupted", "unifi": "interrupted"}
        assert release(("no-holder", "no-holder")) == {"dns": "interrupted", "unifi": "interrupted"}
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
    now = utcnow()
    writes = {"n": 0}

    def is_the_write(statement):
        sql = statement.lower().lstrip()
        if sql.startswith("update") or sql.startswith("insert"):
            writes["n"] += 1
            return writes["n"] == at
        return False

    def second():
        with app.state.session_factory() as db:
            release_abandoned(db, now)
            db.commit()

    try:
        leave_collecting(app, "previous-start", now - HEARTBEAT_BOUND - timedelta(seconds=1), now)
        with hold_the_lock(app, is_the_write, second):
            with app.state.session_factory() as db:
                assert release_abandoned(db, now) == ["dns", "unifi"]
                db.commit()
        assert audits(app) == 2
        with app.state.session_factory() as db:
            assert {row.status for row in db.scalars(select(Integration))} == {"interrupted"}
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
