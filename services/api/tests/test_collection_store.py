"""Storing a collection: off the server's loop, in batches, and a log read from where the last read ended."""

import asyncio
import logging
import threading
from datetime import datetime, timedelta

import httpx
import pytest
from conftest import live_app, live_signin
from fastapi.testclient import TestClient
from sqlalchemy import event, func, select

from nyctr import collection
from nyctr.assistant import attention
from nyctr.collection import collect_integration
from nyctr.integrations import Snapshot, core
from nyctr.models import Audit, Integration, Observation, Relationship, Resource, utcnow

KEY = "fabricated-key-never-logged"
NAME = 'Office "DNS"\nsecond line'


def add_source(app, monkeypatch, name="Office DNS"):
    """Save one DNS source that has never collected, with its secret on the server."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", KEY)
    with app.state.session_factory() as db:
        db.add(Integration(id="dns", provider="nextdns", name=name, config={"profile_id": "abc123"},
                           secret_ref="NYCTR_CONNECTOR_SECRET_DNS", status="configured"))
        db.commit()


def shaped(items, lookups, first=0):
    """Build a snapshot of the production shape: one profile, blocked addresses, and lookups from `first` on."""
    now = utcnow()
    node = {"provider": "nextdns", "site_id": None, "observed_at": now.isoformat(), "attributes": {}}
    names = [f"n{k}.example" for k in range(items - 1)]
    profile = {**node, "id": "dns:dns_profile:p", "name": "Profile", "kind": "dns_profile", "source_id": "p",
               "evidence_kind": "configured"}
    return Snapshot(
        resources=[profile] + [{**node, "id": f"dns:domain:{name}", "name": name, "kind": "domain",
                                "source_id": name, "evidence_kind": "observed"} for name in names],
        relationships=[{**node, "id": f"dns:relation:{name}", "source": profile["id"], "kind": "blocked_dns_query",
                        "target": f"dns:domain:{name}", "evidence_kind": "observed"} for name in names],
        blocks=[{"id": f"dns:block:{first + k}", "device_id": None, "device_name": "Unattributed DNS client",
                 "domain": names[k % len(names)], "source": "nextdns", "reason": "Fabricated list",
                 "observed_at": (now - timedelta(seconds=k)).isoformat(), "evidence_kind": "observed",
                 "attribution": "unattributed", "risk_score": None, "risk_explanation": "Unassessed"}
                for k in range(lookups)])


def returns(monkeypatch, *snapshots, during=None):
    """Stand in for the source read: hand back the given snapshots in turn, running `during` while in flight."""
    queue, loop_thread = list(snapshots), []

    async def collect(provider, integration_id, config, api_key, **_since):
        loop_thread.append(threading.get_ident())
        if during:
            await during()
        return queue.pop(0)
    monkeypatch.setattr("nyctr.integrations.collect", collect)
    return loop_thread


def run(app, actor=None, **options):
    """Run one collection of the DNS source as the schedule or a person would."""
    return asyncio.run(collect_integration(app.state.session_factory, app.state.settings, "dns", actor, **options))


def counts(app):
    """Count what is stored for the DNS source: items, links, lookups and collection records."""
    with app.state.session_factory() as db:
        return tuple(db.scalar(select(func.count()).select_from(model)) for model in
                     (Resource, Relationship, Observation)) + (db.scalar(select(func.count()).where(
                         Audit.action == "integration.collected")),)


def test_requests_are_answered_while_a_collection_of_the_production_shape_is_being_stored(tmp_path, monkeypatch):
    """The store runs on a worker thread, and a health check and a page read made in the middle of it are answered.

    Both are asked from inside the store, after every row is staged and before the commit: on the
    server's loop that call cannot be made at all, so this fails by what blocks, not by a stopwatch.
    """
    app, during = live_app(tmp_path), {}
    with TestClient(app) as client:
        live_signin(client)
        add_source(app, monkeypatch)
        staged = collection.apply_snapshot

        async def second_copy():
            assert await collect_integration(app.state.session_factory, app.state.settings, "dns", None) == (
                None, "busy")

        def storing(*args):
            result = staged(*args)
            during.update(thread=threading.get_ident(), health=client.get("/api/health").status_code,
                          page=client.get("/api/resources").json())
            return result
        monkeypatch.setattr(collection, "apply_snapshot", storing)
        loop_thread = returns(monkeypatch, shaped(1500, 4000), during=second_copy)
        response = client.post("/api/integrations/dns/sync", headers=live_signin(client))
        assert response.status_code == 200, response.text
        assert during["thread"] not in loop_thread
        # Answered mid-store, and with what was stored before it: nothing of a half-stored run is visible.
        assert during["health"] == 200 and during["page"] == []
        assert len(client.get("/api/resources").json()) == 1500
    assert counts(app) == (1500, 1499, 4000, 1)


@pytest.mark.parametrize("items, lookups", [(1500, 4000), (3000, 8000)])
def test_a_store_runs_a_handful_of_statements_however_many_items_it_holds(tmp_path, monkeypatch, items, lookups):
    """No statement per item: a first store and a repeat of it stay under a bound that twice the items also meets."""
    app, ran = live_app(tmp_path), []
    with TestClient(app):
        add_source(app, monkeypatch)
        returns(monkeypatch, shaped(items, lookups), shaped(items, lookups, first=100))
        event.listen(app.state.session_factory.kw["bind"], "before_cursor_execute", lambda *args: ran.append(args[2]))
        for expected in (lookups, lookups + 100):
            del ran[:]
            assert run(app)[1] is None
            # 23 fixed, and one for every LOOKUP_BATCH identifiers looked up or thousand rows written.
            assert len(ran) <= 23 + 2 * (items + lookups) // collection.LOOKUP_BATCH, len(ran)
            assert counts(app)[:3] == (items, items - 1, expected)


def test_a_store_stopped_half_way_leaves_the_source_as_it_was(tmp_path, monkeypatch):
    """A failure after every row was staged stores none of them, and the run before it is untouched."""
    app = live_app(tmp_path)
    with TestClient(app):
        add_source(app, monkeypatch)
        returns(monkeypatch, shaped(20, 30), shaped(40, 60, first=30))
        assert run(app)[1] is None
        before, staged = counts(app), collection.apply_snapshot

        def fails_after_staging(*args):
            staged(*args)
            raise RuntimeError("stopped half way")
        monkeypatch.setattr(collection, "apply_snapshot", fails_after_staging)
        assert run(app)[0] is None
        assert counts(app) == before
        with app.state.session_factory() as db:
            row = db.get(Integration, "dns")
            assert (row.status, row.sync_started_at) == ("error", None)


def test_a_collection_cancelled_during_its_store_waits_for_the_store_to_end_whole(tmp_path, monkeypatch):
    """Stopping the server mid-store never closes the session under the store: it ends stored, all of it."""
    app, entered, release = live_app(tmp_path), threading.Event(), threading.Event()
    with TestClient(app):
        add_source(app, monkeypatch)
        returns(monkeypatch, shaped(20, 30))
        staged = collection.apply_snapshot

        def held(*args):
            result = staged(*args)
            entered.set()
            assert release.wait(30)
            return result
        monkeypatch.setattr(collection, "apply_snapshot", held)

        async def scenario():
            task = asyncio.create_task(collect_integration(app.state.session_factory, app.state.settings,
                                                           "dns", None))
            assert await asyncio.to_thread(entered.wait, 30)
            task.cancel()
            for _ in range(5):
                await asyncio.sleep(0)
            assert not task.done()  # still waiting for the store it started
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        asyncio.run(scenario())
        assert counts(app) == (20, 19, 30, 1)
        with app.state.session_factory() as db:
            assert db.get(Integration, "dns").status == "connected"


class Log:
    """A fabricated DNS source whose log answers `from` and `to`, newest first, a page at a time.

    The clock the adapter and the store read is `at`, so a test moves time by setting it.
    """

    def __init__(self, monkeypatch, at, *, end_included=True):
        self.at, self.rows, self.asked, self.served, self.fail = at, [], [], [], False
        self.end_included = end_included
        monkeypatch.setattr(core, "utc_now", lambda: self.at)
        monkeypatch.setattr(collection, "utcnow", lambda: self.at)
        monkeypatch.setattr(core, "make_http_client", lambda key: httpx.AsyncClient(
            transport=httpx.MockTransport(self.answer), follow_redirects=False, trust_env=False))

    def add(self, when, name):
        self.rows.append((when, name))

    def answer(self, request):
        assert request.method == "GET"
        if self.fail:
            return httpx.Response(503)
        if request.url.path == "/profiles/abc123":
            return httpx.Response(200, json={"data": {
                "name": "Profile", "settings": {"logs": {"enabled": True}}, "security": {}, "privacy": {},
                "parentalControl": {}, "allowlist": [], "denylist": []}})
        asked = request.url.params
        low, high = datetime.fromisoformat(asked["from"]), datetime.fromisoformat(asked["to"])
        hits = sorted((row for row in self.rows
                       if low <= row[0] and (row[0] <= high if self.end_included else row[0] < high)), reverse=True)
        start = int(asked.get("cursor", 0))
        page = hits[start:start + int(asked["limit"])]
        if not start:
            self.asked.append(low)
        self.served.append(len(page))
        return httpx.Response(200, json={
            "data": [{"timestamp": when.isoformat(), "domain": name, "status": "blocked",
                      "reasons": [{"id": "blocklist:example"}]} for when, name in page],
            "meta": {"pagination": {"cursor": str(start + len(page)) if start + len(page) < len(hits) else None}}})


def stored_names(app):
    """Return the address of every stored lookup, once per stored row."""
    with app.state.session_factory() as db:
        return sorted(db.scalars(select(Observation.domain)))


def test_a_run_on_the_owners_shape_reads_what_is_new_and_is_not_partial(tmp_path, monkeypatch, caplog):
    """About 100 new lookups per 15 minutes: the first run fills its bound and is partial, the next reads 167 rows.

    A person pressing Collect straight after the scheduled run picks up the same way, from that run's end.
    """
    start = utcnow().replace(microsecond=0)
    log, app = Log(monkeypatch, start), live_app(tmp_path)
    for k in range(9600):  # one every nine seconds for a day, the newest at the first run's own time
        log.add(start - timedelta(seconds=9 * k), f"a{k % 1400}.example")
    with TestClient(app):
        add_source(app, monkeypatch, NAME)
        snapshot, error = run(app, attempt=0)
        assert error is None and snapshot.partial_rows == 4000 and sum(log.served) == 4000
        with app.state.session_factory() as db:
            assert db.get(Integration, "dns").status == "partial"
            assert [item["title"] for item in attention(db, app.state.settings) if item["kind"] == "source"]
        log.at = start + timedelta(minutes=15)
        for k in range(100):
            log.add(log.at - timedelta(seconds=9 * k), f"b{k}.example")
        del log.served[:], caplog.records[:]
        # Ten minutes of overlap is 67 rows read again; with the 100 new ones that is one page.
        for by, since, rows in (({"attempt": 0}, start, 167), ({"actor": "owner"}, log.at, 67)):
            snapshot, error = run(app, **by)
            assert error is None and snapshot.partial_rows is None and log.served == [rows]
            assert log.asked[-1] == since - collection.RESUME_OVERLAP
            del log.served[:]
        with app.state.session_factory() as db:
            assert db.get(Integration, "dns").status == "connected"
            assert [item for item in attention(db, app.state.settings) if item["kind"] == "source"] == []
        assert len(stored_names(app)) == 4100
    # One line at the start and one at the end of each run, with what it cost and nothing it read.
    assert logging.getLogger("nyctr.collection").isEnabledFor(logging.INFO)
    lines = [record.getMessage() for record in caplog.records if record.name == "nyctr.collection"]
    assert lines[0] == ('Collection started: source="Office \\"DNS\\"\\nsecond line" by=schedule retry=0 '
                        "reading=since_last_read")
    assert lines[1].startswith('Collection ended: source="Office \\"DNS\\"\\nsecond line" outcome=stored seconds=')
    assert lines[1].endswith("requests=2 waited_seconds=0.0 by=schedule retry=0 store_seconds=" +
                             lines[1].split("store_seconds=")[1])
    assert lines[1].split("store_seconds=")[1].split(" ", 1)[1] == (
        "items_read=173 items_new=100 lookups_read=167 lookups_new=100")
    assert "by=person" in lines[2] and "lookups_read=67 lookups_new=0" in lines[3] and len(lines) == 4
    assert not any(secret in line for line in lines for secret in (KEY, "abc123", ".example", "\n"))


def test_overlapping_runs_lose_and_repeat_nothing_across_a_restart_a_failure_and_an_edit(tmp_path, monkeypatch):
    """Lookups sharing the boundary's timestamp, and ones the source showed late, are each stored exactly once.

    The source here leaves its `to` out, the worse of the two readings of the published contract.
    """
    start = utcnow().replace(microsecond=0)
    log, wanted = Log(monkeypatch, start, end_included=False), []

    def happen(when, *names):
        for name in names:
            log.add(when, name)
            wanted.append(name)

    def collect_once():
        app = live_app(tmp_path)  # a new process on the same database
        with TestClient(app) as client:
            if not wanted_source:
                add_source(app, monkeypatch)
                wanted_source.append(True)
            result = run(app, attempt=0)
            return result, client.put("/api/integrations/dns", headers=live_signin(client), json={
                "name": "Office DNS", "config": {"profile_id": "abc123", "lookback_hours": 12},
                "secret_ref": "NYCTR_CONNECTOR_SECRET_DNS"}) if log.at > start + timedelta(minutes=40) else None
    wanted_source = []
    happen(start - timedelta(hours=1), "early.example")
    happen(start, "edge-one.example", "edge-two.example", "edge-three.example")  # at the first read's own end
    assert collect_once()[0][1] is None and log.asked == [start - timedelta(hours=24)]
    happen(start - timedelta(minutes=4), "shown-late.example")  # before the first read ended, visible after it
    happen(start + timedelta(minutes=14), "new.example")
    log.at = start + timedelta(minutes=15)
    assert collect_once()[0][1] is None and log.asked[-1] == start - collection.RESUME_OVERLAP
    assert stored_names(live_app(tmp_path)) == sorted(wanted)
    # A failed run stores nothing, and the run after it reads the whole window again.
    log.at, log.fail = start + timedelta(minutes=30), True
    assert collect_once()[0][0] is None
    log.at, log.fail = start + timedelta(minutes=45), False
    happen(log.at - timedelta(minutes=1), "after-failure.example")
    (_snapshot, error), edit = collect_once()
    assert error is None and log.asked[-1] == log.at - timedelta(hours=24) and edit.status_code == 200
    # So does the run after an edit, here to a shorter window.
    log.at = start + timedelta(minutes=60)
    assert collect_once()[0][1] is None and log.asked[-1] == log.at - timedelta(hours=12)
    log.at = start + timedelta(minutes=75)
    assert collect_once()[0][1] is None and log.asked[-1] == start + timedelta(minutes=60) - collection.RESUME_OVERLAP
    assert stored_names(live_app(tmp_path)) == sorted(wanted)


def dump(app):
    """Everything stored from the source that a reader sees, apart from when its rows were written."""
    with app.state.session_factory() as db:
        return ([(row.id, row.observed_at, row.attributes) for row in db.scalars(select(Resource).order_by(Resource.id))],
                [(row.id, row.observed_at) for row in db.scalars(select(Relationship).order_by(Relationship.id))],
                sorted(db.scalars(select(Observation.id))))


def test_reads_that_pick_up_leave_exactly_what_reads_of_the_whole_window_would(tmp_path, monkeypatch):
    """Items a resumed read did not see stand while inside the window and are missing once older, as before."""
    start, left = utcnow().replace(microsecond=0), []
    for folder, resume in (("picked-up", True), ("whole", False)):
        log, app = Log(monkeypatch, start), live_app(tmp_path / folder)
        (tmp_path / folder).mkdir()
        if not resume:
            monkeypatch.setattr(collection, "_resume_from", lambda db, integration: None)
        log.add(start - timedelta(hours=23, minutes=50), "leaving.example")
        log.add(start - timedelta(hours=1), "staying.example")
        with TestClient(app):
            add_source(app, monkeypatch)
            for minutes in (0, 15, 30):
                log.at = start + timedelta(minutes=minutes)
                log.add(log.at - timedelta(minutes=1), f"new{minutes}.example")
                assert run(app, attempt=0)[1] is None
            assert (log.asked[-1] > start) is resume
            left.append(dump(app))
    assert left[0] == left[1]
    links = {row[0] for row in left[0][1]}
    assert len(left[0][0]) == 11 and len(links) == 9 and len(left[0][2]) == 5
    assert [row[0] for row in left[0][0] if row[2].get("missing_from_latest_snapshot")] == ["dns:domain:leaving.example"]


def test_requests_and_time_waited_at_a_request_limit_are_counted_for_the_log(monkeypatch):
    """The second request waits for the first one's place under a limit of one, and both are counted."""
    clock = [0.0]

    async def pause(seconds):
        clock[0] += seconds
    monkeypatch.setattr(core, "monotonic", lambda: clock[0])
    monkeypatch.setattr(core, "pause", pause)

    async def read_twice():
        transport = httpx.MockTransport(lambda request: httpx.Response(200, json={}))
        async with httpx.AsyncClient(transport=transport) as client:
            reader = core.ReadClient(client, "https://source.example", core.Pace("counted-for-the-log", 1, 30.0))
            with core.capture_probe() as evidence:
                await reader.get("/one")
                await reader.get("/two")
            return evidence
    evidence = asyncio.run(read_twice())
    assert (evidence.requests, evidence.waited) == (2, 30.0)
