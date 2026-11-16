"""Storing a collection: off the server's loop, in batches, and a log read from where the last read ended."""

import asyncio
import logging
import os
import secrets
import threading
from datetime import datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from conftest import live_app, live_signin
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, func, select, text
from test_guests import live_guest

from nyctr import analysis, collection, integrations, removal, worker
from nyctr.assistant import attention
from nyctr.collection import collect_integration
from nyctr.guests import enforce
from nyctr.integrations import Snapshot, core, registry
from nyctr.models import (
    Audit,
    Finding,
    GuestAction,
    Integration,
    Observation,
    Relationship,
    Resource,
    Sighting,
    utcnow,
)

KEY = "fabricated-key-never-logged"
POSTGRES = "NYCTR_TEST_POSTGRES"
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
        analysed = collection.after_collection
        monkeypatch.setattr(collection, "after_collection", lambda *args: (
            during.update(analysis=threading.get_ident()), analysed(*args))[1])
        loop_thread = returns(monkeypatch, shaped(1500, 4000), during=second_copy)
        response = client.post("/api/integrations/dns/sync", headers=live_signin(client))
        assert response.status_code == 200, response.text
        assert during["thread"] not in loop_thread and during["analysis"] not in loop_thread
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


@pytest.mark.parametrize("cancels", [1, 2])
def test_a_collection_cancelled_during_its_store_waits_for_the_store_to_end_whole(tmp_path, monkeypatch, caplog,
                                                                                 cancels):
    """Stopping the server mid-store, however often it cancels, ends stored: all of it, and its record with it.

    The store's session is opened on the store's own thread, so nothing on the loop can close it.
    """
    app, entered, release, opened = live_app(tmp_path), threading.Event(), threading.Event(), []

    def factory():
        opened.append(threading.get_ident())
        return app.state.session_factory()
    with TestClient(app):
        add_source(app, monkeypatch)
        returns(monkeypatch, shaped(20, 30))
        staged = collection.apply_snapshot

        def held(*args):
            result = staged(*args)
            opened.append(("store", threading.get_ident()))
            entered.set()
            assert release.wait(30)
            return result
        monkeypatch.setattr(collection, "apply_snapshot", held)

        async def scenario():
            task = asyncio.create_task(collect_integration(factory, app.state.settings, "dns", None))
            assert await asyncio.to_thread(entered.wait, 30)
            for _ in range(cancels):
                task.cancel()
                for _ in range(5):
                    await asyncio.sleep(0)
                assert not task.done()  # still waiting for the store it started
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        asyncio.run(scenario())
        assert counts(app) == (20, 19, 30, 1)
        assert opened[0] == threading.get_ident() and opened[2] == ("store", opened[1]) and opened[1] != opened[0]
        with app.state.session_factory() as db:
            row = db.get(Integration, "dns")
            assert (row.status, row.sync_started_at) == ("connected", None)
    # The pair of log lines stays whole: a stopped run says so, and that its store was finished.
    last = [record.getMessage() for record in caplog.records if record.name == "nyctr.collection"][-1]
    assert last.startswith('Collection ended: source="Office DNS" outcome=stopped ') and last.endswith(" stored=True")


class Log:
    """A fabricated DNS source whose log answers `from` and `to`, newest first, a page at a time.

    The clock the adapter and the store read is `at`, so a test moves time by setting it. The
    source stamps its rows by its own clock, which is `behind` ours.
    """

    def __init__(self, monkeypatch, at, *, end_included=True, behind=timedelta(0)):
        self.at, self.rows, self.asked, self.served, self.fail = at, [], [], [], False
        self.end_included, self.behind = end_included, behind
        monkeypatch.setattr(core, "utc_now", lambda: self.at)
        monkeypatch.setattr(collection, "utcnow", lambda: self.at)
        monkeypatch.setattr(core, "make_http_client", lambda key: httpx.AsyncClient(
            transport=httpx.MockTransport(self.answer), follow_redirects=False, trust_env=False))

    def add(self, when, name):
        self.rows.append((when - self.behind, name))

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


def test_a_run_on_the_owners_shape_reads_what_is_new_and_is_partial_while_a_hole_is_in_the_window(
        tmp_path, monkeypatch, caplog):
    """About 100 new lookups per 15 minutes: the first run fills its bound and is partial, the next reads 167 rows.

    A person pressing Collect straight after the scheduled run picks up the same way, from that run's end.
    Those runs left nothing unread, but the source stays partly collected until the stretch the first
    run left out, older than the oldest lookup it kept, has passed out of the window.
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
        assert len(stored_names(app)) == 4100
        # The oldest lookup the first run kept is 3,999 nine-second steps before it: 9 seconds short of ten hours.
        for hours_on, status in ((timedelta(hours=14), "partial"), (timedelta(hours=14, seconds=10), "connected")):
            log.at = start + hours_on
            assert run(app, attempt=0)[1] is None
            with app.state.session_factory() as db:
                assert db.get(Integration, "dns").status == status
                last = db.scalar(select(Audit).where(Audit.action == "integration.collected")
                                 .order_by(Audit.created_at.desc()).limit(1))
                assert last.details["partial"] is (status == "partial") and "rows_kept" not in last.details
                assert bool([item for item in attention(db, app.state.settings) if item["kind"] == "source"]) is (
                    status == "partial")
    # One line at the start and one at the end of each run, with what it cost and nothing it read.
    assert logging.getLogger("nyctr.collection").isEnabledFor(logging.INFO)
    lines = [record.getMessage() for record in caplog.records if record.name == "nyctr.collection"]
    assert lines[0] == ('Collection started: source="Office \\"DNS\\"\\nsecond line" by=schedule retry=0 '
                        "reading=since_last_read")
    assert lines[1].startswith('Collection ended: source="Office \\"DNS\\"\\nsecond line" outcome=partial seconds=')
    assert lines[1].endswith("requests=2 waited_seconds=0.0 by=schedule retry=0 store_seconds=" +
                             lines[1].split("store_seconds=")[1])
    assert lines[1].split("store_seconds=")[1].split(" ", 1)[1] == (
        "items_read=173 items_new=100 lookups_read=167 lookups_new=100")
    assert "by=person" in lines[2] and "lookups_read=67 lookups_new=0" in lines[3] and len(lines) == 8
    assert " outcome=partial " in lines[5] and " outcome=stored " in lines[7]
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
    # This source left out the three lookups at the first read's own end, so the newest one stored is the
    # early one, and the read picks up ten minutes before it: the earlier of that and the read's end.
    assert collect_once()[0][1] is None and log.asked[-1] == start - timedelta(hours=1) - collection.RESUME_OVERLAP
    assert stored_names(live_app(tmp_path)) == sorted(wanted)
    # A failed run stores nothing, so the run after it picks up where the last stored one ended:
    # ten minutes before the newest lookup stored, which is the earlier of the two places.
    log.at, log.fail = start + timedelta(minutes=30), True
    assert collect_once()[0][0] is None
    log.at, log.fail = start + timedelta(minutes=45), False
    happen(log.at - timedelta(minutes=1), "after-failure.example")
    (_snapshot, error), edit = collect_once()
    assert error is None and log.asked[-1] == start + timedelta(minutes=14) - collection.RESUME_OVERLAP
    assert edit.status_code == 200
    # The run after an edit reads the whole window, here a shorter one.
    log.at = start + timedelta(minutes=60)
    assert collect_once()[0][1] is None and log.asked[-1] == log.at - timedelta(hours=12)
    log.at = start + timedelta(minutes=75)
    assert collect_once()[0][1] is None and log.asked[-1] == start + timedelta(minutes=44) - collection.RESUME_OVERLAP
    assert stored_names(live_app(tmp_path)) == sorted(wanted)


@pytest.mark.parametrize("behind", [12, 20, 30, 60])
def test_a_source_whose_clock_is_behind_loses_no_lookup(tmp_path, monkeypatch, behind):
    """One lookup a minute for two hours, a collection every 15 minutes: the place to pick up is the source's own."""
    start = utcnow().replace(microsecond=0)
    log, app = Log(monkeypatch, start, behind=timedelta(minutes=behind)), live_app(tmp_path)
    with TestClient(app):
        add_source(app, monkeypatch)
        for quarter in range(10):
            log.at = start + timedelta(minutes=15 * quarter)
            for minute in range(15 if 0 < quarter < 9 else 0):
                log.add(log.at - timedelta(minutes=15) + timedelta(minutes=minute, seconds=30),
                        f"m{quarter}-{minute}.example")
            assert run(app, attempt=0)[1] is None
        assert len(stored_names(app)) == len(log.rows) == 120
        with app.state.session_factory() as db:
            assert db.get(Integration, "dns").status == "connected"


def test_a_read_end_written_by_a_clock_that_was_ahead_loses_no_lookup(tmp_path, monkeypatch):
    """The last read's end is 20 minutes later than it was: the newest stored lookup says where to pick up."""
    start = utcnow().replace(microsecond=0)
    log, app = Log(monkeypatch, start + timedelta(minutes=20)), live_app(tmp_path)
    with TestClient(app):
        add_source(app, monkeypatch)
        log.add(start - timedelta(minutes=1), "before.example")
        assert run(app, attempt=0)[1] is None
        log.at = start + timedelta(minutes=15)  # a copy with the right clock reads 15 real minutes later
        for minute in range(1, 15):
            log.add(start + timedelta(minutes=minute), f"minute{minute}.example")
        assert run(app, attempt=0)[1] is None and log.asked[-1] == start - timedelta(minutes=11)
        assert len(stored_names(app)) == 15


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
            monkeypatch.setattr(collection, "_resume_from", lambda db, integration: (None, None))
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


def test_only_a_source_that_declares_it_is_asked_to_read_its_log_from_a_time(monkeypatch):
    """Every source of blocked lookups declares `resumes`; `since` reaches those and no other, inside the window."""
    assert {source.id for source in registry.providers().values() if source.resumes} == set(
        registry.with_capability("dns.blocks"))
    got = []

    async def collect(integration_id, config, secret, **since):
        got.append(since)
        return Snapshot()
    now = utcnow()
    for resumes in (True, False):
        monkeypatch.setattr(registry, "get", lambda provider, resumes=resumes: SimpleNamespace(
            validate=dict, collect=collect, resumes=resumes))
        asyncio.run(integrations.collect("fabricated", "id", {}, KEY, since=now))
        asyncio.run(integrations.collect("fabricated", "id", {}, KEY))
    assert got == [{"since": now}, {}, {}, {}]
    window = now - timedelta(hours=24)
    assert [core.log_read(window, since, now)[0] for since in (None, window - timedelta(hours=1),
            now - timedelta(minutes=25), now + timedelta(hours=1))] == [window, window, now - timedelta(minutes=25), now]
    assert core.log_read(window, None, now)[1] == {
        "window_from": window.isoformat(), "read_from": window.isoformat(), "read_to": now.isoformat()}


def item(name, kind="domain", evidence="observed", **attributes):
    """Build one fabricated item of the DNS source."""
    return {"id": f"dns:{kind}:{name}", "name": name, "kind": kind, "provider": "nextdns", "source_id": name,
            "site_id": None, "evidence_kind": evidence, "observed_at": utcnow().isoformat(), "attributes": attributes}


def link(name, source, target, **attributes):
    """Build one fabricated relationship between two items."""
    return {"id": f"dns:relation:{name}", "source": source["id"], "target": target["id"], "kind": "blocked_dns_query",
            "provider": "nextdns", "evidence_kind": "observed", "observed_at": utcnow().isoformat(),
            "attributes": attributes}


def lookup(key):
    """Build one fabricated blocked lookup."""
    return {"id": f"dns:block:{key}", "device_id": None, "device_name": "Unattributed DNS client",
            "domain": "a.example", "source": "nextdns", "reason": "Fabricated list",
            "observed_at": utcnow().isoformat(), "evidence_kind": "observed", "attribution": "unattributed",
            "risk_score": None, "risk_explanation": "Unassessed"}


def apply(app, snapshot, source="dns"):
    """Stage one snapshot for a source through the store's own routine and commit it."""
    with app.state.session_factory() as db:
        new = collection.apply_snapshot(db, db.get(Integration, source), snapshot, app.state.settings)
        db.commit()
        return new


def test_an_answer_that_repeats_an_identifier_is_stored_once_and_the_last_one_stands(tmp_path, monkeypatch):
    """An item, a relationship and a lookup listed twice are each one row; a guest listed twice is one sighting
    for each access point it was listed on."""
    app = live_app(tmp_path)
    with TestClient(app):
        add_source(app, monkeypatch)
        profile, address = item("p", "dns_profile", "configured"), item("a.example")
        phone = [item("phone", "client", guest={"authorized": True}, uplink=uplink)
                 for uplink in ("ap-1", "ap-1", "ap-2")]
        assert apply(app, Snapshot(
            resources=[profile, address, {**address, "name": "named again"}, *phone],
            relationships=[link("one", profile, address, order=1), link("one", profile, address, order=2)],
            blocks=[lookup(1), lookup(1)])) == (3, 1)
        with app.state.session_factory() as db:
            assert db.get(Resource, address["id"]).name == "named again"
            assert [row.attributes for row in db.scalars(select(Relationship))] == [{"order": 2}]
            assert db.scalar(select(func.count()).select_from(Observation)) == 1
            assert sorted(db.scalars(select(Sighting.uplink_id))) == ["ap-1", "ap-2"]


def test_what_a_store_refuses_and_what_a_read_that_picked_up_carries(tmp_path, monkeypatch):
    """An item or lookup identifier another source holds is refused. On a read that picked up, a relationship may
    join only what that answer names, and only observed items it did not name are kept from being missing."""
    app, now = live_app(tmp_path), utcnow()
    with TestClient(app):
        add_source(app, monkeypatch)
        with app.state.session_factory() as db:
            db.add(Integration(id="other", provider="nextdns", name="Other DNS", config={"profile_id": "def456"},
                               secret_ref="NYCTR_CONNECTOR_SECRET_DNS", status="configured"))
            db.commit()
        profile, rules, address = item("p", "dns_profile", "configured"), item("rules", "policy", "configured"), \
            item("a.example")
        apply(app, Snapshot(resources=[profile, rules, address], blocks=[lookup(1)]))
        with app.state.session_factory() as db:
            # What a collection records beside the store: it left nothing in doubt, from the window's start.
            db.add(Audit(action="integration.collected", target_id="dns", details={
                "unread": [], "unread_from": (now - timedelta(hours=24)).isoformat()}))
            db.commit()
        with pytest.raises(ValueError, match="Observation identity crosses"):
            apply(app, Snapshot(blocks=[lookup(1)]), source="other")
        with pytest.raises(ValueError, match="Resource identity crosses"):
            apply(app, Snapshot(resources=[address]), source="other")
        picked_up = {"window_from": (now - timedelta(hours=24)).isoformat(),
                     "read_from": (now - timedelta(minutes=25)).isoformat(), "read_to": now.isoformat()}
        with pytest.raises(ValueError, match="outside this snapshot"):
            apply(app, Snapshot(resources=[profile], relationships=[link("kept", profile, address)], log=picked_up))
        apply(app, Snapshot(resources=[profile], log=picked_up))
        with app.state.session_factory() as db:
            assert [row.id for row in db.scalars(select(Resource).order_by(Resource.id))
                    if row.attributes.get("missing_from_latest_snapshot")] == [rules["id"]]
            assert db.scalar(select(func.count()).select_from(Observation)) == 1


def postgres_database(request) -> dict:
    """An empty database of this test's own on the PostgreSQL server named in the environment, as a
    `live_app` override; nothing when no server is named. The database is dropped when the test ends."""
    server = os.environ.get(POSTGRES)
    if not server:
        return {}
    name, admin = f"t_{secrets.token_hex(8)}", create_engine(server + "postgres", isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f"create database {name}"))

    def drop():
        with admin.connect() as connection:
            connection.execute(text(f"drop database if exists {name} with (force)"))
        admin.dispose()
    request.addfinalizer(drop)
    return {"database_url": server + name}


def held_analysis(monkeypatch):
    """Hold the first analysis after it has staged its findings, until `go`; say who arrives at the lock."""
    arrived, inside, go, threads = threading.Semaphore(0), threading.Event(), threading.Event(), []
    lock, refresh = analysis.ONE_AT_A_TIME, analysis.refresh_findings

    class Watched:
        """The analysis lock, saying when someone arrives at it."""

        def __enter__(self):
            arrived.release()
            lock.acquire()

        def __exit__(self, *_error):
            lock.release()

    def held(db):
        refresh(db)  # the finding is staged and flushed, not yet committed
        threads.append(threading.get_ident())
        if not inside.is_set():
            inside.set()
            assert go.wait(30)
    monkeypatch.setattr(analysis, "ONE_AT_A_TIME", Watched())
    monkeypatch.setattr(analysis, "refresh_findings", held)
    return arrived, inside, go, threads


def unlogged_profile(app):
    """Store a DNS profile with logging off: something no analysis has yet made a finding of."""
    with app.state.session_factory() as db:
        db.add(Resource(id="dns:dns_profile:p", integration_id="dns", name="Profile", kind="dns_profile",
                        provider="nextdns", source_id="p", evidence_kind="configured", observed_at=utcnow(),
                        attributes={"logs_enabled": False}, classification="infrastructure"))
        db.commit()


def test_two_analyses_never_run_at_once_and_none_holds_or_runs_on_the_servers_loop(tmp_path, monkeypatch):
    """A scheduled pass, a person's Collect and the guest rule's step that find the same new finding: each
    waits for the one before to be stored, the loop goes on meanwhile, and none fails."""
    app = live_app(tmp_path)
    factory, settings = app.state.session_factory, app.state.settings
    arrived, inside, go, threads = held_analysis(monkeypatch)

    async def step():
        with factory() as db:
            return await enforce(db, settings, [])

    async def scenario():
        scheduled = asyncio.create_task(worker._analyse(factory, settings))
        assert await asyncio.to_thread(inside.wait, 30)
        person = asyncio.create_task(collection.off_loop(lambda: collection.analyse(factory, settings)))
        rule = asyncio.create_task(step())
        for _ in range(3):  # the scheduled analysis, which holds the lock, and the two that wait at it
            assert await asyncio.to_thread(arrived.acquire, True, 30)
        for _ in range(5):  # the loop is not held by the step that waits
            await asyncio.sleep(0)
        assert not rule.done() and not person.done()
        go.set()
        await asyncio.gather(scheduled, person, rule)
    with TestClient(app):
        add_source(app, monkeypatch)
        unlogged_profile(app)
        asyncio.run(scenario())
        with factory() as db:
            assert db.scalar(select(func.count()).select_from(Finding)) == 1
    assert len(threads) == 4 and threading.get_ident() not in threads


@pytest.mark.parametrize("work", ["analysis", "refresh"])
def test_an_analysis_and_a_refresh_of_findings_each_wait_for_the_lock(tmp_path, monkeypatch, work):
    """While the lock is held nothing is refreshed; once it is let go the work runs and is stored."""
    app = live_app(tmp_path)
    factory, arrived, ran = app.state.session_factory, threading.Semaphore(0), []
    lock, refresh = analysis.ONE_AT_A_TIME, analysis.refresh_findings

    class Watched:
        def __enter__(self):
            arrived.release()
            lock.acquire()

        def __exit__(self, *_error):
            lock.release()
    monkeypatch.setattr(analysis, "ONE_AT_A_TIME", Watched())
    monkeypatch.setattr(analysis, "refresh_findings", lambda db: (ran.append(1), refresh(db)))
    with TestClient(app):
        add_source(app, monkeypatch)
        unlogged_profile(app)
        waiting = threading.Thread(target=(lambda: collection.analyse(factory, app.state.settings))
                                   if work == "analysis" else lambda: analysis.refresh_alone(app.state.engine))
        with lock:
            waiting.start()
            assert arrived.acquire(timeout=30) and not ran
        waiting.join(30)
        with factory() as db:
            assert ran == [1] and db.scalar(select(func.count()).select_from(Finding)) == 1


@pytest.mark.postgres
def test_a_guest_action_during_an_analysis_that_holds_a_new_finding_is_recorded_and_answered(tmp_path, monkeypatch, request):
    """An administrator cuts a guest off while an analysis holds a finding it has not stored yet: the action
    is on record before the findings are touched, the refresh waits its turn, and the answer is 200."""
    sent = []

    def source(request):
        """The guest's source, fabricated: it takes the cut-off and then reports the guest without access."""
        sent.append(request.method)
        return httpx.Response(200, json={"id": "g1", "access": {"type": "GUEST", "authorized": False}})
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", KEY)
    monkeypatch.setattr(core, "make_http_client", lambda key, **_: httpx.AsyncClient(
        transport=httpx.MockTransport(source), headers={"X-Api-Key": key}, follow_redirects=False))
    app = live_app(tmp_path, provider_writes="unifi_network", **postgres_database(request))
    if app.state.engine.dialect.name == "sqlite":
        pytest.skip("SQLite has one writer, so the action's own write waits for the analysis. "
                    f"Set {POSTGRES} to a PostgreSQL server's address ending in / to run this.")
    factory, answers = app.state.session_factory, []
    arrived, inside, go, threads = held_analysis(monkeypatch)
    with TestClient(app) as client:
        live_guest(app)
        headers = live_signin(client)
        unlogged_profile(app)
        running = threading.Thread(target=lambda: collection.analyse(factory, app.state.settings))
        asked = threading.Thread(target=lambda: answers.append(client.post(
            "/api/guests/actions", headers=headers, json={"device_id": "unifi:client:g1", "action": "cut"})))
        running.start()
        try:
            assert inside.wait(30)
            asked.start()
            for _ in range(2):  # the analysis, which holds the lock, and the action's refresh, which waits
                assert arrived.acquire(timeout=30)
            with factory() as db:  # sent to the source and on record, before the findings are touched
                assert sent[0] == "POST" and db.scalar(select(GuestAction)).execution == "applied"
        finally:
            go.set()
            running.join(60)
            asked.join(60)
        assert [answer.status_code for answer in answers] == [200], answers[0].text
        with factory() as db:
            assert db.scalar(select(func.count()).select_from(GuestAction)) == 1
            ids = [row.id for row in db.scalars(select(Finding))]
            assert len(ids) == len(set(ids)) and len(ids) >= 2
    assert threading.get_ident() not in threads


def test_a_guest_action_is_answered_when_its_source_is_removed_during_the_refresh(client, app, admin_headers,
                                                                                  monkeypatch):
    """The source, and the guest device with it, is removed while the refresh of findings waits its turn:
    the administrator is still told what was just done, never an error."""
    def removed_meanwhile(bind):
        with app.state.session_factory() as db:
            removal.remove(db, db.get(Integration, db.get(Resource, "guest-hvac").integration_id))
            db.commit()
    monkeypatch.setattr(analysis, "refresh_alone", removed_meanwhile)
    answer = client.post("/api/guests/actions", headers=admin_headers,
                         json={"device_id": "guest-hvac", "action": "cut", "reason": "Unknown device"})
    assert answer.status_code == 200 and answer.json()["state"] == "cut"
    with app.state.session_factory() as db:
        assert db.get(Resource, "guest-hvac") is None
