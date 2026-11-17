"""A request is analysed, and the access rule may count that analysis.

The answer is stored as analysing and returned before the job decides. The job is a claim with a
two-minute takeover. The threat tier opens only when an analysis is present, says the block is not
justified, and the risk is low.
"""

import asyncio
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import signin
from fastapi.testclient import TestClient
from sqlalchemy import event, select
from test_access import settled
from test_tiers import BOTH, engine_for, postgres_database

from nyctr import access, assistant, block_analysis
from nyctr.collection import begin_holder, holder_id, previous_holder
from nyctr.config import Settings
from nyctr.database import migrate, session_factory
from nyctr.main import create_app
from nyctr.models import AccessRequest, Analysis, Audit, Lease, Notice, Observation, User, utcnow
from nyctr.security import hash_password

ROOT = Path(__file__).resolve().parents[3]
# How long the second writer is given before the test asks whether it is still waiting, as the
# sign-in tests do. SQLite gives up on a lock after five seconds, so that bound stays inside it.
WAIT = {"sqlite": 0.5, "postgresql": 5.0}
COPY = ("integration_id", "device_id", "device_name", "domain", "source", "reason", "reason_codes",
        "observed_at", "expires_at", "evidence_kind", "attribution", "risk_score", "risk_explanation")
LEAD = "Nyctr checked this site: "
WAITS = "The analysis of this address does not support opening it, so a person decides."
SAFETY = "This was blocked for safety or by an administrator's rule, so a person decides."
# Present only for ok plus a decided verdict. The one opening is not_justified and low.
CASES = [
    ("missing", None, None, False), ("failed", None, None, False), ("invalid", None, None, False),
    ("timed_out", None, None, False), ("cannot_tell", "cannot_tell", None, False),
    ("ok", "cannot_tell", None, False), ("ok", "justified", "low", False),
    ("ok", "justified", "medium", False), ("ok", "justified", "high", False),
    ("ok", "justified", "unknown", False), ("ok", "not_justified", "medium", False),
    ("ok", "not_justified", "high", False), ("ok", "not_justified", "unknown", False),
    ("ok", "not_justified", "low", True),
]
SENTENCES = (
    "A risk score alone never opens access.",
    "A model's Analysis may be one condition of the Administrator's Access rule, in the tiers the "
    "Administrator switched on; by itself it opens nothing.",
    "No model output edits a rule, cuts a device off, lengthens or widens access, or opens a deliberate Block.",
)


def facts():
    """A registration old enough for the threat tier, and nothing the member is shown raw."""
    registered = (utcnow() - timedelta(days=400)).isoformat()
    return {"facts": [{"kind": "registration", "state": "known", "value": {"registered": registered},
                       "secret": "not for the member"}]}


def rule_body(**changes):
    """Advertising on, threats off, unless a test says otherwise. Threat minutes stay within advertising."""
    body = {"enabled": True, "per_day": 20, "daily_total": 100,
            "ad_tracker": {"mode": "on", "max_score": 25, "max_minutes": 60, "analysis_required": False},
            "threat_feed": {"mode": "off", "max_minutes": 30, "min_registered_days": 180}}
    for name, values in changes.items():
        body[name] = {**body[name], **values}
    return body


def database_url(database, tmp_path, request):
    """This case's database. PostgreSQL is skipped until a server is named, as the other two-engine tests do."""
    if database == "sqlite":
        return f"sqlite:///{tmp_path}/once.db"
    url = postgres_database(request)
    if not url:
        pytest.skip("No PostgreSQL server is named in NYCTR_TEST_POSTGRES")
    return url


def demo(tmp_path, url=None):
    """A demonstration with the upkeep tick left off, so only the request's own job analyses it."""
    return create_app(Settings(mode="demo", database_url=url or f"sqlite:///{tmp_path}/demo.db",
                               public_url="http://testserver", cookie_secure=False, worker_enabled=False))


def plant(db, block_id, **changes):
    """A fresh copy of the gallery block, assigned to the member, with whatever a test changes."""
    one = db.get(Observation, "block-gallery")
    values = {name: getattr(one, name) for name in COPY}
    values.update(changes)
    db.add(Observation(id=block_id, **values))


def store_analysis(db, domain, block_id, state, verdict, risk):
    """The analysis the stand-in stores. The request's job reads it back from its id."""
    row = Analysis(domain=domain[:253], block_id=block_id, facts=facts(), model_state=state, verdict=verdict,
                   risk=risk, reasons=[{"text": "The feed is broader than this site."}],
                   uncertainty="The registry date is several years old.", prompt_version="t", duration_ms=1)
    db.add(row)
    db.commit()
    return row


def one_notice(db, request_id, *, opened):
    """The one notice stored for this request. An opening and a wait use the same kind."""
    found = db.scalars(select(Notice).where(Notice.subject == request_id)).all()
    assert len(found) == 1 and found[0].kind == "request_waiting"
    title = found[0].payload["title"]
    if opened:
        assert title.startswith("Nyctr opened ")
    else:
        assert "is waiting on " in title
    return found[0]


@BOTH
def test_a_request_is_answered_while_it_is_analysing_and_a_restart_finishes_it_once(
        tmp_path, database, request, monkeypatch):
    """The answer is analysing, with no score yet, while the job is still in the check. A tick leaves a fresh
    claim alone. A start leaves another holder's fresh claim alone. A claim older than two minutes is finished."""
    url = database_url(database, tmp_path, request)
    release, calls, mode = threading.Event(), [], {"wait": True}

    async def analyse(db, domain, block_id=None, *, settings):
        calls.append(block_id)
        if mode["wait"]:
            await asyncio.to_thread(release.wait)
        return store_analysis(db, domain, block_id, "missing", None, None)

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    app = demo(tmp_path, url)
    try:
        with TestClient(app) as client:
            admin = signin(client)
            assert client.put("/api/rules/access", headers=admin, json=rule_body()).status_code == 200
            member = signin(client, member=True)
            box = {}

            def post():
                try:
                    box["response"] = client.post(
                        "/api/requests", headers=member,
                        json={"block_id": "block-gallery", "reason": "Need the gallery", "duration_minutes": 60})
                except Exception as error:  # the thread would hide it; the join below raises it
                    box["error"] = error

            poster = threading.Thread(target=post)
            poster.start()
            found = None
            deadline = time.monotonic() + 30
            try:
                while time.monotonic() < deadline and found is None:
                    with app.state.session_factory() as db:
                        row = db.scalar(select(AccessRequest).where(AccessRequest.block_id == "block-gallery"))
                        if row is not None and row.status == "analysing" and row.analysis_id is None:
                            assert poster.is_alive()
                            found = row.id
                    if found is None:
                        time.sleep(0.01)
                assert found
            finally:
                release.set()
                poster.join(30)
            assert not poster.is_alive()
            if "error" in box:
                raise box["error"]
            body = box["response"].json()
            assert body["status"] == "analysing" and body["risk_score"] is None and body["duration_minutes"] == 60
            stored = settled(client, member, box["response"])
            assert stored["status"] == "auto_approved" and stored["risk_score"] == 16 and calls == ["block-gallery"]
            asyncio.run(access.finish_due(app.state.session_factory, app.state.settings))
            assert calls == ["block-gallery"]

            mode["wait"] = False
            holder = holder_id(app.state.engine)
            with app.state.session_factory() as db:
                plant(db, "block-held")
                db.add(AccessRequest(id="still-checking", block_id="block-held", domain="shop.example",
                                     device_name="Jamie's MacBook", requester_id="user-jamie", reason="Need it",
                                     duration_minutes=30, status="analysing", analysis_holder=holder,
                                     analysis_claimed_at=utcnow()))
                db.commit()
            admin = signin(client)
            refused = client.post("/api/requests/still-checking/review", headers=admin,
                                 json={"decision": "approved", "note": "Now"})
            assert refused.status_code == 409 and refused.json()["detail"] == "Nyctr is still checking this request."

            def leave(request_id, block_id, **fields):
                with app.state.session_factory() as db:
                    plant(db, block_id)
                    db.add(AccessRequest(id=request_id, block_id=block_id, domain="shop.example",
                                         device_name="Jamie's MacBook", requester_id="user-jamie", reason="Need it",
                                         duration_minutes=30, status="analysing", **fields))
                    db.commit()

            def finish(**kwargs):
                asyncio.run(access.finish_due(app.state.session_factory, app.state.settings, **kwargs))

            def still(request_id):
                with app.state.session_factory() as db:
                    return db.get(AccessRequest, request_id).status

            leave("fresh", "block-fresh", analysis_holder=holder, analysis_claimed_at=utcnow())
            finish()
            assert calls == ["block-gallery"] and still("fresh") == "analysing"
            leave("young", "block-young", analysis_holder="previous",
                  analysis_claimed_at=utcnow() - timedelta(seconds=30))
            finish()
            assert calls == ["block-gallery"] and still("young") == "analysing"
            leave("after-start", "block-after", analysis_holder="previous", analysis_claimed_at=utcnow())
            finish(restart_of=holder, previous=None)
            assert calls == ["block-gallery"] and still("after-start") == "analysing"
            leave("stale", "block-stale", analysis_holder="previous",
                  analysis_claimed_at=utcnow() - timedelta(minutes=3))
            finish()
            assert calls == ["block-gallery", "block-stale"] and still("stale") == "auto_approved"
            leave("restarted", "block-restarted", analysis_holder="previous",
                  analysis_claimed_at=utcnow() - timedelta(seconds=30))
            finish(restart_of=holder, previous=None)
            assert "block-restarted" not in calls and still("restarted") == "analysing"
            with app.state.session_factory() as db:
                kept = store_analysis(db, "shop.example", "block-kept", "missing", None, None)
            leave("kept", "block-kept", analysis_holder="previous", analysis_id=kept.id,
                  analysis_claimed_at=utcnow() - timedelta(minutes=3))
            before = len(calls)
            finish()
            assert len(calls) == before and still("kept") != "analysing"
            assert still("still-checking") == "analysing" and still("fresh") == "analysing"
    finally:
        app.state.engine.dispose()


class Second:
    """Starts the other writer on the first update of a request, and records whether that writer is still waiting."""

    def __init__(self, engine, database):
        self.wait, self.second, self.entered = WAIT[database], None, None
        self.waiting, self.threads, self.armed = [], [], False
        event.listen(engine, "after_cursor_execute", self.watch)

    def watch(self, _conn, _cursor, statement, _parameters, _context, _executemany):
        text = statement.lower()
        if not self.armed or "access_requests" not in text or not text.lstrip().startswith("update"):
            return
        self.armed = False
        thread = threading.Thread(target=self.second)
        self.threads.append(thread)
        thread.start()
        assert self.entered.wait(30)
        thread.join(self.wait)
        self.waiting.append(thread.is_alive())

    def arm(self, second):
        self.second, self.entered, self.armed = second, threading.Event(), True

    def close(self, engine):
        event.remove(engine, "after_cursor_execute", self.watch)
        for thread in self.threads:
            thread.join(30)
        assert not any(thread.is_alive() for thread in self.threads)


@BOTH
def test_a_second_writer_is_stopped_at_the_claim_the_analysis_and_the_decision(tmp_path, database, request):
    """Each check locks the request, re-reads it, and writes only when it still holds the claim."""
    engine = engine_for(database, tmp_path, request)

    def limits(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        if engine.dialect.name == "postgresql":
            cursor.execute("SET lock_timeout = '20s'")
        else:
            cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    event.listen(engine, "connect", limits)
    migrate(engine)
    factory, gate, results = session_factory(engine), Second(engine, database), {}
    try:
        with factory() as db:
            db.add(User(id="sam", email="sam@example.net", name="Sam"))
            db.commit()
            for request_id in ("req-claim", "req-keep", "req-decide"):
                db.add(AccessRequest(id=request_id, block_id=request_id, domain="shop.example",
                                     device_name="Laptop", requester_id="sam", reason="Need it",
                                     duration_minutes=30, status="analysing"))
            db.commit()
            for request_id in ("req-keep", "req-decide"):
                row = db.get(AccessRequest, request_id)
                row.analysis_holder, row.analysis_claimed_at = "one", utcnow()
            db.commit()

        def other(name, call):
            def run():
                gate.entered.set()
                with factory() as db:
                    results[name] = call(db)
                    if results[name]:
                        db.commit()
            gate.arm(run)

        other("claim", lambda db: access.claim_analysis(db, "req-claim", "two"))
        with factory() as db:
            assert access.claim_analysis(db, "req-claim", "one") is True
            assert gate.waiting == [True]
            db.commit()
        gate.threads[-1].join(30)
        assert results["claim"] is False
        with factory() as db:
            assert db.get(AccessRequest, "req-claim").analysis_holder == "one"

        other("keep", lambda db: access.keep_analysis(db, "req-keep", "two", "analysis-two"))
        with factory() as db:
            assert access.keep_analysis(db, "req-keep", "one", "analysis-one") is True
            assert gate.waiting == [True, True]
            db.commit()
        gate.threads[-1].join(30)
        assert results["keep"] is False
        with factory() as db:
            assert db.get(AccessRequest, "req-keep").analysis_id == "analysis-one"

        other("decide", lambda db: access.keep_decision(
            db, "req-decide", "two", status="auto_approved", decision_note="second"))
        with factory() as db:
            assert access.keep_decision(db, "req-decide", "one", status="pending", decision_note="first") is True
            assert gate.waiting == [True, True, True]
            db.commit()
        gate.threads[-1].join(30)
        assert results["decide"] is False
        with factory() as db:
            row = db.get(AccessRequest, "req-decide")
            assert (row.status, row.decision_note, row.analysis_holder) == ("pending", "first", None)
    finally:
        gate.close(engine)
        engine.dispose()


def test_the_member_reads_one_sentence_and_not_the_facts():
    """Every stored state has one sentence. The facts never appear in it."""
    raw = facts()

    def made(**kwargs):
        return Analysis(domain="shop.example", facts=raw, reasons=[], prompt_version="t", duration_ms=1, **kwargs)

    expected = {
        ("missing", None, None): "no model is connected, so there is no verdict.",
        ("failed", None, None): "the check did not finish.",
        ("invalid", None, None): "the check's answer could not be used.",
        ("timed_out", None, None): "the check took too long.",
        ("cannot_tell", "cannot_tell", None): "the check could not say either way.",
        ("ok", "justified", "low"): "the block looks justified.",
        ("ok", "not_justified", "medium"): "the block does not look justified.",
        ("ok", "not_justified", "low"): "the block does not look justified, and the risk looks low.",
    }
    assert access.plain_check(None) == LEAD + expected[("missing", None, None)]
    for (state, verdict, risk), sentence in expected.items():
        words = access.plain_check(made(model_state=state, verdict=verdict, risk=risk))
        assert words == LEAD + sentence and "not for the member" not in words and "registration" not in words


def test_the_threat_tier_opens_only_when_the_check_vouches_and_the_member_reads_the_sentence(
        tmp_path, monkeypatch):
    """On, with the other conditions met: only a present, not justified, low analysis opens. Anything else waits,
    and the note says so. The member reads the sentence; another member reads nothing; an administrator reads it all."""
    spec = {}

    async def analyse(db, domain, block_id=None, *, settings):
        state, verdict, risk = spec["case"]
        return store_analysis(db, domain, block_id, state, verdict, risk)

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    app = demo(tmp_path)
    try:
        with TestClient(app) as client:
            admin = signin(client)
            assert client.put("/api/rules/access", headers=admin, json=rule_body(
                threat_feed={"mode": "on"})).status_code == 200
            with app.state.session_factory() as db:
                db.add(User(id="user-alex", email="alex@nyctr.demo", name="Alex", role="member",
                            password_hash=hash_password("nyctr-demo")))
                for number, _case in enumerate(CASES):
                    plant(db, f"block-t{number}", domain="shop.example", reason="ai-threat-detection",
                          reason_codes=["ai-threat-detection"], risk_score=None, risk_explanation="")
                db.commit()
            member = signin(client, member=True)
            member_cookies = dict(client.cookies)
            opened = None
            waited = []
            for number, case in enumerate(CASES):
                spec["case"] = case[:3]
                response = client.post("/api/requests", headers=member, json={
                    "block_id": f"block-t{number}", "reason": "Need the site", "duration_minutes": 60})
                assert response.status_code == 201 and response.json()["status"] == "analysing"
                row = settled(client, member, response)
                if case[3]:
                    assert row["status"] == "auto_approved" and row["duration_minutes"] == 30
                    assert row["check"] == LEAD + "the block does not look justified, and the risk looks low."
                    assert "analysis" not in row and "not for the member" not in str(row)
                    opened = row
                else:
                    assert row["status"] == "pending" and row["decision_note"] == WAITS
                    assert row["decided_by"] is None
                    waited.append(row["id"])
            assert opened and len(waited) == len(CASES) - 1
            with app.state.session_factory() as db:
                one_notice(db, opened["id"], opened=True)
                for request_id in waited:
                    one_notice(db, request_id, opened=False)
            client.cookies.clear()
            admin = signin(client)
            full = next(row for row in client.get("/api/requests").json() if row["id"] == opened["id"])
            assert full["analysis"]["verdict"] == "not_justified" and full["analysis"]["risk"] == "low"
            assert full["analysis"]["facts"]["facts"][0]["kind"] == "registration"
            assert full["analysis"]["reasons"][0]["text"] and full["analysis"]["uncertainty"]
            assert "check" not in full
            attention = [item for item in client.get("/api/attention").json() if item.get("action") == "end"
                         and "shop.example" in item["title"]]
            assert len(attention) == 1 and attention[0]["detail"] == opened["check"]
            lease_id = attention[0]["id"]
            assert client.post(f"/api/leases/{lease_id}/end", headers=admin).status_code == 200
            assert next(row["status"] for row in client.get("/api/leases").json() if row["id"] == lease_id) == "ended"
            client.cookies.clear()
            client.cookies.update(member_cookies)
            again = next(row for row in client.get("/api/requests").json() if row["id"] == opened["id"])
            assert again["check"] == opened["check"] and "analysis" not in again
            client.cookies.clear()
            alex = client.post("/api/auth/login", json={"email": "alex@nyctr.demo", "password": "nyctr-demo"})
            assert alex.status_code == 200
            listed = client.get("/api/requests").json()
            assert opened["id"] not in [row["id"] for row in listed] and "shop.example" not in str(listed)
    finally:
        app.state.engine.dispose()


def test_shadow_records_what_would_have_opened_and_opens_nothing(tmp_path, monkeypatch):
    """The check runs. The record says the rule would have opened it. Nothing is opened."""
    async def analyse(db, domain, block_id=None, *, settings):
        return store_analysis(db, domain, block_id, "ok", "not_justified", "low")

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    app = demo(tmp_path)
    try:
        with TestClient(app) as client:
            admin = signin(client)
            assert client.put("/api/rules/access", headers=admin, json=rule_body(
                threat_feed={"mode": "shadow"})).status_code == 200
            with app.state.session_factory() as db:
                plant(db, "block-shadow", domain="shop.example", reason="ai-threat-detection",
                      reason_codes=["ai-threat-detection"], risk_score=None, risk_explanation="")
                db.commit()
            member = signin(client, member=True)
            row = settled(client, member, client.post("/api/requests", headers=member, json={
                "block_id": "block-shadow", "reason": "Need the site", "duration_minutes": 60}))
            assert row["status"] == "pending" and row["decided_by"] is None
            assert row["decision_note"] == ("The access rule would have opened this for 30 minutes. "
                                            "It is set to record only, so a person decides.")
            with app.state.session_factory() as db:
                assert db.scalar(select(Lease.id).where(Lease.request_id == row["id"])) is None
                event_row = db.scalar(select(Audit).where(Audit.action == "rule.access_checked",
                                                          Audit.target_id == row["id"]))
                assert event_row.details["outcome"] == "would_open" and event_row.details["minutes"] == 30
                one_notice(db, row["id"], opened=False)
    finally:
        app.state.engine.dispose()


def test_a_block_that_is_never_automatic_stays_closed_whatever_the_check_says(tmp_path, monkeypatch):
    """A category is a deliberate block. A vouched analysis is stored and opens nothing."""
    async def analyse(db, domain, block_id=None, *, settings):
        return store_analysis(db, domain, block_id, "ok", "not_justified", "low")

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    app = demo(tmp_path)
    try:
        with TestClient(app) as client:
            admin = signin(client)
            assert client.put("/api/rules/access", headers=admin, json=rule_body(
                threat_feed={"mode": "on"})).status_code == 200
            with app.state.session_factory() as db:
                plant(db, "block-never", domain="shop.example", reason="parental control",
                      reason_codes=["parental"], risk_score=None, risk_explanation="")
                db.commit()
            member = signin(client, member=True)
            row = settled(client, member, client.post("/api/requests", headers=member, json={
                "block_id": "block-never", "reason": "Need the site", "duration_minutes": 60}))
            assert row["status"] == "pending" and row["decision_note"] == SAFETY
            # The analysis is on the administrator's copy. The member is not given its facts.
            assert "analysis" not in row and row["check"].startswith(LEAD)
            client.cookies.clear()
            signin(client)
            full = client.get("/api/requests").json()
            admin_row = next(item for item in full if item["id"] == row["id"])
            assert admin_row["analysis"]["verdict"] == "not_justified"
            with app.state.session_factory() as db:
                assert db.scalar(select(Lease.id).where(Lease.request_id == row["id"])) is None
    finally:
        app.state.engine.dispose()


def test_advertising_counts_an_analysis_only_when_the_administrator_requires_one(tmp_path, monkeypatch):
    """Required: the same vouch as a threat feed. Not required: a vouch is not needed, and a justified block stops."""
    spec = {}

    async def analyse(db, domain, block_id=None, *, settings):
        return store_analysis(db, domain, block_id, *spec["case"])

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    app = demo(tmp_path)
    try:
        with TestClient(app) as client:
            admin = signin(client)
            with app.state.session_factory() as db:
                plant(db, "block-stop", domain="fonts.partner-metrics.example")
                plant(db, "block-need", domain="cdn.example")
                plant(db, "block-vouched", domain="img.example")
                db.commit()
            cases = [
                ("block-gallery", False, ("missing", None, None), "auto_approved"),
                ("block-stop", False, ("ok", "justified", "low"), "pending"),
                ("block-need", True, ("missing", None, None), "pending"),
                ("block-vouched", True, ("ok", "not_justified", "low"), "auto_approved"),
            ]
            for block_id, required, case, status in cases:
                assert client.put("/api/rules/access", headers=admin, json=rule_body(
                    ad_tracker={"analysis_required": required})).status_code == 200
                spec["case"] = case
                client.cookies.clear()
                member = signin(client, member=True)
                row = settled(client, member, client.post("/api/requests", headers=member, json={
                    "block_id": block_id, "reason": "Need the pictures", "duration_minutes": 60}))
                assert row["status"] == status
                if status == "pending":
                    assert row["decision_note"] == WAITS
                client.cookies.clear()
                admin = signin(client)
    finally:
        app.state.engine.dispose()


def test_no_model_stores_the_facts_and_marks_the_verdict_missing(tmp_path):
    """The check still runs. With no model connected its verdict is missing, which the rule treats as absent."""
    app = create_app(Settings(mode="live", database_url=f"sqlite:///{tmp_path}/live.db",
                              public_url="http://testserver", cookie_secure=False, worker_enabled=False,
                              bootstrap_admin_email="owner@example.net",
                              bootstrap_admin_password="secure password for tests"))
    with TestClient(app):
        async def once():
            with app.state.session_factory() as db:
                return await block_analysis.analyse(db, "shop.example", "block-1", settings=app.state.settings)

        row = asyncio.run(once())
        assert row.model_state == "missing" and row.verdict is None and row.risk is None
        assert row.facts.get("facts") and block_analysis.analysis_input(row).present is False
    app.state.engine.dispose()


def test_the_guardrail_is_written_in_the_two_places_the_amendment_names():
    """The same three sentences, in the contributor notes and the security model."""
    for name in ("AGENTS.md", "docs/security-model.md"):
        collapsed = " ".join((ROOT / name).read_text().split())
        for sentence in SENTENCES:
            assert sentence in collapsed, name


GONE = "The blocked lookup behind this request is no longer current, so a person decides."


@BOTH
def test_a_lookup_removed_during_the_check_still_records_one_notice(
        tmp_path, database, request, monkeypatch):
    """A lookup removed while the check runs leaves the request waiting, with one notice in that decision.

    The request is accepted while the lookup is still there. Another session then deletes it and commits.
    A second finish does not record another notice.
    """
    url = database_url(database, tmp_path, request)

    async def analyse(db, domain, block_id=None, *, settings):
        with session_factory(db.get_bind())() as other:
            gone = other.get(Observation, block_id)
            assert gone is not None
            other.delete(gone)
            other.commit()
        return store_analysis(db, domain, block_id, "missing", None, None)

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    app = demo(tmp_path, url)
    try:
        with TestClient(app) as client:
            member = signin(client, member=True)
            response = client.post("/api/requests", headers=member, json={
                "block_id": "block-gallery", "reason": "Need the gallery", "duration_minutes": 60})
            assert response.status_code == 201 and response.json()["status"] == "analysing"
            request_id = response.json()["id"]
            with app.state.session_factory() as db:
                row = db.get(AccessRequest, request_id)
                assert row.status == "pending" and row.decision_note == GONE
                assert db.get(Observation, "block-gallery") is None
                one_notice(db, request_id, opened=False)
            asyncio.run(access.finish_one(
                app.state.session_factory, app.state.settings, request_id, holder_id(app.state.engine)))
            with app.state.session_factory() as db:
                assert len(db.scalars(select(Notice)).all()) == 1
                one_notice(db, request_id, opened=False)
    finally:
        app.state.engine.dispose()


@BOTH
def test_an_expired_lookup_during_the_check_still_records_one_notice(
        tmp_path, database, request, monkeypatch):
    """A lookup that expires while the check runs is treated as missing: the request waits, with one notice."""
    url = database_url(database, tmp_path, request)

    async def analyse(db, domain, block_id=None, *, settings):
        with session_factory(db.get_bind())() as other:
            row = other.get(Observation, block_id)
            assert row is not None
            row.expires_at = utcnow() - timedelta(seconds=1)
            other.commit()
        return store_analysis(db, domain, block_id, "missing", None, None)

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    app = demo(tmp_path, url)
    try:
        with TestClient(app) as client:
            member = signin(client, member=True)
            response = client.post("/api/requests", headers=member, json={
                "block_id": "block-gallery", "reason": "Need the gallery", "duration_minutes": 60})
            assert response.status_code == 201 and response.json()["status"] == "analysing"
            request_id = response.json()["id"]
            with app.state.session_factory() as db:
                row = db.get(AccessRequest, request_id)
                assert row.status == "pending" and row.decision_note == GONE
                assert db.get(Observation, "block-gallery") is not None
                one_notice(db, request_id, opened=False)
            asyncio.run(access.finish_one(
                app.state.session_factory, app.state.settings, request_id, holder_id(app.state.engine)))
            with app.state.session_factory() as db:
                assert len(db.scalars(select(Notice)).all()) == 1
                one_notice(db, request_id, opened=False)
    finally:
        app.state.engine.dispose()


@BOTH
def test_a_fresh_claim_held_by_someone_else_survives_a_second_start(
        tmp_path, database, request, monkeypatch):
    """A claim a few seconds old, held by someone else, stays theirs when this process starts again.

    A claim held by this process's own previous start is finished. A tick still leaves a fresh claim alone.
    """
    url = database_url(database, tmp_path, request)
    calls = []

    async def analyse(db, domain, block_id=None, *, settings):
        calls.append(block_id)
        return store_analysis(db, domain, block_id, "missing", None, None)

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    app = demo(tmp_path, url)
    try:
        with TestClient(app) as client:
            signin(client)
            factory = app.state.session_factory

            def leave(request_id, block_id, **fields):
                with factory() as db:
                    plant(db, block_id)
                    db.add(AccessRequest(id=request_id, block_id=block_id, domain="shop.example",
                                         device_name="Jamie's MacBook", requester_id="user-jamie", reason="Need it",
                                         duration_minutes=30, status="analysing", **fields))
                    db.commit()

            def row(request_id):
                with factory() as db:
                    return db.get(AccessRequest, request_id)

            holder = holder_id(app.state.engine)
            claimed = utcnow() - timedelta(seconds=5)
            leave("theirs", "block-theirs", analysis_holder="someone-else", analysis_claimed_at=claimed)
            asyncio.run(access.finish_due(
                factory, app.state.settings, restart_of=holder, previous=previous_holder(app.state.engine)))
            kept = row("theirs")
            assert kept.status == "analysing" and kept.analysis_holder == "someone-else"
            assert calls == []

            old = holder
            new = begin_holder(app.state.engine)
            assert previous_holder(app.state.engine) == old and new != old
            leave("own", "block-own", analysis_holder=old, analysis_claimed_at=utcnow() - timedelta(seconds=5))
            asyncio.run(access.finish_due(
                factory, app.state.settings, restart_of=new, previous=previous_holder(app.state.engine)))
            kept = row("theirs")
            assert kept.status == "analysing" and kept.analysis_holder == "someone-else"
            own = row("own")
            assert own.status == "auto_approved" and own.analysis_holder is None
            assert calls == ["block-own"]
    finally:
        app.state.engine.dispose()


def test_a_failed_startup_recovery_still_serves(tmp_path, monkeypatch):
    """A failure while finishing leftover checks does not stop the API from serving."""

    async def boom(*_args, **_kwargs):
        raise RuntimeError("recovery")

    monkeypatch.setattr(access, "finish_due", boom)
    app = demo(tmp_path)
    try:
        with TestClient(app) as client:
            assert client.get("/api/health").status_code == 200
            assert client.get("/api/health").json()["status"] == "ok"
    finally:
        app.state.engine.dispose()


def test_startup_recovery_finishes_a_request_left_analysing(tmp_path, monkeypatch):
    """A request left being checked is finished by the background recovery, after the API is serving."""

    async def analyse(db, domain, block_id=None, *, settings):
        return store_analysis(db, domain, block_id, "missing", None, None)

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    planted = {"done": False}

    def plant_left(db, **kwargs):
        from nyctr.collection import release_abandoned
        release_abandoned(db, **kwargs)
        if planted["done"]:
            return
        planted["done"] = True
        db.add(AccessRequest(id="left-behind", block_id="block-gallery", domain="shop.example",
                             device_name="Jamie's MacBook", requester_id="user-jamie", reason="Need it",
                             duration_minutes=30, status="analysing"))

    monkeypatch.setattr("nyctr.main.release_abandoned", plant_left)
    app = demo(tmp_path)
    try:
        with TestClient(app) as client:
            status = "missing"
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                assert client.get("/api/health").status_code == 200
                with app.state.session_factory() as db:
                    row = db.get(AccessRequest, "left-behind")
                    status = row.status if row is not None else "missing"
                if status != "analysing":
                    break
                time.sleep(0.02)
            assert status == "auto_approved"
    finally:
        app.state.engine.dispose()


def test_two_checks_are_not_both_inside_the_model_call_when_the_limit_is_one(tmp_path, monkeypatch):
    """Automatic checks share the explicit analysis endpoint's in-flight limit."""
    monkeypatch.setattr(assistant, "MODEL_CALLS", 1)
    monkeypatch.setattr(assistant, "_room", None)
    monkeypatch.setattr(assistant, "_room_bound", 0)
    flying = {"n": 0, "peak": 0}
    entered, release = asyncio.Event(), asyncio.Event()
    # The start finishes its own recovery before this test plants the two checks, so that recovery
    # does not take the in-flight limit on the server's loop.
    startup = threading.Event()
    real_finish = access.finish_due

    async def finish_due(*args, **kwargs):
        try:
            await real_finish(*args, **kwargs)
        finally:
            startup.set()

    monkeypatch.setattr(access, "finish_due", finish_due)

    async def analyse(db, domain, block_id=None, *, settings):
        flying["n"] += 1
        flying["peak"] = max(flying["peak"], flying["n"])
        if not entered.is_set():
            entered.set()
            await release.wait()
        flying["n"] -= 1
        return store_analysis(db, domain, block_id, "missing", None, None)

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    app = demo(tmp_path)
    try:
        with TestClient(app) as client:
            assert startup.wait(10)
            signin(client)
            factory = app.state.session_factory
            with factory() as db:
                for block_id in ("block-one", "block-two"):
                    plant(db, block_id)
                    db.add(AccessRequest(id=block_id, block_id=block_id, domain="shop.example",
                                         device_name="Jamie's MacBook", requester_id="user-jamie", reason="Need it",
                                         duration_minutes=30, status="analysing"))
                db.commit()
            holder = holder_id(app.state.engine)

            async def both():
                first = asyncio.create_task(access.finish_one(factory, app.state.settings, "block-one", holder))
                await entered.wait()
                second = asyncio.create_task(access.finish_one(factory, app.state.settings, "block-two", holder))
                _done, pending = await asyncio.wait([second], timeout=1)
                assert second in pending and flying["n"] == 1 and flying["peak"] == 1
                release.set()
                await first
                await second

            asyncio.run(both())
            assert flying["peak"] == 1
            with factory() as db:
                assert db.get(AccessRequest, "block-one").status != "analysing"
                assert db.get(AccessRequest, "block-two").status != "analysing"
    finally:
        app.state.engine.dispose()


def test_one_failed_completion_does_not_stop_the_next_request(tmp_path, monkeypatch):
    """A request whose check raises leaves the later request in that pass to finish."""
    real = access.finish_one

    async def finish_one(factory, settings, request_id, holder, **kwargs):
        if request_id == "block-one":
            raise RuntimeError("one")
        await real(factory, settings, request_id, holder, **kwargs)

    monkeypatch.setattr(access, "finish_one", finish_one)

    async def analyse(db, domain, block_id=None, *, settings):
        return store_analysis(db, domain, block_id, "missing", None, None)

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    app = demo(tmp_path)
    try:
        with TestClient(app) as client:
            signin(client)
            factory = app.state.session_factory
            with factory() as db:
                for block_id in ("block-one", "block-two"):
                    plant(db, block_id)
                    db.add(AccessRequest(id=block_id, block_id=block_id, domain="shop.example",
                                         device_name="Jamie's MacBook", requester_id="user-jamie", reason="Need it",
                                         duration_minutes=30, status="analysing"))
                db.commit()
            asyncio.run(access.finish_due(factory, app.state.settings))
            with factory() as db:
                failed = db.get(AccessRequest, "block-one")
                done = db.get(AccessRequest, "block-two")
            assert failed.status == "analysing" and failed.analysis_holder is None
            assert done.status == "auto_approved"
    finally:
        app.state.engine.dispose()


def held_clock(monkeypatch):
    """A frozen clock, and a gate on any recovery wait that is longer than the short retry.

    The clock starts at the real time, so a seeded opening keeps its age. A clock set in the past
    would count every seeded opening as today's. The first long wait parks until `release` is set.
    Moving the clock does not end the wait.
    """
    clock = {"now": datetime.now(UTC)}
    release, parked = threading.Event(), threading.Event()

    def now():
        return clock["now"]

    async def until(delay, _wake):
        if delay > access.RECOVERY_RETRY and not release.is_set():
            parked.set()
            await asyncio.to_thread(release.wait)

    monkeypatch.setattr(access, "utcnow", now)
    monkeypatch.setattr("nyctr.models.utcnow", now)
    monkeypatch.setattr("nyctr.main._until", until)
    monkeypatch.setattr(access, "ANALYSIS_HOLD", timedelta(seconds=30))
    return clock, release, parked


def counting_passes(monkeypatch):
    """Count each recovery pass, including one that raises."""
    passes = {"n": 0}
    real_finish = access.finish_due

    async def finish_due(*args, **kwargs):
        try:
            await real_finish(*args, **kwargs)
        finally:
            passes["n"] += 1

    monkeypatch.setattr(access, "finish_due", finish_due)
    return passes


@BOTH
def test_a_fresh_claim_is_finished_after_its_hold_when_upkeep_is_off(
        tmp_path, database, request, monkeypatch):
    """With the upkeep tick off, a fresh claim is left alone and finished once its hold ends.

    A request with no claim is finished on the first pass. The clock stays still until the test
    has read that pass, then moves past the hold. The API is serving the whole time.
    """
    url = database_url(database, tmp_path, request)
    clock, release, parked = held_clock(monkeypatch)
    calls = []

    async def analyse(db, domain, block_id=None, *, settings):
        calls.append(block_id)
        return store_analysis(db, domain, block_id, "missing", None, None)

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    passes = counting_passes(monkeypatch)
    planted = {"done": False}

    def plant_left(db, **kwargs):
        from nyctr.collection import release_abandoned
        release_abandoned(db, **kwargs)
        if planted["done"]:
            return
        planted["done"] = True
        plant(db, "block-free")
        plant(db, "block-theirs")
        db.add(AccessRequest(id="free", block_id="block-free", domain="shop.example",
                             device_name="Jamie's MacBook", requester_id="user-jamie", reason="Need it",
                             duration_minutes=30, status="analysing"))
        db.add(AccessRequest(id="theirs", block_id="block-theirs", domain="shop.example",
                             device_name="Jamie's MacBook", requester_id="user-jamie", reason="Need it",
                             duration_minutes=30, status="analysing", analysis_holder="someone-else",
                             analysis_claimed_at=clock["now"]))

    monkeypatch.setattr("nyctr.main.release_abandoned", plant_left)
    app = demo(tmp_path, url)
    try:
        with TestClient(app) as client:
            try:
                assert parked.wait(5)
                assert passes["n"] == 1 and calls == ["block-free"]
                with app.state.session_factory() as db:
                    free = db.get(AccessRequest, "free")
                    kept = db.get(AccessRequest, "theirs")
                assert free.status == "auto_approved"
                assert kept.status == "analysing" and kept.analysis_holder == "someone-else"
                assert client.get("/api/health").json()["status"] == "ok"
                clock["now"] += timedelta(seconds=31)
                release.set()
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and passes["n"] < 2:
                    time.sleep(0.02)
                assert passes["n"] >= 2 and calls == ["block-free", "block-theirs"]
                with app.state.session_factory() as db:
                    done = db.get(AccessRequest, "theirs")
                    status, holder = done.status, done.analysis_holder
                assert status == "auto_approved" and holder is None
            finally:
                release.set()  # A failed check must not leave recovery parked in the wait.
    finally:
        app.state.engine.dispose()


@BOTH
def test_a_job_that_fails_after_its_claim_is_finished_once_the_hold_ends(
        tmp_path, database, request, monkeypatch):
    """Nothing is waiting at startup, and the upkeep tick is off.

    A later job that raises after its claim stays claimed. Recovery does not take that claim, or a
    fresh claim of another holder, until the hold ends. It then finishes the failed job.
    """
    url = database_url(database, tmp_path, request)
    clock, release, parked = held_clock(monkeypatch)
    calls = []

    async def analyse(db, domain, block_id=None, *, settings):
        calls.append(block_id)
        if block_id == "block-gallery" and calls.count("block-gallery") == 1:
            raise RuntimeError("after the claim")
        return store_analysis(db, domain, block_id, "missing", None, None)

    monkeypatch.setattr(block_analysis, "analyse", analyse)
    passes = counting_passes(monkeypatch)
    real_delay = access.recovery_delay
    idle = threading.Event()

    def delay(factory, *, now=None):
        found = real_delay(factory, now=now)
        if found is None:
            idle.set()
        return found

    monkeypatch.setattr(access, "recovery_delay", delay)
    app = demo(tmp_path, url)
    try:
        with TestClient(app) as client:
            try:
                assert idle.wait(5)
                assert passes["n"] == 1 and calls == []
                assert client.get("/api/health").json()["status"] == "ok"
                with app.state.session_factory() as db:
                    plant(db, "block-theirs")
                    db.add(AccessRequest(id="theirs", block_id="block-theirs", domain="shop.example",
                                         device_name="Jamie's MacBook", requester_id="user-jamie", reason="Need it",
                                         duration_minutes=30, status="analysing", analysis_holder="someone-else",
                                         analysis_claimed_at=clock["now"]))
                    db.commit()
                admin = signin(client)
                assert client.put("/api/rules/access", headers=admin, json=rule_body()).status_code == 200
                member = signin(client, member=True)
                # The answer is stored first. The job then raises, and the test client reports that raise.
                with pytest.raises(RuntimeError, match="after the claim"):
                    client.post("/api/requests", headers=member, json={
                        "block_id": "block-gallery", "reason": "Need the gallery", "duration_minutes": 60})
                assert parked.wait(5)
                with app.state.session_factory() as db:
                    own = db.scalar(select(AccessRequest).where(AccessRequest.block_id == "block-gallery"))
                    kept = db.get(AccessRequest, "theirs")
                assert own.status == "analysing" and own.analysis_holder
                assert kept.status == "analysing" and kept.analysis_holder == "someone-else"
                assert calls == ["block-gallery"]
                clock["now"] += timedelta(seconds=31)
                release.set()
                own_status, kept_status, kept_holder = "analysing", "analysing", "someone-else"
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    with app.state.session_factory() as db:
                        own = db.scalar(select(AccessRequest).where(AccessRequest.block_id == "block-gallery"))
                        kept = db.get(AccessRequest, "theirs")
                        own_status, kept_status, kept_holder = own.status, kept.status, kept.analysis_holder
                    if own_status != "analysing" and kept_status != "analysing":
                        break
                    time.sleep(0.02)
                assert own_status == "auto_approved"
                assert kept_status == "auto_approved" and kept_holder is None
                assert calls.count("block-gallery") == 2 and "block-theirs" in calls
            finally:
                release.set()  # A failed check must not leave recovery parked in the wait.
    finally:
        app.state.engine.dispose()


def test_a_simulated_opening_is_not_described_as_opened_at_the_source(tmp_path):
    """The attention title uses the lease's execution, so a simulated opening is not called an opening."""
    from nyctr.assistant import attention
    app = demo(tmp_path)
    try:
        with TestClient(app):
            with app.state.session_factory() as db:
                db.add(Lease(domain="shop.example", status="active", execution="simulated", decided_by="rule",
                             owned=True))
                db.add(Lease(domain="applied.example", status="active", execution="applied", decided_by="rule",
                             owned=True))
                db.commit()
                titles = [item["title"] for item in attention(db, app.state.settings)
                          if item.get("action") == "end"]
        assert "Simulated: shop.example was not opened at the source" in titles
        assert "applied.example was opened by the access rule" in titles
        assert all("shop.example was opened" not in title for title in titles)
    finally:
        app.state.engine.dispose()
