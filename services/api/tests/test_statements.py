"""A member on a recognised device names a site that did not open.

These cases mount the statement routes on the app they build. The application
that serves requests does not include them.
"""

import asyncio
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager, contextmanager
from datetime import timedelta

import httpx
import pytest
from conftest import LIVE_MEMBER, live_app, live_signin, seed_live_member, signin
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from test_access import put_rule
from test_presence import KIM, LAPTOP, PHONE, PRINTER, TABLET, browser, change, home, two_sites
from test_tiers import postgres_database

from nyctr import access, presence, statements
from nyctr.access import STATEMENT_WAITING
from nyctr.collection import holder_id
from nyctr.config import Settings
from nyctr.deps import statement_current
from nyctr.integrations import core
from nyctr.main import create_app
from nyctr.models import (
    AccessRequest,
    Audit,
    DeviceGrant,
    DevicePresence,
    Integration,
    Lease,
    LoginAttempt,
    LoginSession,
    Notice,
    Observation,
    Resource,
    Setting,
    StatementQuota,
    User,
    utcnow,
)
from nyctr.presence import WHY
from nyctr.security import COOKIE_NAME
from nyctr.statements import CONSOLE, DUPLICATE, FILED, LIMITED, MISSED, NO_DEVICE

BOTH = pytest.mark.parametrize("database", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
PRIVACY = ["blocklist:hagezi-multi-pro-plusplus"]
# Long enough for the checks made while a provider call is paused, short enough that a missed release ends.
PAUSE_LIMIT = 30
ALLOWLIST = "/profiles/abc123/allowlist"
OFF = WHY["off"]
# Nothing a statement may repeat from someone else's lookup.
HIDDEN = ("Unknown source device", "downloads.filemirror.example", "Alex's workstation",
          "gallery.imagehost.example", "user-admin")


def mount_for_test(app):
    """Include the statement routes on this app only.

    The unknown-path route is already registered and matches first. These routes
    move ahead of it on this app, so a test reaches the module. The application
    that serves requests is left as it was built.
    """
    seen = {id(route) for route in app.router.routes}
    app.include_router(statements.router)
    added = [route for route in app.router.routes if id(route) not in seen]
    rest = [route for route in app.router.routes if id(route) in seen]
    index = next(i for i, route in enumerate(rest) if getattr(route, "path", None) == "/api/{path:path}")
    app.router.routes[:] = [*rest[:index], *added, *rest[index:]]
    return app


def open_demo(database, tmp_path, request, name, **overrides):
    """A demo API on this case's own database. PostgreSQL is skipped when no server is named."""
    if database == "sqlite":
        url = f"sqlite:///{tmp_path}/{name}.db"
    else:
        url = postgres_database(request)
        if not url:
            pytest.skip("No PostgreSQL server is named in NYCTR_TEST_POSTGRES")
    values = {"mode": "demo", "database_url": url, "public_url": "http://testserver",
              "cookie_secure": False, "worker_enabled": False}
    values.update(overrides)
    return mount_for_test(create_app(Settings(**values)))


def ask(client, headers, domain):
    """Post one statement. `headers` is None when nobody is signed in."""
    return client.post("/api/statements", headers=headers, json={"domain": domain})


def stated(app, outcome=None):
    """Statement audits, oldest first. `outcome` keeps one kind."""
    with app.state.session_factory() as db:
        rows = list(db.scalars(select(Audit).where(Audit.action == "access.statement")
                               .order_by(Audit.created_at, Audit.id)))
    return [row for row in rows if outcome is None or row.details.get("outcome") == outcome]


def filed_for(app, domain):
    """Stored requests for this domain."""
    with app.state.session_factory() as db:
        return list(db.scalars(select(AccessRequest).where(AccessRequest.domain == domain)))


def quota(app, user_id="user-jamie"):
    """How many attempts this member has used in the current hour, or None before the first."""
    with app.state.session_factory() as db:
        row = db.get(StatementQuota, user_id)
        return None if row is None else row.count


def clear_quota(app, user_id="user-jamie"):
    """Forget the hour, so a later case is not refused for attempts an earlier one already used."""
    with app.state.session_factory() as db:
        row = db.get(StatementQuota, user_id)
        if row is not None:
            db.delete(row)
            db.commit()


def recognition(app, enabled):
    """Switch device recognition on or off without changing how far a tie reaches."""
    with app.state.session_factory() as db:
        row = db.get(Setting, "device_recognition")
        row.value = {"enabled": enabled, "reach_back_hours": row.value.get("reach_back_hours", 2)}
        db.commit()


def add_block(app, id_, domain, *, device=None, name="Unknown source device", reason="HaGeZi Multi PRO++",
              codes=None, age=2, life=timedelta(hours=20), attribution=None):
    """Store one blocked lookup. No device means the source did not name one."""
    now = utcnow()
    when = now - timedelta(minutes=age)
    with app.state.session_factory() as db:
        db.add(Observation(
            id=id_, integration_id="demo-nextdns", device_id=device, device_name=name, domain=domain,
            source="nextdns", reason=reason, reason_codes=list(PRIVACY if codes is None else codes),
            observed_at=when, expires_at=when + life, evidence_kind="observed",
            attribution=attribution or ("assigned" if device else "unattributed"),
            risk_score=None, risk_explanation=""))
        db.commit()


def stored(client, headers, body):
    """The request after its check has finished. The answer itself is still analysing."""
    wanted = body["request"]["id"]
    listed = client.get("/api/requests", headers=headers).json()
    return next(row for row in listed if row["id"] == wanted)


def allow(client, enabled):
    """Turn the statement switch on or off and come back as the member."""
    admin = signin(client)
    rule = client.get("/api/rules", headers=admin).json()["access"]
    rule["allow_statement"] = enabled
    assert client.put("/api/rules/access", headers=admin, json=rule).status_code == 200
    return signin(client, member=True)


@BOTH
def test_a_statement_is_refused_in_plain_words_and_audited(tmp_path, database, request):
    """No session, a bad name, a stale or inexact name, the sixth attempt, recognition off, no device, the console."""
    app = open_demo(database, tmp_path, request, "refused")
    with TestClient(app) as client:
        stranger = ask(client, None, "secret.example")
        assert stranger.status_code == 401 and stranger.json() == {"detail": "Sign in to continue"}
        assert "secret.example" not in stranger.text
        assert filed_for(app, "secret.example") == [] and quota(app) is None
        unsigned = stated(app)
        assert len(unsigned) == 1 and unsigned[0].actor_id is None
        assert unsigned[0].details == {"domain": "secret.example", "device_id": "", "device_name": "",
                                        "outcome": "no_session"}
        headers = signin(client, member=True)
        bad = ask(client, headers, "https://10.1.1.1/secret")
        assert bad.status_code == 422 and "name" in bad.json()["detail"].lower()
        assert quota(app) is None
        add_block(app, "stmt-old", "old.stale.example", age=20)
        add_block(app, "stmt-parent", "images.cdn.example")
        add_block(app, "stmt-child", "pics.example")
        add_block(app, "stmt-gone", "gone.example", life=timedelta(minutes=-5))
        misses = [
            ("old.stale.example", "stale"),
            ("cdn.example", "not_exact"),
            ("www.pics.example", "not_exact"),
            ("gone.example", "stale"),
            ("hub.example", "miss"),
        ]
        for domain, outcome in misses:
            answer = ask(client, headers, domain)
            assert answer.status_code == 200, answer.text
            assert answer.json() == {"matched": False, "message": MISSED}
            assert outcome == stated(app)[-1].details["outcome"]
            assert "images.cdn.example" not in answer.text and "pics.example" not in answer.text
            assert "metrics.analytics-hub.example" not in answer.text
        sixth = ask(client, headers, "metrics.analytics-hub.example")
        assert sixth.status_code == 429 and sixth.json()["detail"] == LIMITED
        assert "blocked recently" not in sixth.text
        assert filed_for(app, "metrics.analytics-hub.example") == []
        assert quota(app) == 5
        outcomes = [row.details["outcome"] for row in stated(app)]
        assert outcomes == ["no_session", "not_a_name", "stale", "not_exact", "not_exact", "stale", "miss", "limited"]
        for row in stated(app):
            assert set(row.details) == {"domain", "device_id", "device_name", "outcome"}
            if row.details["outcome"] == "no_session":
                assert row.actor_id is None and row.details["device_id"] == ""
                continue
            assert row.details["device_id"] == "laptop-jamie"
            assert row.details["device_name"] == "Jamie's MacBook"
            assert row.actor_id == "user-jamie"
        recognition(app, False)
        off = ask(client, headers, "metrics.analytics-hub.example")
        assert off.status_code == 403 and off.json()["detail"] == OFF
        assert stated(app, "off")[-1].details["device_id"] == ""
        assert quota(app) == 5
        recognition(app, True)
        with app.state.session_factory() as db:
            db.query(DeviceGrant).filter(DeviceGrant.user_id == "user-jamie").delete()
            db.query(DevicePresence).filter(DevicePresence.user_id == "user-jamie").delete()
            db.commit()
        nowhere = ask(client, headers, "metrics.analytics-hub.example")
        assert nowhere.status_code == 403 and nowhere.json()["detail"] == NO_DEVICE
        assert quota(app) == 5
        assert filed_for(app, "metrics.analytics-hub.example") == []

    console, portal = "http://console.test", "http://portal.test"
    other = open_demo(database, tmp_path, request, "split", public_url=console, portal_url=portal)
    with TestClient(other, base_url=console) as on_console, TestClient(other, base_url=portal) as on_portal:
        logged = on_portal.post("/api/auth/login", json={"email": "jamie@nyctr.demo", "password": "nyctr-demo"})
        assert logged.status_code == 200, logged.text
        headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
        on_site = ask(on_portal, headers, "missing.example")
        assert on_site.status_code == 200 and on_site.json()["message"] == MISSED
        on_console.cookies.set(COOKIE_NAME, logged.cookies[COOKIE_NAME], domain="console.test")
        refused = ask(on_console, headers, "metrics.analytics-hub.example")
        assert refused.status_code == 403 and refused.json()["detail"] == CONSOLE
        assert "blocked recently" not in refused.text and quota(other) == 1
        assert stated(other, "console")[-1].details["outcome"] == "console"


@BOTH
def test_an_unsigned_statement_is_audited_without_a_member(tmp_path, database, request):
    """A missing, repeated, or unusable session is refused and audited. Nothing is filed.

    The actor stays empty, including when an expired or disabled session used to
    name a member. A live session with no mutation token stays a mutation refusal.
    """
    app = open_demo(database, tmp_path, request, "unsigned")
    with TestClient(app) as client:
        marker = "Alex's workstation"
        first = ask(client, None, "secret.example")
        second = ask(client, None, "secret.example")
        assert first.status_code == second.status_code == 401
        assert first.json() == second.json() == {"detail": "Sign in to continue"}
        assert "secret.example" not in first.text and marker not in second.text
        assert filed_for(app, "secret.example") == [] and quota(app) is None
        empty = client.post("/api/statements", json={})
        assert empty.status_code == 401 and empty.json() == {"detail": "Sign in to continue"}
        before_broken = len(stated(app, "no_session"))
        broken = client.post("/api/statements", content=b"{", headers={"content-type": "application/json"})
        # The body is rejected before sign-in runs, so there is no session audit and no stored copy.
        assert broken.status_code == 422 and len(stated(app, "no_session")) == before_broken
        assert marker not in broken.text and "downloads.filemirror.example" not in broken.text
        extra = client.post("/api/statements", json={"domain": "secret.example", "note": marker})
        assert extra.status_code == 401 and marker not in extra.text and "secret.example" not in extra.text
        client.cookies.set(COOKIE_NAME, "not-a-session")
        junk = client.post("/api/statements", json={"domain": "secret.example"})
        assert junk.status_code == 401 and junk.json()["detail"] == "Sign in to continue"
        client.cookies.clear()
        rows = stated(app, "no_session")
        assert [row.details["domain"] for row in rows] == [
            "secret.example", "secret.example", "", "secret.example", "secret.example"]
        for row in rows:
            assert row.actor_id is None and row.target_id is None
            assert row.details["device_id"] == "" and row.details["device_name"] == ""
            assert marker not in str(row.details) and "user-jamie" not in str(row.details)
            assert "testclient" not in str(row.details) and "192.0.2" not in str(row.details)
        assert quota(app) is None and filed_for(app, "secret.example") == []

        headers = signin(client, member=True)
        bare = client.post("/api/statements", json={"domain": "secret.example"})
        assert bare.status_code == 403 and bare.json()["detail"] == "Invalid or missing CSRF token"
        assert len(stated(app, "no_session")) == len(rows)
        with app.state.session_factory() as db:
            account = db.get(User, "user-jamie")
            account.active = False
            db.commit()
        disabled = ask(client, headers, "secret.example")
        assert disabled.status_code == 401 and disabled.json()["detail"] == "Sign in to continue"
        denied = stated(app, "no_session")[-1]
        assert denied.actor_id is None and "user-jamie" not in str(denied.details)
        assert denied.details["domain"] == "secret.example"
        with app.state.session_factory() as db:
            account = db.get(User, "user-jamie")
            account.active = True
            for session in db.scalars(select(LoginSession)):
                session.expires_at = utcnow() - timedelta(seconds=5)
            db.commit()
        expired = ask(client, headers, "later.example")
        assert expired.status_code == 401 and expired.json()["detail"] == "Sign in to continue"
        late = stated(app, "no_session")[-1]
        assert late.actor_id is None and late.details["domain"] == "later.example"
        assert "user-jamie" not in str(late.details) and "user-admin" not in str(late.details)
        assert filed_for(app, "later.example") == [] and quota(app) is None
        headers = signin(client, member=True)
        again = ask(client, headers, "hub.example")
        assert again.status_code == 200 and again.json()["message"] == MISSED
        assert stated(app)[-1].actor_id == "user-jamie" and stated(app)[-1].details["outcome"] == "miss"
        assert quota(app) == 1


@BOTH
def test_a_matched_name_files_one_statement_and_the_rule_still_decides(tmp_path, database, request):
    """An exact block with no device files one request. The switch and the existing rule decide it."""
    app = open_demo(database, tmp_path, request, "filed")
    with TestClient(app) as client:
        headers = signin(client, member=True)
        seen = {row["domain"] for row in client.get("/api/blocks", headers=headers).json()["rows"]}
        assert "metrics.analytics-hub.example" not in seen
        filed = ask(client, headers, "https://Metrics.Analytics-Hub.example/page?q=1")
        assert filed.status_code == 201, filed.text
        body = filed.json()
        assert body["matched"] is True and body["message"] == FILED
        shown = body["request"]
        assert shown["domain"] == "metrics.analytics-hub.example"
        assert shown["device_name"] == "Jamie's MacBook" and shown["requester_id"] == "user-jamie"
        assert shown["status"] == "analysing" and "basis" not in shown
        for hidden in HIDDEN:
            assert hidden not in filed.text
        decided = stored(client, headers, body)
        assert decided["status"] == "pending" and "could not score" in decided["decision_note"]
        assert "basis" not in decided
        with app.state.session_factory() as db:
            saved = db.get(AccessRequest, decided["id"])
            assert saved.basis == "statement" and saved.block_id == "block-unattributed"
            assert saved.device_id == "laptop-jamie" and saved.requester_id == "user-jamie"
            audit = db.scalar(select(Audit).where(Audit.action == "access.statement", Audit.target_id == saved.id))
            assert audit.details["outcome"] == "filed" and audit.details["domain"] == saved.domain
        again = ask(client, headers, "metrics.analytics-hub.example.")
        assert again.status_code == 200 and again.json()["message"] == DUPLICATE
        assert again.json()["request"]["id"] == decided["id"] and again.json()["matched"] is True
        assert len(filed_for(app, "metrics.analytics-hub.example")) == 1 and quota(app) == 2

        clear_quota(app)
        add_block(app, "stmt-said", "trackers.partner.example", device="laptop-jamie", name="Jamie's MacBook")
        said = ask(client, headers, "trackers.partner.example")
        assert said.status_code == 201, said.text
        waiting = stored(client, headers, said.json())
        assert waiting["status"] == "pending" and "not opened on its own" in waiting["decision_note"]
        with app.state.session_factory() as db:
            assert db.get(AccessRequest, waiting["id"]).basis == "statement"
            checked = db.scalar(select(Audit).where(Audit.action == "rule.access_checked",
                                                     Audit.target_id == waiting["id"]))
            assert checked.details["outcome"] == "waits" and ["match", "failed"] in checked.details["checks"]

        headers = allow(client, True)
        clear_quota(app)
        add_block(app, "stmt-open", "ads.named.example")
        opened = ask(client, headers, "ads.named.example")
        assert opened.status_code == 201, opened.text
        done = stored(client, headers, opened.json())
        assert done["status"] == "auto_approved" and done["decided_by"] == "rule"
        repeated = ask(client, headers, "ads.named.example")
        assert repeated.status_code == 200 and repeated.json()["request"]["id"] == done["id"]
        assert len(filed_for(app, "ads.named.example")) == 1
        lease = next(row for row in client.get("/api/leases").json() if row["request_id"] == done["id"])
        assert lease["execution"] == "simulated" and lease["status"] == "active"
        add_block(app, "stmt-deny", "blocked-on-purpose.example", reason="Denylist", codes=["denylist"])
        held = ask(client, headers, "blocked-on-purpose.example")
        assert held.status_code == 201, held.text
        person = stored(client, headers, held.json())
        assert person["status"] == "pending" and "administrator's rule" in person["decision_note"]
        assert "not opened on its own" not in person["decision_note"]
        assert not [row for row in client.get("/api/leases").json() if row["request_id"] == person["id"]]
        with app.state.session_factory() as db:
            checked = db.scalar(select(Audit).where(Audit.action == "rule.access_checked",
                                                     Audit.target_id == person["id"]))
            assert ["tier", "failed"] in checked.details["checks"]
            assert all(name != "match" for name, _result in checked.details["checks"])


def _many(client, headers, domain, count=12):
    """Send the same statement from several threads and keep each answer."""
    def once(_number):
        response = client.post("/api/statements", headers=headers, json={"domain": domain})
        body = response.json()
        request_id = body.get("request", {}).get("id") if isinstance(body, dict) else None
        return response.status_code, request_id, body.get("message") if isinstance(body, dict) else None, body.get(
            "detail") if isinstance(body, dict) else None

    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(once, range(count)))


@BOTH
def test_concurrent_statements_share_one_request_and_stop_at_five(tmp_path, database, request):
    """Misses and a match, sent together, keep one hour and do not file the same request twice."""
    app = open_demo(database, tmp_path, request, "race")
    with TestClient(app) as client:
        headers = signin(client, member=True)
        missed = _many(client, headers, "never-seen.example")
        assert [item[0] for item in missed].count(200) == 5
        assert [item[0] for item in missed].count(429) == 7
        assert all(item[2] == MISSED for item in missed if item[0] == 200)
        assert all(item[3] == LIMITED for item in missed if item[0] == 429)
        assert filed_for(app, "never-seen.example") == [] and quota(app) == 5
        clear_quota(app)
        add_block(app, "stmt-race", "race.example")
        raced = _many(client, headers, "race.example")
        assert [item[0] for item in raced].count(201) == 1
        assert [item[0] for item in raced].count(429) == 7
        kept = [item for item in raced if item[0] != 429]
        assert len(kept) <= 5 and len({item[1] for item in kept}) == 1
        rows = filed_for(app, "race.example")
        assert len(rows) == 1 and rows[0].basis == "statement"
        assert rows[0].device_id == "laptop-jamie"
        assert rows[0].device_name == "Jamie's MacBook" and rows[0].requester_id == "user-jamie"
        assert rows[0].id == kept[0][1] and quota(app) == 5


def test_the_production_app_has_no_statement_route(tmp_path):
    """A fresh application, the one the server builds, has no typed-site path."""
    app = create_app(Settings(
        mode="demo", database_url=f"sqlite:///{tmp_path}/absent.db",
        public_url="http://testserver", cookie_secure=False, worker_enabled=False))
    assert "/api/statements" not in {getattr(route, "path", "") for route in app.routes}
    with TestClient(app) as client:
        spec = client.get("/api/openapi.json").json()["paths"]
        assert not any(path == "/api/statements" or path.startswith("/api/statements/") for path in spec)
        body = {"domain": "fonts.partner-metrics.example"}
        unsigned = client.post("/api/statements", json=body)
        assert unsigned.status_code == 404 and unsigned.json()["detail"] == "API endpoint not found"
        member = client.post("/api/statements", headers=signin(client, member=True), json=body)
        assert member.status_code == 404 and member.json()["detail"] == "API endpoint not found"

def test_a_live_tie_lets_a_member_name_a_site_and_recognition_off_does_not(tmp_path):
    """Recognition off refuses. An address outside every collected network refuses too.

    Once the network is on record, recognition ties the member and the statement is filed
    for that device. The stored address is not used while recognition has nothing to name.
    """
    app = mount_for_test(live_app(tmp_path))
    with TestClient(app, client=("10.0.0.9", 50000)) as client:
        seed_live_member(app)
        now = utcnow()
        with app.state.session_factory() as db:
            db.add(Observation(
                id="dns:block:named", integration_id="dns", device_id=None, device_name="Unknown source device",
                domain="ads.named.example", source="nextdns", reason="HaGeZi Multi PRO++", reason_codes=PRIVACY,
                observed_at=now - timedelta(minutes=2), expires_at=now + timedelta(hours=2),
                evidence_kind="observed", attribution="unattributed", risk_score=None, risk_explanation=""))
            db.get(Integration, "unifi").secret_ref = "local-test"
            db.query(DeviceGrant).delete()
            db.commit()
        member = live_signin(client, LIVE_MEMBER)
        refused = ask(client, member, "ads.named.example")
        assert refused.status_code == 403 and refused.json()["detail"] == OFF
        assert filed_for(app, "ads.named.example") == []
        admin = live_signin(client)
        assert client.put("/api/presence", headers=admin, json={"enabled": True}).status_code == 200
        member = live_signin(client, LIVE_MEMBER)
        refused = ask(client, member, "ads.named.example")
        assert refused.status_code == 403 and refused.json()["detail"] == WHY["outside"]
        assert "Sam's laptop" not in refused.text and filed_for(app, "ads.named.example") == []
        assert stated(app, "outside")[-1].details["device_id"] == ""
        now = utcnow()
        with app.state.session_factory() as db:
            db.add(Resource(
                id="unifi:network:lan", integration_id="unifi", name="LAN", kind="network",
                provider="unifi_network", source_id="lan", observed_at=now, evidence_kind="configured",
                classification="infrastructure", attributes={"subnets": ["10.0.0.0/24"]}))
            db.commit()
        filed = ask(client, member, "https://Ads.Named.example/x")
        assert filed.status_code == 201, filed.text
        body = filed.json()["request"]
        assert body["domain"] == "ads.named.example" and body["device_name"] == "Sam's laptop"
        assert "Unknown source device" not in filed.text and "basis" not in body
        with app.state.session_factory() as db:
            row = db.get(AccessRequest, body["id"])
            assert row.basis == "statement" and row.requester_id == "sam"
            assert row.device_name == "Sam's laptop" and row.device_id == "unifi:client:laptop"


HIDDEN_DEVICES = ("Laptop", "Phone", "Tablet", "Printer", "Kim", "Boat")


def live_place(database, tmp_path, request, name):
    """This case's own database. A second app in one test must not reuse the first file."""
    if database == "sqlite":
        return {"database_url": f"sqlite:///{tmp_path}/{name}.db"}
    url = postgres_database(request)
    if not url:
        pytest.skip("No PostgreSQL server is named in NYCTR_TEST_POSTGRES")
    return {"database_url": url}


def plant_named(app, domain, *, observed=None, expires=None, integration_id="dns"):
    """Store one exact block. A live app gets a local DNS source the first time."""
    now = utcnow()
    when = now - timedelta(minutes=2) if observed is None else observed
    ends = when + timedelta(hours=2) if expires is None else expires
    with app.state.session_factory() as db:
        if integration_id == "dns" and db.get(Integration, "dns") is None:
            db.add(Integration(id="dns", provider="nextdns", name="DNS", status="connected", last_sync=now,
                               config={}, secret_ref="local-test"))
            db.flush()
        db.add(Observation(
            id=f"dns:block:{domain}", integration_id=integration_id, device_id=None,
            device_name="Unknown source device", domain=domain, source="nextdns", reason="HaGezi Multi PRO++",
            reason_codes=list(PRIVACY), observed_at=when, expires_at=ends, evidence_kind="observed",
            attribution="unattributed", risk_score=None, risk_explanation=""))
        db.commit()


def clear_logins(app):
    """Forget the sign-in quota so a test can open the sessions it needs."""
    with app.state.session_factory() as db:
        db.query(LoginAttempt).delete()
        db.commit()


@contextmanager
def member(app, address, who=LIVE_MEMBER, **options):
    """Sign in from an address. The sign-in quota is cleared first."""
    clear_logins(app)
    with browser(app, address, who, **options) as client:
        yield client


def assign_device(app, device_id, classification, user_ids):
    """Set whose a device is, through the same route an administrator uses."""
    clear_logins(app)
    with TestClient(app, client=("198.51.100.50", 50000)) as client:
        headers = live_signin(client)
        response = client.put(f"/api/devices/{device_id}/assignment", headers=headers,
                              json={"classification": classification, "user_ids": user_ids})
        assert response.status_code == 200, response.text


def drop_grants(app, device_id):
    """Remove current grants and leave any sign-in tie as it is."""
    with app.state.session_factory() as db:
        db.query(DeviceGrant).filter(DeviceGrant.device_id == device_id).delete()
        db.commit()


def end_ties(app, user_id, device_id):
    """End this member's open ties on one device without changing the grant."""
    now = utcnow()
    with app.state.session_factory() as db:
        rows = db.scalars(select(DevicePresence).where(
            DevicePresence.user_id == user_id, DevicePresence.device_id == device_id,
            DevicePresence.ended_at.is_(None)))
        for row in rows:
            row.ended_at = now
        db.commit()


def refusal(app, client, domain, code, *hidden):
    """A recognition refusal: the sentence, an empty device on the audit, and no attempt counted."""
    before = quota(app, "sam")
    answer = ask(client, None, domain)
    assert answer.status_code == 403, answer.text
    assert answer.json()["detail"] == WHY[code]
    for word in hidden:
        assert word not in answer.text
    row = stated(app)[-1]
    assert row.details["outcome"] == code
    assert row.details["device_id"] == "" and row.details["device_name"] == ""
    assert row.actor_id == "sam"
    for word in hidden:
        assert word not in str(row.details)
    assert quota(app, "sam") == before


@BOTH
def test_a_recognition_refusal_is_final(tmp_path, database, request, monkeypatch):
    """Recognition names the device or refuses. A stored address does not override the refusal."""
    app, gateway = home(tmp_path, monkeypatch, **live_place(database, tmp_path, request, "refusal"))
    mount_for_test(app)
    original = dict(gateway["holds"])
    domain = "zz-named.example"
    plant_named(app, domain)
    assign_device(app, "gw:client:laptop", "personal", ["sam"])

    def restore():
        gateway["down"] = False
        gateway.pop("answer", None)
        gateway["holds"].clear()
        gateway["holds"].update(original)
        presence._answers.clear()
        change(app, Integration, "gw", last_sync=utcnow())

    def deny_from(address, code, prepare=None):
        restore()
        if prepare:
            prepare()
        with member(app, address) as client:
            refusal(app, client, domain, code, request_id, *HIDDEN_DEVICES)

    with member(app, LAPTOP) as sam:
        filed = ask(sam, None, domain)
        assert filed.status_code == 201, filed.text
        body = filed.json()["request"]
        request_id = body["id"]
        told = sam.get("/api/me/device").json()
        assert (told["device_id"], told["name"], told["how"]) == ("gw:client:laptop", "Laptop", "assigned")
        assert body["requester_id"] == "sam" and body["device_name"] == told["name"]
        assert "basis" not in body and "device_id" not in body and "Phone" not in filed.text
        with app.state.session_factory() as db:
            saved = db.get(AccessRequest, request_id)
            assert saved.device_id == "gw:client:laptop" and saved.requester_id == "sam"
            assert saved.basis == "statement"
        again = ask(sam, None, domain)
        assert again.status_code == 200 and again.json()["request"]["id"] == request_id
        assert quota(app, "sam") == 2 and len(filed_for(app, domain)) == 1
        drop_grants(app, "gw:client:laptop")
        tied = ask(sam, None, domain)
        assert tied.status_code == 200 and tied.json()["request"]["id"] == request_id
        assert quota(app, "sam") == 3
        assign_device(app, "gw:client:laptop", "personal", ["sam"])
        end_ties(app, "sam", "gw:client:laptop")
        forgotten = ask(sam, None, domain)
        assert forgotten.status_code == 403 and forgotten.json()["detail"] == WHY["forgotten"]
        assert request_id not in forgotten.text and "Laptop" not in forgotten.text
        assert quota(app, "sam") == 3 and len(filed_for(app, domain)) == 1
        assert stated(app, "forgotten")[-1].details["device_id"] == ""

    with member(app, LAPTOP) as sam:
        returned = ask(sam, None, domain)
        assert returned.status_code == 200 and returned.json()["request"]["id"] == request_id
        assert quota(app, "sam") == 4
        def several():
            gateway["holds"]["phone"] = LAPTOP
            presence._answers.clear()

        def nobody():
            gateway["holds"]["laptop"] = None
            presence._answers.clear()

        deny_from(LAPTOP, "several", several)
        deny_from(LAPTOP, "nobody", nobody)
        deny_from("198.51.100.7", "outside")
        deny_from("2001:db8::10", "ipv6")
        deny_from(PRINTER, "infrastructure")
        deny_from(TABLET, "other_person")

        def silent():
            gateway["down"] = True
            change(app, Integration, "gw", last_sync=utcnow() - timedelta(minutes=16))
            presence._answers.clear()

        def unknown():
            gateway["answer"] = [{"id": "gw:client:nobody", "mac": None}]
            presence._answers.clear()

        deny_from(LAPTOP, "not_answering", silent)
        deny_from(LAPTOP, "not_collected", unknown)
        saved_record = presence._record

        def locked(*_args, **_kwargs):
            raise OperationalError("INSERT INTO device_presence", {}, Exception("database is locked"))

        monkeypatch.setattr(presence, "_record", locked)
        try:
            deny_from(LAPTOP, "busy")
        finally:
            monkeypatch.setattr(presence, "_record", saved_record)
        restore()
        before = quota(app, "sam")
        with member(app, PHONE, KIM) as kim:
            hers = ask(kim, None, domain)
            assert hers.status_code == 201, hers.text
            hers_body = hers.json()["request"]
            assert hers_body["id"] != request_id and hers_body["requester_id"] == "kim"
            assert hers_body["device_name"] == "Phone"
            assert request_id not in hers.text and "Laptop" not in hers.text
        with app.state.session_factory() as db:
            hers_row = db.scalar(select(AccessRequest).where(AccessRequest.requester_id == "kim"))
            assert hers_row.device_id == "gw:client:phone" and hers_row.domain == domain
        assert quota(app, "sam") == before
        assign_device(app, "gw:client:laptop", "personal", ["kim"])
        moved = ask(sam, None, domain)
        assert moved.status_code == 403 and moved.json()["detail"] == WHY["forgotten"]
        assert request_id not in moved.text and "Kim" not in moved.text and "Laptop" not in moved.text
        assert quota(app, "sam") == before
        sam_rows = [row.device_id for row in filed_for(app, domain) if row.requester_id == "sam"]
        assert sam_rows == ["gw:client:laptop"]

    proxy, _gateway = home(tmp_path, monkeypatch, trusted_proxies=LAPTOP,
                           **live_place(database, tmp_path, request, "proxy"))
    mount_for_test(proxy)
    assign_device(proxy, "gw:client:laptop", "personal", ["sam"])
    with member(proxy, LAPTOP, headers={"X-Forwarded-For": LAPTOP}) as sam:
        refusal(proxy, sam, domain, "proxy", *HIDDEN_DEVICES)
    odd, _gateway = home(tmp_path, monkeypatch, trusted_proxies="198.51.100.1",
                         **live_place(database, tmp_path, request, "malformed"))
    mount_for_test(odd)
    with member(odd, "198.51.100.1", headers={"X-Forwarded-For": "not-an-address"}) as sam:
        refusal(odd, sam, domain, "no_address", *HIDDEN_DEVICES)
    split, split_gateway = home(tmp_path, monkeypatch, **live_place(database, tmp_path, request, "split"))
    mount_for_test(split)
    two_sites(split, "192.0.2.0/24")
    split_gateway["holds"].update(phone=None, boat=PHONE)
    assign_device(split, "gw:client:phone", "personal", ["sam"])
    with member(split, PHONE) as sam:
        refusal(split, sam, domain, "two_networks", *HIDDEN_DEVICES)


@BOTH
def test_two_devices_of_one_member_keep_separate_requests(tmp_path, database, request, monkeypatch):
    """The same member on two devices gets two requests. A conflict retry stays on the device that asked."""
    app, _gateway = home(tmp_path, monkeypatch, **live_place(database, tmp_path, request, "devices"))
    mount_for_test(app)
    own, overlap = "zz-own.example", "zz-overlap.example"
    plant_named(app, own)
    plant_named(app, overlap)
    with browser(app, LAPTOP) as laptop, browser(app, PHONE) as phone:
        first = ask(laptop, None, own)
        second = ask(phone, None, own)
        assert first.status_code == 201 and second.status_code == 201, (first.text, second.text)
        left, right = first.json()["request"], second.json()["request"]
        assert left["id"] != right["id"] and right["id"] not in first.text and left["id"] not in second.text
        assert left["device_name"] == "Laptop" and right["device_name"] == "Phone"
        assert left["requester_id"] == right["requester_id"] == "sam"
        saved = {row.device_id: row.id for row in filed_for(app, own)}
        assert saved == {"gw:client:laptop": left["id"], "gw:client:phone": right["id"]}
        assert all(row.basis == "statement" and row.requester_id == "sam" for row in filed_for(app, own))
        repeated = ask(laptop, None, own)
        assert repeated.status_code == 200 and repeated.json()["request"]["id"] == left["id"]
        repeated = ask(phone, None, own)
        assert repeated.status_code == 200 and repeated.json()["request"]["id"] == right["id"]
        assert quota(app, "sam") == 4 and len(filed_for(app, own)) == 2
        clear_quota(app, "sam")

        def post(client):
            response = client.post("/api/statements", json={"domain": overlap})
            body = response.json()
            found = body.get("request", {}).get("id") if isinstance(body, dict) else None
            return response.status_code, found, response.text

        with ThreadPoolExecutor(max_workers=2) as pool:
            raced = list(pool.map(post, (laptop, phone)))
        assert [item[0] for item in raced].count(201) == 2
        ids = {item[1] for item in raced}
        assert len(ids) == 2 and None not in ids
        rows = filed_for(app, overlap)
        assert {row.device_id for row in rows} == {"gw:client:laptop", "gw:client:phone"}
        for _status, found, text in raced:
            other = next(value for value in ids if value != found)
            assert other not in text
        clear_quota(app, "sam")
        real = statements._open_request
        state = {"left": 2}

        def miss_then_real(*args, **kwargs):
            if state["left"]:
                state["left"] -= 1
                return None
            return real(*args, **kwargs)

        monkeypatch.setattr(statements, "_open_request", miss_then_real)
        retried = ask(laptop, None, own)
        assert retried.status_code == 200, retried.text
        assert retried.json()["request"]["id"] == left["id"] and right["id"] not in retried.text
        assert len(filed_for(app, own)) == 2 and quota(app, "sam") == 1
        assert stated(app)[-1].details["outcome"] == "duplicate"
        assert stated(app)[-1].details["device_id"] == "gw:client:laptop"


@BOTH
def test_an_open_request_returns_after_its_evidence_is_gone(tmp_path, database, request, monkeypatch):
    """This device's open request comes back after the block is old or gone. Another device is not shown it."""
    app, _gateway = home(tmp_path, monkeypatch, **live_place(database, tmp_path, request, "window"))
    mount_for_test(app)
    held, cold = "zz-held.example", "zz-cold.example"
    plant_named(app, held)
    plant_named(app, cold)
    with browser(app, LAPTOP) as laptop, browser(app, PHONE) as phone:
        filed = ask(laptop, None, held)
        assert filed.status_code == 201, filed.text
        kept = filed.json()["request"]["id"]
        with app.state.session_factory() as db:
            row = db.get(AccessRequest, kept)
            assert row.device_id == "gw:client:laptop" and row.requester_id == "sam"
            seen = db.get(Observation, f"dns:block:{held}")
            seen.observed_at = utcnow() - timedelta(minutes=20)
            db.commit()
        again = ask(laptop, None, held)
        assert again.status_code == 200 and again.json()["message"] == DUPLICATE
        assert again.json()["request"]["id"] == kept and quota(app, "sam") == 2
        assert len(filed_for(app, held)) == 1 and stated(app)[-1].details["outcome"] == "duplicate"
        with app.state.session_factory() as db:
            db.delete(db.get(Observation, f"dns:block:{held}"))
            db.commit()
        still = ask(laptop, None, held)
        assert still.status_code == 200 and still.json()["request"]["id"] == kept
        assert quota(app, "sam") == 3 and len(filed_for(app, held)) == 1
        other = ask(phone, None, held)
        assert other.status_code == 200 and other.json() == {"matched": False, "message": MISSED}
        assert kept not in other.text and "Laptop" not in other.text
        assert len(filed_for(app, held)) == 1 and quota(app, "sam") == 4
        assert stated(app)[-1].details["outcome"] == "miss"
        assert stated(app)[-1].details["device_id"] == "gw:client:phone"
        with app.state.session_factory() as db:
            aged = db.get(Observation, f"dns:block:{cold}")
            aged.observed_at = utcnow() - timedelta(minutes=20)
            db.commit()
        missed = ask(laptop, None, cold)
        assert missed.status_code == 200 and missed.json() == {"matched": False, "message": MISSED}
        assert filed_for(app, cold) == [] and stated(app)[-1].details["outcome"] == "stale"
        assert quota(app, "sam") == 5 and len(filed_for(app, held)) == 1


@BOTH
def test_a_block_in_the_future_or_outside_the_window_is_not_filed(tmp_path, database, request, monkeypatch):
    """The window includes its edges and excludes a future or just-expired block. A parent is not the name."""
    app = open_demo(database, tmp_path, request, "fresh")
    frozen = utcnow()
    monkeypatch.setattr(statements, "utcnow", lambda: frozen)
    window = frozen - timedelta(minutes=15)
    later = frozen + timedelta(hours=1)

    def plant(domain, observed, expires):
        plant_named(app, domain, observed=observed, expires=expires, integration_id="demo-nextdns")

    with TestClient(app) as client:
        headers = signin(client, member=True)
        plant("zz-lower.example", window, later)
        lower = ask(client, headers, "zz-lower.example")
        assert lower.status_code == 201, lower.text
        plant("zz-current.example", frozen, later)
        current = ask(client, headers, "zz-current.example")
        assert current.status_code == 201, current.text
        with app.state.session_factory() as db:
            stored = list(db.scalars(select(AccessRequest).where(AccessRequest.basis == "statement")))
            assert {row.domain: row.device_id for row in stored} == {
                "zz-lower.example": "laptop-jamie", "zz-current.example": "laptop-jamie"}
        plant("zz-early.example", window - timedelta(seconds=1), later)
        early = ask(client, headers, "zz-early.example")
        assert early.status_code == 200 and early.json() == {"matched": False, "message": MISSED}
        assert stated(app)[-1].details["outcome"] == "stale" and filed_for(app, "zz-early.example") == []
        plant("zz-future.example", frozen + timedelta(minutes=5), later)
        future = ask(client, headers, "zz-future.example")
        assert future.status_code == 200 and future.json() == {"matched": False, "message": MISSED}
        assert stated(app)[-1].details["outcome"] == "stale" and filed_for(app, "zz-future.example") == []
        plant("zz-ending.example", frozen - timedelta(minutes=1), frozen)
        ending = ask(client, headers, "zz-ending.example")
        assert ending.status_code == 200 and ending.json() == {"matched": False, "message": MISSED}
        assert stated(app)[-1].details["outcome"] == "stale" and filed_for(app, "zz-ending.example") == []
        clear_quota(app)
        plant("images.zz-parent.example", frozen - timedelta(minutes=1), later)
        parent = ask(client, headers, "zz-parent.example")
        assert parent.status_code == 200 and parent.json() == {"matched": False, "message": MISSED}
        assert "images.zz-parent.example" not in parent.text
        assert stated(app)[-1].details["outcome"] == "not_exact"
        assert filed_for(app, "zz-parent.example") == []
        plant("zz-child.example", frozen - timedelta(minutes=1), later)
        child = ask(client, headers, "www.zz-child.example")
        assert child.status_code == 200 and "zz-child.example" not in child.text
        assert stated(app)[-1].details["outcome"] == "not_exact"
        assert filed_for(app, "www.zz-child.example") == []
        plant("later.zz-kin.example", frozen + timedelta(minutes=5), later)
        kin = ask(client, headers, "zz-kin.example")
        assert kin.status_code == 200 and kin.json() == {"matched": False, "message": MISSED}
        assert "later.zz-kin.example" not in kin.text and stated(app)[-1].details["outcome"] == "miss"
        assert filed_for(app, "zz-kin.example") == []


def _rows(app, model, request_id):
    """Rows of one table that belong to this request."""
    with app.state.session_factory() as db:
        column = model.subject if model is Notice else model.request_id
        return list(db.scalars(select(model).where(column == request_id)))


def _finish(app):
    """Run the check the request would have started once the answer was sent."""
    asyncio.run(access.finish_due(app.state.session_factory, app.state.settings))


def _give_laptop(app):
    """Give Jamie the laptop again, the way an assignment does."""
    now = utcnow()
    with app.state.session_factory() as db:
        laptop = db.get(Resource, "laptop-jamie")
        laptop.owner_id = "user-jamie"
        laptop.classification = "personal"
        db.query(DeviceGrant).filter(DeviceGrant.device_id == "laptop-jamie",
                                     DeviceGrant.user_id == "user-jamie").delete()
        db.add(DeviceGrant(device_id="laptop-jamie", user_id="user-jamie", valid_from=now - timedelta(days=1)))
        db.commit()


def _take_laptop(app):
    """Remove every way Jamie may use the laptop, including the sign-in."""
    with app.state.session_factory() as db:
        db.query(DeviceGrant).filter(DeviceGrant.user_id == "user-jamie").delete()
        db.query(DevicePresence).filter(DevicePresence.user_id == "user-jamie").delete()
        db.get(Resource, "laptop-jamie").owner_id = "user-admin"
        db.query(LoginSession).delete()
        db.commit()


def _waiting(app, request_id, domain):
    """The statement is still Jamie's, on the laptop, and it did not open."""
    with app.state.session_factory() as db:
        row = db.get(AccessRequest, request_id)
        assert row.status == "pending" and row.decision_note == STATEMENT_WAITING
        assert row.basis == "statement" and row.requester_id == "user-jamie"
        assert row.device_id == "laptop-jamie" and row.domain == domain
        assert row.device_name == "Jamie's MacBook"
    assert _rows(app, Lease, request_id) == []
    notes = _rows(app, Notice, request_id)
    assert len(notes) == 1 and notes[0].kind == "request_waiting"
    assert "Alex" not in str(notes[0].payload) and "workstation" not in str(notes[0].payload)
    assert stated(app, "filed") and any(item.details["domain"] == domain for item in stated(app, "filed"))


@BOTH
def test_the_page_and_the_statement_name_the_same_device(tmp_path, database, request):
    """Two of the member's devices: the page and the statement name the same one."""
    app = open_demo(database, tmp_path, request, "same-device")
    with TestClient(app) as client:
        now = utcnow()
        with app.state.session_factory() as db:
            db.add(Resource(
                id="phone-jamie", integration_id="demo-unifi", name="AAA phone", kind="client",
                provider="unifi_network", source_id="example-phone-jamie", site_id="site-home",
                observed_at=now, evidence_kind="observed", classification="personal", owner_id="user-jamie",
                attributes={"ip": "192.0.2.77", "demo": True}))
            db.flush()
            db.add(DeviceGrant(device_id="phone-jamie", user_id="user-jamie",
                               valid_from=now - timedelta(days=1)))
            db.commit()
        add_block(app, "stmt-page", "zz-page.example")
        headers = signin(client, member=True)
        page = client.get("/api/me/device", headers=headers).json()
        assert (page["device_id"], page["name"], page["simulated"], page["how"]) == (
            "phone-jamie", "AAA phone", True, "assigned")
        filed = ask(client, headers, "zz-page.example")
        assert filed.status_code == 201, filed.text
        body = filed.json()["request"]
        assert body["device_name"] == "AAA phone" and "Jamie's MacBook" not in filed.text
        phone_id = body["id"]
        with app.state.session_factory() as db:
            saved = db.get(AccessRequest, phone_id)
            assert saved.device_id == "phone-jamie" and saved.requester_id == "user-jamie"
            audit = db.scalar(select(Audit).where(Audit.target_id == phone_id, Audit.action == "access.statement"))
            assert audit.details["device_id"] == "phone-jamie" and audit.details["device_name"] == "AAA phone"
    with TestClient(app, client=("192.0.2.42", 50000)) as client:
        headers = signin(client, member=True)
        page = client.get("/api/me/device", headers=headers).json()
        assert (page["device_id"], page["name"], page["simulated"]) == ("laptop-jamie", "Jamie's MacBook", False)
        filed = ask(client, headers, "zz-page.example")
        assert filed.status_code == 201, filed.text
        body = filed.json()["request"]
        assert body["device_name"] == "Jamie's MacBook" and body["id"] != phone_id
        assert "AAA phone" not in filed.text and phone_id not in filed.text
        with app.state.session_factory() as db:
            other = db.get(AccessRequest, body["id"])
            assert other.device_id == "laptop-jamie" and other.requester_id == "user-jamie"
        assert {row.device_id for row in filed_for(app, "zz-page.example")} == {"phone-jamie", "laptop-jamie"}


@BOTH
def test_losing_the_device_stops_the_opening_and_keeps_the_request(tmp_path, database, request, monkeypatch):
    """A statement waits once the device is no longer the member's. An older kind of request still opens."""
    app = open_demo(database, tmp_path, request, "revoked")

    async def paused(*_args, **_kwargs):
        return None

    monkeypatch.setattr("nyctr.main._finish_request", paused)
    with TestClient(app) as client:
        headers = allow(client, True)
        admin = signin(client)
        rule = client.get("/api/rules", headers=admin).json()["access"]
        rule["per_day"] = 20
        assert client.put("/api/rules/access", headers=admin, json=rule).status_code == 200
        headers = signin(client, member=True)
        add_block(app, "stmt-revoke", "zz-revoke.example")
        filed = ask(client, headers, "zz-revoke.example")
        assert filed.status_code == 201, filed.text
        revoked_id = filed.json()["request"]["id"]
        event = client.post("/api/requests", headers=headers, json={
            "block_id": "block-gallery", "reason": "Need the picture", "duration_minutes": 60})
        assert event.status_code == 201, event.text
        event_id = event.json()["id"]
        _take_laptop(app)
        _finish(app)
        _waiting(app, revoked_id, "zz-revoke.example")
        with app.state.session_factory() as db:
            opened = db.get(AccessRequest, event_id)
            assert opened.status == "auto_approved" and opened.basis == "event" and opened.device_id is None
            assert opened.decided_by == "rule"
        event_leases = _rows(app, Lease, event_id)
        assert len(event_leases) == 1 and event_leases[0].execution == "simulated" and event_leases[0].owned is True
        _finish(app)
        _waiting(app, revoked_id, "zz-revoke.example")
        assert len(_rows(app, Lease, event_id)) == 1

        _give_laptop(app)
        headers = signin(client, member=True)
        add_block(app, "stmt-together", "zz-together.example")
        together = ask(client, headers, "zz-together.example")
        assert together.status_code == 201, together.text
        together_id = together.json()["request"]["id"]
        _take_laptop(app)

        async def both():
            factory, settings = app.state.session_factory, app.state.settings
            holder = holder_id(app.state.engine)
            await asyncio.gather(
                access.finish_one(factory, settings, together_id, holder),
                access.finish_one(factory, settings, together_id, holder))

        asyncio.run(both())
        _waiting(app, together_id, "zz-together.example")

        _give_laptop(app)
        headers = signin(client, member=True)
        add_block(app, "stmt-session", "zz-session.example")
        signed = ask(client, headers, "zz-session.example")
        assert signed.status_code == 201, signed.text
        session_id = signed.json()["request"]["id"]
        with app.state.session_factory() as db:
            db.query(LoginSession).delete()
            db.commit()
        _finish(app)
        with app.state.session_factory() as db:
            row = db.get(AccessRequest, session_id)
            assert row.status == "auto_approved" and row.decided_by == "rule"
            assert row.device_id == "laptop-jamie" and row.requester_id == "user-jamie"
        kept = _rows(app, Lease, session_id)
        assert len(kept) == 1 and kept[0].execution == "simulated" and kept[0].owned is True

        with app.state.session_factory() as db:
            db.query(DeviceGrant).filter(DeviceGrant.user_id == "user-jamie").delete()
            now = utcnow()
            db.add(DevicePresence(
                kind="tie", user_id="user-jamie", device_id="laptop-jamie", basis="live",
                first_at=now, last_at=now, reach_from=now - timedelta(hours=1)))
            db.commit()
        headers = signin(client, member=True)
        add_block(app, "stmt-tie", "zz-tie.example")
        tied = ask(client, headers, "zz-tie.example")
        assert tied.status_code == 201, tied.text
        tie_id = tied.json()["request"]["id"]
        with app.state.session_factory() as db:
            db.query(LoginSession).delete()
            db.commit()
        _finish(app)
        with app.state.session_factory() as db:
            row = db.get(AccessRequest, tie_id)
            assert row.status == "auto_approved" and row.device_id == "laptop-jamie"
        assert len(_rows(app, Lease, tie_id)) == 1

        _give_laptop(app)
        headers = signin(client, member=True)
        add_block(app, "stmt-during", "zz-during.example")
        during = ask(client, headers, "zz-during.example")
        assert during.status_code == 201, during.text
        during_id = during.json()["request"]["id"]
        real_open = access.open_lease

        async def open_and_take(db, settings, **kwargs):
            db.commit()
            _take_laptop(app)
            return await real_open(db, settings, **kwargs)

        monkeypatch.setattr(access, "open_lease", open_and_take)
        _finish(app)
        _waiting(app, during_id, "zz-during.example")
        assert len(filed_for(app, "zz-during.example")) == 1


def wait_for_release(event, what, limit=PAUSE_LIMIT):
    """Block until the test releases the pause. A missed release ends the wait."""
    if not event.wait(limit):
        raise TimeoutError(f"{what} was not released within {limit} seconds")


def release_paused(thread, event):
    """Let the paused request continue, and wait until that thread has stopped."""
    event.set()
    thread.join(PAUSE_LIMIT)


class HeldAllowlist:
    """A fabricated allowlist. One call can wait after it has already changed the list.

    The wait is bounded. The test releases it in a finally, so a failed assertion
    cannot leave the provider thread parked.
    """

    def __init__(self, monkeypatch, hold=None):
        self.listed, self.calls, self.hold = [], [], hold
        self.paused = None
        self.reached, self.go = threading.Event(), threading.Event()
        monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "dns-secret")
        monkeypatch.setattr(core, "make_http_client", lambda key, **_: httpx.AsyncClient(
            transport=httpx.MockTransport(self.answer), headers={"X-Api-Key": key}, trust_env=False))

    async def answer(self, request):
        call = len(self.calls)
        path = request.url.path
        name = path.rsplit("/", 1)[1]
        self.calls.append(request.method)
        if request.method == "POST":
            self.listed.append(json.loads(request.content)["id"])
        elif request.method == "DELETE" and name in self.listed:
            self.listed.remove(name)
        response = httpx.Response(200, json={"data": [{"id": item, "active": True} for item in self.listed]})
        if self.hold == call:
            self.paused = (request.method, path)
            self.reached.set()
            await asyncio.to_thread(wait_for_release, self.go, "the paused provider call")
        return response


def _prepared(tmp_path, monkeypatch, request, database, name):
    """A live app whose fabricated DNS source may be changed, with the laptop assigned to Sam."""
    app, _gateway = home(tmp_path, monkeypatch, provider_writes="nextdns",
                         **live_place(database, tmp_path, request, name))
    app = mount_for_test(app)
    now = utcnow()
    with app.state.session_factory() as db:
        db.add(Integration(
            id="dns", provider="nextdns", name="Office DNS", config={"profile_id": "abc123"},
            secret_ref="NYCTR_CONNECTOR_SECRET_DNS", status="connected", last_sync=now))
        for device_id in ("gw:client:laptop", "gw:client:phone"):
            device = db.get(Resource, device_id)
            device.owner_id = "sam"
            device.classification = "personal"
            db.add(DeviceGrant(device_id=device_id, user_id="sam", valid_from=now - timedelta(days=1)))
        db.commit()
    with TestClient(app) as client:
        put_rule(client, live_signin(client), per_day=20, allow_statement=True)
    return app


def _plant_live(app, domain):
    """One fresh exact block of this name, on the laptop, from the fabricated DNS source."""
    now = utcnow()
    with app.state.session_factory() as db:
        db.add(Observation(
            id=f"dns:block:{domain}", integration_id="dns", device_id="gw:client:laptop",
            device_name="Laptop", domain=domain, source="nextdns", reason="HaGeZi Multi PRO++",
            reason_codes=list(PRIVACY), observed_at=now - timedelta(minutes=2),
            expires_at=now + timedelta(hours=20), evidence_kind="observed", attribution="assigned",
            risk_score=None, risk_explanation=""))
        db.commit()


def _set_active(app, user_id, active):
    """Commit the account flag from a session of its own."""
    with app.state.session_factory() as db:
        db.get(User, user_id).active = active
        db.commit()


def _post_live(app, domain):
    """File a statement from the laptop while this thread waits on the provider call."""
    box = {}

    def run():
        try:
            with TestClient(app, client=(LAPTOP, 50000)) as client:
                headers = live_signin(client, LIVE_MEMBER)
                box["response"] = client.post("/api/statements", headers=headers, json={"domain": domain})
        except Exception as exc:  # The assertion reports it. A hung client is the timeout below.
            box["error"] = repr(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, box


def _saved(app, domain):
    """The request, its leases and its notices."""
    with app.state.session_factory() as db:
        row = db.scalar(select(AccessRequest).where(AccessRequest.domain == domain))
        leases = [] if row is None else list(db.scalars(select(Lease).where(Lease.domain == domain)))
        notes = [] if row is None else list(db.scalars(select(Notice).where(Notice.subject == row.id)))
        return row, leases, notes


@BOTH
def test_an_inactive_account_stops_a_statement_before_it_opens(tmp_path, database, request, monkeypatch):
    """A disabled account waits before anything is opened. An event, and a row with no basis, still open.

    A stored request cannot lose its account: the user is a foreign key. The missing account is the
    same read, on a copy this session already holds, after another session has removed the row.
    """
    app = open_demo(database, tmp_path, request, "inactive-before")

    async def paused(*_args, **_kwargs):
        return None

    monkeypatch.setattr("nyctr.main._finish_request", paused)
    with TestClient(app) as client:
        allow(client, True)
        admin = signin(client)
        rule = client.get("/api/rules", headers=admin).json()["access"]
        rule["per_day"] = 20
        assert client.put("/api/rules/access", headers=admin, json=rule).status_code == 200
        headers = signin(client, member=True)
        add_block(app, "stmt-inactive", "zz-inactive.example")
        filed = ask(client, headers, "zz-inactive.example")
        assert filed.status_code == 201, filed.text
        statement_id = filed.json()["request"]["id"]
        event = client.post("/api/requests", headers=headers, json={
            "block_id": "block-gallery", "reason": "Need the picture", "duration_minutes": 60})
        assert event.status_code == 201, event.text
        event_id = event.json()["id"]
        blank = client.post("/api/requests", headers=headers, json={
            "block_id": "block-fonts", "reason": "Need the fonts", "duration_minutes": 60})
        assert blank.status_code == 201, blank.text
        blank_id = blank.json()["id"]
        with app.state.session_factory() as db:
            db.execute(text("UPDATE access_requests SET basis = NULL WHERE id = :id"), {"id": blank_id})
            db.commit()
        with app.state.session_factory() as held:
            cached = held.get(User, "user-jamie")
            assert cached.active is True
            statement = held.get(AccessRequest, statement_id)
            event_row = held.get(AccessRequest, event_id)
            blank_row = held.get(AccessRequest, blank_id)
            assert event_row.basis == "event" and blank_row.basis is None
            held.commit()  # The copy stays. The other session can commit while this one holds no lock.
            _set_active(app, "user-jamie", False)
            assert statement_current(held, statement) is False
            assert statement_current(held, event_row) is True
            assert statement_current(held, blank_row) is True
            held.add(User(id="gone", email="gone@example.net", name="Gone", role="member"))
            held.commit()
            # This name has to stay live through the check. A clean instance is only held weakly.
            gone = held.get(User, "gone")
            assert gone is not None and gone.active is True
            with app.state.session_factory() as other:
                other.delete(other.get(User, "gone"))
                other.commit()
            missing = AccessRequest(
                basis="statement", device_id="laptop-jamie", requester_id="gone", domain="zz-gone.example")
            assert held.get(User, "gone") is gone
            assert gone.active is True
            assert statement_current(held, missing) is False
            assert held.get(User, "gone") is None
        _finish(app)
        _waiting(app, statement_id, "zz-inactive.example")
        with app.state.session_factory() as db:
            opened = db.get(AccessRequest, event_id)
            assert opened.status == "auto_approved" and opened.basis == "event"
            assert opened.decided_by == "rule"
            emptied = db.get(AccessRequest, blank_id)
            assert emptied.status == "auto_approved" and emptied.basis is None
            assert emptied.decided_by == "rule"
        assert len(_rows(app, Lease, event_id)) == 1 and len(_rows(app, Lease, blank_id)) == 1
        _finish(app)
        _waiting(app, statement_id, "zz-inactive.example")
        assert len(_rows(app, Lease, statement_id)) == 0

        _set_active(app, "user-jamie", True)
        headers = signin(client, member=True)
        add_block(app, "stmt-active", "zz-active.example")
        again = ask(client, headers, "zz-active.example")
        assert again.status_code == 201, again.text
        active_id = again.json()["request"]["id"]
        with app.state.session_factory() as db:
            db.query(LoginSession).delete()
            db.commit()
        _finish(app)
        with app.state.session_factory() as db:
            row = db.get(AccessRequest, active_id)
            assert row.status == "auto_approved" and row.decided_by == "rule"
            assert row.basis == "statement" and row.requester_id == "user-jamie"
            assert row.device_id == "laptop-jamie"
        kept = _rows(app, Lease, active_id)
        assert len(kept) == 1 and kept[0].execution == "simulated" and kept[0].owned is True


@BOTH
def test_disabling_the_account_during_the_provider_add_compensates(tmp_path, database, request, monkeypatch):
    """The account is read again after the add.

    What this opening added is removed, and a later pass adds nothing.
    """
    app = _prepared(tmp_path, monkeypatch, request, database, "during-add")
    source = HeldAllowlist(monkeypatch, hold=2)
    domain = "zz-disabled.example"
    _plant_live(app, domain)
    thread, box = _post_live(app, domain)
    try:
        assert source.reached.wait(20), {"calls": source.calls, "box": box}
        assert source.calls == ["GET", "GET", "POST"] and source.listed == [domain], source.calls
        # The add itself, after the claim's read and the fresh eligibility check. Not an earlier GET.
        assert source.paused == ("POST", ALLOWLIST), source.paused
        _set_active(app, "sam", False)
    finally:
        release_paused(thread, source.go)
    assert not thread.is_alive(), box
    assert "error" not in box, box
    assert box["response"].status_code == 201, box["response"].text
    row, leases, notes = _saved(app, domain)
    assert row.status == "pending" and row.decision_note == STATEMENT_WAITING, (row.status, row.decision_note)
    assert row.basis == "statement" and row.device_id == "gw:client:laptop" and row.requester_id == "sam"
    assert len(notes) == 1 and notes[0].kind == "request_waiting"
    assert not any(lease.status == "active" for lease in leases), [lease.status for lease in leases]
    compensation = [lease for lease in leases
                    if lease.status == "unconfirmed" and lease.owned and lease.request_id is None]
    assert len(compensation) == 1, [(lease.status, lease.owned, lease.request_id) for lease in leases]
    with app.state.session_factory() as db:
        closed = asyncio.run(access.reconcile(db, app.state.settings))
    assert closed == 1, (closed, source.calls, source.listed)
    assert source.listed == [] and source.calls.count("POST") == 1 and source.calls.count("DELETE") == 1
    before = list(source.calls)
    _finish(app)
    row, leases, notes = _saved(app, domain)
    assert row.status == "pending" and len(notes) == 1 and source.calls == before
    assert not any(lease.status == "active" for lease in leases)


@BOTH
def test_an_entry_already_there_stays_when_the_account_is_disabled(tmp_path, database, request, monkeypatch):
    """A disable while the provider is being read does not remove an entry this opening did not add."""
    app = _prepared(tmp_path, monkeypatch, request, database, "already-there")
    source = HeldAllowlist(monkeypatch, hold=1)
    domain = "zz-kept.example"
    source.listed.append(domain)
    _plant_live(app, domain)
    thread, box = _post_live(app, domain)
    try:
        assert source.reached.wait(20), {"calls": source.calls, "box": box}
        assert source.calls == ["GET", "GET"] and source.listed == [domain] and "POST" not in source.calls
        # The add's own read, after the claim's read. The entry was already listed, so nothing is posted.
        assert source.paused == ("GET", ALLOWLIST), source.paused
        _set_active(app, "sam", False)
    finally:
        release_paused(thread, source.go)
    assert not thread.is_alive(), box
    assert "error" not in box, box
    assert box["response"].status_code == 201, box["response"].text
    row, leases, notes = _saved(app, domain)
    assert row.status == "pending" and row.decision_note == STATEMENT_WAITING, (row.status, row.decision_note)
    assert len(notes) == 1 and notes[0].kind == "request_waiting"
    assert leases == [], [(lease.status, lease.owned, lease.execution) for lease in leases]
    assert source.listed == [domain] and "DELETE" not in source.calls and source.calls.count("POST") == 0
    before = list(source.calls)
    _finish(app)
    row, leases, notes = _saved(app, domain)
    assert row.status == "pending" and len(notes) == 1 and leases == [] and source.calls == before
    assert source.listed == [domain]


@BOTH
def test_an_active_account_still_opens_through_the_provider(tmp_path, database, request, monkeypatch):
    """An active account with a current assignment opens. Taking away only the sign-in leaves that opening."""
    app = _prepared(tmp_path, monkeypatch, request, database, "stays-active")

    async def paused(*_args, **_kwargs):
        return None

    monkeypatch.setattr("nyctr.main._finish_request", paused)
    source = HeldAllowlist(monkeypatch, hold=None)
    domain = "zz-open.example"
    _plant_live(app, domain)
    with TestClient(app, client=(LAPTOP, 50000)) as client:
        headers = live_signin(client, LIVE_MEMBER)
        filed = client.post("/api/statements", headers=headers, json={"domain": domain})
        assert filed.status_code == 201, filed.text
        with app.state.session_factory() as db:
            db.query(LoginSession).delete()
            assert db.get(User, "sam").active is True
            db.commit()
    _finish(app)
    row, leases, _notes = _saved(app, domain)
    assert row.status == "auto_approved" and row.decided_by == "rule", (row.status, row.decision_note)
    assert row.basis == "statement" and row.device_id == "gw:client:laptop" and row.requester_id == "sam"
    assert len(leases) == 1 and leases[0].status == "active" and leases[0].execution == "applied"
    assert leases[0].owned is True and leases[0].request_id == row.id
    assert source.listed == [domain] and source.calls.count("POST") == 1 and "DELETE" not in source.calls
    before = list(source.calls)
    _finish(app)
    again, leases, _notes = _saved(app, domain)
    assert again.status == "auto_approved" and len(leases) == 1 and source.calls == before


@asynccontextmanager
async def _on_one_loop(app):
    """One lifespan and one client, so two requests share the server's event loop."""
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            yield client


def _pause(label: str) -> None:
    """Block this worker until the test releases it. The wait itself is not the proof.

    The proof is the other request, which has to finish while this event is still
    unset. The short waits only let a failed test release the worker.
    """
    assert threading.current_thread() is not holder["loop_thread"]
    if not holder.get("pause", True) or holder["abort"].is_set():
        return
    release = threading.Event()
    holder["loop"].call_soon_threadsafe(holder["queue"].put_nowait, (label, release))
    deadline = time.monotonic() + PAUSE_LIMIT
    while not release.is_set():
        if holder["abort"].is_set():
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"the {label} wait was not released")
        release.wait(min(0.05, remaining))


async def _through_pauses(client, call, labels, during=None):
    """Run `call` and, at each labelled pause, finish one other request on the same loop."""
    holder["abort"].clear()
    holder["pause"] = True
    task = asyncio.create_task(call())
    release = None
    try:
        for label in labels:
            found, release = await asyncio.wait_for(holder["queue"].get(), PAUSE_LIMIT)
            assert found == label
            witness = await asyncio.wait_for(client.get("/api/auth/config"), 5)
            assert witness.status_code == 200 and witness.json()["local_enabled"] is True
            assert not release.is_set() and not task.done()
            if during is not None:
                during(label)
            release.set()
            release = None
        return await asyncio.wait_for(task, PAUSE_LIMIT)
    finally:
        holder["abort"].set()
        if release is not None:
            release.set()
        while True:
            try:
                _found, pending = holder["queue"].get_nowait()
            except asyncio.QueueEmpty:
                break
            pending.set()
        if not task.done():
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass


holder: dict = {}


def _hold_signin(monkeypatch):
    """Hold the real session lookup and, separately, the unsigned audit commit."""
    real_auth = statements.authenticate
    real_record = statements._record_unsigned
    holder["loop_thread"] = threading.current_thread()

    def held_auth(request, db):
        try:
            return real_auth(request, db)
        finally:
            _pause("auth")

    def held_record(db, domain):
        _pause("audit")
        return real_record(db, domain)

    monkeypatch.setattr(statements, "authenticate", held_auth)
    monkeypatch.setattr(statements, "_record_unsigned", held_record)


@BOTH
def test_sign_in_database_work_stays_off_the_event_loop(tmp_path, database, request, monkeypatch):
    """A held session lookup, and a held unsigned audit, each leave the loop free.

    Covers a missing session, a live session with no mutation token, and a member.
    The audit row stays uncommitted until its own pause is released, so neither
    wait keeps a write open across the other request.
    """
    app = open_demo(database, tmp_path, request, "off-loop")
    _hold_signin(monkeypatch)

    async def scenario():
        holder["loop"] = asyncio.get_running_loop()
        holder["queue"] = asyncio.Queue()
        holder["abort"] = threading.Event()
        holder["pause"] = True
        async with _on_one_loop(app) as client:
            before = len(stated(app, "no_session"))

            def still_uncommitted(_label):
                assert len(stated(app, "no_session")) == before

            missing = await _through_pauses(
                client, lambda: client.post("/api/statements", json={"domain": "secret.example"}),
                ["auth", "audit"], still_uncommitted)
            assert missing.status_code == 401 and missing.json() == {"detail": "Sign in to continue"}
            unsigned = stated(app, "no_session")
            assert len(unsigned) == before + 1 and unsigned[-1].actor_id is None
            assert unsigned[-1].details == {"domain": "secret.example", "device_id": "", "device_name": "",
                                             "outcome": "no_session"}
            logged = await client.post("/api/auth/login", json={"email": "jamie@nyctr.demo", "password": "nyctr-demo"})
            assert logged.status_code == 200, logged.text
            token = logged.json()["csrf_token"]
            audits = len(stated(app, "no_session"))
            forbidden = await _through_pauses(
                client, lambda: client.post("/api/statements", json={"domain": "secret.example"}), ["auth"])
            assert forbidden.status_code == 403 and forbidden.json()["detail"] == "Invalid or missing CSRF token"
            assert len(stated(app, "no_session")) == audits
            allowed = await _through_pauses(
                client, lambda: client.post(
                    "/api/statements", headers={"X-CSRF-Token": token}, json={"domain": "missing.example"}),
                ["auth"])
            assert allowed.status_code == 200 and allowed.json()["message"] == MISSED
            assert stated(app)[-1].actor_id == "user-jamie" and stated(app)[-1].details["outcome"] == "miss"

    asyncio.run(scenario())


@BOTH
def test_cancelling_sign_in_closes_the_session_after_the_worker(tmp_path, database, request, monkeypatch):
    """Cancelling the request task waits for the session lookup, then closes that session.

    The client task is not the task inside the route. The route task is cancelled
    directly. It stays pending while the worker is held, and the session close is
    recorded only after that worker returns. The next refusal is audited on its own.
    """
    app = open_demo(database, tmp_path, request, "cancel-signin")
    order, sessions = [], set()
    real = statements.authenticate
    original_close = Session.close

    def held(request, db):
        sessions.add(id(db))
        order.append("auth-in")
        try:
            return real(request, db)
        finally:
            if holder.get("pause", True):
                holder["loop"].call_soon_threadsafe(holder["entered"].set)
                if not holder["release"].wait(PAUSE_LIMIT):
                    raise TimeoutError("the sign-in wait was not released")
            order.append("auth-out")

    def close(self):
        if id(self) in sessions:
            order.append("close")
        return original_close(self)

    async def marking(func, *args):
        holder["task"] = asyncio.current_task()
        return await real_off(func, *args)

    real_off = statements._off_loop
    monkeypatch.setattr(statements, "authenticate", held)
    monkeypatch.setattr(statements, "_off_loop", marking)
    monkeypatch.setattr(Session, "close", close)

    async def scenario():
        holder["loop"] = asyncio.get_running_loop()
        holder["pause"] = True
        holder["entered"] = asyncio.Event()
        holder["release"] = threading.Event()
        async with _on_one_loop(app) as client:
            post = asyncio.create_task(client.post("/api/statements", json={"domain": "secret.example"}))
            try:
                await asyncio.wait_for(holder["entered"].wait(), PAUSE_LIMIT)
                route = holder["task"]
                route.cancel()
                for _ in range(5):
                    await asyncio.sleep(0)
                    assert not route.done()
                    assert "auth-out" not in order and "close" not in order
                witness = await asyncio.wait_for(client.get("/api/auth/config"), 5)
                assert witness.status_code == 200 and not holder["release"].is_set()
                holder["release"].set()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(route, PAUSE_LIMIT)
            finally:
                holder["release"].set()
                if not post.done():
                    post.cancel()
                try:
                    await post
                except (asyncio.CancelledError, Exception):
                    pass
            assert "auth-out" in order and "close" in order
            assert order.index("auth-out") < order.index("close")
            assert stated(app, "no_session") == []
            holder["pause"] = False
            again = await client.post("/api/statements", json={"domain": "secret.example"})
            assert again.status_code == 401 and again.json()["detail"] == "Sign in to continue"
            row = stated(app, "no_session")
            assert len(row) == 1 and row[0].actor_id is None
            assert row[0].details["domain"] == "secret.example" and row[0].details["device_id"] == ""
            follow = await client.get("/api/auth/config")
            assert follow.status_code == 200

    asyncio.run(scenario())


@BOTH
def test_a_failed_unsigned_audit_rolls_back(tmp_path, database, request, monkeypatch):
    """A commit that fails leaves no unsigned audit, and the next refusal records one."""
    app = open_demo(database, tmp_path, request, "audit-rollback")
    real = statements._record_unsigned
    armed = {"fail": True}

    def once(db, domain):
        if armed["fail"]:
            armed["fail"] = False
            original = db.commit

            def fail():
                db.commit = original
                raise OperationalError("INSERT", {}, Exception("disk full"))

            db.commit = fail
        return real(db, domain)

    monkeypatch.setattr(statements, "_record_unsigned", once)
    with TestClient(app, raise_server_exceptions=False) as client:
        failed = client.post("/api/statements", json={"domain": "secret.example"})
        assert failed.status_code == 500
        assert stated(app, "no_session") == []
        again = client.post("/api/statements", json={"domain": "secret.example"})
        assert again.status_code == 401 and again.json()["detail"] == "Sign in to continue"
        rows = stated(app, "no_session")
        assert len(rows) == 1 and rows[0].actor_id is None
        assert rows[0].details == {"domain": "secret.example", "device_id": "", "device_name": "",
                                    "outcome": "no_session"}
        assert filed_for(app, "secret.example") == [] and quota(app) is None


def _blocks(app, rows):
    """Store block rows. `rows` names the id, domain, observed time, expiry and source."""
    with app.state.session_factory() as db:
        if db.get(Integration, "json-only") is None:
            db.add(Integration(id="json-only", provider="not-a-source", name="JSON only", status="connected",
                               config={}, secret_ref="", capabilities=["dns.blocks"]))
        saved = db.get(Integration, "demo-nextdns")
        saved.capabilities = ["unrelated"]
        for row in rows:
            when = row["observed"]
            db.add(Observation(
                id=row["id"], integration_id=row.get("integration_id", "demo-nextdns"), device_id=None,
                device_name="Unknown source device", domain=row["domain"], source="nextdns", reason="list",
                reason_codes=[], observed_at=when, expires_at=row["expires"], evidence_kind="observed",
                attribution="unattributed", risk_score=None, risk_explanation=""))
        db.commit()


@BOTH
def test_a_buried_block_is_one_fresh_exact_row(tmp_path, database, request, monkeypatch):
    """Hundreds of newer unrelated blocks do not hide one exact row, and only that row is loaded.

    The same clock covers the inclusive window edge, a tie on that clock, a parent,
    a child, a sibling, a label glued on without a dot, a future child and an empty
    provider list. Two fresh rows with the same time file the greater id text.
    Capability comes from the registry. A list stored on the source does not add
    or remove one. A stored name that `LIKE` would confuse with an underscore is
    still a miss.
    """
    app = open_demo(database, tmp_path, request, "buried")
    frozen = utcnow()
    monkeypatch.setattr(statements, "utcnow", lambda: frozen)
    window = frozen - timedelta(minutes=15)
    later = frozen + timedelta(hours=1)
    fresh_at = frozen - timedelta(minutes=10)
    noise_at = frozen - timedelta(minutes=1)
    rows = [
        {"id": "zz-older", "domain": "zz-exact.example", "observed": frozen - timedelta(minutes=14), "expires": later},
        {"id": "zz-fresh", "domain": "zz-exact.example", "observed": fresh_at, "expires": later},
        {"id": "zz-expired", "domain": "zz-exact.example", "observed": frozen - timedelta(seconds=30), "expires": frozen},
        {"id": "zz-ahead", "domain": "zz-exact.example", "observed": frozen + timedelta(minutes=5), "expires": later},
        {"id": "zz-foreign", "domain": "zz-exact.example", "observed": frozen - timedelta(seconds=1),
         "expires": later, "integration_id": "json-only"},
        {"id": "zz-tie-a", "domain": "zz-tie.example", "observed": fresh_at, "expires": later},
        {"id": "zz-tie-b", "domain": "zz-tie.example", "observed": fresh_at, "expires": later},
        {"id": "zz-stale", "domain": "zz-stale.example", "observed": frozen - timedelta(minutes=20), "expires": later},
        {"id": "zz-stale-child", "domain": "www.zz-stale.example", "observed": fresh_at, "expires": later},
        {"id": "zz-child", "domain": "www.zz-kin.example", "observed": fresh_at, "expires": later},
        {"id": "zz-parent", "domain": "zz-root", "observed": fresh_at, "expires": later},
        {"id": "zz-suffix", "domain": "zz-pub", "observed": fresh_at, "expires": later},
        {"id": "zz-sibling", "domain": "right.zz-pair.zz-only", "observed": fresh_at, "expires": later},
        {"id": "zz-glued", "domain": "notzz-glued.zz-only", "observed": fresh_at, "expires": later},
        {"id": "zz-later-child", "domain": "www.zz-later.zz-only", "observed": frozen + timedelta(minutes=5),
         "expires": later},
        {"id": "zz-ahead-only", "domain": "zz-ahead.zz-only", "observed": frozen + timedelta(minutes=5),
         "expires": later},
        {"id": "zz-wild", "domain": "exXample.zz-wild", "observed": fresh_at, "expires": later},
        {"id": "zz-edge", "domain": "zz-edge.example", "observed": window, "expires": later},
        {"id": "zz-early", "domain": "zz-early.example", "observed": window - timedelta(seconds=1), "expires": later},
        {"id": "zz-now", "domain": "zz-now.example", "observed": frozen, "expires": later},
        {"id": "zz-ending", "domain": "zz-ending.example", "observed": frozen - timedelta(minutes=1), "expires": frozen},
        {"id": "zz-empty", "domain": "zz-empty.example", "observed": fresh_at, "expires": later},
    ]
    rows.extend(
        {"id": f"zz-noise-{number:03d}", "domain": f"n{number:03d}.zz-noise.test", "observed": noise_at, "expires": later}
        for number in range(300))
    seen = []
    real_match = statements._match

    def watch(db, name):
        before = {id(obj) for obj in db.identity_map.values() if isinstance(obj, Observation)}
        chosen, outcome = real_match(db, name)
        loaded = [obj for obj in db.identity_map.values() if isinstance(obj, Observation) and id(obj) not in before]
        seen.append((name, outcome, len(loaded), None if chosen is None else chosen.id))
        return chosen, outcome

    monkeypatch.setattr(statements, "_match", watch)

    def expect(client, headers, domain, outcome, block=None):
        clear_quota(app)
        answer = ask(client, headers, domain)
        assert seen[-1][0] == domain and seen[-1][1] == outcome and seen[-1][2] == (1 if outcome == "filed" else 0)
        if outcome == "filed":
            assert answer.status_code == 201, answer.text
            assert seen[-1][3] == block
            with app.state.session_factory() as db:
                assert db.scalar(select(AccessRequest).where(AccessRequest.domain == domain)).block_id == block
        else:
            assert answer.status_code == 200 and answer.json() == {"matched": False, "message": MISSED}
            assert stated(app)[-1].details["outcome"] == outcome and filed_for(app, domain) == []

    with TestClient(app) as client:
        _blocks(app, rows)
        headers = signin(client, member=True)
        expect(client, headers, "zz-exact.example", "filed", "zz-fresh")
        expect(client, headers, "zz-tie.example", "filed", "zz-tie-b")
        expect(client, headers, "zz-edge.example", "filed", "zz-edge")
        expect(client, headers, "zz-now.example", "filed", "zz-now")
        expect(client, headers, "zz-stale.example", "stale")
        expect(client, headers, "zz-early.example", "stale")
        expect(client, headers, "zz-kin.example", "not_exact")
        expect(client, headers, "leaf.zz-root", "not_exact")
        expect(client, headers, "leaf.zz-pub", "not_exact")
        expect(client, headers, "left.zz-pair.zz-only", "miss")
        expect(client, headers, "zz-glued.zz-only", "miss")
        expect(client, headers, "zz-later.zz-only", "miss")
        expect(client, headers, "zz-ahead.zz-only", "stale")
        expect(client, headers, "zz-ending.example", "stale")
        real_capability = statements.registry.with_capability
        monkeypatch.setattr(statements.registry, "with_capability", lambda capability: [])
        expect(client, headers, "zz-empty.example", "miss")
        monkeypatch.setattr(statements.registry, "with_capability", real_capability)
        expect(client, headers, "zz-empty.example", "filed", "zz-empty")
        with app.state.session_factory() as db:
            # `_` is a LIKE wildcard. The same stored row must not become a match.
            like_hit = db.scalar(select(Observation.id).where(Observation.domain.like("ex_ample.zz-wild")))
            assert like_hit == "zz-wild"
            chosen, outcome = statements._match(db, "ex_ample.zz-wild")
            assert chosen is None and outcome == "miss"
    assert seen and all(count <= 1 for _name, _outcome, count, _chosen in seen)


class _Closable:
    """A stand-in session. These cases check when close runs, not a database."""

    def __init__(self, order, loop_ident):
        self.order = order
        self.loop_ident = loop_ident

    def close(self):
        self.order.append("close")
        self.loop_ident["close"] = threading.get_ident()


def test_a_cancelled_request_wakes_when_the_pool_ends_before_the_call(monkeypatch):
    """A cancelled sign-in, already waiting, finishes when the pool task fails before the call.

    The lookup is never called. asyncio.wait reports the request done, and that
    result is read before any later cancel. The session is closed afterwards,
    off the event loop.
    """
    order = []
    idents = {}
    release = asyncio.Event()
    parked = asyncio.Event()
    real_pool = statements.run_in_threadpool
    first = {"open": True}

    async def fail_first(func, *args):
        if first["open"]:
            first["open"] = False
            parked.set()
            await release.wait()
            order.append("pool-end")
            raise RuntimeError("pool ended before the call")
        return await real_pool(func, *args)

    def auth(request, db):
        order.append("auth")
        return None, None

    monkeypatch.setattr(statements, "run_in_threadpool", fail_first)
    monkeypatch.setattr(statements, "authenticate", auth)

    async def scenario():
        loop = asyncio.get_running_loop()
        idents["loop"] = threading.get_ident()
        member = asyncio.create_task(statements.signed_member(object(), _Closable(order, idents)))
        try:
            await asyncio.wait_for(parked.wait(), 2)
            member.cancel()
            for _ in range(8):
                await asyncio.sleep(0)
            assert not member.done()
            assert member.cancelling() == 0
            assert order == []
            release.set()
            finished, pending = await asyncio.wait({member}, timeout=1)
            assert member in finished and member not in pending
            assert member.cancelling() == 0
            with pytest.raises(asyncio.CancelledError):
                await member
            assert order == ["pool-end", "close"]
            assert idents["close"] != idents["loop"]
            assert asyncio.get_running_loop() is loop
        finally:
            release.set()
            if not member.done():
                member.cancel()
                await asyncio.wait({member}, timeout=1)

    asyncio.run(asyncio.wait_for(scenario(), 5))


def test_ending_the_pool_task_during_the_call_does_not_close_the_session(monkeypatch):
    """The session stays open when the pool task ends while sign-in is still inside the worker.

    The request is already cancelled and waiting. asyncio.wait leaves it pending
    across that pool-task cancel, and does not cancel it. Close runs only after
    the worker returns, on another thread, on the same loop.
    """
    order = []
    idents = {}
    entered = threading.Event()
    release = threading.Event()
    real_pool = statements.run_in_threadpool
    seen = {}

    async def capture(func, *args):
        seen.setdefault("work", asyncio.current_task())
        return await real_pool(func, *args)

    def auth(request, db):
        order.append("in")
        entered.set()
        if not release.wait(3):
            raise TimeoutError("the sign-in wait was not released")
        order.append("out")
        return None, None

    monkeypatch.setattr(statements, "run_in_threadpool", capture)
    monkeypatch.setattr(statements, "authenticate", auth)

    async def scenario():
        loop = asyncio.get_running_loop()
        idents["loop"] = threading.get_ident()
        member = asyncio.create_task(statements.signed_member(object(), _Closable(order, idents)))
        try:
            assert await asyncio.to_thread(entered.wait, 2)
            member.cancel()
            for _ in range(8):
                await asyncio.sleep(0)
            assert not member.done()
            assert member.cancelling() == 0
            assert order == ["in"]
            work = seen["work"]
            work.cancel()
            for _ in range(8):
                await asyncio.sleep(0)
            assert work.done()
            assert not member.done()
            assert order == ["in"]
            finished, pending = await asyncio.wait({member}, timeout=0.4)
            assert member in pending and member not in finished
            assert not member.done()
            assert member.cancelling() == 0
            assert order == ["in"]
            release.set()
            finished, pending = await asyncio.wait({member}, timeout=2)
            assert member in finished and member not in pending
            with pytest.raises(asyncio.CancelledError):
                await member
            assert order == ["in", "out", "close"]
            assert idents["close"] != idents["loop"]
            assert asyncio.get_running_loop() is loop
        finally:
            release.set()
            if not member.done():
                member.cancel()
                await asyncio.wait({member}, timeout=2)

    asyncio.run(asyncio.wait_for(scenario(), 8))
