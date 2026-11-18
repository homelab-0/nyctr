"""A member on a recognised device names a site that did not open.

These cases mount the statement routes on the app they build. The application
that serves requests does not include them.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from conftest import signin
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_tiers import postgres_database

from nyctr import statements
from nyctr.config import Settings
from nyctr.main import create_app
from nyctr.models import (
    AccessRequest,
    Audit,
    DeviceGrant,
    DevicePresence,
    LoginSession,
    Observation,
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
