"""A member on a recognised device names a site that did not open."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta

import pytest
from conftest import LIVE_MEMBER, live_app, live_signin, seed_live_member, signin
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from test_presence import KIM, LAPTOP, PHONE, PRINTER, TABLET, browser, change, home, two_sites
from test_tiers import postgres_database

from nyctr import access, presence, statements
from nyctr.access import STATEMENT_WAITING
from nyctr.collection import holder_id
from nyctr.config import Settings
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
OFF = WHY["off"]
# Nothing a statement may repeat from someone else's lookup.
HIDDEN = ("Unknown source device", "downloads.filemirror.example", "Alex's workstation",
          "gallery.imagehost.example", "user-admin")


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
    return create_app(Settings(**values))


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


def test_a_live_tie_lets_a_member_name_a_site_and_recognition_off_does_not(tmp_path):
    """Recognition off refuses. An address outside every collected network refuses too.

    Once the network is on record, recognition ties the member and the statement is filed
    for that device. The stored address is not used while recognition has nothing to name.
    """
    app = live_app(tmp_path)
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
    assign_device(proxy, "gw:client:laptop", "personal", ["sam"])
    with member(proxy, LAPTOP, headers={"X-Forwarded-For": LAPTOP}) as sam:
        refusal(proxy, sam, domain, "proxy", *HIDDEN_DEVICES)
    odd, _gateway = home(tmp_path, monkeypatch, trusted_proxies="198.51.100.1",
                         **live_place(database, tmp_path, request, "malformed"))
    with member(odd, "198.51.100.1", headers={"X-Forwarded-For": "not-an-address"}) as sam:
        refusal(odd, sam, domain, "no_address", *HIDDEN_DEVICES)
    split, split_gateway = home(tmp_path, monkeypatch, **live_place(database, tmp_path, request, "split"))
    two_sites(split, "192.0.2.0/24")
    split_gateway["holds"].update(phone=None, boat=PHONE)
    assign_device(split, "gw:client:phone", "personal", ["sam"])
    with member(split, PHONE) as sam:
        refusal(split, sam, domain, "two_networks", *HIDDEN_DEVICES)


@BOTH
def test_two_devices_of_one_member_keep_separate_requests(tmp_path, database, request, monkeypatch):
    """The same member on two devices gets two requests. A conflict retry stays on the device that asked."""
    app, _gateway = home(tmp_path, monkeypatch, **live_place(database, tmp_path, request, "devices"))
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
