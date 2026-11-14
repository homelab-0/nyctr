"""Screens say what they do not know: the facts the pages need, and who may read them."""

from datetime import timedelta

from conftest import LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import update

from nyctr.integrations import registry
from nyctr.models import Integration, Observation, Resource, utcnow


def test_finding_checks_follow_the_sources_connected(tmp_path):
    """A check with no source to look at is marked, and collected kinds no rule reads are listed."""
    app = live_app(tmp_path)
    with TestClient(app) as client:
        assert client.get("/api/findings/checks").status_code == 401
        seed_live_member(app)
        with app.state.session_factory() as db:
            db.add(Resource(id="rule-1", integration_id="unifi", name="Block IoT to LAN", kind="policy",
                            provider="unifi_network", source_id="rule-1", observed_at=utcnow(),
                            evidence_kind="configured", attributes={}))
            db.commit()
        live_signin(client, LIVE_MEMBER)
        assert client.get("/api/findings/checks").status_code == 403
        live_signin(client)
        body = client.get("/api/findings/checks").json()
        active = {row["text"]: row["active"] for row in body["checks"]}
        assert len(active) == 4
        assert active["A DNS profile with logging switched off"] is True
        assert active["A hosted workload whose firewall is switched off"] is False
        with app.state.session_factory() as db:
            db.execute(update(Integration).values(last_sync=None))
            db.commit()
        assert not any(row["active"] for row in client.get("/api/findings/checks").json()["checks"])
        assert "Firewall rules" in body["not_checked"]
        assert "Hosts and bridges" not in body["not_checked"]


def test_catalog_carries_what_each_kind_of_source_never_gives(client, admin_headers):
    """Declared gaps travel in the catalog, so pages word them without knowing a vendor."""
    listed = {row["id"]: row for row in client.get("/api/integrations/catalog").json()["providers"]}
    for provider in registry.providers().values():
        limits = [(row["id"], row["title"], row["summary"]) for row in listed[provider.id]["limits"]]
        assert limits == list(provider.gaps)
        assert listed[provider.id]["not_collected"] == list(provider.not_collected)
    # Only blocked lookups are stored, so every source of them says the allowed ones are not collected.
    for provider in registry.providers().values():
        if "dns.blocks" in provider.provides:
            assert "DNS lookups that were allowed" in listed[provider.id]["not_collected"]


def test_block_coverage_needs_a_session_and_gives_two_words_only(client):
    """Signed out it is refused; signed in it is one word and a yes or no, with no source, count, address or device."""
    assert client.get("/api/blocks/coverage").status_code == 401
    client.post("/api/auth/login", json={"email": "jamie@nyctr.demo", "password": "nyctr-demo"})
    body = client.get("/api/blocks/coverage").json()
    assert body == {"collected": "yes", "unassigned": True}


def _coverage(app, client):
    """Return a helper that changes every source, then reads the member route."""
    def answer(**values):
        with app.state.session_factory() as db:
            if values:
                db.execute(update(Integration).values(**values))
            db.commit()
        return client.get("/api/blocks/coverage").json()
    return answer


def test_block_coverage_tells_not_collected_and_failed_from_nothing_blocked(tmp_path):
    """A source that never stored a collection is not the same as a quiet one, and a failure is named."""
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        live_signin(client, LIVE_MEMBER)
        answer = _coverage(app, client)
        assert answer() == {"collected": "yes", "unassigned": False}
        # A second source still waiting for its first collection: its blocked lookups are not known yet.
        with app.state.session_factory() as db:
            db.add(Integration(id="dns2", provider="nextdns", name="Second DNS", config={"profile_id": "def456"},
                               secret_ref="NYCTR_CONNECTOR_SECRET_DNS", status="configured"))
            db.commit()
        assert answer()["collected"] == "no"
        assert answer(last_sync=None)["collected"] == "no"
        assert answer(last_sync=None, last_error="The source refused the key")["collected"] == "failed"
        with app.state.session_factory() as db:
            for row in db.query(Observation):
                db.delete(row)
            for row in db.query(Integration):
                row.provider = "not_a_dns_source"
            db.commit()
        assert client.get("/api/blocks/coverage").json() == {"collected": "none", "unassigned": False}


def test_block_coverage_is_failed_while_a_source_that_once_collected_is_failing(tmp_path):
    """An old collection does not make a failing source collected, so a member is never told nothing was blocked."""
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        live_signin(client, LIVE_MEMBER)
        answer = _coverage(app, client)
        # Collected two days ago, refused since: the stored lookups have expired and none is left.
        with app.state.session_factory() as db:
            for row in db.query(Observation):
                db.delete(row)
            db.commit()
        assert client.get("/api/blocks").json()["rows"] == []
        failing = answer(last_sync=utcnow() - timedelta(days=2), last_error="The source refused the key")
        assert failing == {"collected": "failed", "unassigned": False}
        # A retry is waiting, so the status is not "error" yet; the failure still counts.
        assert answer(status="connected")["collected"] == "failed"
        assert answer(status="error", last_error=None)["collected"] == "failed"
        assert answer(status="connected", last_error=None)["collected"] == "yes"


def test_block_coverage_counts_only_stored_lookups_no_member_could_be_shown(tmp_path):
    """A lookup assigned to no device says one may be missing; an expired one, or an assigned one, does not."""
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        live_signin(client, LIVE_MEMBER)
        answer = _coverage(app, client)

        def lookups(**values):
            with app.state.session_factory() as db:
                db.execute(update(Observation).values(**values))
                db.commit()
            return answer()

        assert answer()["unassigned"] is False
        # The source stops naming devices: the member's list empties, and the reason is given.
        assert lookups(device_id=None, attribution="unattributed")["unassigned"] is True
        assert client.get("/api/blocks").json()["rows"] == []
        # A tie Nyctr only inferred has a device, but no member is shown it, so it counts the same.
        assert lookups(device_id="unifi:client:laptop", attribution="inferred")["unassigned"] is True
        assert client.get("/api/blocks").json()["rows"] == []
        # Once it has expired it is no longer stored evidence of anything.
        assert lookups(expires_at=utcnow() - timedelta(minutes=1))["unassigned"] is False


def test_block_coverage_does_not_change_when_another_person_has_a_site_blocked(tmp_path):
    """A member with no devices gets the same answer before and after a lookup is assigned to someone else's device."""
    from nyctr.models import User
    from nyctr.security import hash_password

    other = ("pat@example.net", "a different secure password")
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        with app.state.session_factory() as db:
            db.add(User(id="pat", email=other[0], name="Pat", role="member", password_hash=hash_password(other[1])))
            for row in db.query(Observation):
                db.delete(row)
            db.commit()
        live_signin(client, other)
        assert client.get("/api/devices").json() == []
        before = client.get("/api/blocks/coverage").json()
        assert before == {"collected": "yes", "unassigned": False}
        now = utcnow()
        with app.state.session_factory() as db:
            db.add(Observation(id="dns:block:two", integration_id="dns", device_id="unifi:client:laptop",
                               device_name="Sam's laptop", domain="blocked.example", source="nextdns",
                               reason="On a block list", reason_codes=[], observed_at=now,
                               expires_at=now + timedelta(hours=20), evidence_kind="observed",
                               attribution="assigned", risk_score=None, risk_explanation=""))
            db.commit()
        assert client.get("/api/blocks").json()["rows"] == []
        assert client.get("/api/blocks/coverage").json() == before
        # The person whose device it is sees the lookup, and gets the same two answers.
        live_signin(client, LIVE_MEMBER)
        assert [row["domain"] for row in client.get("/api/blocks").json()["rows"]] == ["blocked.example"]
        assert client.get("/api/blocks/coverage").json() == before
