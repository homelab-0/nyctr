"""Screens say what they do not know: the facts the pages need, and who may read them."""

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
    """Signed out it is refused; signed in it carries no source, count, address or device."""
    assert client.get("/api/blocks/coverage").status_code == 401
    client.post("/api/auth/login", json={"email": "jamie@nyctr.demo", "password": "nyctr-demo"})
    body = client.get("/api/blocks/coverage").json()
    assert body == {"collected": "yes", "devices_named": "some"}


def test_block_coverage_tells_not_collected_and_failed_from_nothing_blocked(tmp_path):
    """A source that never stored a collection is not the same as a quiet one, and a failure is named."""
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        live_signin(client, LIVE_MEMBER)

        def answer(**values):
            with app.state.session_factory() as db:
                if values:
                    db.execute(update(Integration).values(**values))
                db.commit()
            return client.get("/api/blocks/coverage").json()

        assert answer() == {"collected": "yes", "devices_named": "all"}
        # The source stops naming devices: the member's list empties, and the reason is given.
        with app.state.session_factory() as db:
            db.execute(update(Observation).values(device_id=None, attribution="unattributed"))
            db.commit()
        assert client.get("/api/blocks").json() == []
        assert answer() == {"collected": "yes", "devices_named": "none"}
        assert answer(last_sync=None)["collected"] == "no"
        assert answer(last_sync=None, last_error="The source refused the key")["collected"] == "failed"
        with app.state.session_factory() as db:
            for row in db.query(Observation):
                db.delete(row)
            for row in db.query(Integration):
                row.provider = "not_a_dns_source"
            db.commit()
        assert client.get("/api/blocks/coverage").json() == {"collected": "none", "devices_named": "unknown"}
