"""Screens say what they do not know: the facts the pages need, and who may read them."""

from conftest import LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import update

from nyctr.integrations import registry
from nyctr.models import Integration, Resource, utcnow


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
