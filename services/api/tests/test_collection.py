from datetime import timedelta

from fastapi.testclient import TestClient

from nyctr.config import Settings
from nyctr.integrations import Snapshot
from nyctr.main import create_app
from nyctr.models import Observation, Resource, utcnow


def live_client(tmp_path):
    """Create an isolated live database with explicit bootstrap credentials for collector tests."""
    settings = Settings(mode="live", database_url=f"sqlite:///{tmp_path / 'api.db'}", cookie_secure=False,
                        public_url="http://testserver", bootstrap_admin_email="owner@example.net",
                        bootstrap_admin_password="secure password for tests")
    return TestClient(create_app(settings))


def setup_integration(client):
    """Sign in as the test administrator and persist a NextDNS secret-reference configuration."""
    logged = client.post("/api/auth/login", json={"email": "owner@example.net", "password": "secure password for tests"})
    headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
    row = client.post("/api/integrations", headers=headers, json={"provider": "nextdns", "name": "DNS",
                      "config": {"profile_id": "abc123"}, "secret_ref": "NYCTR_CONNECTOR_SECRET_DNS"}).json()
    return headers, row["id"]


def test_collection_persists_namespaced_evidence_without_claiming_user_attribution(tmp_path, monkeypatch):
    """Collected evidence must persist without assigning an unknown device to a user or leaking its key."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "test-api-key")
    async def collect(provider, integration_id, config, api_key):
        """Return a fabricated profile and unattributed block after checking the resolved credential."""
        assert api_key == "test-api-key"
        now = utcnow()
        return Snapshot(resources=[{"id": integration_id + ":profile", "name": "Home profile", "kind": "dns_profile",
            "provider": provider, "source_id": "abc123", "site_id": None, "observed_at": now.isoformat(),
            "evidence_kind": "configured", "attributes": {}}], relationships=[], capabilities=["dns_configuration"],
            blocks=[{"id": integration_id + ":event", "device_id": None, "device_name": "Unidentified resolver",
                "domain": "example.com", "source": "nextdns", "reason": "Privacy blocklist", "observed_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=24)).isoformat(), "evidence_kind": "observed",
                "attribution": "unattributed", "risk_score": None, "risk_explanation": "Unassessed"}])
    monkeypatch.setattr("nyctr.integrations.collect", collect)
    with live_client(tmp_path) as client:
        headers, id_ = setup_integration(client)
        response = client.post(f"/api/integrations/{id_}/sync", headers=headers)
        assert response.status_code == 200, response.text
        assert client.get("/api/resources").json()[0]["owner_id"] is None
        assert client.get("/api/blocks").json()[0]["attribution"] == "unattributed"
        # The score is rule-based on the stored reason; it never changes who may see the event.
        assert client.get("/api/blocks").json()[0]["risk_category"] == "privacy_list"
        assert "test-api-key" not in client.get("/api/audit").text


def test_replayed_observation_does_not_extend_expiry(tmp_path, monkeypatch):
    """Recollecting an event must preserve its existing shorter inbox expiration."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "test-api-key")
    now = utcnow()
    async def collect(provider, integration_id, config, api_key):
        """Replay the same synthetic observation identifier and source timestamps on every call."""
        return Snapshot(resources=[], relationships=[], capabilities=[], blocks=[{
            "id": integration_id + ":event", "device_id": None, "device_name": "Unknown", "domain": "example.com",
            "source": "nextdns", "reason": "Blocked", "observed_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=24)).isoformat(), "evidence_kind": "observed",
            "attribution": "unattributed", "risk_score": None, "risk_explanation": "Unassessed"}])
    monkeypatch.setattr("nyctr.integrations.collect", collect)
    with live_client(tmp_path) as client:
        headers, id_ = setup_integration(client)
        client.post(f"/api/integrations/{id_}/sync", headers=headers)
        with client.app.state.session_factory() as db:
            event = db.get(Observation, id_ + ":event")
            event.expires_at = now + timedelta(minutes=10)
            db.commit()
        client.post(f"/api/integrations/{id_}/sync", headers=headers)
        assert client.get("/api/blocks").json()[0]["expires_at"].startswith((now + timedelta(minutes=10)).isoformat()[:19])


def test_failed_collection_does_not_destroy_previous_snapshot_or_leak_secret(tmp_path, monkeypatch):
    """Unexpected provider failures must preserve inventory and redact credential-bearing exception text."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "test-api-key")
    async def fail(*args):
        """Simulate an unsafe upstream exception containing the synthetic API key."""
        raise RuntimeError("upstream included test-api-key in an error")
    monkeypatch.setattr("nyctr.integrations.collect", fail)
    with live_client(tmp_path) as client:
        headers, id_ = setup_integration(client)
        with client.app.state.session_factory() as db:
            db.add(Resource(id=id_ + ":old", integration_id=id_, name="Existing profile", kind="dns_profile",
                            provider="nextdns", source_id="old", evidence_kind="configured", observed_at=utcnow()))
            db.commit()
        response = client.post(f"/api/integrations/{id_}/sync", headers=headers)
        assert response.status_code == 502
        assert "test-api-key" not in response.text
        assert "test-api-key" not in client.get("/api/integrations").text
        assert len(client.get("/api/resources").json()) == 1


def test_sync_requires_configured_secret(tmp_path):
    """A stored secret reference without a server-side value must prevent collection."""
    with live_client(tmp_path) as client:
        headers, id_ = setup_integration(client)
        assert client.post(f"/api/integrations/{id_}/sync", headers=headers).status_code == 409
