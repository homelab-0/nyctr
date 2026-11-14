import pytest
from fastapi.testclient import TestClient

from nyctr.config import Settings
from nyctr.main import create_app


@pytest.fixture
def app():
    """Provide an isolated demo API with in-memory SQLite and test-origin cookies."""
    return create_app(Settings(mode="demo", database_url="sqlite:///:memory:",
                               public_url="http://testserver", cookie_secure=False))


@pytest.fixture
def client(app):
    """Run the API lifespan around a synchronous HTTP test client."""
    with TestClient(app) as c:
        yield c


def signin(client, member=False):
    """Authenticate a demo admin or member and return its valid mutation CSRF header."""
    response = client.post("/api/auth/login", json={"email": "jamie@nyctr.demo" if member else "admin@nyctr.demo",
                                                    "password": "nyctr-demo"})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


@pytest.fixture
def admin_headers(client):
    """Provide an administrator session and its CSRF header to a test."""
    return signin(client)


@pytest.fixture
def member_headers(client):
    """Provide a member session and its CSRF header to a test."""
    return signin(client, member=True)


LIVE_ADMIN = ("owner@example.net", "secure password for tests")
LIVE_MEMBER = ("sam@example.net", "another secure password")


def live_app(tmp_path, **overrides):
    """Build a live-mode API on a throwaway SQLite file with a bootstrap administrator."""
    values = {"mode": "live", "database_url": f"sqlite:///{tmp_path}/live.db", "public_url": "http://testserver",
              "cookie_secure": False, "bootstrap_admin_email": LIVE_ADMIN[0],
              "bootstrap_admin_password": LIVE_ADMIN[1], "worker_enabled": False}
    values.update(overrides)
    return create_app(Settings(**values))


def live_signin(client, who=LIVE_ADMIN):
    """Sign a live user in and return the CSRF header for mutations."""
    response = client.post("/api/auth/login", json={"email": who[0], "password": who[1]})
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


def seed_live_member(app, *, reason="HaGeZi Multi PRO++", codes=("blocklist:hagezi-multi-pro-plusplus",),
                     domain="click.proofing-studio.example"):
    """Insert a NextDNS source, one member with one personal device, and one fresh attributed block."""
    from datetime import timedelta

    from nyctr.models import DeviceGrant, Integration, Observation, Resource, User, utcnow
    from nyctr.security import hash_password

    now = utcnow()
    with app.state.session_factory() as db:
        # Both have collected once: Nyctr changes nothing at a source it has never collected from.
        db.add(Integration(id="dns", provider="nextdns", name="Office DNS", config={"profile_id": "abc123"},
                           secret_ref="NYCTR_CONNECTOR_SECRET_DNS", status="connected", last_sync=now))
        db.add(Integration(id="unifi", provider="unifi_network", name="UniFi", status="connected", last_sync=now,
                           config={"base_url": "https://unifi.example/proxy/network/integration"},
                           secret_ref="NYCTR_CONNECTOR_SECRET_UNIFI"))
        db.add(User(id="sam", email=LIVE_MEMBER[0], name="Sam", role="member",
                    password_hash=hash_password(LIVE_MEMBER[1])))
        db.flush()
        db.add(Resource(id="unifi:client:laptop", integration_id="unifi", name="Sam's laptop", kind="client",
                        provider="unifi_network", source_id="laptop", site_id=None, observed_at=now,
                        evidence_kind="observed", classification="personal", owner_id="sam",
                        attributes={"ip": "10.0.0.9"}))
        db.flush()
        db.add(DeviceGrant(device_id="unifi:client:laptop", user_id="sam", valid_from=now - timedelta(days=1)))
        db.add(Observation(id="dns:block:one", integration_id="dns", device_id="unifi:client:laptop",
                           device_name="Sam's laptop", domain=domain, source="nextdns", reason=reason,
                           reason_codes=list(codes), observed_at=now - timedelta(minutes=2),
                           expires_at=now + timedelta(hours=20), evidence_kind="observed",
                           attribution="assigned", risk_score=None, risk_explanation=""))
        db.commit()
