from datetime import timedelta

import pytest
from conftest import signin
from fastapi.testclient import TestClient
from sqlalchemy import select

from nyctr.config import Settings
from nyctr.main import create_app
from nyctr.models import AccessRequest, DeviceGrant, LoginSession, Observation, Resource, utcnow
from nyctr.security import COOKIE_NAME


def test_api_requires_authentication(client):
    assert client.get("/api/health").json()["status"] == "ok"
    for path in ["overview", "resources", "graph", "findings", "integrations", "audit", "devices", "blocks", "requests"]:
        assert client.get("/api/" + path).status_code == 401


def test_real_cookie_session_and_logout_revocation(client, app, admin_headers):
    response = client.get("/api/auth/me")
    assert response.json()["role"] == "admin"
    token = client.cookies.get(COOKIE_NAME)
    with app.state.session_factory() as db:
        session = db.scalar(select(LoginSession))
        assert session.token_hash != token
        assert len(session.token_hash) == 64
    assert client.post("/api/auth/logout").status_code == 403
    assert client.post("/api/auth/logout", headers=admin_headers).status_code == 200
    client.cookies.set(COOKIE_NAME, token)
    assert client.get("/api/auth/me").status_code == 401


def test_invalid_password_and_cookie_are_rejected(client):
    assert client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "incorrect"}).status_code == 401
    client.cookies.set(COOKIE_NAME, "forged-token")
    assert client.get("/api/auth/me").status_code == 401


def test_sign_in_cookie_attributes(client):
    response = client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "nyctr-demo"})
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie


def test_login_origin_protection(client):
    response = client.post("/api/auth/login", headers={"Origin": "https://attacker.invalid"},
                           json={"email": "admin@nyctr.demo", "password": "nyctr-demo"})
    assert response.status_code == 403


def test_password_throttle_is_enforced(client):
    for _ in range(10):
        assert client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "nyctr-demo"}).status_code == 429


def test_member_cannot_access_admin_data(client, member_headers):
    for path in ["overview", "resources", "graph", "findings", "integrations", "audit"]:
        assert client.get("/api/" + path).status_code == 403
    assert client.post("/api/integrations", headers=member_headers, json={
        "provider": "nextdns", "name": "Other profile", "config": {"profile_id": "abc123"},
        "secret_ref": "NYCTR_CONNECTOR_SECRET_HOME"}).status_code == 403


def test_member_sees_only_current_and_event_time_authorized_devices(client, member_headers):
    assert {x["id"] for x in client.get("/api/devices").json()} == {"laptop-jamie", "tablet-family"}
    blocks = client.get("/api/blocks").json()
    assert {x["id"] for x in blocks} == {"block-gallery", "block-tablet"}
    assert all(x["risk_score"] is None for x in blocks)


def test_new_assignment_cannot_expose_historical_blocks(client, app, member_headers):
    with app.state.session_factory() as db:
        resource = db.get(Resource, "old-laptop")
        resource.owner_id = "user-jamie"
        db.add(DeviceGrant(device_id=resource.id, user_id="user-jamie", valid_from=utcnow() - timedelta(minutes=1)))
        # Historical grant ended an hour ago; an intervening event is not visible.
        event = db.get(Observation, "block-old-owner")
        event.observed_at = utcnow() - timedelta(minutes=30)
        db.commit()
    assert "old-laptop" in {x["id"] for x in client.get("/api/devices").json()}
    assert "block-old-owner" not in {x["id"] for x in client.get("/api/blocks").json()}


def test_admin_sees_iot_unattributed_and_other_owners_not_stale(client, admin_headers):
    blocks = {x["id"] for x in client.get("/api/blocks").json()}
    assert {"block-washer", "block-unattributed", "block-admin", "block-old-owner"} <= blocks
    assert "block-expired" not in blocks


def test_expired_observations_are_removed(client, app, admin_headers):
    client.get("/api/blocks")
    with app.state.session_factory() as db:
        assert db.get(Observation, "block-expired") is None


def test_request_checks_csrf_ownership_freshness_and_duration(client, member_headers):
    body = {"block_id": "block-gallery", "reason": "Need to open a family gallery", "duration_minutes": 60}
    assert client.post("/api/requests", json=body).status_code == 403
    for block_id in ["block-washer", "block-admin", "block-unattributed", "block-old-owner"]:
        assert client.post("/api/requests", headers=member_headers, json={**body, "block_id": block_id}).status_code == 404
    assert client.post("/api/requests", headers=member_headers, json={**body, "block_id": "block-expired"}).status_code == 409
    assert client.post("/api/requests", headers=member_headers, json={**body, "duration_minutes": 10000}).status_code == 422


def test_request_idempotence_and_review_never_grant_access(client, app, member_headers):
    body = {"block_id": "block-gallery", "reason": "Need to open a family gallery", "duration_minutes": 60}
    first = client.post("/api/requests", headers=member_headers, json=body)
    assert first.status_code == 201
    request_id = first.json()["id"]
    assert first.json()["status"] == "pending"
    duplicate = client.post("/api/requests", headers=member_headers, json=body)
    assert duplicate.json()["id"] == request_id
    assert client.post(f"/api/requests/{request_id}/review", headers=member_headers,
                        json={"decision": "reviewed", "note": "Looks reasonable"}).status_code == 403
    admin_headers = signin(client)
    assert client.post(f"/api/requests/{request_id}/review", headers=admin_headers,
                        json={"decision": "approved", "note": "Allow access"}).status_code == 422
    reviewed = client.post(f"/api/requests/{request_id}/review", headers=admin_headers,
                            json={"decision": "reviewed", "note": "Evidence reviewed; no infrastructure action"})
    assert reviewed.status_code == 200 and reviewed.json()["status"] == "reviewed"
    events = client.get("/api/audit").json()
    assert any(x["action"] == "access.reviewed" and x["details"]["execution"] == "not_performed" for x in events)
    with app.state.session_factory() as db:
        assert len(list(db.scalars(select(AccessRequest)))) == 1


def test_requests_survive_inbox_expiry_and_remain_private(client, app, member_headers):
    body = {"block_id": "block-gallery", "reason": "Need photos", "duration_minutes": 60}
    request_id = client.post("/api/requests", headers=member_headers, json=body).json()["id"]
    with app.state.session_factory() as db:
        db.get(Observation, "block-gallery").expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    client.get("/api/blocks")
    assert client.get("/api/requests").json()[0]["id"] == request_id
    headers = signin(client)
    client.post("/api/requests", headers=headers,
                json={"block_id": "block-admin", "reason": "Need software", "duration_minutes": 30})
    signin(client, member=True)
    assert len(client.get("/api/requests").json()) == 1


def test_graph_focus_is_bounded_and_exposes_evidence(client, admin_headers):
    full = client.get("/api/graph").json()
    focused = client.get("/api/graph?focus=workload-photos&depth=1").json()
    assert len(focused["nodes"]) < len(full["nodes"])
    assert {x["id"] for x in focused["nodes"]} == {"workload-photos", "host-compute"}
    assert all("evidence_kind" in e for e in full["edges"])
    assert client.get("/api/graph?depth=99").status_code == 422
    assert client.get("/api/graph?focus=missing").status_code == 404


def test_demo_cannot_create_or_sync_live_connectors(client, admin_headers):
    assert client.post("/api/integrations", headers=admin_headers, json={
        "provider": "nextdns", "name": "Live", "config": {"profile_id": "abc123"},
        "secret_ref": "NYCTR_CONNECTOR_SECRET_HOME"}).status_code == 409
    assert client.post("/api/integrations/demo-nextdns/sync", headers=admin_headers).status_code == 409


def test_assignment_revokes_access_and_history_is_not_backdated(client, admin_headers):
    response = client.put("/api/devices/laptop-jamie/assignment", headers=admin_headers,
                          json={"classification": "personal", "user_ids": ["user-admin"]})
    assert response.status_code == 200
    signin(client, member=True)
    assert "block-gallery" not in {x["id"] for x in client.get("/api/blocks").json()}


def test_live_requires_bootstrap_and_has_no_demo_data(tmp_path):
    settings = Settings(mode="live", database_url=f"sqlite:///{tmp_path / 'live.db'}",
                        public_url="http://testserver", cookie_secure=False)
    with pytest.raises(RuntimeError, match="Configure NYCTR_BOOTSTRAP"):
        with TestClient(create_app(settings)):
            pass
    settings.bootstrap_admin_email = "owner@example.net"
    settings.bootstrap_admin_password = "correct horse battery staple"
    with TestClient(create_app(settings)) as client:
        assert client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "nyctr-demo"}).status_code == 401
        login = client.post("/api/auth/login", json={"email": "owner@example.net", "password": settings.bootstrap_admin_password})
        assert login.status_code == 200
        assert client.get("/api/resources").json() == []
        assert client.get("/api/findings").json() == []
        assert client.get("/api/integrations").json() == []


def test_demo_database_cannot_be_promoted_to_live(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'isolation.db'}"
    with TestClient(create_app(Settings(mode="demo", database_url=database_url))):
        pass
    with pytest.raises(RuntimeError, match="mode mismatch"):
        with TestClient(create_app(Settings(mode="live", database_url=database_url))):
            pass


def test_unknown_api_stays_json_404_with_static_site(tmp_path):
    (tmp_path / "index.html").write_text("<html>Nyctr</html>")
    settings = Settings(mode="demo", database_url="sqlite:///:memory:", static_dir=str(tmp_path))
    with TestClient(create_app(settings)) as client:
        assert client.get("/").status_code == 200
        assert client.get("/api/not-a-route").status_code == 404
        assert client.get("/api/not-a-route").headers["content-type"].startswith("application/json")


def test_credentials_not_returned_and_unsafe_secret_reference_rejected(tmp_path, monkeypatch):
    settings = Settings(mode="live", database_url=f"sqlite:///{tmp_path / 'live.db'}", cookie_secure=False,
                        bootstrap_admin_email="owner@example.net", bootstrap_admin_password="secure admin password")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_HOME", "super-secret-key")
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/auth/login", json={"email": settings.bootstrap_admin_email,
                                                     "password": settings.bootstrap_admin_password})
        headers = {"X-CSRF-Token": login.json()["csrf_token"]}
        body = {"provider": "nextdns", "name": "Home DNS", "config": {"profile_id": "abc123"},
                "secret_ref": "NYCTR_CONNECTOR_SECRET_HOME"}
        created = client.post("/api/integrations", headers=headers, json=body)
        assert created.status_code == 201, created.text
        assert "super-secret-key" not in created.text
        assert "super-secret-key" not in client.get("/api/integrations").text
        assert client.post("/api/integrations", headers=headers, json={**body, "secret_ref": "NYCTR_BOOTSTRAP_ADMIN_PASSWORD"}).status_code == 422


def test_invalid_settings_never_print_credentials():
    with pytest.raises(ValueError) as error:
        Settings(mode="live", bootstrap_admin_password="BOOTSTRAP_SENTINEL_SECRET",
                 oidc_client_secret="OIDC_SENTINEL_SECRET")
    assert "BOOTSTRAP_SENTINEL_SECRET" not in str(error.value)
    assert "OIDC_SENTINEL_SECRET" not in str(error.value)


def test_chunked_body_without_content_length_is_bounded(client):
    def chunks():
        yield b'{"email":"'
        for _ in range(5):
            yield b"x" * 8192
        yield b'","password":"secret"}'
    result = client.post("/api/auth/login", content=chunks(), headers={"Content-Type": "application/json"})
    assert "content-length" not in result.request.headers
    assert result.status_code == 413
    assert result.json() == {"detail": "Request body is too large"}


def test_concurrent_password_attempts_cannot_bypass_atomic_quota(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    settings = Settings(mode="demo", database_url=f"sqlite:///{tmp_path / 'concurrent.db'}")
    with TestClient(create_app(settings)) as client:
        def attempt(_):
            return client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "wrong"}).status_code
        with ThreadPoolExecutor(max_workers=16) as workers:
            statuses = list(workers.map(attempt, range(24)))
        assert statuses.count(401) == 10
        assert statuses.count(429) == 14
