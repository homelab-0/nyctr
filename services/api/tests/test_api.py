from datetime import timedelta

import pytest
from conftest import signin
from fastapi.testclient import TestClient
from sqlalchemy import select

from nyctr.config import Settings
from nyctr.main import create_app
from nyctr.models import AccessRequest, DeviceGrant, Lease, LoginSession, Observation, Resource, utcnow
from nyctr.security import COOKIE_NAME


def test_api_requires_authentication(client):
    """Business endpoints must reject anonymous requests while health remains public."""
    assert client.get("/api/health").json()["status"] == "ok"
    for path in ["overview", "resources", "graph", "findings", "integrations", "audit", "devices", "blocks", "requests"]:
        assert client.get("/api/" + path).status_code == 401


def test_real_cookie_session_and_logout_revocation(client, app, admin_headers):
    """Sessions store token hashes, require logout CSRF, and reject a replayed revoked cookie."""
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
    """Wrong credentials and fabricated session tokens must never establish identity."""
    assert client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "incorrect"}).status_code == 401
    client.cookies.set(COOKIE_NAME, "forged-token")
    assert client.get("/api/auth/me").status_code == 401


def test_sign_in_cookie_attributes(client):
    """Session cookies must be HTTP-only, SameSite=Lax, and scoped to the application root."""
    response = client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "nyctr-demo"})
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie


def test_login_origin_protection(client):
    """A foreign browser origin must not establish a local authenticated session."""
    response = client.post("/api/auth/login", headers={"Origin": "https://attacker.invalid"},
                           json={"email": "admin@nyctr.demo", "password": "nyctr-demo"})
    assert response.status_code == 403


def test_password_throttle_is_enforced(client):
    """Ten failed attempts exhaust the account window before a correct password is checked."""
    for _ in range(10):
        assert client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "wrong"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "nyctr-demo"}).status_code == 429


def test_member_cannot_access_admin_data(client, member_headers):
    """Member sessions cannot inspect workspace-wide data or configure integrations."""
    for path in ["overview", "resources", "graph", "findings", "integrations", "audit"]:
        assert client.get("/api/" + path).status_code == 403
    assert client.post("/api/integrations", headers=member_headers, json={
        "provider": "nextdns", "name": "Other profile", "config": {"profile_id": "abc123"},
        "secret_ref": "NYCTR_CONNECTOR_SECRET_HOME"}).status_code == 403


def test_member_sees_only_current_and_event_time_authorized_devices(client, member_headers):
    """The member inbox includes only owned/shared devices; guest, admin and unattributed events stay hidden."""
    assert {x["id"] for x in client.get("/api/devices").json()} == {"laptop-jamie", "tablet-family"}
    blocks = client.get("/api/blocks").json()
    assert {x["id"] for x in blocks} == {"block-gallery", "block-tablet", "block-fonts", "block-verify",
                                         "block-stream", "block-print"}
    assert {x["device_id"] for x in blocks} == {"laptop-jamie", "tablet-family"}


def test_new_assignment_cannot_expose_historical_blocks(client, app, member_headers):
    """A current grant cannot expose an event from an intervening unauthorized ownership period."""
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
    """Administrator scope includes infrastructure and unknown origins but excludes expired events."""
    blocks = {x["id"] for x in client.get("/api/blocks").json()}
    assert {"block-washer", "block-unattributed", "block-admin", "block-old-owner"} <= blocks
    assert "block-expired" not in blocks


def test_expired_observations_are_removed(client, app, admin_headers):
    """Reading the inbox physically removes observations whose retention window has expired."""
    client.get("/api/blocks")
    with app.state.session_factory() as db:
        assert db.get(Observation, "block-expired") is None


def test_request_checks_csrf_ownership_freshness_and_duration(client, member_headers):
    """Request creation must enforce CSRF, event visibility, freshness, and duration limits."""
    body = {"block_id": "block-gallery", "reason": "Need to open a family gallery", "duration_minutes": 60}
    assert client.post("/api/requests", json=body).status_code == 403
    for block_id in ["block-washer", "block-admin", "block-unattributed", "block-old-owner"]:
        assert client.post("/api/requests", headers=member_headers, json={**body, "block_id": block_id}).status_code == 404
    assert client.post("/api/requests", headers=member_headers, json={**body, "block_id": "block-expired"}).status_code == 409
    assert client.post("/api/requests", headers=member_headers, json={**body, "duration_minutes": 10000}).status_code == 422


def test_request_idempotence_and_review_never_grant_access(client, app, member_headers):
    """Duplicate submissions share one request and a `reviewed` decision never becomes a grant."""
    body = {"block_id": "block-tablet", "reason": "Need to open a family gallery", "duration_minutes": 60}
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
                        json={"decision": "granted", "note": "Allow access"}).status_code == 422
    reviewed = client.post(f"/api/requests/{request_id}/review", headers=admin_headers,
                            json={"decision": "reviewed", "note": "Evidence reviewed; no infrastructure action"})
    assert reviewed.status_code == 200 and reviewed.json()["status"] == "reviewed"
    events = client.get("/api/audit").json()
    assert any(x["action"] == "access.reviewed" and x["details"]["execution"] == "not_performed" for x in events)
    with app.state.session_factory() as db:
        assert {r.id for r in db.scalars(select(AccessRequest))} == {request_id, "request-stream"}
        assert not list(db.scalars(select(Lease).where(Lease.request_id == request_id)))


def test_requests_survive_inbox_expiry_and_remain_private(client, app, member_headers):
    """Request snapshots survive observation cleanup and remain scoped to their requester."""
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
    assert {r["id"] for r in client.get("/api/requests").json()} == {request_id, "request-stream"}


def test_graph_focus_is_bounded_and_exposes_evidence(client, admin_headers):
    """Focused graph queries enforce hop limits and preserve relationship evidence metadata."""
    full = client.get("/api/graph").json()
    focused = client.get("/api/graph?focus=workload-photos&depth=1").json()
    assert len(focused["nodes"]) < len(full["nodes"])
    # The bridge and host are configured; the Servers network is inferred from the card's VLAN tag.
    assert {x["id"] for x in focused["nodes"]} == {"workload-photos", "host-compute", "bridge-vmbr0",
                                                   "network-servers"}
    inferred = [e for e in focused["edges"] if e["evidence_kind"] == "inferred"]
    assert [e["target"] for e in inferred] == ["network-servers"] and inferred[0]["provider"] == "nyctr"
    assert all("evidence_kind" in e for e in full["edges"])
    assert client.get("/api/graph?depth=99").status_code == 422
    assert client.get("/api/graph?focus=missing").status_code == 404


def test_demo_cannot_create_or_sync_live_connectors(client, admin_headers):
    """Known demo credentials must not configure or invoke a live provider collector."""
    assert client.post("/api/integrations", headers=admin_headers, json={
        "provider": "nextdns", "name": "Live", "config": {"profile_id": "abc123"},
        "secret_ref": "NYCTR_CONNECTOR_SECRET_HOME"}).status_code == 409
    assert client.post("/api/integrations/demo-nextdns/sync", headers=admin_headers).status_code == 409


def test_assignment_revokes_access_and_history_is_not_backdated(client, admin_headers):
    """Reassigning a personal device immediately removes the former owner inbox visibility."""
    response = client.put("/api/devices/laptop-jamie/assignment", headers=admin_headers,
                          json={"classification": "personal", "user_ids": ["user-admin"]})
    assert response.status_code == 200
    signin(client, member=True)
    assert "block-gallery" not in {x["id"] for x in client.get("/api/blocks").json()}


def test_live_requires_bootstrap_and_has_no_demo_data(tmp_path):
    """Live startup requires configured identity and never imports demo accounts or network evidence."""
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
    """A database containing demo identities must be rejected when started in live mode."""
    database_url = f"sqlite:///{tmp_path / 'isolation.db'}"
    with TestClient(create_app(Settings(mode="demo", database_url=database_url))):
        pass
    with pytest.raises(RuntimeError, match="mode mismatch"):
        with TestClient(create_app(Settings(mode="live", database_url=database_url))):
            pass


def test_unknown_api_stays_json_404_with_static_site(tmp_path):
    """Serving the frontend must not turn a missing API route into an HTML success response."""
    (tmp_path / "index.html").write_text("<html>Nyctr</html>")
    settings = Settings(mode="demo", database_url="sqlite:///:memory:", static_dir=str(tmp_path))
    with TestClient(create_app(settings)) as client:
        assert client.get("/").status_code == 200
        assert client.get("/api/not-a-route").status_code == 404
        assert client.get("/api/not-a-route").headers["content-type"].startswith("application/json")


def test_credentials_not_returned_and_unsafe_secret_reference_rejected(tmp_path, monkeypatch):
    """Connector responses omit credential values and reject access to unrelated environment secrets."""
    settings = Settings(mode="live", database_url=f"sqlite:///{tmp_path / 'live.db'}", cookie_secure=False,
                        bootstrap_admin_email="owner@example.net", bootstrap_admin_password="secure admin password")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_HOME", "super-secret-key")
    with TestClient(create_app(settings)) as client:
        login = client.post("/api/auth/login", json={"email": settings.bootstrap_admin_email,
                                                     "password": settings.bootstrap_admin_password})
        headers = {"X-CSRF-Token": login.json()["csrf_token"]}
        body = {"provider": "nextdns", "name": "Office DNS", "config": {"profile_id": "abc123"},
                "secret_ref": "NYCTR_CONNECTOR_SECRET_HOME"}
        created = client.post("/api/integrations", headers=headers, json=body)
        assert created.status_code == 201, created.text
        assert "super-secret-key" not in created.text
        assert "super-secret-key" not in client.get("/api/integrations").text
        assert client.post("/api/integrations", headers=headers, json={**body, "secret_ref": "NYCTR_BOOTSTRAP_ADMIN_PASSWORD"}).status_code == 422


def test_invalid_settings_never_print_credentials():
    """Configuration validation messages must not include supplied bootstrap or OIDC secrets."""
    with pytest.raises(ValueError) as error:
        Settings(mode="live", bootstrap_admin_password="BOOTSTRAP_SENTINEL_SECRET",
                 oidc_client_secret="OIDC_SENTINEL_SECRET")
    assert "BOOTSTRAP_SENTINEL_SECRET" not in str(error.value)
    assert "OIDC_SENTINEL_SECRET" not in str(error.value)


def test_chunked_body_without_content_length_is_bounded(client):
    """The actual streamed request size must be capped even when no Content-Length is sent."""
    def chunks():
        """Yield a syntactically shaped JSON body that exceeds the limit across multiple chunks."""
        yield b'{"email":"'
        for _ in range(5):
            yield b"x" * 8192
        yield b'","password":"secret"}'
    result = client.post("/api/auth/login", content=chunks(), headers={"Content-Type": "application/json"})
    assert "content-length" not in result.request.headers
    assert result.status_code == 413
    assert result.json() == {"detail": "Request body is too large"}


def test_concurrent_password_attempts_cannot_bypass_atomic_quota(tmp_path):
    """Parallel first-use attempts must consume exactly the account quota without lost increments."""
    from concurrent.futures import ThreadPoolExecutor

    settings = Settings(mode="demo", database_url=f"sqlite:///{tmp_path / 'concurrent.db'}")
    with TestClient(create_app(settings)) as client:
        def attempt(_):
            """Submit one deliberately invalid password and return its denial status for quota accounting."""
            return client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "wrong"}).status_code
        with ThreadPoolExecutor(max_workers=16) as workers:
            statuses = list(workers.map(attempt, range(24)))
        assert statuses.count(401) == 10
        assert statuses.count(429) == 14


def test_overview_names_what_it_counts_and_the_span_of_stored_blocks(client, admin_headers):
    """Counts come per kind and agree with the inventory; blocked lookups carry the span they cover."""
    overview = client.get("/api/overview").json()
    resources = client.get("/api/resources").json()
    kinds = {}
    for row in resources:
        kinds[row["kind"]] = kinds.get(row["kind"], 0) + 1
    assert overview["kind_counts"] == kinds
    assert sum(overview["kind_counts"].values()) == overview["resource_count"] == len(resources)
    times = sorted(block["observed_at"] for block in client.get("/api/blocks").json())
    assert overview["recent_block_count"] == len(times) > 1
    assert (overview["oldest_block_at"], overview["newest_block_at"]) == (times[0], times[-1])


def test_overview_span_is_empty_when_no_blocked_lookup_is_stored(client, app, admin_headers):
    """With nothing stored the span is absent rather than a made-up window."""
    with app.state.session_factory() as db:
        db.query(AccessRequest).delete()
        db.query(Observation).delete()
        db.commit()
    overview = client.get("/api/overview").json()
    assert overview["recent_block_count"] == 0
    assert overview["oldest_block_at"] is None and overview["newest_block_at"] is None
