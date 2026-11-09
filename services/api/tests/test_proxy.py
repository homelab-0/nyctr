"""Exercise Uvicorn's proxy trust boundary together with Nyctr's login quotas."""

from contextlib import contextmanager
from datetime import timedelta

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from uvicorn import Config

from nyctr.models import LoginAttempt, utcnow
from nyctr.security import digest

PROXY = "10.42.0.10"
ATTACKER = "198.51.100.20"
MEMBER = "198.51.100.21"


@contextmanager
def through_uvicorn(app, monkeypatch, *, trusted=PROXY, peer=PROXY):
    """Load the deployed Uvicorn middleware using its real environment setting."""
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", trusted)
    config = Config(app, interface="asgi3", log_config=None)
    config.load()
    with TestClient(config.loaded_app, client=(peer, 45678)) as client:
        yield client


def wrong_password(client, email, forwarded_for):
    """Make a genuine failed login with a caller-selected forwarding header."""
    return client.post("/api/auth/login", headers={"X-Forwarded-For": forwarded_for},
                       json={"email": email, "password": "incorrect"})


def valid_member_login(client, forwarded_for):
    """Authenticate the seeded member through the same proxy and quota path."""
    return client.post("/api/auth/login", headers={"X-Forwarded-For": forwarded_for},
                       json={"email": "jamie@nyctr.demo", "password": "nyctr-demo"})


@pytest.mark.parametrize(("trusted", "peer", "forwarded", "expected", "scheme"), [
    (PROXY, PROXY, MEMBER, MEMBER, "https"),
    (PROXY, ATTACKER, MEMBER, ATTACKER, "http"),
    ("", PROXY, MEMBER, PROXY, "http"),
    ("2001:db8:42::10", "2001:db8:42::10", "2001:db8:51::20", "2001:db8:51::20", "https"),
    (f"{PROXY},10.42.0.11", PROXY, f"192.0.2.99, {MEMBER}, 10.42.0.11", MEMBER, "https"),
])
def test_forwarded_address_and_scheme_require_a_trusted_peer(app, monkeypatch, trusted, peer,
                                                            forwarded, expected, scheme):
    """Honor verified proxy chains while ignoring direct or earlier spoofed values."""
    @app.get("/api/proxy-test-client")
    def client_address(request: Request):
        """Expose the ASGI client and scheme only on this isolated test application."""
        return {"client": request.client.host, "scheme": request.url.scheme}

    # Keep this test-only route ahead of the application's unknown-API fallback.
    app.router.routes.insert(0, app.router.routes.pop())
    with through_uvicorn(app, monkeypatch, trusted=trusted, peer=peer) as client:
        response = client.get("/api/proxy-test-client", headers={
            "X-Forwarded-For": forwarded, "X-Forwarded-Proto": "https",
        })
        assert response.status_code == 200
        assert response.json() == {"client": expected, "scheme": scheme}


def test_trusted_proxy_keeps_one_clients_exhausted_quota_out_of_anothers_login(app, monkeypatch):
    """Sixty rotating-account failures must throttle only their verified client."""
    with through_uvicorn(app, monkeypatch) as client:
        for attempt in range(60):
            assert wrong_password(client, f"attempt-{attempt}@example.test", ATTACKER).status_code == 401
        assert wrong_password(client, "one-more@example.test", ATTACKER).status_code == 429
        assert valid_member_login(client, MEMBER).status_code == 200
        with app.state.session_factory() as db:
            assert db.get(LoginAttempt, digest("peer:" + ATTACKER)).count == 60
            assert db.get(LoginAttempt, digest("peer:" + MEMBER)).count == 1
            assert db.get(LoginAttempt, digest("peer:" + PROXY)) is None


def test_untrusted_forwarded_headers_cannot_rotate_away_a_peer_quota(app, monkeypatch):
    """An untrusted direct caller cannot bypass throttling by changing XFF."""
    with through_uvicorn(app, monkeypatch, peer=ATTACKER) as client:
        for attempt in range(60):
            spoofed = f"192.0.2.{attempt + 1}"
            assert wrong_password(client, f"attempt-{attempt}@example.test", spoofed).status_code == 401
        assert valid_member_login(client, MEMBER).status_code == 429
        with app.state.session_factory() as db:
            assert db.get(LoginAttempt, digest("peer:" + ATTACKER)).count == 60
            assert db.get(LoginAttempt, digest("peer:" + MEMBER)) is None
            assert db.get(LoginAttempt, digest("peer:192.0.2.1")) is None


def test_proxy_without_forwarding_trust_causes_shared_peer_denial(app, monkeypatch):
    """Reproduce the deployment failure when different users share a proxy quota."""
    with through_uvicorn(app, monkeypatch, trusted="") as client:
        # Put the proxy at its boundary without repeating the password work above.
        with app.state.session_factory() as db:
            db.add(LoginAttempt(key=digest("peer:" + PROXY), count=59,
                                reset_at=utcnow() + timedelta(minutes=15)))
            db.commit()
        assert wrong_password(client, "last-attempt@example.test", ATTACKER).status_code == 401
        assert valid_member_login(client, MEMBER).status_code == 429


def test_trusted_client_addresses_cannot_bypass_the_account_quota(app, monkeypatch):
    """Keep account throttling effective even when verified source addresses differ."""
    with through_uvicorn(app, monkeypatch) as client:
        for attempt in range(10):
            assert wrong_password(client, "jamie@nyctr.demo", f"192.0.2.{attempt + 1}").status_code == 401
        assert valid_member_login(client, MEMBER).status_code == 429
