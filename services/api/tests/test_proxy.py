"""Sign-in limits, device recognition, the scheme and the operator's check, served as the image serves them."""

import json
import re
import sys
import time
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from conftest import LIVE_ADMIN, LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi import Request
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey
from uvicorn import Config

from nyctr import peer
from nyctr.config import Settings
from nyctr.main import create_app
from nyctr.models import LoginAttempt, utcnow
from nyctr.security import COOKIE_NAME, NO_ADDRESS, digest

PROXY, EDGE = "10.42.0.10", "10.42.0.11"
ATTACKER, MEMBER, FORGED = "198.51.100.20", "198.51.100.21", "192.0.2.99"
DOCKERFILE = Path(__file__).resolve().parents[3] / "Dockerfile"


def demo_app(listed=PROXY, hops=1):
    """Build an isolated demo API that believes the given proxies."""
    return create_app(Settings(mode="demo", database_url="sqlite:///:memory:", public_url="http://testserver",
                               cookie_secure=False, forwarded_allow_ips=listed, proxy_hops=hops))


@contextmanager
def served(app, peer_address=PROXY, **options):
    """Serve the app as the image does, the web server's own forwarded-header handling off."""
    config = Config(app, interface="asgi3", log_config=None, proxy_headers=False)
    config.load()
    with TestClient(config.loaded_app, client=(peer_address, 45678), **options) as client:
        yield client


def wrong_password(client, email, forwarded_for=None):
    """Make a genuine failed login with a caller-selected forwarding header."""
    return client.post("/api/auth/login", headers={"X-Forwarded-For": forwarded_for} if forwarded_for else {},
                       json={"email": email, "password": "incorrect"})


def valid_member_login(client, forwarded_for=None):
    """Authenticate the seeded member through the same proxy and quota path."""
    return client.post("/api/auth/login", headers={"X-Forwarded-For": forwarded_for} if forwarded_for else {},
                       json={"email": "jamie@nyctr.demo", "password": "nyctr-demo"})


def attempts(app, address):
    """Read how many sign-in attempts were counted against one address, or None."""
    with app.state.session_factory() as db:
        row = db.get(LoginAttempt, digest("peer:" + address))
        return row.count if row else None


def spend(app, address, count=59):
    """Bring one address to the edge of its quota without repeating the password work."""
    with app.state.session_factory() as db:
        db.add(LoginAttempt(key=digest("peer:" + address), count=count, reset_at=utcnow() + timedelta(minutes=15)))
        db.commit()


def test_the_image_starts_the_web_server_with_its_own_forwarded_handling_off(monkeypatch):
    """Left on, the server rewrites the peer before Nyctr sees it and the forged address comes back."""
    command = json.loads(re.search(r"^CMD (\[.*\])$", DOCKERFILE.read_text(), re.M).group(1))
    started = {}
    server = sys.modules["uvicorn.main"]  # the package's own `main` attribute is the command, not the module
    monkeypatch.setattr(server, "run", lambda app, **options: started.update(options, app=app))
    server.main(command[1:], standalone_mode=False)
    assert (started["app"], started["proxy_headers"]) == ("nyctr.main:app", False)


@pytest.mark.parametrize(("listed", "hops", "peer_address", "forwarded", "expected", "scheme"), [
    (PROXY, 1, PROXY, MEMBER, MEMBER, "https"),
    (PROXY, 1, ATTACKER, MEMBER, ATTACKER, "http"),
    ("", 1, PROXY, MEMBER, PROXY, "http"),
    ("2001:db8:42::10", 1, "2001:db8:42::10", "2001:db8:51::20", "2001:db8:51::20", "https"),
    # Two proxies: counted as one hop the edge is the client; counted as two, the member is.
    (f"{PROXY},{EDGE}", 1, PROXY, f"{FORGED}, {MEMBER}, {EDGE}", EDGE, "https"),
    (f"{PROXY},{EDGE}", 2, PROXY, f"{FORGED}, {MEMBER}, {EDGE}", MEMBER, "https"),
    # A range, as the chart allows behind its network policy: any proxy pod in it is believed, a
    # peer outside it is not, and a client inside it that goes through the proxy is itself.
    ("10.42.0.0/16", 1, "10.42.9.77", MEMBER, MEMBER, "https"),
    ("10.42.0.0/16", 1, "10.43.0.5", MEMBER, "10.43.0.5", "http"),
    ("10.42.0.0/16", 1, "10.42.9.77", f"{FORGED}, 10.42.3.3", "10.42.3.3", "https"),
    ("2001:db8:42::/56", 1, "2001:db8:42:1::10", "[2001:db8:51::20]:443", "2001:db8:51::20", "https"),
    (PROXY, 1, PROXY, "", None, "https"),
])
def test_address_and_scheme_are_believed_only_from_a_listed_proxy(listed, hops, peer_address, forwarded,
                                                                 expected, scheme):
    """A listed proxy is believed about the address it saw and the scheme; nobody else is."""
    app = demo_app(listed, hops)

    @app.get("/api/proxy-test-client")
    def client_address(request: Request):
        """Expose what Nyctr worked out, only on this isolated test application."""
        return {"client": peer.client_address(request), "scheme": request.url.scheme}

    # Keep this test-only route ahead of the application's unknown-API fallback.
    app.router.routes.insert(0, app.router.routes.pop())
    with served(app, peer_address) as client:
        response = client.get("/api/proxy-test-client", headers={
            "X-Forwarded-For": forwarded, "X-Forwarded-Proto": "https",
        })
        assert response.status_code == 200
        assert response.json() == {"client": expected, "scheme": scheme}
        for unclear in ("https, http", "ftp", ""):
            again = client.get("/api/proxy-test-client", headers={"X-Forwarded-Proto": unclear})
            assert again.json()["scheme"] == "http"


def test_a_listed_proxy_keeps_one_clients_exhausted_quota_out_of_anothers_login():
    """Sixty rotating-account failures must throttle only their verified client."""
    app = demo_app()
    with served(app) as client:
        for attempt in range(60):
            assert wrong_password(client, f"attempt-{attempt}@example.test", ATTACKER).status_code == 401
        assert wrong_password(client, "one-more@example.test", ATTACKER).status_code == 429
        # Forging entries to the left of the proxy's own does not move the attacker to a new quota.
        assert wrong_password(client, "moved@example.test", f"{MEMBER}, {ATTACKER}").status_code == 429
        assert valid_member_login(client, f"{ATTACKER}, {MEMBER}").status_code == 200
        assert (attempts(app, ATTACKER), attempts(app, MEMBER), attempts(app, PROXY)) == (60, 1, None)


def test_forwarded_headers_from_an_unlisted_peer_cannot_rotate_away_its_quota():
    """A direct caller cannot get round the limit by changing its header."""
    app = demo_app()
    with served(app, ATTACKER) as client:
        for attempt in range(60):
            spoofed = f"192.0.2.{attempt + 1}"
            assert wrong_password(client, f"attempt-{attempt}@example.test", spoofed).status_code == 401
        assert valid_member_login(client, MEMBER).status_code == 429
        assert (attempts(app, ATTACKER), attempts(app, MEMBER), attempts(app, "192.0.2.1")) == (60, None, None)


def test_a_client_inside_a_trusted_range_cannot_rotate_away_its_quota():
    """Behind the proxy, a client in the trusted range is counted as itself whatever it claims."""
    app, inside = demo_app("10.42.0.0/16"), "10.42.3.3"
    with served(app, "10.42.9.77") as client:
        spend(app, inside)
        assert wrong_password(client, "last@example.test", f"{FORGED}, {inside}").status_code == 401
        assert wrong_password(client, "more@example.test", f"192.0.2.7, {inside}").status_code == 429
        assert (attempts(app, inside), attempts(app, FORGED), attempts(app, "192.0.2.7")) == (60, None, None)


@pytest.mark.parametrize("forwarded", [None, "", "garbage", f"{MEMBER}, garbage"])
def test_requests_with_no_address_share_one_quota_and_are_never_unlimited(forwarded):
    """No address is one shared bucket: limited like any other, and never the proxy's or a header's."""
    app = demo_app()
    with served(app) as client:
        spend(app, NO_ADDRESS)
        assert wrong_password(client, "last@example.test", forwarded).status_code == 401
        assert valid_member_login(client, forwarded).status_code == 429
        assert (attempts(app, NO_ADDRESS), attempts(app, PROXY), attempts(app, MEMBER)) == (60, None, None)
        # A request whose address is known is not caught in that bucket.
        assert valid_member_login(client, MEMBER).status_code == 200


def test_a_proxy_that_is_not_listed_puts_everyone_behind_it_in_one_quota():
    """Reproduce the deployment failure when different users share a proxy quota."""
    app = demo_app("")
    with served(app) as client:
        spend(app, PROXY)
        assert wrong_password(client, "last-attempt@example.test", ATTACKER).status_code == 401
        assert valid_member_login(client, MEMBER).status_code == 429


def test_different_addresses_cannot_get_round_the_account_quota():
    """Keep account throttling effective even when verified source addresses differ."""
    with served(demo_app()) as client:
        for attempt in range(10):
            assert wrong_password(client, "jamie@nyctr.demo", f"192.0.2.{attempt + 1}").status_code == 401
        assert valid_member_login(client, MEMBER).status_code == 429


def test_a_device_is_recognised_by_the_address_the_listed_proxy_wrote(tmp_path):
    """Recognition reads the same function: a forged entry or a header from elsewhere names no device."""
    app = live_app(tmp_path, forwarded_allow_ips=PROXY)
    laptop = {"X-Forwarded-For": f"{FORGED}, 10.0.0.9"}
    with served(app) as client:
        seed_live_member(app)
        live_signin(client, LIVE_MEMBER)
        assert client.get("/api/me/device", headers=laptop).json()["device_id"] == "unifi:client:laptop"
        for forged in ("10.0.0.9, 10.0.0.77", "10.0.0.9, garbage", ""):
            seen = client.get("/api/me/device", headers={"X-Forwarded-For": forged}).json()
            assert seen == {"device_id": None, "name": None, "simulated": False}
    with served(app, "10.0.0.77") as direct:
        live_signin(direct, LIVE_MEMBER)
        assert direct.get("/api/me/device", headers=laptop).json()["device_id"] is None


def test_only_an_administrator_on_the_console_address_is_told_the_address_nyctr_sees(tmp_path):
    """A member is refused, and so is anyone on the portal address, an administrator included."""
    app = live_app(tmp_path, forwarded_allow_ips=PROXY, public_url="http://console.example.test",
                   portal_url="http://portal.example.test")
    with served(app, base_url="http://console.example.test") as client:
        seed_live_member(app)
        assert client.get("/api/me/address").status_code == 401
        live_signin(client, LIVE_ADMIN)
        assert client.get("/api/me/address", headers={"X-Forwarded-For": f"{FORGED}, {MEMBER}"}).json() == {
            "address": MEMBER, "peer": PROXY, "via_proxy": True, "why": "forwarded", "entry": 1, "entries": 2,
            "proxy_hops": 1}
        assert client.get("/api/me/address").json() == {
            "address": None, "peer": PROXY, "via_proxy": True, "why": "missing", "entry": None, "entries": 0,
            "proxy_hops": 1}
    with served(app, base_url="http://portal.example.test") as portal:
        for who in (LIVE_MEMBER, LIVE_ADMIN):
            live_signin(portal, who)
            assert portal.get("/api/me/address").status_code == 403
    with served(app, ATTACKER, base_url="http://console.example.test") as direct:
        live_signin(direct, LIVE_ADMIN)
        assert direct.get("/api/me/address", headers={"X-Forwarded-For": MEMBER}).json() == {
            "address": ATTACKER, "peer": ATTACKER, "via_proxy": False, "why": "peer", "entry": None,
            "entries": 0, "proxy_hops": 1}


@pytest.fixture(scope="module")
def signing_key():
    """Generate a test-only RSA signing key for the fabricated identity provider."""
    return RSAKey.generate_key(2048, parameters={"kid": "test-key"})


@pytest.mark.parametrize(("peer_address", "headers"), [
    (PROXY, {"X-Forwarded-For": MEMBER, "X-Forwarded-Proto": "https"}),
    # A proxy that reports plain HTTP, or a forged claim of it, cannot weaken the cookie or the return address.
    (PROXY, {"X-Forwarded-For": MEMBER, "X-Forwarded-Proto": "http"}),
    (ATTACKER, {"X-Forwarded-Proto": "http", "X-Forwarded-Host": "attacker.example"}),
    (ATTACKER, {}),
])
def test_secure_cookies_and_the_sign_in_return_address_come_from_configuration(tmp_path, signing_key,
                                                                              peer_address, headers):
    """Behind a proxy or not, single sign-on returns to the configured origin and every cookie is Secure."""
    origin, issuer = "https://nyctr.example.test", "https://id.example/issuer/"
    app = live_app(tmp_path, forwarded_allow_ips=PROXY, public_url=origin, cookie_secure=True,
                   oidc_issuer=issuer, oidc_client_id="nyctr", oidc_client_secret="test-client-secret")
    sent = {}

    def idp(request):
        """Emulate discovery, keys and the token endpoint, keeping the return address Nyctr sent."""
        if request.url.path == "/keys":
            return httpx.Response(200, json={"keys": [signing_key.as_dict()]})
        if request.url.path == "/token":
            sent["returned_to"] = parse_qs(request.content.decode())["redirect_uri"]
            claims = {"iss": issuer, "aud": "nyctr", "sub": "subject-123", "nonce": sent["nonce"][0],
                      "exp": int(time.time()) + 300, "iat": int(time.time())}
            token = jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, signing_key)
            return httpx.Response(200, json={"access_token": "test-access", "id_token": token})
        return httpx.Response(200, json={
            "issuer": issuer, "authorization_endpoint": "https://id.example/authorize",
            "token_endpoint": "https://id.example/token", "jwks_uri": "https://id.example/keys",
            "code_challenge_methods_supported": ["S256"]})

    app.state.oidc_transport = httpx.MockTransport(idp)
    here = origin + "/api/auth/oidc/callback"
    with served(app, peer_address, base_url=origin) as client:
        started = client.get("/api/auth/oidc/login", headers=headers, follow_redirects=False)
        assert started.status_code == 302
        sent.update(parse_qs(urlsplit(started.headers["location"]).query))
        assert sent["redirect_uri"] == [here]
        assert "secure" in started.headers["set-cookie"].lower()
        back = client.get("/api/auth/oidc/callback", params={"state": sent["state"][0], "code": "code"},
                          headers=headers, follow_redirects=False)
        assert (back.status_code, back.headers["location"], sent["returned_to"]) == (302, "/#/portal", [here])
        session = [x for x in back.headers.get_list("set-cookie") if x.startswith(COOKIE_NAME + "=")]
        assert len(session) == 1 and "secure" in session[0].lower()
        assert client.get("/api/auth/me", headers=headers).json()["role"] == "member"
        signed_in = client.post("/api/auth/login", headers=headers,
                                json={"email": LIVE_ADMIN[0], "password": LIVE_ADMIN[1]})
        assert signed_in.status_code == 200
        cookie = signed_in.headers["set-cookie"]
        assert cookie.startswith(COOKIE_NAME + "=") and "secure" in cookie.lower()
