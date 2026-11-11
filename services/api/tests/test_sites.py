"""The console address and the member portal address: who gets which rights where."""

import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey
from sqlalchemy import select

from nyctr.config import Settings
from nyctr.main import create_app
from nyctr.models import Audit, LoginSession, User
from nyctr.security import COOKIE_NAME
from nyctr.sites import PortalIdentity

CONSOLE = "http://console.test"
PORTAL = "http://portal.test"
ADMIN = {"email": "admin@nyctr.demo", "password": "nyctr-demo"}
MEMBER = {"email": "jamie@nyctr.demo", "password": "nyctr-demo"}


@pytest.fixture
def two_addresses():
    """A demo API served on a console address and a separate portal address."""
    return create_app(Settings(mode="demo", database_url="sqlite:///:memory:", public_url=CONSOLE,
                               portal_url=PORTAL, cookie_secure=False))


def signin(client, who):
    """Sign in on whichever address the client talks to and return the response."""
    return client.post("/api/auth/login", json=who)


@pytest.mark.parametrize("portal_url,message", [
    ("http://console.test", "different host"),
    ("http://CONSOLE.test/", "different host"),
    ("https://portal.test", "same scheme"),
    ("http://portal.test/blocked", "without a path"),
    ("http://user:secret@portal.test", "plain HTTP"),
    ("http://portal.test?x=1", "plain HTTP"),
    ("ftp://portal.test", "without a path"),
    ("portal.test", "without a path"),
])
def test_portal_address_must_be_a_second_plain_origin(portal_url, message):
    """Refuse a portal address that is the console's own host, another scheme, or not a bare origin."""
    with pytest.raises(ValueError, match=message):
        Settings(mode="demo", database_url="sqlite:///:memory:", public_url=CONSOLE, portal_url=portal_url)


def test_portal_address_is_optional_and_normalised():
    """No portal address keeps one address for everyone; a trailing slash is dropped."""
    assert Settings(mode="demo", database_url="sqlite:///:memory:", public_url=CONSOLE).portal_url == ""
    assert Settings(mode="demo", database_url="sqlite:///:memory:", public_url=CONSOLE,
                    portal_url=PORTAL + "/").portal_url == PORTAL


def test_each_address_says_which_one_it_is(two_addresses, client):
    """The sign-in page can tell the addresses apart; with no portal configured there is only the console."""
    with TestClient(two_addresses, base_url=CONSOLE) as console, TestClient(two_addresses, base_url=PORTAL) as portal:
        assert console.get("/api/auth/config").json()["site"] == "console"
        assert console.get("/api/auth/config").json()["portal_url"] == PORTAL
        assert portal.get("/api/auth/config").json()["site"] == "portal"
    single = client.get("/api/auth/config").json()
    assert single["site"] == "console" and single["portal_url"] is None


@pytest.mark.parametrize("host,site", [
    ("portal.test", "portal"), ("PORTAL.TEST", "portal"), ("portal.test:80", "portal"),
    ("portal.test:8080", "console"), ("console.test", "console"), ("portal.test.attacker.example", "console"),
    ("10.42.0.9:8080", "console"), ("", "console"),
])
def test_only_the_exact_portal_host_is_the_portal(two_addresses, host, site):
    """Match the configured portal host exactly, ignoring case and the default port; everything else is the console."""
    with TestClient(two_addresses, base_url=CONSOLE) as client:
        assert client.get("/api/auth/config", headers={"host": host}).json()["site"] == site


def test_an_administrator_has_member_rights_on_the_portal_address(two_addresses):
    """Same account, same password: full console on one address, only their own devices on the other."""
    with TestClient(two_addresses, base_url=CONSOLE) as console, TestClient(two_addresses, base_url=PORTAL) as portal:
        on_console = signin(console, ADMIN).json()
        on_portal = signin(portal, ADMIN).json()
        assert on_console["role"] == "admin" and on_console["console_url"] is None
        assert on_portal["role"] == "member" and on_portal["console_url"] == CONSOLE
        assert portal.get("/api/auth/me").json()["role"] == "member"

        # Administrator reads and changes are not reachable on the portal address.
        csrf = {"X-CSRF-Token": on_portal["csrf_token"], "Origin": PORTAL}
        for path in ("/api/overview", "/api/integrations", "/api/audit", "/api/users", "/api/rules"):
            assert portal.get(path).status_code == 403, path
        assert portal.post("/api/integrations/demo-dns/sync", headers=csrf).status_code == 403
        assert portal.post("/api/guests/passes", headers=csrf, json={}).status_code == 403
        assert console.get("/api/overview").status_code == 200

        # Lists are narrowed to what a member may see: the administrator's own devices only.
        everything, own = console.get("/api/blocks").json(), portal.get("/api/blocks").json()
        assert 0 < len(own) < len(everything)
        own_devices = {row["id"] for row in portal.get("/api/devices").json()}
        assert own_devices and all(row["device_id"] in own_devices for row in own)
        assert len(own_devices) < len(console.get("/api/devices").json())

        # Nothing about the account changed by using the portal.
        with two_addresses.state.session_factory() as db:
            assert db.scalar(select(User).where(User.email == ADMIN["email"])).role == "admin"


def test_the_portal_view_of_an_account_cannot_be_written_through():
    """The member view forwards reads and refuses writes, so it can never alter the stored role."""
    account = User(id="u1", email="a@example.test", name="A", role="admin")
    view = PortalIdentity(account)
    assert (view.id, view.email, view.role, view.administers_console()) == ("u1", "a@example.test", "member", True)
    with pytest.raises(AttributeError):
        view.role = "admin"
    with pytest.raises(AttributeError):
        view.email = "b@example.test"
    assert account.role == "admin" and account.email == "a@example.test"


def test_a_member_signs_in_on_the_portal_and_is_turned_away_from_the_console(two_addresses):
    """Members use the portal address. The console address refuses them, but only after the password is right."""
    with TestClient(two_addresses, base_url=CONSOLE) as console, TestClient(two_addresses, base_url=PORTAL) as portal:
        accepted = signin(portal, MEMBER)
        assert accepted.status_code == 200 and accepted.json()["role"] == "member"
        assert accepted.json()["console_url"] is None
        assert portal.get("/api/blocks").status_code == 200

        refused = signin(console, MEMBER)
        assert refused.status_code == 403 and PORTAL in refused.json()["detail"]
        assert COOKIE_NAME not in console.cookies
        assert console.get("/api/auth/me").status_code == 401

        # A wrong password looks the same for everyone: no hint that the account is a member.
        wrong = signin(console, {**MEMBER, "password": "not-the-password"})
        assert wrong.status_code == 401 and PORTAL not in wrong.text


def test_without_a_portal_address_members_use_the_one_address(client):
    """Unchanged behaviour when no portal address is configured."""
    response = signin(client, MEMBER)
    assert response.status_code == 200 and response.json()["role"] == "member"
    assert response.json()["console_url"] is None


def test_a_change_must_come_from_the_address_it_arrives_on(two_addresses):
    """A page on one address cannot change anything through the other, in either direction."""
    with TestClient(two_addresses, base_url=CONSOLE) as console, TestClient(two_addresses, base_url=PORTAL) as portal:
        admin = {"X-CSRF-Token": signin(console, ADMIN).json()["csrf_token"]}
        member = {"X-CSRF-Token": signin(portal, MEMBER).json()["csrf_token"]}
        assert console.post("/api/auth/logout", headers={**admin, "Origin": PORTAL}).status_code == 403
        assert portal.post("/api/auth/logout", headers={**member, "Origin": CONSOLE}).status_code == 403
        assert portal.post("/api/auth/logout", headers={**member, "Origin": "http://attacker.example"}).status_code == 403
        assert console.get("/api/auth/me").status_code == 200
        assert portal.post("/api/auth/logout", headers={**member, "Origin": PORTAL}).status_code == 200
        assert console.post("/api/auth/logout", headers={**admin, "Origin": CONSOLE}).status_code == 200


# Single sign-on across the two addresses.

ISSUER = "https://id.example/issuer/"
SSO_CONSOLE = "https://nyctr.example"
SSO_PORTAL = "https://blocked.example"


@pytest.fixture(scope="module")
def signing_key():
    """A test-only RSA key for signing fabricated ID tokens."""
    return RSAKey.generate_key(2048, parameters={"kid": "test-key"})


def sso_app(signing_key, groups, seen):
    """A live single sign-on API on two addresses with a stub identity provider that records what it is sent."""
    settings = Settings(mode="live", database_url="sqlite:///:memory:", cookie_secure=False,
                        public_url=SSO_CONSOLE, portal_url=SSO_PORTAL, local_login_enabled=False,
                        oidc_issuer=ISSUER, oidc_client_id="nyctr", oidc_client_secret="test-client-secret",
                        oidc_admin_groups="nyctr-admins", oidc_allowed_groups="nyctr-members")
    app = create_app(settings)

    def idp(request):
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={
                "issuer": ISSUER, "authorization_endpoint": "https://id.example/authorize",
                "token_endpoint": "https://id.example/token", "jwks_uri": "https://id.example/keys",
                "code_challenge_methods_supported": ["S256"]})
        if request.url.path == "/keys":
            return httpx.Response(200, json={"keys": [signing_key.as_dict()]})
        if request.url.path == "/token":
            seen["token_redirect_uri"] = parse_qs(request.content.decode())["redirect_uri"][0]
            now = int(time.time())
            claims = {"iss": ISSUER, "aud": "nyctr", "sub": "subject-1", "exp": now + 300, "iat": now,
                      "nonce": seen["nonce"], "email": "sam@example.test", "name": "Sam", "groups": groups}
            token = jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, signing_key)
            return httpx.Response(200, json={"access_token": "unused", "id_token": token})
        return httpx.Response(404)

    app.state.oidc_transport = httpx.MockTransport(idp)
    return app


def sso(client, seen):
    """Run the code flow on the client's address and return the callback response."""
    started = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert started.status_code == 302, started.text
    sent = parse_qs(urlsplit(started.headers["location"]).query)
    seen["authorize_redirect_uri"], seen["nonce"] = sent["redirect_uri"][0], sent["nonce"][0]
    return client.get("/api/auth/oidc/callback", params={"state": sent["state"][0], "code": "code"},
                      follow_redirects=False)


@pytest.mark.parametrize("address", [SSO_CONSOLE, SSO_PORTAL])
def test_single_sign_on_returns_to_the_address_it_started_from(signing_key, address):
    """The redirect is the configured origin of the address in use, at both the authorize and the token step."""
    seen = {}
    with TestClient(sso_app(signing_key, ["nyctr-admins"], seen), base_url=address) as client:
        assert sso(client, seen).status_code == 302
        assert seen["authorize_redirect_uri"] == seen["token_redirect_uri"] == address + "/api/auth/oidc/callback"


def test_single_sign_on_never_builds_its_redirect_from_the_host_header(signing_key):
    """An unknown Host is the console address: the redirect stays the configured origin, not the header's value."""
    seen = {}
    with TestClient(sso_app(signing_key, ["nyctr-admins"], seen), base_url=SSO_CONSOLE) as client:
        started = client.get("/api/auth/oidc/login", headers={"host": "attacker.example"}, follow_redirects=False)
        sent = parse_qs(urlsplit(started.headers["location"]).query)
        assert sent["redirect_uri"] == [SSO_CONSOLE + "/api/auth/oidc/callback"]


def test_an_administrator_signing_in_on_the_portal_lands_in_the_portal(signing_key):
    """Administrator group, portal address: member rights there, and the way to the console is offered."""
    seen = {}
    app = sso_app(signing_key, ["nyctr-admins"], seen)
    with TestClient(app, base_url=SSO_PORTAL) as portal, TestClient(app, base_url=SSO_CONSOLE) as console:
        assert sso(portal, seen).headers["location"] == "/#/portal"
        me = portal.get("/api/auth/me").json()
        assert me["role"] == "member" and me["console_url"] == SSO_CONSOLE
        assert portal.get("/api/overview").status_code == 403
        assert sso(console, seen).headers["location"] == "/#/overview"
        assert console.get("/api/auth/me").json()["role"] == "admin"


def test_a_member_using_single_sign_on_at_the_console_is_sent_to_the_portal(signing_key):
    """No console session for a member: sign-in restarts on the configured portal address and succeeds there."""
    seen = {}
    app = sso_app(signing_key, ["nyctr-members"], seen)
    with TestClient(app, base_url=SSO_CONSOLE) as console, TestClient(app, base_url=SSO_PORTAL) as portal:
        sent_on = sso(console, seen)
        assert sent_on.status_code == 302
        assert sent_on.headers["location"] == SSO_PORTAL + "/api/auth/oidc/login"
        assert COOKIE_NAME not in console.cookies and console.get("/api/auth/me").status_code == 401
        with app.state.session_factory() as db:
            assert db.scalars(select(LoginSession)).all() == []
            assert db.scalar(select(Audit).where(Audit.action == "auth.sent_to_portal")) is not None
            assert db.scalar(select(User)).role == "member"

        assert sso(portal, seen).headers["location"] == "/#/portal"
        assert portal.get("/api/auth/me").json()["role"] == "member"
