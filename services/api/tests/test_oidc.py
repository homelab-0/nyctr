import base64
import hashlib
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import RSAKey
from sqlalchemy import select

from nyctr.config import Settings
from nyctr.main import create_app
from nyctr.models import OIDCFlow, User
from nyctr.oidc import FLOW_COOKIE, roles_for_claims, validate_id_token


@pytest.fixture(scope="module")
def signing_key():
    return RSAKey.generate_key(2048, parameters={"kid": "test-key"})


def oidc_settings(**kwargs):
    return Settings(mode="live", database_url="sqlite:///:memory:", cookie_secure=False,
                    public_url="https://nyctr.example", local_login_enabled=False,
                    oidc_issuer="https://id.example/issuer/", oidc_client_id="nyctr",
                    oidc_client_secret="test-client-secret", oidc_admin_groups="nyctr-admins", **kwargs)


def token_claims(**changes):
    return {"iss": "https://id.example/issuer/", "aud": "nyctr", "sub": "subject-123",
            "exp": int(time.time()) + 300, "iat": int(time.time()), "nonce": "expected-nonce", **changes}


def signed(claims, signing_key):
    return jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, signing_key)


@pytest.mark.parametrize("changes", [
    {"iss": "https://attacker.example"}, {"aud": "other-client"}, {"nonce": "incorrect"},
    {"nonce": None, "nonce_supported": False}, {"exp": 1}, {"sub": ""},
])
def test_oidc_rejects_invalid_verified_claims(signing_key, changes):
    token = {"id_token": signed(token_claims(**changes), signing_key)}
    with pytest.raises((JoseError, ValueError)):
        validate_id_token(token, {"keys": [signing_key.as_dict()]}, oidc_settings(), "expected-nonce")


def test_oidc_rejects_wrong_signature(signing_key):
    attacker = RSAKey.generate_key(2048, parameters={"kid": "test-key"})
    token = {"id_token": signed(token_claims(), attacker)}
    with pytest.raises(JoseError):
        validate_id_token(token, {"keys": [signing_key.as_dict()]}, oidc_settings(), "expected-nonce")


def test_oidc_groups_are_explicit_and_do_not_trust_role_claim():
    settings = oidc_settings()
    assert roles_for_claims({"role": "admin", "groups": "nyctr-admins"}, settings) == "member"
    assert roles_for_claims({"groups": ["nyctr-admins"]}, settings) == "admin"
    settings.oidc_allowed_groups = "nyctr-members"
    with pytest.raises(HTTPException):
        roles_for_claims({"groups": ["unrelated"]}, settings)


def test_oidc_full_flow_binds_browser_state_pkce_identity_and_rejects_replay(signing_key):
    settings = oidc_settings()
    app = create_app(settings)
    sent = {}

    def idp(request):
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200, json={"issuer": settings.oidc_issuer,
                "authorization_endpoint": "https://id.example/authorize", "token_endpoint": "https://id.example/token",
                "jwks_uri": "https://id.example/keys", "code_challenge_methods_supported": ["S256"]})
        if request.url.path == "/keys":
            return httpx.Response(200, json={"keys": [signing_key.as_dict()]})
        if request.url.path == "/token":
            data = parse_qs(request.content.decode())
            assert data["redirect_uri"] == ["https://nyctr.example/api/auth/oidc/callback"]
            assert data["code"] == ["authorization-code"]
            assert "basic " in request.headers["authorization"].lower()
            challenge = base64.urlsafe_b64encode(hashlib.sha256(data["code_verifier"][0].encode()).digest()).rstrip(b"=").decode()
            assert challenge == sent["code_challenge"][0]
            claims = token_claims(nonce=sent["nonce"][0], email="admin@nyctr.demo", name="OIDC Member", groups=[])
            return httpx.Response(200, json={"access_token": "test-access", "id_token": signed(claims, signing_key)})
        return httpx.Response(404)

    app.state.oidc_transport = httpx.MockTransport(idp)
    with TestClient(app, base_url="https://nyctr.example") as client:
        started = client.get("/api/auth/oidc/login", follow_redirects=False)
        assert started.status_code == 302
        sent.update(parse_qs(urlsplit(started.headers["location"]).query))
        assert sent["code_challenge_method"] == ["S256"]
        assert sent["scope"] == ["openid profile email"]
        state = sent["state"][0]
        with app.state.session_factory() as db:
            flow = db.scalar(select(OIDCFlow))
            assert flow.state_hash != state
            assert flow.binding_hash != client.cookies.get(FLOW_COOKIE)
        callback = client.get("/api/auth/oidc/callback", params={"state": state, "code": "authorization-code"}, follow_redirects=False)
        assert callback.status_code == 302, callback.text
        me = client.get("/api/auth/me").json()
        assert me["role"] == "member"
        assert me["email"] == "admin@nyctr.demo"  # Display email does not grant local administrator identity.
        assert client.get("/api/overview").status_code == 403
        assert client.get("/api/auth/oidc/callback", params={"state": state, "code": "authorization-code"}).status_code == 400
        with app.state.session_factory() as db:
            user = db.get(User, me["id"])
            assert user.oidc_subject == "subject-123"
            assert user.password_hash is None


def test_oidc_callback_requires_browser_binding(signing_key):
    settings = oidc_settings()
    app = create_app(settings)
    def idp(request):
        return httpx.Response(200, json={"issuer": settings.oidc_issuer,
            "authorization_endpoint": "https://id.example/authorize", "token_endpoint": "https://id.example/token",
            "jwks_uri": "https://id.example/keys"})
    app.state.oidc_transport = httpx.MockTransport(idp)
    with TestClient(app, base_url="https://nyctr.example") as client:
        started = client.get("/api/auth/oidc/login", follow_redirects=False)
        state = parse_qs(urlsplit(started.headers["location"]).query)["state"][0]
        client.cookies.clear()
        result = client.get("/api/auth/oidc/callback", params={"state": state, "code": "test"})
        assert result.status_code == 400


def test_oidc_rejects_discovery_issuer_mismatch():
    app = create_app(oidc_settings())
    app.state.oidc_transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"issuer": "https://attacker.example"}))
    with TestClient(app) as client:
        assert client.get("/api/auth/oidc/login").status_code == 502
