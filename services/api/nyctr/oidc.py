"""OIDC authorization-code + PKCE flow with server-stored, browser-bound state.

Issuer discovery is configuration-controlled. Identity comes from verified issuer
and subject, never by linking an untrusted email to an existing administrator.
"""

import base64
import hashlib
import hmac
import secrets
from datetime import timedelta
from urllib.parse import urlencode, urlsplit

import httpx
from authlib.oidc.core import CodeIDToken
from fastapi import APIRouter, HTTPException, Request
from joserfc import jwt
from joserfc.jwk import KeySet
from sqlalchemy import delete, select
from starlette.responses import RedirectResponse

from .models import OIDCFlow, User, utc, utcnow
from .security import COOKIE_NAME, audit, digest, issue_session
from .sites import members_use_portal, origin_of, seen_as, site_of

router = APIRouter(prefix="/api/auth/oidc")
FLOW_COOKIE = "nyctr_oidc"
ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA")


def secure_endpoint(value: str) -> str:
    """Require a usable HTTPS identity-provider endpoint without credentials or a fragment.

    Returns the original URL or raises ValueError before it can receive a request.
    """
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Invalid identity-provider endpoint")
    return value


async def discovery(client, settings):
    """Load the configured issuer metadata and validate its endpoint and PKCE contracts.

    The returned issuer must exactly match configuration. Network, malformed
    metadata, issuer mismatch, and unsupported S256 errors propagate to the caller.
    """
    url = settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
    response = await client.get(url)
    response.raise_for_status()
    data = response.json()
    if data.get("issuer") != settings.oidc_issuer:
        raise ValueError("Identity-provider issuer mismatch")
    for key in ["authorization_endpoint", "token_endpoint", "jwks_uri"]:
        secure_endpoint(data[key])
    if "S256" not in data.get("code_challenge_methods_supported", ["S256"]):
        raise ValueError("Identity provider does not support S256 PKCE")
    return data


def validate_id_token(token: dict, jwks: dict, settings, nonce: str):
    """Verify the ID-token signature and expected issuer, audience, subject, expiry, and nonce.

    Only the configured asymmetric algorithm set is accepted. Claims validation
    allows 30 seconds of clock skew; provider claims cannot disable nonce checks.
    Cryptographic or claim failures raise before an application identity is created.
    """
    decoded = jwt.decode(token["id_token"], KeySet.import_key_set(jwks), algorithms=ALGORITHMS)
    claims = CodeIDToken(decoded.claims, decoded.header,
                         options={"iss": {"essential": True, "value": settings.oidc_issuer},
                                  "aud": {"essential": True, "value": settings.oidc_client_id}},
                         params={"client_id": settings.oidc_client_id, "nonce": nonce,
                                 "access_token": token.get("access_token")})
    claims.validate(leeway=30)
    # Explicit equality remains deliberate even if the upstream library changes.
    if not isinstance(claims.get("nonce"), str) or not hmac.compare_digest(claims["nonce"], nonce):
        raise ValueError("Invalid nonce")
    if not isinstance(claims.get("sub"), str) or not claims["sub"] or len(claims["sub"]) > 255:
        raise ValueError("Invalid subject")
    return claims


def roles_for_claims(claims, settings):
    """Derive access and role solely from configured groups in already verified claims.

    Malformed group values grant no privileges. Users outside an explicit
    allowlist receive HTTP 403; only matching administrator groups grant admin.
    """
    raw = claims.get(settings.oidc_groups_claim, [])
    groups = set(raw) if isinstance(raw, list) and all(isinstance(x, str) for x in raw) else set()
    if settings.allowed_groups and not groups.intersection(settings.allowed_groups | settings.admin_groups):
        raise HTTPException(403, "Your identity-provider group does not have access to Nyctr")
    return "admin" if groups.intersection(settings.admin_groups) else "member"


@router.get("/login")
async def login(request: Request):
    """Begin a ten-minute OIDC code flow with S256 PKCE and a browser-bound cookie.

    Persists hashed state and binding plus nonce and verifier, prunes expired
    flows, and redirects to the validated provider. Disabled OIDC returns 404;
    discovery failures return a sanitized 502 response.
    """
    settings = request.app.state.settings
    if not settings.oidc_enabled:
        raise HTTPException(404, "OIDC is not configured")
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=False,
                                     transport=getattr(request.app.state, "oidc_transport", None)) as client:
            metadata = await discovery(client, settings)
    except Exception:
        raise HTTPException(502, "Unable to load identity-provider configuration") from None
    state, binding = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
    with request.app.state.session_factory() as db:
        db.execute(delete(OIDCFlow).where(OIDCFlow.expires_at <= utcnow()))
        db.add(OIDCFlow(state_hash=digest(state), binding_hash=digest(binding), nonce=nonce,
                        code_verifier=verifier, expires_at=utcnow() + timedelta(minutes=10)))
        db.commit()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    url = metadata["authorization_endpoint"]
    url += ("&" if "?" in url else "?") + urlencode({
        "response_type": "code", "client_id": settings.oidc_client_id,
        # Back to the address the person started from: the session cookie belongs to that host.
        "redirect_uri": origin_of(settings, site_of(request)) + "/api/auth/oidc/callback",
        "scope": "openid profile email", "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    })
    response = RedirectResponse(url, status_code=302)
    response.set_cookie(FLOW_COOKIE, binding, httponly=True, secure=settings.cookie_secure,
                        samesite="lax", max_age=600, path="/api/auth/oidc")
    return response


@router.get("/callback")
async def callback(request: Request, state: str = "", code: str = ""):
    """Consume a valid browser-bound flow and exchange its code for a verified identity.

    State is atomically consumed before token exchange to prevent replay.
    Accounts bind to issuer and subject, never email; current trusted groups
    determine the role. Success rotates the application session and redirects
    to the appropriate workspace without retaining provider tokens.
    """
    settings = request.app.state.settings
    if not settings.oidc_enabled:
        raise HTTPException(404, "OIDC is not configured")
    if not state or not code or len(state) > 256 or len(code) > 8192:
        raise HTTPException(400, "Invalid sign-in response")
    with request.app.state.session_factory() as db:
        flow = db.get(OIDCFlow, digest(state))
        binding = request.cookies.get(FLOW_COOKIE, "")
        if (not flow or utc(flow.expires_at) <= utcnow() or not binding
                or not hmac.compare_digest(flow.binding_hash, digest(binding))):
            raise HTTPException(400, "Sign-in expired or state was invalid. Start again.")
        nonce, verifier = flow.nonce, flow.code_verifier
        # Atomic consume prevents simultaneous code replay across API replicas.
        deleted = db.execute(delete(OIDCFlow).where(OIDCFlow.state_hash == digest(state)))
        if deleted.rowcount != 1:
            raise HTTPException(400, "Sign-in response was already used")
        db.commit()
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False,
                                         transport=getattr(request.app.state, "oidc_transport", None)) as client:
                metadata = await discovery(client, settings)
                methods = metadata.get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
                data = {"grant_type": "authorization_code", "code": code, "code_verifier": verifier,
                        "redirect_uri": origin_of(settings, site_of(request)) + "/api/auth/oidc/callback"}
                if "client_secret_basic" in methods:
                    auth = httpx.BasicAuth(settings.oidc_client_id, settings.oidc_client_secret)
                elif "client_secret_post" in methods:
                    auth = None
                    data.update(client_id=settings.oidc_client_id, client_secret=settings.oidc_client_secret)
                else:
                    raise ValueError("Unsupported token endpoint authentication")
                exchanged = await client.post(metadata["token_endpoint"], data=data, auth=auth)
                exchanged.raise_for_status()
                keys = await client.get(metadata["jwks_uri"])
                keys.raise_for_status()
                claims = validate_id_token(exchanged.json(), keys.json(), settings, nonce)
        except Exception:
            raise HTTPException(401, "Identity-provider response could not be verified") from None
        role = roles_for_claims(claims, settings)
        user = db.scalar(select(User).where(User.oidc_issuer == settings.oidc_issuer,
                                            User.oidc_subject == claims["sub"]))
        email = str(claims.get("email", claims["sub"]))[:320]
        name = str(claims.get("name") or claims.get("preferred_username") or email)[:160]
        if not user:
            user = User(oidc_issuer=settings.oidc_issuer, oidc_subject=claims["sub"],
                        email=email, name=name, role=role)
            db.add(user)
            db.flush()
        elif not user.active:
            raise HTTPException(403, "This account is disabled")
        else:
            user.role, user.email, user.name = role, email, name
        if members_use_portal(request, user):
            # The console address is for administrators. Keep the account up to date, give no
            # session here, and start sign-in again on the portal address. The target is the
            # configured portal origin, never a value from the request.
            audit(db, user.id, "auth.sent_to_portal", user.id)
            db.commit()
            response = RedirectResponse(settings.portal_url + "/api/auth/oidc/login", status_code=302)
            response.delete_cookie(FLOW_COOKIE, path="/api/auth/oidc")
            return response
        here = seen_as(request, user).role
        response = RedirectResponse("/#/overview" if here == "admin" else "/#/portal", status_code=302)
        response.delete_cookie(FLOW_COOKIE, path="/api/auth/oidc")
        issue_session(db, user, response, settings, request.cookies.get(COOKIE_NAME, ""))
        return response
