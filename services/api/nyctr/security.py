"""Authentication primitives and bounded login throttling."""

import base64
import hashlib
import hmac
import secrets
from datetime import timedelta

from fastapi import HTTPException, Request
from sqlalchemy import case, delete, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from .config import Settings
from .models import Audit, LoginAttempt, LoginSession, User, utc, utcnow

COOKIE_NAME = "nyctr_session"


def digest(value: str) -> str:
    """Return the SHA-256 lookup digest for a high-entropy token or quota identifier."""
    return hashlib.sha256(value.encode()).hexdigest()


def hash_password(password: str) -> str:
    """Encode a password with scrypt, a fresh salt, and stored work parameters."""
    salt = secrets.token_bytes(16)
    result = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(result).decode()


def verify_password(password: str, stored: str | None) -> bool:
    """Compare a password against its scrypt encoding using a constant-time digest check.

    Missing accounts still run scrypt to reduce timing differences. Malformed
    stored encodings return False instead of authenticating or revealing details.
    """
    if not stored:
        # Match the expensive path for a missing user to reduce username enumeration.
        stored = "scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    try:
        _, n, r, p, salt, expected = stored.split("$")
        calculated = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt),
                                    n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(calculated, base64.b64decode(expected))
    except (ValueError, TypeError):
        return False


def audit(db: Session, actor: str | None, action: str, target: str | None = None, **details):
    """Stage caller-sanitized audit details in the current transaction without committing it."""
    db.add(Audit(actor_id=actor, action=action, target_id=target, details=details))


def authenticate(request: Request, db: Session):
    """Resolve an active, unexpired cookie session and enforce CSRF on mutations.

    Returns the current user and session. Missing, expired, or disabled identities
    raise HTTP 401; an absent or mismatched mutation token raises HTTP 403.
    """
    token = request.cookies.get(COOKIE_NAME, "")
    session = db.get(LoginSession, digest(token)) if token and len(token) < 256 else None
    if session is None or utc(session.expires_at) <= utcnow():
        raise HTTPException(401, "Sign in to continue")
    user = db.get(User, session.user_id)
    if user is None or not user.active:
        raise HTTPException(401, "Sign in to continue")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        token = request.headers.get("x-csrf-token", "")
        if not token or not hmac.compare_digest(token, session.csrf_token):
            raise HTTPException(403, "Invalid or missing CSRF token")
    return user, session


def user_response(user: User, session: LoginSession, settings: Settings):
    """Expose signed-in identity, mode, and CSRF token without credentials or session hashes."""
    return {"id": user.id, "email": user.email, "name": user.name, "role": user.role,
            "csrf_token": session.csrf_token, "mode": settings.mode}


def issue_session(db: Session, user: User, response, settings: Settings, old_token: str = ""):
    """Rotate the caller session, remove expired sessions, and set an HTTP-only cookie.

    The database stores only the new session-token hash. This function commits
    the new session, login audit event, and any pending identity updates.
    """
    if old_token:
        db.execute(delete(LoginSession).where(LoginSession.token_hash == digest(old_token)))
    db.execute(delete(LoginSession).where(LoginSession.expires_at <= utcnow()))
    token = secrets.token_urlsafe(48)
    session = LoginSession(token_hash=digest(token), user_id=user.id, csrf_token=secrets.token_urlsafe(32),
                           expires_at=utcnow() + timedelta(hours=settings.session_hours))
    db.add(session)
    audit(db, user.id, "auth.login", user.id)
    db.commit()
    response.set_cookie(COOKIE_NAME, token, httponly=True, secure=settings.cookie_secure,
                        samesite="lax", max_age=settings.session_hours * 3600, path="/")
    return session


def check_login_attempt(db: Session, request: Request, email: str):
    # Per-account AND peer quotas. Never trust arbitrary X-Forwarded-For values.
    """Atomically consume account and peer login quotas in a 15-minute window.

    Database upserts serialize concurrent attempts. Exhausting either quota
    rolls back the transaction and raises HTTP 429; accepted attempts commit
    before expensive password verification.
    """
    peer = request.client.host if request.client else "unknown"
    now = utcnow()
    next_reset = now + timedelta(minutes=15)
    insert = pg_insert if db.bind.dialect.name == "postgresql" else sqlite_insert
    for key, limit in [(digest("account:" + email.casefold()), 10), (digest("peer:" + peer), 60)]:
        # An atomic upsert both covers first-use races and limits concurrent
        # attempts. The WHERE condition denies excess attempts without a write.
        expired = LoginAttempt.reset_at <= now
        statement = insert(LoginAttempt).values(key=key, count=1, reset_at=next_reset)
        statement = statement.on_conflict_do_update(index_elements=["key"], set_={
            "count": case((expired, 1), else_=LoginAttempt.count + 1),
            "reset_at": case((expired, next_reset), else_=LoginAttempt.reset_at),
        }, where=or_(expired, LoginAttempt.count < limit)).returning(LoginAttempt.count)
        if db.execute(statement).scalar_one_or_none() is None:
            db.rollback()
            raise HTTPException(429, "Too many sign-in attempts. Try again in 15 minutes.")
    db.commit()


def local_user(db: Session, email: str):
    """Find a case-normalized local account without linking an OIDC identity by email."""
    return db.scalar(select(User).where(User.email == email.casefold(), User.oidc_subject.is_(None)))
