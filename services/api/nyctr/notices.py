"""Tell an administrator when something waits, by a webhook.

A notice is written in the same transaction as the request or the opening it
reports. The background tick sends what is due, on a worker thread, and does
not hold the database while the call is open. The body carries no secret, no
hardware address and no network address. The link carries no token.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from http.client import HTTPConnection, HTTPSConnection
from typing import Any
from urllib.parse import quote, urlsplit

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import __version__
from .config import Settings
from .deps import admin, get_db
from .models import AccessRequest, Lease, Notice, Observation, Setting, User, uid, utc, utcnow
from .redact import clean
from .security import audit

router = APIRouter(prefix="/api")
KEY = "notices"
KINDS = ("request_waiting", "lease_stuck", "test")
# After the first try: 1 minute, 5, 15 and 60. The fifth failure gives up.
DELAYS = (60, 300, 900, 3600)
TRIES = 5
TIMEOUT = 10
# Longer than one send and one tick. A claim younger than this belongs to a live copy.
CLAIM_TTL = 60
TARGET_LIMIT = 500
LINE_LIMIT = 120
SECRET_REF = re.compile(r"NYCTR_NOTICE_SECRET_[A-Z0-9_]{1,100}")
_HEADER = re.compile(r"^t=(\d+),v1=([0-9a-f]{64})$")
_IPV6 = re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])")
_METADATA = {"metadata.google.internal", "metadata.azure.internal"}
SHAPE = "Send only the address and the name of the secret, each as text."
# Tests set this to a function of one step name. Production leaves it unset.
pause: Callable[[str], None] | None = None
# Forms that can name a private address while Python still calls them global.
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_COMPAT = ipaddress.ip_network("::/96")
_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")


class Refused(ValueError):
    """The address is not a place Nyctr may send a notice."""


class Unreachable(OSError):
    """The address could not be reached just now. Try again later."""


class Saved(BaseModel):
    """The address and the secret's name. The secret's value is never stored."""
    model_config = ConfigDict(extra="forbid")
    target: str = ""
    secret_ref: str = ""


class PutBody(BaseModel):
    """What Setup may send. A field too many is refused without being repeated."""
    model_config = ConfigDict(extra="forbid")
    target: str = Field(default="", max_length=TARGET_LIMIT)
    secret_ref: str = Field(default="", max_length=120)


@dataclass(frozen=True)
class Plan:
    """Where one notice will be sent, pinned to the address that was checked."""
    scheme: str
    host: str
    port: int
    path: str
    ip: str
    listed: bool


def _pause(step: str) -> None:
    if pause is not None:
        pause(step)


def _clip(value: object, secret: str = "", limit: int = 240) -> str:
    """Drop a secret, an IPv6 address, and what `clean` already drops, then cut to `limit`."""
    text = str(value or "")
    if secret:
        text = text.replace(secret, "[removed]")
    text = _IPV6.sub("[removed]", text)
    return clean(text, limit)


def _number(value: object) -> int | None:
    """A count or a score. A yes/no is not a number, and a missing score stays missing."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def dumps(payload: dict) -> bytes:
    """The bytes that are signed and sent. Key order is the order of the dict."""
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()


def signature(secret: str, body: bytes, when: int) -> str:
    """`t=<seconds>,v1=<hex>` over `<t>.<body>` with HMAC-SHA-256."""
    digest = hmac.new(secret.encode(), f"{when}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={when},v1={digest}"


def verify(secret: str, body: bytes, header: str) -> bool:
    """Whether `header` is the signature of this body. A changed body or time does not match."""
    match = _HEADER.fullmatch(header or "")
    if not match:
        return False
    expected = signature(secret, body, int(match.group(1)))
    return hmac.compare_digest(expected, header)


# Written by Nyctr, not by a person. The time of day inside `at` matches an address pattern.
_KEPT = frozenset({"link", "id", "at", "kind", "nyctr"})


def _scrub(payload: dict, secret: str) -> dict:
    """Scrub text a person wrote. A time, an id, the kind, the version and the console link stay."""
    def walk(value: object, keep: bool) -> object:
        if isinstance(value, str):
            return value if keep else _clip(value, secret)
        if isinstance(value, list):
            return [walk(item, False) for item in value]
        if isinstance(value, dict):
            return {key: walk(item, key in _KEPT) for key, item in value.items()}
        return value
    walked = walk(payload, False)
    return walked if isinstance(walked, dict) else {}


def _secret_value(name: str) -> str:
    """The secret named for notices, or empty when it is missing or not a single line."""
    if not name or not SECRET_REF.fullmatch(name):
        return ""
    value = os.environ.get(name) or ""
    if "\r" in value or "\n" in value:
        return ""
    return value


def _load(db: Session) -> tuple[Saved, str | None]:
    """The saved address and secret name, and a sentence when they cannot be used."""
    row = db.get(Setting, KEY)
    if row is None:
        return Saved(), None
    try:
        saved = Saved.model_validate(row.value)
    except ValidationError:
        return Saved(), "The saved notice setting cannot be read, so nothing is sent."
    if not saved.secret_ref:
        return saved, None
    if not SECRET_REF.fullmatch(saved.secret_ref):
        return saved, "The secret's name is not one Nyctr can read, so nothing is sent."
    value = os.environ.get(saved.secret_ref)
    if not value:
        return saved, "The secret named for notices is not set on the server, so nothing is sent."
    if "\r" in value or "\n" in value:
        return saved, "The secret named for notices cannot be used, so nothing is sent."
    return saved, None


def _addr(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value.split("%", 1)[0])
    mapped = getattr(address, "ipv4_mapped", None)
    return mapped or address


def _blocked(value: str) -> bool:
    """True for a loopback, private, translated, multicast or other address a notice must not use.

    `64:ff9b::/96` and `::ffff:0:0:0/96` are refused whole. `::/96` is judged by the IPv4
    address it embeds. `::` and multicast are refused as well.
    """
    try:
        raw = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return True
    if raw.is_multicast or raw.is_unspecified:
        return True
    if isinstance(raw, ipaddress.IPv6Address):
        if raw in _NAT64 or raw in _TRANSLATED:
            return True
        if raw in _COMPAT:
            embedded = ipaddress.IPv4Address(int(raw) & 0xFFFFFFFF)
            return not embedded.is_global or embedded.is_multicast
        mapped = raw.ipv4_mapped
        if mapped is not None:
            return not mapped.is_global or mapped.is_multicast
    return not raw.is_global


def _same(left: str, right: str) -> bool:
    try:
        return _addr(left) == _addr(right)
    except ValueError:
        return False


def _metadata(host: str) -> bool:
    name = host.lower().rstrip(".")
    return name in _METADATA or name.endswith(".metadata.google.internal")


def resolve(host: str, port: int) -> list[str]:
    """The addresses a name resolves to. A literal is itself. A lookup failure can be tried again."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise Unreachable("The address could not be looked up.") from error
    found: list[str] = []
    for info in infos:
        ip = str(info[4][0]).split("%", 1)[0]
        if ip not in found:
            found.append(ip)
    if not found:
        raise Unreachable("The address could not be looked up.")
    return found


def _parts(target: str) -> tuple[Any, str, int]:
    if target and not target.isascii():
        raise Refused("The address must use only plain letters, numbers and the marks in a web address.")
    if not target or len(target) > TARGET_LIMIT or not target.isprintable() or any(char.isspace() for char in target) \
            or "\\" in target:
        raise Refused("The address must be one web address, on one line.")
    try:
        parsed = urlsplit(target)
        port = parsed.port if parsed.port is not None else {"http": 80, "https": 443}.get(parsed.scheme)
    except ValueError:
        raise Refused("The address must be one web address Nyctr can read.") from None
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in ("http", "https") or not host or not port:
        raise Refused("The address must start with https://.")
    if parsed.query or parsed.fragment or "?" in target or "#" in target:
        raise Refused("The address must not hold a question mark or a #.")
    return parsed, host, port


def _listed(scheme: str, host: str, port: int, settings: Settings) -> bool:
    return (scheme, host, port) in settings.notice_origins


def _normal(target: str, settings: Settings) -> str:
    """The address as it will be called: no name, no password, no question mark."""
    parsed, host, port = _parts(target)
    listed = _listed(parsed.scheme, host, port, settings)
    if (parsed.username or parsed.password or "@" in parsed.netloc) and not listed:
        raise Refused("The address has a name and password in it. Take them out, or list this server.")
    if parsed.scheme != "https" and not listed:
        raise Refused("Notices go over HTTPS. List this server if it has to be plain HTTP.")
    if _metadata(host) and not listed:
        raise Refused("That address is not a place a notice can be sent.")
    try:
        number = ipaddress.ip_address(host)
    except ValueError:
        number = None
    if number is not None and _blocked(host) and not listed:
        raise Refused("That address is not a public server. List it if a notice should go there.")
    return _join(parsed.scheme, host, port) + (parsed.path or "")


def _join(scheme: str, host: str, port: int) -> str:
    """scheme://host[:port], with an IPv6 host in brackets and a default port left off."""
    name = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{name}" + ("" if port == default else f":{port}")


def _origin(target: str) -> str:
    """The server only. The path can hold a secret, so it is not shown or written into the activity record."""
    if not target:
        return ""
    try:
        parsed, host, port = _parts(target)
    except Refused:
        return ""
    return _join(parsed.scheme, host, port)


def vet(target: str, settings: Settings, lookup: Callable[[str, int], list[str]] = resolve) -> Plan:
    """Refuse an address Nyctr may not call, and pin the address it will connect to.

    Plain HTTP, a name and password, a metadata name and any non-public address
    are refused unless that exact server is listed. If any answer for the name
    is non-public, the name is refused unless it is listed. A redirect is never
    followed; that is the caller's job, because this only chooses the address.
    """
    parsed, host, port = _parts(target)
    listed = _listed(parsed.scheme, host, port, settings)
    if (parsed.username or parsed.password or "@" in parsed.netloc) and not listed:
        raise Refused("The address has a name and password in it. Take them out, or list this server.")
    if parsed.scheme != "https" and not listed:
        raise Refused("Notices go over HTTPS. List this server if it has to be plain HTTP.")
    if _metadata(host) and not listed:
        raise Refused("That address is not a place a notice can be sent.")
    answers = lookup(host, port)
    if any(_blocked(ip) for ip in answers) and not listed:
        raise Refused("That address is not a public server. List it if a notice should go there.")
    if not answers:
        raise Unreachable("The address could not be looked up.")
    return Plan(parsed.scheme, host, port, parsed.path or "/", answers[0], listed)


def _budget(deadline: float) -> float:
    """Seconds left before this send must stop."""
    left = deadline - time.monotonic()
    if left <= 0:
        raise Unreachable("Nyctr could not reach that address.")
    return left


def _interrupt(sock: socket.socket | None) -> None:
    """Stop a read that `close` cannot stop, because the reply's file still holds the socket."""
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _drain(response: Any, sock: socket.socket, deadline: float) -> None:
    """Read at most 64KiB, and stop at the deadline even when bytes are still arriving."""
    left = 65536
    while left > 0 and time.monotonic() < deadline:
        try:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            piece = response.read(1)
        except (TimeoutError, OSError):
            return
        if not piece:
            return
        left -= len(piece)


def _post(plan: Plan, body: bytes, headers: dict[str, str], deadline: float | None = None,
          holder: dict[str, Any] | None = None) -> int:
    """POST the body to the pinned address. A redirect is not followed. The peer must be that address.

    One deadline covers the connection and the reply. A status line already read is kept when the
    body runs past that deadline. Any other failure, including a reply that is not HTTP, is a miss.
    """
    deadline = time.monotonic() + TIMEOUT if deadline is None else deadline
    raw: socket.socket | ssl.SSLSocket | None = None
    conn: HTTPConnection | None = None
    try:
        raw = socket.create_connection((plan.ip, plan.port), _budget(deadline))
        if holder is not None:
            holder["sock"] = raw
        raw.settimeout(_budget(deadline))
        peer = raw.getpeername()[0]
        if not _same(peer, plan.ip) or (_blocked(peer) and not plan.listed):
            raise Refused("The connection reached an address Nyctr will not send to.")
        if plan.scheme == "https":
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=plan.host)
            if holder is not None:
                holder["sock"] = raw
        conn = (HTTPSConnection if plan.scheme == "https" else HTTPConnection)(plan.host, plan.port)
        conn.sock = raw
        raw = None
        conn.request("POST", plan.path, body=body, headers=headers)
        response = conn.getresponse()
        status = response.status
        if holder is not None:
            holder["status"] = status
        _drain(response, conn.sock, deadline)
        return status
    except Refused:
        raise
    except Exception as error:
        if holder is not None and "status" in holder:
            return int(holder["status"])
        raise Unreachable("Nyctr could not reach that address.") from error
    finally:
        if raw is not None:
            raw.close()
        if conn is not None:
            conn.close()


def _exchange(target: str, settings: Settings, body: bytes, headers: dict[str, str]) -> int:
    """Look up the name, connect and read the reply inside one deadline of TIMEOUT seconds.

    A lookup that never returns is left behind. A reply that is still arriving is cut off,
    and that read ends before this returns, so the next try does not overlap it.
    """
    holder: dict[str, Any] = {}
    deadline = time.monotonic() + TIMEOUT

    def run() -> None:
        try:
            plan = vet(target, settings)
            holder["status"] = _post(plan, body, headers, deadline, holder)
        except Exception as error:
            holder["error"] = error

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(max(0.0, deadline - time.monotonic()))
    if worker.is_alive():
        sock = holder.get("sock")
        _interrupt(sock)
        # No socket yet means the lookup has not connected. Leave that thread behind.
        worker.join(5 if sock is not None else 2)
    if "status" in holder:
        return int(holder["status"])
    error = holder.get("error")
    if isinstance(error, (Refused, Unreachable)):
        raise error
    raise Unreachable("Nyctr could not reach that address.")


def _exists(db: Session, kind: str, subject: str) -> bool:
    return db.scalar(select(Notice.id).where(Notice.kind == kind, Notice.subject == subject).limit(1)) is not None


def _request_fields(row: AccessRequest, person: str, reason: str, secret: str) -> dict[str, Any]:
    return {"id": row.id, "address": _clip(row.domain, secret, 255), "device": _clip(row.device_name, secret, 255),
            "person": _clip(person, secret, 160), "reason": _clip(reason, secret, 240),
            "score": _number(row.risk_score), "minutes": _number(row.duration_minutes)}


def _envelope(notice: Notice, settings: Settings, title: str, lines: list[str], request: dict | None, link: str,
              secret: str) -> dict[str, Any]:
    return {"v": 1, "id": notice.id, "kind": notice.kind, "at": utc(notice.created_at).isoformat(),
            "nyctr": __version__, "title": _clip(title, secret, LINE_LIMIT),
            "lines": [_clip(line, secret, LINE_LIMIT) for line in lines[:3]],
            "request": request, "link": link}


def _add(db: Session, settings: Settings, kind: str, subject: str, title: str, lines: list[str],
         request: dict | None, link: str, secret: str, notice_id: str | None = None) -> Notice | None:
    """Insert one notice. A second writer for the same kind and subject inserts nothing."""
    now = utcnow()
    notice = Notice(id=notice_id or uid(), kind=kind, subject=subject, payload={}, state="due", attempts=0,
                    next_try_at=now, created_at=now)
    notice.payload = _envelope(notice, settings, title, lines, request, link, secret)
    _pause("adding")
    try:
        with db.begin_nested():
            db.add(notice)
            db.flush()
    except IntegrityError:
        if notice in db:
            db.expunge(notice)
        return None
    return notice


def waiting(db: Session, settings: Settings, row: AccessRequest) -> Notice | None:
    """Queue one notice that this request is waiting. The caller commits it with the decision."""
    if row.status != "pending" or _exists(db, "request_waiting", row.id):
        return None
    secret = _secret_value(_load(db)[0].secret_ref)
    person = db.get(User, row.requester_id)
    observation = db.get(Observation, row.block_id) if row.block_id else None
    name = person.name if person and person.name else "Someone"
    lines = [part.strip() for part in (row.decision_note or "").splitlines() if part.strip()][:3]
    request = _request_fields(row, name, observation.reason if observation else "", secret)
    link = f"{settings.public_url}/#/requests?id={quote(row.id, safe='')}"
    return _add(db, settings, "request_waiting", row.id, f"{name} is waiting on {row.domain}", lines, request, link,
                secret)


def stuck(db: Session, settings: Settings, lease: Lease) -> Notice | None:
    """Queue one notice that this opening could not be removed. A later try does not queue another."""
    if lease.status not in ("active", "unconfirmed") or _exists(db, "lease_stuck", lease.id):
        return None
    secret = _secret_value(_load(db)[0].secret_ref)
    request = None
    link = f"{settings.public_url}/#/access"
    if lease.request_id and (row := db.get(AccessRequest, lease.request_id)):
        person = db.get(User, row.requester_id)
        observation = db.get(Observation, row.block_id) if row.block_id else None
        name = person.name if person and person.name else "Someone"
        request = _request_fields(row, name, observation.reason if observation else "", secret)
        link = f"{settings.public_url}/#/requests?id={quote(row.id, safe='')}"
    return _add(db, settings, "lease_stuck", lease.id, "An opening could not be removed",
                ["Nyctr could not remove this opening and will keep trying."], request, link, secret)


def _queue_test(db: Session, settings: Settings) -> Notice:
    secret = _secret_value(_load(db)[0].secret_ref)
    notice_id = uid()
    notice = _add(db, settings, "test", notice_id, "This is a test", ["Nyctr can reach this address."], None,
                  f"{settings.public_url}/#/setup?tab=system", secret, notice_id)
    if notice is None:
        raise Refused("That test was already queued.")
    return notice


def words(notice: Notice) -> str:
    """What the last send did, in plain words. No address and no secret."""
    if notice.state == "sent":
        return "Sent."
    if notice.state == "sending":
        return "Sending."
    if notice.state == "due":
        return "Waiting to send."
    status = notice.last_status
    if status is not None and 300 <= status < 400:
        return "The server sent Nyctr somewhere else. Nyctr did not follow it."
    if status is not None and 400 <= status < 500:
        return "The server refused the notice, so Nyctr will not try again."
    if notice.attempts >= TRIES:
        return "Nyctr tried five times and could not deliver this notice."
    return "Nyctr will not send this notice to that address."


def attention_items(db: Session) -> list[dict[str, Any]]:
    """Notices that will not be tried again, and a setting that stops every send."""
    items = []
    _saved, problem = _load(db)
    if problem:
        items.append({"kind": "notice", "id": KEY, "severity": "medium", "at": None,
                      "title": "Notices are not being sent", "detail": problem})
    for notice in db.scalars(select(Notice).where(Notice.state == "gave_up").order_by(Notice.created_at)):
        payload = notice.payload if isinstance(notice.payload, dict) else {}
        title = payload.get("title") if isinstance(payload.get("title"), str) else ""
        items.append({"kind": "notice", "id": notice.id, "severity": "medium",
                      "at": utc(notice.created_at).isoformat(),
                      "title": title or "A notice was not sent", "detail": words(notice)})
    return items


def _hosts(settings: Settings) -> list[str]:
    return [_join(scheme, host, port) for scheme, host, port in sorted(settings.notice_origins)]


def _recent(db: Session) -> list[dict[str, Any]]:
    rows = db.scalars(select(Notice).order_by(Notice.created_at.desc()).limit(8)).all()
    return [{"id": row.id, "kind": row.kind, "state": row.state, "attempts": row.attempts,
             "last_status": row.last_status, "at": utc(row.created_at).isoformat(), "words": words(row)}
            for row in rows]


def describe(db: Session, settings: Settings) -> dict[str, Any]:
    """The notice setting for Setup. The secret's value is never included."""
    saved, problem = _load(db)
    if saved.secret_ref and not problem:
        signing = "Notices are signed with the secret named here. The secret stays on the server."
    elif problem:
        signing = problem
    else:
        signing = "Notices are sent without a signature. Name a secret to sign them."
    return {"target": _origin(saved.target), "secret_ref": saved.secret_ref, "unsigned": not saved.secret_ref,
            "signing": signing, "problem": problem, "editable": settings.mode != "demo",
            "hosts": _hosts(settings), "recent": _recent(db)}


def save(db: Session, settings: Settings, body: PutBody) -> Saved:
    """Store the address and the secret's name. The secret's value is never stored."""
    secret_ref = body.secret_ref.strip()
    if secret_ref and not SECRET_REF.fullmatch(secret_ref):
        raise Refused("The secret's name must start with NYCTR_NOTICE_SECRET_ and use only capital letters, "
                      "digits and underscores.")
    previous = _load(db)[0].target
    stripped = body.target.strip()
    if not stripped:
        stored = ""
    else:
        stored = _normal(stripped, settings)
        # The card shows the server only. Saving that again must not drop a path the card does not show.
        if previous and stored == _origin(previous):
            stored = previous
    saved = Saved(target=stored, secret_ref=secret_ref)
    row = db.get(Setting, KEY)
    if row is None:
        db.add(Setting(key=KEY, value=saved.model_dump()))
    else:
        row.value = saved.model_dump()
        row.updated_at = utcnow()
    return saved


def _release_stale(factory, now: datetime) -> None:
    """Give back a claim older than CLAIM_TTL. A claim another copy still holds is left alone."""
    bound = now - timedelta(seconds=CLAIM_TTL)
    with factory() as db:
        rows = db.execute(select(Notice.id, Notice.claimed_by, Notice.claimed_at).where(Notice.state == "sending")).all()
        stale = [(notice_id, holder) for notice_id, holder, claimed in rows
                 if claimed is None or utc(claimed) < bound]
        if not stale:
            return
        for notice_id, holder in stale:
            holder_match = Notice.claimed_by.is_(None) if holder is None else Notice.claimed_by == holder
            db.execute(update(Notice).where(Notice.id == notice_id, Notice.state == "sending", holder_match)
                       .values(state="due", claimed_by=None, claimed_at=None))
        db.commit()


def _due_ids(factory, now: datetime, only: frozenset[str] | None, skip: frozenset[str]) -> list[str]:
    """Ids that looked due. The claim update checks the schedule again, so this list can be stale."""
    with factory() as db:
        rows = db.execute(select(Notice.id, Notice.next_try_at).where(Notice.state == "due")
                          .order_by(Notice.created_at, Notice.id)).all()
        due = [row.id for row in rows if row.id not in skip and utc(row.next_try_at) <= now
               and (only is None or row.id in only)]
        db.rollback()
        return due


def _claim(factory, now: datetime, only: frozenset[str] | None,
           skip: frozenset[str] = frozenset()) -> list[tuple[str, str]]:
    """Take one due notice. The update itself requires that it is still due at `now`.

    Nothing is remembered until that update commits. `now` is the same value stored on the claim.
    """
    for notice_id in _due_ids(factory, now, only, skip):
        _pause("picking")
        token = uid()
        with factory() as db:
            changed = db.execute(update(Notice).where(Notice.id == notice_id, Notice.state == "due",
                                                      Notice.next_try_at <= now)
                                 .values(state="sending", claimed_by=token, claimed_at=now)).rowcount
            if changed != 1:
                db.rollback()
                continue
            db.flush()
            _pause("claiming")
            db.commit()
            return [(notice_id, token)]
    return []


def _owns(factory, notice_id: str, token: str) -> bool:
    """True when this copy still holds the claim. A row lock is not enough."""
    with factory() as db:
        found = db.execute(select(Notice.state, Notice.claimed_by).where(Notice.id == notice_id)).first()
        db.rollback()
    return found is not None and found.state == "sending" and found.claimed_by == token


def _left(factory, notice_id: str) -> str:
    """The row's state, unchanged. Used when this copy no longer holds the claim."""
    with factory() as db:
        notice = db.get(Notice, notice_id)
        state = notice.state if notice is not None else "missing"
        db.rollback()
        return state


def _finish(factory, notice_id: str, outcome: str, status: int | None, clock: Callable[[], datetime],
            token: str) -> str:
    """Record the outcome only while this copy's claim is the one on the row."""
    now = utc(clock())
    with factory() as db:
        notice = db.scalar(select(Notice).where(Notice.id == notice_id).with_for_update())
        if notice is None:
            return "missing"
        if notice.state != "sending" or notice.claimed_by != token:
            state = notice.state
            db.rollback()
            return state
        notice.claimed_by = None
        notice.claimed_at = None
        if outcome == "sent":
            notice.state = "sent"
            notice.last_status = status
        elif outcome == "restore":
            notice.state = "due"
        else:
            notice.attempts += 1
            notice.last_status = status
            if outcome == "retry" and notice.attempts < TRIES:
                notice.state = "due"
                notice.next_try_at = now + timedelta(seconds=DELAYS[notice.attempts - 1])
            else:
                notice.state = "gave_up"
        db.flush()
        _pause("writing")
        db.commit()
        return notice.state


def _send(factory, settings: Settings, notice_id: str, clock: Callable[[], datetime], token: str) -> str:
    with factory() as db:
        notice = db.get(Notice, notice_id)
        if notice is None:
            return "missing"
        saved, problem = _load(db)
        secret = _secret_value(saved.secret_ref)
        payload = _scrub(dict(notice.payload or {}), secret)
        body = dumps(payload)
        if dumps(notice.payload or {}) != body:
            notice.payload = payload
            db.commit()
        else:
            db.rollback()
        target = saved.target
    _pause("checked")
    if not target or problem:
        return _finish(factory, notice_id, "restore", None, clock, token)
    headers = {"Content-Type": "application/json", "X-Nyctr-Notice-Id": notice_id}
    if secret:
        headers["X-Nyctr-Signature"] = signature(secret, body, int(utc(clock()).timestamp()))
    _pause("sending")
    if not _owns(factory, notice_id, token):
        return _left(factory, notice_id)
    try:
        status = _exchange(target, settings, body, headers)
    except Unreachable:
        return _finish(factory, notice_id, "retry", None, clock, token)
    except Refused:
        return _finish(factory, notice_id, "give_up", None, clock, token)
    except Exception:
        return _finish(factory, notice_id, "retry", None, clock, token)
    if 200 <= status < 300:
        return _finish(factory, notice_id, "sent", status, clock, token)
    if status in (408, 429) or status >= 500:
        return _finish(factory, notice_id, "retry", status, clock, token)
    return _finish(factory, notice_id, "give_up", status, clock, token)


def deliver_due(factory, settings: Settings, clock: Callable[[], datetime] | None = None,
                only: frozenset[str] | None = None) -> list[str]:
    """Send every notice that is due. The network call happens with no database session open.

    A claim older than one minute is sent once. A claim another copy still holds
    is not sent. Each notice is claimed immediately before its own send, so a slow
    send does not let the later claims lapse. With no address, or with a secret
    name that cannot be used, nothing is claimed and no try is spent.
    """
    clock = clock or utcnow
    _release_stale(factory, utc(clock()))
    with factory() as db:
        saved, problem = _load(db)
        db.rollback()
    if not saved.target or problem:
        return []
    outcomes: list[str] = []
    done: set[str] = set()
    while True:
        claimed = _claim(factory, utc(clock()), only, frozenset(done))
        if not claimed:
            return outcomes
        notice_id, token = claimed[0]
        done.add(notice_id)
        _pause("claimed")
        outcomes.append(_send(factory, settings, notice_id, clock, token))


@router.get("/notices")
def get_notices(request: Request, _user=Depends(admin), db: Session = Depends(get_db)):
    """The address, the secret's name, and the last few sends. Never the secret."""
    return describe(db, request.app.state.settings)


@router.put("/notices")
def put_notices(request: Request, body: Any = Body(None), user=Depends(admin), db: Session = Depends(get_db)):
    """Save the address and the secret's name. A refusal does not repeat what was typed."""
    settings = request.app.state.settings
    if settings.mode == "demo":
        raise HTTPException(409, "Notices cannot be set in the demo workspace.")
    try:
        incoming = PutBody.model_validate(body)
    except ValidationError:
        raise HTTPException(422, f"Not saved. {SHAPE}") from None
    try:
        saved = save(db, settings, incoming)
    except Refused as refusal:
        raise HTTPException(422, f"Not saved. {refusal}") from None
    audit(db, user.id, "notices.changed", KEY, secret_ref=saved.secret_ref, address=_origin(saved.target))
    db.commit()
    return describe(db, settings)


@router.post("/notices/test")
async def send_test(request: Request, user=Depends(admin), db: Session = Depends(get_db)):
    """Send one test notice, off this request's loop, and say how it went."""
    settings = request.app.state.settings
    if settings.mode == "demo":
        raise HTTPException(409, "Notices cannot be set in the demo workspace.")
    saved, problem = _load(db)
    if not saved.target:
        raise HTTPException(409, "Set the address first, then test it.")
    if problem:
        raise HTTPException(409, problem)
    notice = _queue_test(db, settings)
    audit(db, user.id, "notices.tested", notice.id, secret_ref=saved.secret_ref)
    db.commit()
    from .collection import off_loop

    factory, notice_id = request.app.state.session_factory, notice.id
    await off_loop(lambda: deliver_due(factory, settings, only=frozenset({notice_id})))
    db.expire_all()  # The send wrote the outcome on another connection.
    return describe(db, settings)
