"""The model: where it is, the one function every call goes through, and what a trace carries.

An administrator connects the model in the console (`PUT /api/model`). Until
one does, the server's own `NYCTR_AI_*` settings are the starting value; a saved
value wins, the rule the collection schedule follows. With only the server's
settings no trace is sent unless `NYCTR_AI_TRACE` asks for one, so such an
installation sends what it always sent.

Two limits keep a signed-in administrator from sending a key somewhere else:

- The key is named, never typed. The console takes the name of a server
  environment variable, which must match `NYCTR_MODEL_SECRET_*`. A source's
  secret has its own pattern, so neither can be pointed at the other. The key
  the server was given directly (`NYCTR_AI_API_KEY`) is sent only to the
  address it was given beside (`NYCTR_AI_BASE_URL`).
- The endpoint must be on a server the operator named, by scheme, host and
  port: an entry of `NYCTR_MODEL_HOSTS`, or the server's own
  `NYCTR_AI_BASE_URL`. A bare name in the list means HTTPS on port 443 only;
  plain HTTP or another port is allowed only where the operator wrote it. Both
  limits are checked when a value is saved and again before every call, and no
  redirect is followed.

A saved value this version cannot read never falls back to the server's own
endpoint and key: the model is off, and says so, until it is saved again.

Every call to the model goes through `call`. It adds the trace fields as
request headers, because an endpoint ignores a header it does not know. Nothing
about a person or a device goes in them: the purpose is one of a fixed set, and
what the call is about is named by a keyed digest of its id, never by the id.
The key is this installation's own, made at start-up and kept in the settings
table. A call only reads it. Without a key a digest could be matched against
guessed ids, so a call that cannot read one sends no session at all: a
database error, an empty key or a key that is not 32 bytes never fails the
call and never sends an unkeyed digest. It is not the model's key, which every
endpoint receives, and it is never sent or shown. It is read in a database
session of its own, so asking the model never saves or discards work the
caller has not saved.
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from hashlib import sha256
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, StrictInt
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from . import __version__
from .config import Settings
from .models import Setting, utcnow

KEY = "model_connection"
SECRET_REF = re.compile(r"NYCTR_MODEL_SECRET_[A-Z0-9_]{1,100}")
STYLES = ("off", "standard", "proxy", "proxy_body")
PURPOSES = frozenset({"nyctr.question", "nyctr.explanation", "nyctr.test", "nyctr.analysis"})
SUBJECTS = frozenset({"finding", "request"})
SECONDS = (5, 120, 60)  # the shortest and longest time limit, and the one in force until another is saved
# The tracing proxy's header for each neutral field. Data only: no code branches on which proxy is there.
PROXY_HEADERS = {"trace_id": "langfuse_trace_id", "trace_name": "langfuse_trace_name",
                 "session_id": "langfuse_session_id", "trace_metadata": "langfuse_trace_metadata",
                 "trace_release": "langfuse_trace_release"}
TRACE_KEY = "model_trace_key"
SERVER_SETTING = ("The model's address set on the server (NYCTR_AI_BASE_URL) cannot be used: it names no server, "
                  "or its port is not a number from 1 to 65535. Whoever runs the Nyctr server corrects it there. "
                  "Until then the model is off.")
UNREADABLE = ("The saved model setting cannot be read by this version of Nyctr, so the model is off. "
              "Save it again under Setup, This installation.")
SHAPE = ("Send only the endpoint, the model, the name of the secret, the trace style and the time limit, "
         "each in the form the Model card sends.")
# Tests put a stand-in endpoint here. None is the network.
transport: httpx.AsyncBaseTransport | None = None
# The trace id of the call just made, for the caller to store. None when tracing is off or the call
# stopped before a trace was built. Every call clears it first, so an earlier id cannot leak into this one.
current_trace: ContextVar[str | None] = ContextVar("nyctr_current_trace", default=None)


class Refused(ValueError):
    """A connection that may not be saved or used, in words an administrator can act on. Repeats no value."""


class ModelError(Exception):
    """A call that got no usable answer: why, and the status if the endpoint gave one. Never its text."""

    def __init__(self, outcome: str, status: int | None = None):
        super().__init__(outcome)
        self.outcome, self.status = outcome, status


class Connection(BaseModel):
    """What an administrator saves. `check` applies the rules, and a body of another shape is refused by
    the route in fixed words, so that no refusal repeats what was typed."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    endpoint: str
    model: str
    secret_ref: str = ""
    trace: str = "proxy"
    timeout_seconds: StrictInt = SECONDS[2]


@dataclass(frozen=True)
class InForce:
    """The connection that applies now. `source` is console, deployment or none.

    `trace` here is what a saved connection gets when it names none. The
    server's own settings bring theirs, which is off unless the operator set it.
    """
    endpoint: str = ""
    model: str = ""
    secret_ref: str = ""
    trace: str = "proxy"
    timeout_seconds: float = SECONDS[2]
    source: str = "none"

    @property
    def connected(self) -> bool:
        """Say whether there is a model to call."""
        return bool(self.endpoint and self.model)

    @property
    def unusable(self) -> str | None:
        """Say in plain words why a model that was set cannot be called at all, or None.

        Either the console holds a saved value this version cannot read, or
        the server's own address is one no request can be sent to.
        """
        if self.connected or self.source == "none":
            return None
        return UNREADABLE if self.source == "console" else SERVER_SETTING


def in_force(db: Session, settings: Settings) -> InForce:
    """Return the connection that applies now: the console's if one was saved, else the server's own.

    A saved value that cannot be read is still the console's: it comes back
    with no endpoint, so nothing is sent and the server's own endpoint and key,
    which an administrator replaced, are not used in its place.
    """
    row = db.get(Setting, KEY)
    if row is not None and settings.mode != "demo":
        try:
            saved = Connection(**row.value)
        except (ValueError, TypeError):
            return InForce(source="console")
        if not (saved.endpoint and saved.model):  # no save stores this, so it is not a value this version wrote
            return InForce(source="console")
        return InForce(saved.endpoint, saved.model, saved.secret_ref, saved.trace, saved.timeout_seconds, "console")
    if settings.ai_enabled:
        # An address with no server name or an unusable port is the server's, but nothing can be sent to it.
        usable = _own(settings) is not None
        return InForce(settings.ai_base_url if usable else "", settings.ai_model if usable else "",
                       trace=settings.ai_trace, source="deployment")
    return InForce()


def _origin(address: str) -> tuple[str, str, int | None]:
    """Reduce an address to scheme, host and port, to tell whether two are the same server."""
    parsed = urlsplit(address)
    port = parsed.port if parsed.port is not None else {"http": 80, "https": 443}.get(parsed.scheme)
    return parsed.scheme, (parsed.hostname or "").lower(), port


def _own(settings: Settings) -> tuple[str, str, int | None] | None:
    """Return the server in the server's own address, or None when it has none or names an unusable one."""
    try:
        own = _origin(settings.ai_base_url)
    except ValueError:  # a port that is not a number, or over 65535
        return None
    return own if own[1] and own[2] else None


def allowed_origins(settings: Settings) -> set[tuple[str, str, int | None]]:
    """Name the servers the operator lets the model's key and evidence go to, each by scheme, host and port."""
    own = _own(settings)
    return settings.model_origins | ({own} if own else set())


def _written(origin: tuple[str, str, int | None]) -> str:
    """Write an allowed server the way an endpoint on it starts."""
    scheme, host, port = origin
    name = f"[{host}]" if ":" in host else host
    return f"{scheme}://{name}" + ("" if port == {"http": 80, "https": 443}[scheme] else f":{port}")


def check(connection: Connection | InForce, settings: Settings) -> None:
    """Refuse a connection the rules do not allow. Run when one is saved and again before every call."""
    address = connection.endpoint
    try:
        parsed = urlsplit(address)
        host, _port = (parsed.hostname or "").lower(), parsed.port
    except ValueError:
        raise Refused("The endpoint is not a web address Nyctr can read.") from None
    if parsed.scheme not in ("http", "https") or not host or len(address) > 300 or "\\" in address \
            or any(char.isspace() for char in address) or not address.isprintable():
        raise Refused("The endpoint must be one web address that starts with https://, or with http:// where "
                      "whoever runs the Nyctr server allowed that.")
    if "@" in parsed.netloc:
        raise Refused("The endpoint must not hold a sign-in name or a password. The key is given by the name of "
                      "its secret.")
    if parsed.query or parsed.fragment or "?" in address or "#" in address:
        raise Refused("The endpoint must not hold a question mark or a #.")
    try:
        number = ipaddress.ip_address(host)
    except ValueError:
        number = None
    if host in {"metadata.google.internal", "metadata.azure.internal"} or (
            number and (number.is_link_local or number.is_multicast or number.is_unspecified)):
        raise Refused("The endpoint cannot be a cloud metadata or link-local address.")
    if _origin(address) not in allowed_origins(settings):
        raise Refused("The endpoint names a server Nyctr is not allowed to send the model's key to. Check it for "
                      "a typing mistake first, down to http or https and the port. Only whoever runs the Nyctr "
                      "server can allow a server: ask them to add it to NYCTR_MODEL_HOSTS.")
    if not 1 <= len(connection.model) <= 200 or not connection.model.isprintable():
        raise Refused("Give the model's name as the endpoint knows it, on one line.")
    if connection.secret_ref:
        if not SECRET_REF.fullmatch(connection.secret_ref):
            raise Refused("The secret's name must start with NYCTR_MODEL_SECRET_ and go on in capital letters, "
                          "digits or underscores. Give the name of the secret, never the key itself.")
        key = os.environ.get(connection.secret_ref)
        if not key:
            raise Refused("That secret is not set on the server. Whoever runs the Nyctr server adds it there "
                          "under that name.")
        if "\r" in key or "\n" in key:
            raise Refused("The key in that secret holds a line break, so it cannot be sent.")
    if connection.trace not in STYLES:
        raise Refused("Pick one of the four ways to trace calls.")
    if isinstance(connection.timeout_seconds, bool) or not SECONDS[0] <= connection.timeout_seconds <= SECONDS[1]:
        raise Refused("The time limit must be between 5 and 120 seconds.")


def _key(connection: InForce, settings: Settings) -> str | None:
    """Return the key for a checked connection, or None when the endpoint takes none."""
    if connection.secret_ref:
        return os.environ.get(connection.secret_ref) or None
    # The key the server was given directly goes only to the address it was given beside.
    same = connection.source == "deployment" or _origin(connection.endpoint) == _own(settings)
    return settings.ai_api_key or None if same else None


def save(db: Session, settings: Settings, body: Connection, actor: str) -> tuple[dict, dict]:
    """Store a checked connection and return the old and new record for the audit. The caller commits."""
    body.endpoint = body.endpoint.rstrip("/")
    check(body, settings)
    old = asdict(in_force(db, settings))
    # Written here, and not by the rule writer, so this module does not import it. A model's
    # answer must have no path to the code that stores a rule.
    row = db.get(Setting, KEY)
    if row is None:
        row = Setting(key=KEY)
        db.add(row)
    row.value = body.model_dump()
    row.updated_at = utcnow()
    row.updated_by = actor
    return old, body.model_dump()


def problem(connection: InForce, settings: Settings) -> str | None:
    """Say in plain words why the model that was set cannot be used now, or None when it can."""
    if connection.unusable:
        return connection.unusable
    if connection.source == "console":
        try:
            check(connection, settings)
        except Refused as refusal:
            return str(refusal)
    return None


def describe(db: Session, settings: Settings) -> dict:
    """Describe the connection in force for an administrator: where it came from, and never the key."""
    now = in_force(db, settings)
    key = "reference" if now.secret_ref else "server" if now.connected and _key(now, settings) else "none"
    return {**asdict(now), "connected": now.connected, "key": key, "problem": problem(now, settings),
            "editable": settings.mode != "demo", "hosts": sorted(_written(origin) for origin in
                                                                 allowed_origins(settings)),
            "styles": list(STYLES), "seconds": list(SECONDS[:2])}


def _stored_key(row: Setting | None) -> bytes:
    """Read the trace key out of its settings row, or nothing when the row is missing or is not a key."""
    try:
        key = bytes.fromhex(row.value["key"]) if row is not None else b""
    except (KeyError, TypeError, ValueError):
        return b""
    return key if len(key) == 32 else b""


def trace_key(db: Session) -> bytes:
    """Return this installation's key for trace sessions, making one when there is none.

    32 random bytes kept in the settings table under their own name. It is not
    the model's key and it goes in no request, answer or audit record, and in
    no log line Nyctr writes; SQL statement logging, if an operator turns it
    on, writes stored values, this one included. A new key only splits old and
    new traces into separate groups.

    The key is read and made in a short session of its own, on the caller's
    database. The caller's session is never committed or rolled back here, so
    work it has not saved is neither saved early nor lost. A stored value that
    is not a key is replaced. Two copies of Nyctr making the key at the same
    moment end on one: the second finds the row taken and uses the first's.
    """
    with Session(db.get_bind()) as own:
        row = own.get(Setting, TRACE_KEY)
        if key := _stored_key(row):
            return key
        if row is None:
            own.add(Setting(key=TRACE_KEY, value={"key": secrets.token_hex(32)}))
        else:  # not a key this version wrote
            row.value = {"key": secrets.token_hex(32)}
        try:
            own.commit()
        except IntegrityError:  # another copy made it between the read and the write: use that one
            own.rollback()
        return _stored_key(own.get(Setting, TRACE_KEY))


def read_trace_key(db: Session) -> bytes:
    """Read the trace key. A database error, a missing key or a key that is not one returns nothing.

    A call only reads. Making or replacing the key is start-up's job (`ensure_trace_key`), so a
    pool timeout or an empty key cannot fail the call. Nothing is logged: the message is fixed
    and the key is not in it, because this function does not log at all.
    """
    try:
        with Session(db.get_bind()) as own:
            return _stored_key(own.get(Setting, TRACE_KEY))
    except SQLAlchemyError:
        return b""


def ensure_trace_key(db: Session) -> None:
    """Make the trace key if this installation has none. A database error does not stop start-up.

    The warning is a fixed sentence. It does not include the key or the database's own message.
    """
    try:
        trace_key(db)
    except SQLAlchemyError:
        logging.getLogger("nyctr").warning("The trace key could not be made at start-up. Calls still go out.")


def trace(purpose: str, subject: tuple[str, str] | None, style: str, mode: str, prompt_version: str,
          key: bytes = b"") -> tuple[dict[str, str], dict | None]:
    """Build the trace headers for one call and, for `proxy_body`, the same fields for the body.

    Every value is a fixed word, a version, a new random id or a keyed digest.
    A subject's id is never sent: ids of findings are built from device ids,
    which can hold a name or a hardware address, and a plain digest of one can
    be matched against guesses by anyone who knows how the id begins. So the
    session is an HMAC under `key`, and a subject without a key is refused.
    """
    kind, ident = subject or ("none", "")
    if purpose not in PURPOSES or style not in STYLES or (subject and kind not in SUBJECTS) \
            or not re.fullmatch(r"[a-z0-9.-]{1,16}", prompt_version):
        raise ValueError("Not a known purpose, subject, trace style or prompt version")
    if style == "off":
        return {}, None
    trace_id = secrets.token_hex(16)
    headers = {"traceparent": f"00-{trace_id}-{secrets.token_hex(8)}-01"}
    if style == "standard":
        return headers, None
    about = {"nyctr_version": __version__, "prompt_version": prompt_version, "purpose": purpose,
             "subject_kind": kind, "mode": mode}
    fields = {"trace_id": trace_id, "trace_name": purpose, "trace_metadata": about, "trace_release": __version__}
    if subject:
        if len(key) != 32:
            raise ValueError("A trace session needs this installation's key")
        fields["session_id"] = f"{kind}:{hmac.new(key, f'{kind}:{ident}'.encode(), sha256).hexdigest()[:16]}"
    for name, value in fields.items():
        headers[PROXY_HEADERS[name]] = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
    return headers, fields if style == "proxy_body" else None


async def call(purpose: str, subject: tuple[str, str] | None, connection: InForce, settings: Settings, *,
               system: str, user: str, prompt_version: str = "1", max_tokens: int = 700,
               db: Session | None = None) -> str:
    """Ask the model once and return its text. The only place a request to the model is built.

    A call about a subject needs `db`, to read this installation's trace key. The key
    is not made here. The caller's session is only passed on: nothing here commits it
    or rolls it back. `current_trace` is set to this call's trace id, or to none.

    Raises Refused, before anything is sent, when the connection may not be
    used. Raises ModelError when no usable answer came back: `refused` (with
    the status, a redirect included, which is never followed), `not_reachable`,
    `wrong_shape` or `too_slow`. Neither repeats the endpoint's text or the key.
    """
    current_trace.set(None)
    if not connection.connected:
        raise Refused(connection.unusable or "No model is connected.")
    if connection.source == "console":
        check(connection, settings)
    key = _key(connection, settings)
    if key and ("\r" in key or "\n" in key):
        raise Refused("The model's key holds a line break, so it cannot be sent.")
    # Only a style that sends a session reads the key. A missing or unreadable key drops the
    # subject before the digest is built, so the call goes out and no unkeyed digest is sent.
    session_key, traced = b"", subject
    if subject is not None and connection.trace in ("proxy", "proxy_body") and db is not None:
        session_key = read_trace_key(db)
        if len(session_key) != 32:
            traced = None
    headers, about = trace(purpose, traced, connection.trace, settings.mode, prompt_version, session_key)
    parent = headers.get("traceparent")
    current_trace.set(parent.split("-")[1] if parent else None)
    if key:
        headers["Authorization"] = f"Bearer {key}"
    body = {"model": connection.model, "temperature": 0.2, "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
    if about:
        body["metadata"] = about
    limit, raw = connection.timeout_seconds, bytearray()
    try:
        async with asyncio.timeout(limit), httpx.AsyncClient(
                timeout=httpx.Timeout(limit, connect=min(10.0, limit)), follow_redirects=False, trust_env=False,
                transport=transport) as client, client.stream(
                    "POST", connection.endpoint + "/chat/completions", headers=headers, json=body) as response:
            if response.status_code != 200:
                raise ModelError("refused", response.status_code)
            async for chunk in response.aiter_bytes():
                raw += chunk
                if len(raw) > 512_000:
                    raise ModelError("wrong_shape")
        text = str(json.loads(raw)["choices"][0]["message"]["content"])
    except (TimeoutError, httpx.TimeoutException):
        raise ModelError("too_slow") from None
    except (httpx.HTTPError, httpx.InvalidURL):
        raise ModelError("not_reachable") from None
    except (ValueError, KeyError, IndexError, TypeError, RecursionError):  # an answer nested too deep included
        raise ModelError("wrong_shape") from None
    if key and key in text:  # An endpoint that hands the key back has not given a usable answer.
        raise ModelError("wrong_shape")
    return text


async def probe(connection: InForce, settings: Settings) -> dict:
    """Send one tiny fixed question and say how it went, repeating nothing the endpoint said."""
    try:
        await call("nyctr.test", None, connection, settings, system="Reply with one word.", user="Say: ready",
                   max_tokens=8)
    except ModelError as error:
        return {"outcome": error.outcome, "status": error.status}
    return {"outcome": "reachable", "status": None}
