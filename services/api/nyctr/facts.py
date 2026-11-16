"""Facts about a blocked name, gathered by fixed code.

Each fact is known, unavailable (with a plain reason) or not asked. A fact that
could not be had is never filled in with a default, and an unknown score stays
unknown. The registry and the system resolver are the only places asked. The
certificate would mean connecting to the host itself, and a third-party
reputation service would be told what was looked up, so both are left unasked.

Every outbound request is HTTPS, with no redirect, five seconds for the call
and eight for the whole gathering, and at most 256 kB read. The registry host,
and the host of the registry list, are resolved first; a private, loopback,
link-local or reserved address is refused before any connection. A request
carries the name and nothing else: no person, no device and no network.

Answers are kept for a day. Each name that was resolved or asked about is
written down for a day, so a later change can ignore Nyctr's own questions.
Nothing reads that list yet.

The gathering holds one settings row across each check and the write that
follows it, and flushes at three points while that hold lasts: the registry
list, the registration, and the lookup list. A second gathering waits at each.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

import httpx
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import risk
from .models import FactCache, Observation, OwnLookup, Setting, Workspace, utc, utcnow

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
LOCK_KEY = "fact_gather"
CALL_TIMEOUT = 5.0
GATHER_BUDGET = 8.0
RESOLVE_TIMEOUT = 3.0
MAX_BYTES = 256 * 1024
KEPT = timedelta(hours=24)
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"(?=^.{{1,253}}$)(?:{_LABEL}\.)+{_LABEL}")
_NO_ANSWER = frozenset(code for name in ("EAI_NONAME", "EAI_NODATA", "EAI_FAIL")
                       if (code := getattr(socket, name, None)) is not None)
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
# Replaced in tests that answer the registry without a connection.
_transport: httpx.BaseTransport | None = None

_REFUSED = {
    "private": "The registry's address is on a private network, so Nyctr did not connect.",
    "loopback": "The registry's address is on this server, so Nyctr did not connect.",
    "link-local": "The registry's address is only valid on the local link, so Nyctr did not connect.",
    "reserved": "The registry's address is reserved, so Nyctr did not connect.",
}
DEMONSTRATION = "The demonstration does not look names up."
NO_BLOCK = "Nyctr has no stored block for this address."
NO_SCORE = "There is no stored block to score."
REFUSES = "the resolver refuses it"


class NotAName(ValueError):
    """The text is not a domain name Nyctr will look up."""


class _GiveUp(Exception):
    """This outbound fact cannot be had. `cache` is false when the next gathering should try again."""

    def __init__(self, reason: str, *, cache: bool = True):
        super().__init__(reason)
        self.reason = reason
        self.cache = cache


class _TooBig(Exception):
    """The answer went past the most Nyctr reads."""


@dataclass
class Fact:
    """One fact from a single gathering. `id` is `f1`, `f2`, ... in that gathering only."""

    id: str
    kind: str
    value: object
    source: str
    at: datetime | None
    state: str
    reason: str | None = None

    def as_dict(self) -> dict:
        """The fact as JSON. A reason is included only when the fact could not be had."""
        body = {"id": self.id, "kind": self.kind, "value": self.value, "source": self.source,
                "at": self.at.isoformat() if self.at else None, "state": self.state}
        if self.state == "unavailable":
            body["reason"] = self.reason
        return body


def _wall() -> datetime:
    """The clock the cache is judged by. Tests move it instead of waiting."""
    return utcnow()


def _mono() -> float:
    """The clock the eight seconds are judged by. Tests move it instead of waiting."""
    return time.monotonic()


def _name(domain: str) -> str:
    """The name Nyctr will ask about: lower case, punycode, and nothing but the name."""
    if not isinstance(domain, str):
        raise NotAName("Give the address as a name.")
    text = domain.strip().lower().rstrip(".")
    if not text or any(char.isspace() for char in text) or not text.isprintable():
        raise NotAName("That is not an address Nyctr can look up.")
    if "://" in text or any(mark in text for mark in "/\\@?#"):
        raise NotAName("Give the address on its own, without a page or a path.")
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        raise NotAName("Give a name, not a numeric address.")
    try:
        ascii_name = text.encode("idna").decode("ascii")
    except UnicodeError:
        raise NotAName("That is not an address Nyctr can look up.") from None
    if not _DOMAIN.fullmatch(ascii_name):
        raise NotAName("That is not an address Nyctr can look up.")
    return ascii_name


def _plain(value: object, limit: int) -> str | None:
    """One line of text from an outside answer, or nothing when it is not text."""
    if not isinstance(value, str):
        return None
    cleaned = " ".join("".join(char for char in value if char.isprintable()).split())
    return cleaned[:limit] or None


def _known(kind: str, source: str, value: object, at: datetime) -> Fact:
    return Fact("", kind, value, source, at, "known")


def _unavailable(kind: str, source: str, reason: str, at: datetime) -> Fact:
    return Fact("", kind, None, source, at, "unavailable", reason)


def _not_asked(kind: str, at: datetime) -> Fact:
    return Fact("", kind, None, "nyctr", at, "not_asked")


def _number(facts: list[Fact]) -> list[Fact]:
    for number, fact in enumerate(facts, 1):
        fact.id = f"f{number}"
    return facts


def _demonstration(db: Session) -> bool:
    """The demonstration never contacts the registry or the resolver."""
    return db.scalar(select(Workspace.mode).where(Workspace.id == "default")) == "demo"


def _observations(db: Session, name: str) -> list[Observation]:
    rows = list(db.scalars(select(Observation).where(func.lower(Observation.domain) == name)))
    rows.sort(key=lambda row: (utc(row.observed_at), row.id))
    return rows


def _block(rows: list[Observation], at: datetime) -> Fact:
    """The newest stored block: its reason and the evidence kind, never a device or a person."""
    if not rows:
        return _unavailable("block", "stored", NO_BLOCK, at)
    row = rows[-1]
    return _known("block", "stored", {
        "reason": row.reason, "reason_codes": list(row.reason_codes or []), "reported_by": row.source,
        "evidence_kind": row.evidence_kind, "observed_at": utc(row.observed_at).isoformat()}, at)


def _score(name: str, rows: list[Observation], at: datetime) -> Fact:
    """The rule-based score. A missing score stays missing; it is never stored as a low one."""
    if not rows:
        return _unavailable("risk", "rules", NO_SCORE, at)
    row = rows[-1]
    assessment = risk.assess(name, row.reason or "", list(row.reason_codes or []), row.source)
    return _known("risk", "rules", assessment.as_dict(), at)


def _seen(rows: list[Observation], at: datetime) -> Fact:
    """How the stored blocks show this name: first time, how many devices, how often."""
    devices = {row.device_id for row in rows if row.device_id}
    first = utc(rows[0].observed_at).isoformat() if rows else None
    return _known("seen", "stored", {"first_seen": first, "devices": len(devices), "times": len(rows)}, at)


def _lock(db: Session) -> None:
    """Hold the row every gathering writes under, until this transaction ends.

    The row is committed on its own the first time, so the hold exists before
    the check that decides whether to ask the registry again. The update changes
    nothing: it locks the row on PostgreSQL and takes SQLite's write lock.
    """
    if db.get(Setting, LOCK_KEY) is None:
        db.add(Setting(key=LOCK_KEY, value={}))
        try:
            db.commit()
        except IntegrityError:  # another gathering created it between the read and the write
            db.rollback()
    db.execute(update(Setting).where(Setting.key == LOCK_KEY).values(updated_at=Setting.updated_at)
               .execution_options(synchronize_session=False))


def _fresh(row: FactCache | None, wall: datetime) -> bool:
    return row is not None and wall - utc(row.fetched_at) < KEPT


def _cached(db: Session, domain: str, kind: str, wall: datetime) -> FactCache | None:
    row = db.get(FactCache, (domain, kind))
    return row if _fresh(row, wall) else None


def _store(db: Session, domain: str, kind: str, fact: Fact, wall: datetime) -> None:
    """Write one cache row and flush it, still holding the lock taken in `_lock`."""
    payload = {"value": fact.value, "reason": fact.reason}
    row = db.get(FactCache, (domain, kind))
    if row is None:
        db.add(FactCache(domain=domain, kind=kind, value=payload, state=fact.state, fetched_at=wall))
    else:
        row.value, row.state, row.fetched_at = payload, fact.state, wall
    db.flush()


def _from_cache(row: FactCache, kind: str, source: str) -> Fact:
    payload = row.value or {}
    return Fact("", kind, payload.get("value"), source, utc(row.fetched_at), row.state, payload.get("reason"))


@dataclass
class _Job:
    db: Session
    started: float
    wall: datetime
    lookups: list[str]


def _note(job: _Job, name: str) -> None:
    """Remember a name that is about to be resolved or asked about."""
    job.lookups.append(name)


def _left(job: _Job) -> float:
    return GATHER_BUDGET - (_mono() - job.started)


def _budget(job: _Job, limit: float, fn, timeout_reason: str):
    """Run `fn` only while the gathering still has time, and give it no more than that."""
    left = _left(job)
    if left <= 0:
        raise _GiveUp("Nyctr ran out of time before it could ask about this name.", cache=False)
    try:
        return fn(min(limit, left))
    except TimeoutError:
        raise _GiveUp(timeout_reason) from None


def _literal(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _why(address) -> str | None:
    """Which refused class an address is in, or nothing when Nyctr may connect to it."""
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        return _why(mapped) or "reserved"
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast or address.is_unspecified or address.is_reserved:
        return "reserved"
    if address.is_private or not address.is_global:
        return "private"
    return None


def _resolve(host: str, timeout: float) -> list | None:
    """Addresses for `host`, or None when the resolver has no answer.

    A literal address is not a lookup. Anything else is resolved in a thread:
    a resolver that never answers cannot be interrupted in place, and the
    thread is abandoned when `timeout` passes so the gathering can move on.
    """
    if (literal := _literal(host)) is not None:
        return [literal]

    def work():
        try:
            infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            if error.errno in _NO_ANSWER:
                return None
            raise
        found = []
        for info in infos:
            text = info[4][0].split("%", 1)[0]
            try:
                found.append(ipaddress.ip_address(text))
            except ValueError:
                return "refused"
        return found or None

    pool = ThreadPoolExecutor(max_workers=1)
    try:
        answer = pool.submit(work).result(timeout=timeout)
    finally:
        # Do not wait. A resolver that never answers must not hold the gathering.
        pool.shutdown(wait=False, cancel_futures=True)
    if answer == "refused":
        raise _GiveUp(_REFUSED["reserved"])
    return answer


def _read(url: str, address, timeout: float) -> tuple[int, bytes]:
    """GET `url` at the address already checked, and stop past 256 kB.

    The connection is to that address, not to whatever the name resolves to a
    moment later. Redirects are returned as they are and never followed.
    """
    parsed = urlsplit(url)
    host, port = parsed.hostname or "", parsed.port or 443
    literal = f"[{address}]" if address.version == 6 else str(address)
    pinned = urlunsplit(("https", f"{literal}:{port}", parsed.path, "", ""))
    headers = {"Accept": "application/rdap+json", "Host": host if port == 443 else f"{host}:{port}"}
    options: dict = {"follow_redirects": False, "trust_env": False, "timeout": httpx.Timeout(timeout), "verify": True}
    if _transport is not None:
        options["transport"] = _transport
    try:
        with httpx.Client(**options) as client:
            with client.stream("GET", pinned, headers=headers, extensions={"sni_hostname": host}) as response:
                chunks, size = [], 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise _TooBig()
                    chunks.append(chunk)
                return response.status_code, b"".join(chunks)
    except httpx.TimeoutException:
        raise TimeoutError from None
    except httpx.HTTPError:
        raise _GiveUp("The registry could not be reached.") from None


def _fetch(job: _Job, url: str, asked: str | None = None) -> tuple[int, bytes]:
    """Fetch one HTTPS URL, or give up before connecting when the address is not a public one.

    The host is recorded when it is resolved, and `asked` when the request is sent.
    A gathering that has run out of time does neither.
    """
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise _GiveUp("The registry's address is not a secure one, so Nyctr did not connect.")

    def resolve(timeout: float):
        if _literal(host) is None:
            _note(job, host)
        return _resolve(host, timeout)

    try:
        addresses = _budget(job, RESOLVE_TIMEOUT, resolve, "The registry's name did not resolve in time.")
    except _GiveUp:
        raise
    except OSError:
        raise _GiveUp("The registry's name did not resolve, so Nyctr did not connect.") from None
    if not addresses:
        raise _GiveUp("The registry's name did not resolve, so Nyctr did not connect.")
    if refused := next((_why(item) for item in addresses if _why(item)), None):
        raise _GiveUp(_REFUSED[refused])

    def read(timeout: float):
        if asked:
            _note(job, asked)
        return _read(url, addresses[0], timeout)

    try:
        status, body = _budget(job, CALL_TIMEOUT, read, "The registry did not answer in time.")
    except _TooBig:
        raise _GiveUp("The registry's answer was larger than Nyctr reads.") from None
    if len(body) > MAX_BYTES:
        raise _GiveUp("The registry's answer was larger than Nyctr reads.")
    if status in _REDIRECTS:
        raise _GiveUp("The registry redirected the request, which Nyctr does not follow.")
    return status, body


def _https_base(url: object) -> str | None:
    if not isinstance(url, str) or url.startswith("http://"):
        return None
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        return None
    return url


def _services(body: bytes) -> dict[str, str]:
    """The registry list: each suffix and the first secure address that serves it."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise _GiveUp("The list of domain registries could not be read.") from None
    services = data.get("services") if isinstance(data, dict) else None
    if not isinstance(services, list):
        raise _GiveUp("The list of domain registries could not be read.")
    found: dict[str, str] = {}
    insecure = False
    for entry in services:
        if not isinstance(entry, list) or len(entry) != 2:
            continue
        suffixes, urls = entry
        if not isinstance(suffixes, list) or not isinstance(urls, list):
            continue
        insecure = insecure or any(isinstance(url, str) and url.startswith("http://") for url in urls)
        secure = next((base for url in urls if (base := _https_base(url))), None)
        if secure is None:
            continue
        for suffix in suffixes:
            if isinstance(suffix, str) and (key := suffix.lower()) and key not in found:
                found[key] = secure
    if not found:
        if insecure:
            raise _GiveUp("The registry's address is not a secure one, so Nyctr did not connect.")
        raise _GiveUp("The list of domain registries could not be read.")
    return found


def _bootstrap(job: _Job) -> dict[str, str]:
    row = _cached(job.db, "", "rdap_bootstrap", job.wall)
    if row is not None and isinstance((row.value or {}).get("value"), dict):
        return row.value["value"]
    status, body = _fetch(job, BOOTSTRAP_URL)
    if status != 200:
        raise _GiveUp("Nyctr could not read the list of domain registries.")
    services = _services(body)
    _store(job.db, "", "rdap_bootstrap", _known("rdap_bootstrap", "registry", services, job.wall), job.wall)
    return services


def _match(services: dict[str, str], name: str) -> str | None:
    """The registry for the longest suffix of `name` the list knows."""
    labels = name.split(".")
    for length in range(len(labels), 0, -1):
        if (base := services.get(".".join(labels[-length:]))):
            return base
    return None


def _join(base: str, name: str) -> str:
    parsed = urlsplit(base)
    path = parsed.path if parsed.path.endswith("/") else parsed.path + "/"
    return urlunsplit(("https", parsed.netloc, f"{path}domain/{name}", "", ""))


def _registrar(entities: list) -> str | None:
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        if not isinstance(roles, list) or "registrar" not in roles:
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) >= 2 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn" and (name := _plain(item[3], 200)):
                    return name
    return None


def _parse(body: bytes) -> dict:
    """Registration date, expiry, registrar and status words. Nothing is filled in when absent."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise _GiveUp("The registry's answer could not be read.") from None
    if not isinstance(data, dict):
        raise _GiveUp("The registry's answer could not be read.")
    events, status, entities = data.get("events", []), data.get("status", []), data.get("entities", [])
    if not isinstance(events, list) or not isinstance(status, list) or not isinstance(entities, list):
        raise _GiveUp("The registry's answer could not be read.")
    registered = expires = None
    for event in events:
        if not isinstance(event, dict):
            continue
        when = _plain(event.get("eventDate"), 40)
        if event.get("eventAction") == "registration":
            registered = registered or when
        elif event.get("eventAction") == "expiration":
            expires = expires or when
    words = []
    for word in status:
        if len(words) == 32:
            break
        if cleaned := _plain(word, 80):
            words.append(cleaned)
    value = {}
    if registered:
        value["registered"] = registered
    if expires:
        value["expires"] = expires
    if registrar := _registrar(entities):
        value["registrar"] = registrar
    if words:
        value["status"] = words
    if not value:
        raise _GiveUp("The registry's answer named no registration.")
    return value


def _candidates(name: str) -> list[str]:
    """The registered name: the last two labels, then the last three when the first is missing."""
    labels = name.split(".")
    found = [".".join(labels[-2:])] if len(labels) >= 2 else []
    if len(labels) >= 3 and (third := ".".join(labels[-3:])) not in found:
        found.append(third)
    return found


def _rdap(job: _Job, name: str) -> dict:
    services = _bootstrap(job)
    missed = "The registry has no record of this name."
    for candidate in _candidates(name):
        base = _match(services, candidate)
        if base is None:
            raise _GiveUp("The list of domain registries has no registry for this name.")
        if urlsplit(base).scheme != "https":
            raise _GiveUp("The registry's address is not a secure one, so Nyctr did not connect.")
        status, body = _fetch(job, _join(base, candidate), asked=candidate)
        if status == 404:
            continue
        if status >= 500:
            raise _GiveUp("The registry reported an error.")
        if status != 200:
            raise _GiveUp("The registry did not return a registration.")
        value = _parse(body)
        value["name"] = candidate
        return value
    raise _GiveUp(missed)


def _registration(job: _Job, name: str) -> Fact:
    if (row := _cached(job.db, name, "registration", job.wall)) is not None:
        return _from_cache(row, "registration", "registry")
    try:
        value = _rdap(job, name)
    except _GiveUp as error:
        fact = _unavailable("registration", "registry", error.reason, job.wall)
        if error.cache:
            _store(job.db, name, "registration", fact, job.wall)
        return fact
    fact = _known("registration", "registry", value, job.wall)
    _store(job.db, name, "registration", fact, job.wall)
    return fact


def _resolution(job: _Job, name: str) -> Fact:
    """Where the name resolves. No answer is kept as a refusal, not as an address."""
    def ask(timeout: float):
        _note(job, name)
        return _resolve(name, timeout)

    try:
        found = _budget(job, RESOLVE_TIMEOUT, ask, "The resolver did not answer in time.")
    except _GiveUp as error:
        return _unavailable("resolution", "resolver", error.reason, job.wall)
    except OSError:
        return _unavailable("resolution", "resolver", "The resolver could not answer.", job.wall)
    if not found:
        return _known("resolution", "resolver", REFUSES, job.wall)
    return _known("resolution", "resolver", sorted({str(item) for item in found}), job.wall)


def _save_lookups(job: _Job) -> None:
    """Write the names this gathering resolved or asked about, and drop those older than a day."""
    job.db.execute(delete(OwnLookup).where(OwnLookup.at <= job.wall - KEPT))
    for name in job.lookups:
        job.db.add(OwnLookup(name=name, at=job.wall))
    job.db.flush()


def _outside(db: Session, name: str, wall: datetime, started: float) -> tuple[Fact, Fact]:
    """Registration and resolution, under the lock, then the names that were asked about."""
    _lock(db)
    job = _Job(db, started, wall, [])
    registration = _registration(job, name)
    resolution = _resolution(job, name)
    _save_lookups(job)
    db.commit()
    return registration, resolution


def gather(db: Session, domain: str) -> list[Fact]:
    """Gather the facts for one name. Commits the cache and the lookup list.

    The caller's session is committed when a lookup is stored. A failure rolls
    the unfinished write back; a fact that could not be had is in the list, not
    raised, except a name Nyctr will not look up.
    """
    name = _name(domain)
    wall, started = _wall(), _mono()
    try:
        rows = _observations(db, name)
        stored = [_block(rows, wall), _score(name, rows, wall), _seen(rows, wall)]
        if _demonstration(db):
            outside = [_unavailable("registration", "registry", DEMONSTRATION, wall),
                       _unavailable("resolution", "resolver", DEMONSTRATION, wall)]
        else:
            outside = list(_outside(db, name, wall, started))
    except Exception:
        db.rollback()
        raise
    return _number([*stored, *outside, _not_asked("certificate", wall), _not_asked("reputation", wall)])
