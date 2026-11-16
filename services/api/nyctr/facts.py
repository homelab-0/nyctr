"""Facts about a blocked name, gathered by fixed code.

Each fact is known, unavailable (with a plain reason) or not asked. A fact that
could not be had is never filled in with a default, and an unknown score stays
unknown. The registry and the system resolver are the only places asked. The
certificate would mean connecting to the host itself, and a third-party
reputation service would be told what was looked up, so both are left unasked.

Every outbound request is HTTPS, with no redirect, five seconds of clock time
for the call and eight for the whole gathering, and at most 256 kB read. The
read stops when the time is up or the size is past, whichever comes first. The
registry host, and the host of the registry list, are resolved first; a private,
loopback, link-local, site-local or other address that is not a public one is
refused before any connection. A request carries the name and nothing else: no
person, no device and no network.

A registration that was read, and the list of registries, are kept for a day.
A failure is kept for ten minutes. Running out of time is not kept. Each name
that was resolved or asked about is written down for a day, so a later change
can ignore Nyctr's own questions. Nothing reads that list yet.

The cache is read and the database is closed before any of those calls. The
answers and the lookup list are written afterwards, in one short step. A call
does not hold the database.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

import httpx
import idna
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from . import risk
from .models import FactCache, Observation, OwnLookup, Workspace, utc, utcnow

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
CALL_TIMEOUT = 5.0
GATHER_BUDGET = 8.0
RESOLVE_TIMEOUT = 3.0
MAX_BYTES = 256 * 1024
KEPT = timedelta(hours=24)
FAILURE_KEPT = timedelta(minutes=10)
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"(?=^.{{1,253}}$)(?:{_LABEL}\.)+{_LABEL}")
_WHEN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_NO_ANSWER = frozenset(code for name in ("EAI_NONAME", "EAI_NODATA", "EAI_FAIL")
                       if (code := getattr(socket, name, None)) is not None)
_REDIRECTS = frozenset({301, 302, 303, 307, 308})
# Python reports fec0::/10 as a global address. It is the old site-local range.
_SITE_LOCAL = ipaddress.IPv6Network("fec0::/10")
_SEPARATORS = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
# Replaced in tests that answer the registry without a connection.
_transport: httpx.BaseTransport | None = None
# Tests point this at a stand-in's certificate. The default checks the public authorities.
_verify: object = True

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
    """The name Nyctr will ask about, in IDNA 2008.

    A mapping that would turn the name into a different one is refused. The old
    IDNA 2003 rules do that to some names, and the registration would then be
    for a name the person did not ask about.
    """
    if not isinstance(domain, str):
        raise NotAName("Give the address as a name.")
    text = domain.strip().lower().rstrip(".").translate(_SEPARATORS)
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
        remapped = idna.uts46_remap(text, std3_rules=True, transitional=False)
    except idna.IDNAError:
        raise NotAName("That is not an address Nyctr can look up.") from None
    if unicodedata.normalize("NFC", remapped) != unicodedata.normalize("NFC", text):
        raise NotAName("That is not an address Nyctr can look up.")
    try:
        ascii_name = idna.encode(remapped, strict=True, std3_rules=True).decode("ascii")
    except idna.IDNAError:
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


def _when(value: object) -> str | None:
    """An RFC 3339 date, or nothing when the text is not one. A missing date stays missing."""
    text = _plain(value, 40)
    if text is None or _WHEN.fullmatch(text) is None:
        return None
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return text


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


def _fresh(row: FactCache | None, wall: datetime) -> bool:
    """A registration that was read lasts a day. A failure lasts ten minutes."""
    if row is None:
        return False
    kept = FAILURE_KEPT if row.state == "unavailable" else KEPT
    return wall - utc(row.fetched_at) < kept


def _cached(db: Session, domain: str, kind: str, wall: datetime) -> FactCache | None:
    row = db.get(FactCache, (domain, kind))
    return row if _fresh(row, wall) else None


def _store(db: Session, domain: str, kind: str, fact: Fact, wall: datetime) -> None:
    """Write one cache row. The caller commits it, with no network call left open."""
    payload = {"value": fact.value, "reason": fact.reason}
    row = db.get(FactCache, (domain, kind))
    if row is None:
        db.add(FactCache(domain=domain, kind=kind, value=payload, state=fact.state, fetched_at=wall))
    else:
        row.value, row.state, row.fetched_at = payload, fact.state, wall


def _from_cache(row: FactCache, kind: str, source: str) -> Fact:
    payload = row.value or {}
    return Fact("", kind, payload.get("value"), source, utc(row.fetched_at), row.state, payload.get("reason"))


@dataclass
class _Memo:
    """Plain copies of the cache, taken so the session can close before any network call."""

    services: dict[str, str] | None
    registration: Fact | None


def _memo(db: Session, name: str, wall: datetime) -> _Memo:
    boot = _cached(db, "", "rdap_bootstrap", wall)
    services = None
    if boot is not None and isinstance((boot.value or {}).get("value"), dict):
        services = dict(boot.value["value"])
    row = _cached(db, name, "registration", wall)
    registration = _from_cache(row, "registration", "registry") if row is not None else None
    return _Memo(services, registration)


@dataclass
class _Job:
    started: float
    wall: datetime
    lookups: list[str]


def _note(job: _Job, name: str) -> None:
    """Remember a name that is about to be resolved or asked about."""
    job.lookups.append(name)


def _left(job: _Job) -> float:
    return GATHER_BUDGET - (_mono() - job.started)


def _budget(job: _Job, limit: float, fn, timeout_reason: str):
    """Run `fn` only while the gathering still has time, and give it no more than that.

    `fn` is given a number of seconds and has to finish inside it. That number
    is the call's own limit or whatever the gathering has left, whichever is
    smaller, so one slow answer cannot use the next call's time.
    """
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
    if address.version == 6 and address in _SITE_LOCAL:
        return "reserved"
    if getattr(address, "is_site_local", False):
        return "reserved"
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

    A literal address is not a lookup. Anything else is asked with a trailing
    dot, so a search list is not tried first, and the lookup runs in a thread:
    a resolver that never answers cannot be interrupted in place, and the
    thread is abandoned when `timeout` passes so the gathering can move on.
    """
    if (literal := _literal(host)) is not None:
        return [literal]
    queried = host if host.endswith(".") else f"{host}."

    def work():
        try:
            infos = socket.getaddrinfo(queried, None, type=socket.SOCK_STREAM)
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
    """GET `url` at the address already checked, and stop at the clock or at 256 kB.

    The connection is to that address, not to whatever the name resolves to a
    moment later. Redirects are returned as they are and never followed. The
    time limit is for the whole call: a registry that sends one byte at a time
    does not get another five seconds for each byte.
    """
    parsed = urlsplit(url)
    try:
        port = parsed.port or 443
    except ValueError:
        raise _GiveUp("The registry's address is not a secure one, so Nyctr did not connect.") from None
    if timeout <= 0:
        raise TimeoutError
    try:
        return asyncio.run(_read_async(url, address, port, timeout))
    except TimeoutError:
        raise TimeoutError from None


async def _read_async(url: str, address, port: int, timeout: float) -> tuple[int, bytes]:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    literal = f"[{address}]" if address.version == 6 else str(address)
    pinned = urlunsplit(("https", f"{literal}:{port}", parsed.path, "", ""))
    headers = {"Accept": "application/rdap+json", "Accept-Encoding": "identity",
               "Host": host if port == 443 else f"{host}:{port}"}
    options: dict = {"follow_redirects": False, "trust_env": False, "timeout": httpx.Timeout(timeout),
                     "verify": _verify}
    if _transport is not None:
        options["transport"] = _transport
    deadline = time.monotonic() + timeout

    async def once():
        async with httpx.AsyncClient(**options) as client:
            async with client.stream("GET", pinned, headers=headers, extensions={"sni_hostname": host}) as response:
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    if time.monotonic() >= deadline:
                        raise TimeoutError
                    size += len(chunk)
                    if size > MAX_BYTES:
                        raise _TooBig()
                    chunks.append(chunk)
                return response.status_code, b"".join(chunks)

    try:
        async with asyncio.timeout(timeout):
            return await once()
    except TimeoutError:
        raise TimeoutError from None
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
    """A registry address Nyctr will use: https, port 443, and nothing else in the URL."""
    if not isinstance(url, str) or url.startswith("http://"):
        return None
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port not in (None, 443):
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
        when = _when(event.get("eventDate"))
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


def _rdap(job: _Job, name: str, services: dict[str, str]) -> dict:
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
        if candidate != name:
            value["for"] = "parent"
        return value
    raise _GiveUp(missed)


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


def _network(memo: _Memo, name: str, wall: datetime, started: float):
    """Ask the registry and the resolver. This function never touches the database.

    An unexpected error becomes an unavailable fact. Names already resolved or
    asked about are still returned, so the caller can write them down.
    """
    job = _Job(started, wall, [])
    services_to_store = None
    remembered = None
    try:
        if memo.registration is not None:
            registration = memo.registration
        else:
            services = memo.services
            if services is None:
                status, body = _fetch(job, BOOTSTRAP_URL)
                if status != 200:
                    raise _GiveUp("Nyctr could not read the list of domain registries.")
                services = _services(body)
                services_to_store = services
            value = _rdap(job, name, services)
            registration = _known("registration", "registry", value, wall)
            remembered = registration
    except _GiveUp as error:
        registration = _unavailable("registration", "registry", error.reason, wall)
        remembered = registration if error.cache else None
    except Exception:
        registration = _unavailable("registration", "registry", "The registry could not be reached.", wall)
        remembered = registration
    try:
        resolution = _resolution(job, name)
    except Exception:
        resolution = _unavailable("resolution", "resolver", "The resolver could not answer.", wall)
    return registration, resolution, list(job.lookups), services_to_store, remembered


def _persist(db: Session, name: str, wall: datetime, lookups: list[str], services, remembered: Fact | None) -> None:
    """Write the cache and the lookup list in one transaction, after the calls have finished."""
    if services is not None:
        _store(db, "", "rdap_bootstrap", _known("rdap_bootstrap", "registry", services, wall), wall)
    if remembered is not None:
        _store(db, name, "registration", remembered, wall)
    db.execute(delete(OwnLookup).where(OwnLookup.at <= wall - KEPT))
    for item in lookups:
        db.add(OwnLookup(name=item, at=wall))
    db.commit()


def gather(db: Session, domain: str) -> list[Fact]:
    """Gather the facts for one name. Commits the cache and the lookup list.

    Stored facts are read first and the transaction is closed before any
    registry or resolver call. A name Nyctr will not look up is raised. Any
    other failure is a fact in the list.
    """
    name = _name(domain)
    wall, started = _wall(), _mono()
    rows = _observations(db, name)
    stored = [_block(rows, wall), _score(name, rows, wall), _seen(rows, wall)]
    demo = _demonstration(db)
    memo = None if demo else _memo(db, name, wall)
    db.rollback()
    if demo:
        outside = [_unavailable("registration", "registry", DEMONSTRATION, wall),
                   _unavailable("resolution", "resolver", DEMONSTRATION, wall)]
    else:
        registration, resolution, lookups, services, remembered = _network(memo, name, wall, started)
        try:
            _persist(db, name, wall, lookups, services, remembered)
        except Exception:
            db.rollback()
            raise
        outside = [registration, resolution]
    return _number([*stored, *outside, _not_asked("certificate", wall), _not_asked("reputation", wall)])
