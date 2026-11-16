"""Facts about a name: stored evidence, the registry and the resolver, each marked honestly."""

import ipaddress
import json
import socket
import ssl
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest
from conftest import LIVE_ADMIN, live_app, live_signin
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from test_collection_store import POSTGRES, postgres_database

from nyctr import facts
from nyctr.database import make_engine, migrate, session_factory
from nyctr.models import Integration, Observation, OwnLookup, Setting

_real_read, _real_resolve = facts._read, facts._resolve
PUBLIC = ipaddress.ip_address("1.1.1.1")
WHEN = datetime(2026, 6, 1, tzinfo=UTC)
BOOTSTRAP = json.dumps({"services": [[["com"], ["https://rdap.example/v1/"]]]}).encode()
RDAP = json.dumps({
    "events": [{"eventAction": "registration", "eventDate": "1999-01-01T00:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}],
    "status": ["active", "client transfer prohibited"],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
}).encode()
REFUSED = [
    ("private", "10.1.2.3"), ("private", "fd00::1"), ("private", "100.64.0.1"),
    ("loopback", "127.0.0.1"), ("loopback", "::1"),
    ("link-local", "169.254.1.1"), ("link-local", "fe80::1"),
    ("reserved", "240.0.0.1"), ("reserved", "100::1"), ("reserved", "224.0.0.1"),
    ("reserved", "fec0::1"), ("reserved", "fec0:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
]


def _boom(*_args, **_kwargs):
    """A test that reaches the network has forgotten its stand-in."""
    raise AssertionError("this test tried to use the network")


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """No test in this module contacts a registry or a resolver unless it puts a stand-in back."""
    monkeypatch.setattr(facts, "_read", _boom)
    monkeypatch.setattr(facts, "_resolve", _boom)


class Net:
    """A registry and a resolver that answer from memory and watch the time they are given."""

    def __init__(self):
        self.reads, self.resolves = [], []
        self.clock = 0.0
        self.wall_at = WHEN
        self.bootstrap, self.bootstrap_status = BOOTSTRAP, 200
        self.body, self.status = RDAP, 200
        self.addresses = {}

    def install(self, monkeypatch):
        monkeypatch.setattr(facts, "_read", self.read)
        monkeypatch.setattr(facts, "_resolve", self.resolve)
        monkeypatch.setattr(facts, "_mono", lambda: self.clock)
        monkeypatch.setattr(facts, "_wall", lambda: self.wall_at)

    def resolve(self, host, timeout):
        self.resolves.append((host, timeout))
        assert self.clock < facts.GATHER_BUDGET
        assert timeout <= facts.GATHER_BUDGET - self.clock
        return self.addresses.get(host, [PUBLIC] if host in {"data.iana.org", "rdap.example"} else None)

    def read(self, url, address, timeout):
        self.reads.append({"url": url, "address": str(address), "timeout": timeout})
        assert self.clock < facts.GATHER_BUDGET
        assert 0 < timeout <= min(facts.CALL_TIMEOUT, facts.GATHER_BUDGET - self.clock)
        assert url.startswith("https://") and "?" not in url and "#" not in url and "@" not in url
        if url.endswith("/rdap/dns.json"):
            return self.bootstrap_status, self.bootstrap
        return self.status, self.body


def database(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path}/facts.db")
    migrate(engine)
    return engine


def gather(engine, domain="example.com"):
    with session_factory(engine)() as db:
        found = facts.gather(db, domain)
    return {item.kind: item for item in found}


def kinds(body):
    return {item["kind"]: item for item in body}


def observe(db, domain="example.com", reason="Threat Intelligence Feeds", codes=("threat-intelligence-feeds",),
            device="device-a", name="Laptop", when=None, id_="block-1", source="dns"):
    if db.get(Integration, "dns") is None:
        db.add(Integration(id="dns", provider="dns", name="DNS", status="connected"))
        db.flush()
    when = when or WHEN - timedelta(days=2)
    db.add(Observation(id=id_, integration_id="dns", device_id=device, device_name=name, domain=domain,
                       source=source, reason=reason, reason_codes=list(codes), observed_at=when,
                       expires_at=when + timedelta(days=1), evidence_kind="observed", attribution="assigned",
                       risk_score=None, risk_explanation=""))


# Denial before anything the route returns.


def test_no_session_is_refused(client):
    """A caller who has not signed in learns nothing about a name."""
    assert client.get("/api/facts", params={"domain": "example.com"}).status_code == 401


def test_a_member_is_refused(client, member_headers):
    """A member is refused, and the refusal says nothing about the name."""
    refused = client.get("/api/facts", params={"domain": "example.com"}, headers=member_headers)
    assert refused.status_code == 403
    assert "example.com" not in refused.text


def test_the_portal_address_is_refused_even_for_an_administrator(tmp_path):
    """On the portal address every account has member rights, so the facts are refused there too."""
    app = live_app(tmp_path, public_url="http://console.example.test", portal_url="http://portal.example.test")
    with TestClient(app, base_url="http://portal.example.test") as portal:
        live_signin(portal)
        assert portal.get("/api/facts", params={"domain": "example.com"}).status_code == 403
        live_signin(portal, LIVE_ADMIN)
        assert portal.get("/api/facts", params={"domain": "example.com"}).status_code == 403


def test_an_administrator_is_given_the_facts(tmp_path, monkeypatch):
    """The console answers an administrator with the facts as JSON."""
    net = Net()
    net.install(monkeypatch)
    net.addresses["example.com"] = [PUBLIC]
    app = live_app(tmp_path, public_url="http://console.example.test", portal_url="http://portal.example.test")
    with TestClient(app, base_url="http://console.example.test") as client:
        live_signin(client, LIVE_ADMIN)
        answer = client.get("/api/facts", params={"domain": "Example.COM"})
        assert answer.status_code == 200, answer.text
        found = kinds(answer.json())
        assert [item["id"] for item in answer.json()] == [f"f{n}" for n in range(1, 8)]
        assert found["registration"]["state"] == "known"
        assert found["registration"]["value"]["name"] == "example.com"
        assert found["resolution"]["value"] == ["1.1.1.1"]
        assert found["certificate"]["state"] == "not_asked" and "reason" not in found["certificate"]
        assert found["reputation"]["state"] == "not_asked"


def test_a_name_that_is_not_a_domain_is_refused(client, admin_headers):
    """A page, a sentence or a numeric address is not looked up."""
    for domain in ("http://example.com/a", "not a name", "1.1.1.1", "example", "-bad.com"):
        assert client.get("/api/facts", params={"domain": domain}, headers=admin_headers).status_code == 422


def test_the_demonstration_does_not_look_names_up(client, admin_headers):
    """The demonstration returns the stored block and does not contact a registry or a resolver."""
    answer = client.get("/api/facts", params={"domain": "click.proofing-studio.example"}, headers=admin_headers)
    found = kinds(answer.json())
    assert answer.status_code == 200
    assert found["block"]["state"] == "known" and found["block"]["value"]["reason"]
    assert found["registration"]["state"] == "unavailable" and "demonstration" in found["registration"]["reason"]
    assert found["resolution"]["state"] == "unavailable" and found["resolution"]["value"] is None
    assert found["certificate"]["state"] == "not_asked" and found["reputation"]["state"] == "not_asked"


def test_every_fact_is_marked_and_a_missing_one_is_not_invented(tmp_path, monkeypatch):
    """The seven facts, in order. No stored block is unavailable, not a low score and not a made-up date."""
    net = Net()
    net.install(monkeypatch)
    net.addresses["example.com"] = [PUBLIC]
    engine = database(tmp_path)
    empty = gather(engine)
    assert [fact.id for fact in empty.values()] == [f"f{n}" for n in range(1, 8)]
    assert empty["block"].state == "unavailable" and empty["block"].value is None
    assert empty["block"].reason == facts.NO_BLOCK
    assert empty["risk"].state == "unavailable" and empty["risk"].reason == facts.NO_SCORE
    assert empty["seen"].state == "known" and empty["seen"].value == {"first_seen": None, "devices": 0, "times": 0}
    assert empty["registration"].state == "known"
    assert empty["registration"].value["registered"] == "1999-01-01T00:00:00Z"
    assert empty["registration"].value["expires"] == "2030-01-01T00:00:00Z"
    assert empty["registration"].value["registrar"] == "Example Registrar"
    assert empty["registration"].value["status"] == ["active", "client transfer prohibited"]
    assert empty["registration"].value["name"] == "example.com"
    assert empty["resolution"].value == ["1.1.1.1"]
    assert empty["certificate"].state == "not_asked" and empty["reputation"].state == "not_asked"
    with session_factory(engine)() as db:
        observe(db, reason="no reason Nyctr knows", codes=(), device=None, name="Jamie's laptop", id_="one")
        observe(db, device="device-b", name="Other laptop", when=WHEN - timedelta(days=9), id_="older")
        observe(db, device=None, name="Unknown source device", when=WHEN - timedelta(days=3), id_="none")
        db.commit()
    found = gather(engine)
    assert found["block"].value["reason"] == "no reason Nyctr knows"
    assert "Jamie" not in json.dumps(found["block"].as_dict())
    assert found["risk"].state == "known" and found["risk"].value["score"] is None
    assert found["risk"].value["band"] == "unknown"
    assert found["seen"].value["times"] == 3 and found["seen"].value["devices"] == 1
    assert found["seen"].value["first_seen"].startswith("2026-05-23")
    with session_factory(engine)() as db:
        db.get(Observation, "one").reason = "Threat Intelligence Feeds"
        db.get(Observation, "one").reason_codes = ["threat-intelligence-feeds"]
        db.commit()
    scored = gather(engine)
    assert scored["risk"].value["score"] >= 92 and scored["risk"].value["band"] == "high"
    assert scored["risk"].value["factors"]


def test_a_resolver_with_no_answer_is_kept_as_a_refusal(tmp_path, monkeypatch):
    """No address from the resolver is a fact, and it is not stored as an address."""
    net = Net()
    net.install(monkeypatch)
    found = gather(database(tmp_path))
    assert found["resolution"].state == "known" and found["resolution"].value == facts.REFUSES


@pytest.mark.parametrize("status, body, reason", [
    (404, b"{}", "no record of this name"),
    (503, b'{"error":"down"}', "reported an error"),
    (200, b"not-json", "could not be read"),
    (200, b"[1]", "could not be read"),
    (200, b'{"events":"no"}', "could not be read"),
    (200, b"{}", "named no registration"),
    (302, b"", "does not follow"),
    (200, b"x" * (256 * 1024 + 1), "larger than Nyctr reads"),
])
def test_an_outbound_failure_is_unavailable_and_not_a_default(tmp_path, monkeypatch, status, body, reason):
    """A bad answer, a redirect, a 404 or an oversized body never becomes a registration."""
    net = Net()
    net.install(monkeypatch)
    net.status, net.body = status, body
    found = gather(database(tmp_path))
    assert found["registration"].state == "unavailable" and found["registration"].value is None
    assert reason in found["registration"].reason
    assert "1999" not in found["registration"].reason


def test_a_timeout_is_unavailable_and_asked_again_after_ten_minutes(tmp_path, monkeypatch):
    """A registry that does not answer is unavailable, and that failure is kept for ten minutes, not a day."""
    assert facts.FAILURE_KEPT == timedelta(minutes=10)
    net = Net()
    net.install(monkeypatch)

    def read(url, address, timeout):
        net.reads.append(url)
        if url.endswith("dns.json"):
            return 200, BOOTSTRAP
        raise TimeoutError

    monkeypatch.setattr(facts, "_read", read)
    engine = database(tmp_path)
    first = gather(engine)
    assert first["registration"].state == "unavailable" and "did not answer in time" in first["registration"].reason
    asked = len(net.reads)
    net.wall_at += timedelta(minutes=9)
    assert gather(engine)["registration"].reason == first["registration"].reason
    assert len(net.reads) == asked
    net.wall_at += timedelta(minutes=1)
    assert "did not answer in time" in gather(engine)["registration"].reason
    assert len(net.reads) > asked


def test_plain_http_is_not_connected(tmp_path, monkeypatch):
    """A registry list that offers only an http address is refused before that address is opened."""
    net = Net()
    net.install(monkeypatch)
    net.bootstrap = json.dumps({"services": [[["com"], ["http://rdap.example/v1/"]]]}).encode()
    found = gather(database(tmp_path))
    assert found["registration"].state == "unavailable" and "not a secure one" in found["registration"].reason
    assert [item["url"] for item in net.reads] == [facts.BOOTSTRAP_URL]


def test_the_gathering_stops_when_eight_seconds_are_gone(tmp_path, monkeypatch):
    """A call that uses up the gathering's time is the last call. Nothing starts after eight seconds."""
    net = Net()
    net.install(monkeypatch)
    assert (facts.CALL_TIMEOUT, facts.GATHER_BUDGET, facts.RESOLVE_TIMEOUT, facts.MAX_BYTES) == (5.0, 8.0, 3.0,
                                                                                                  256 * 1024)

    def charge(timeout):
        assert net.clock < facts.GATHER_BUDGET
        assert timeout <= facts.GATHER_BUDGET - net.clock
        net.clock += timeout

    def resolve(host, timeout):
        charge(timeout)
        net.resolves.append(host)
        return [PUBLIC] if host in {"data.iana.org", "rdap.example"} else None

    def read(url, address, timeout):
        charge(timeout)
        net.reads.append(url)
        return 200, BOOTSTRAP if url.endswith("dns.json") else RDAP

    monkeypatch.setattr(facts, "_resolve", resolve)
    monkeypatch.setattr(facts, "_read", read)
    engine = database(tmp_path)
    found = gather(engine)
    assert net.clock <= facts.GATHER_BUDGET
    assert found["registration"].state == "unavailable" and "ran out of time" in found["registration"].reason
    assert found["resolution"].state == "unavailable" and "ran out of time" in found["resolution"].reason
    assert net.reads == [facts.BOOTSTRAP_URL]
    # Running out of time is not kept. The list was stored; the registration is asked on the next gathering.
    net.clock = 0
    again = gather(engine)
    assert again["registration"].state == "known"
    assert len(net.reads) == 2


def test_a_stalled_call_is_the_last_one(tmp_path, monkeypatch):
    """A stand-in that never returns still ends the gathering, and no second call is started."""
    net = Net()
    net.install(monkeypatch)

    def read(url, address, timeout):
        net.reads.append(url)
        net.clock += 100
        raise TimeoutError

    monkeypatch.setattr(facts, "_read", read)
    found = gather(database(tmp_path))
    assert net.reads == [facts.BOOTSTRAP_URL]
    assert found["registration"].state == "unavailable" and found["registration"].value is None
    assert "ran out of time" in found["resolution"].reason


@pytest.mark.parametrize("kind, text", REFUSED)
@pytest.mark.parametrize("place", ["bootstrap", "registry"])
def test_a_refused_address_is_not_connected(tmp_path, monkeypatch, kind, text, place):
    """Each refused class, on IPv4 and IPv6, is turned away before a connection, for the list and the registry."""
    bad = ipaddress.ip_address(text)
    assert facts._why(bad) == kind
    net = Net()
    net.install(monkeypatch)
    host = "data.iana.org" if place == "bootstrap" else "rdap.example"
    net.addresses[host] = [bad]
    if place == "registry":
        net.addresses["data.iana.org"] = [PUBLIC]
    found = gather(database(tmp_path))
    assert found["registration"].state == "unavailable" and found["registration"].value is None
    assert "did not connect" in found["registration"].reason
    assert all(item["url"] == facts.BOOTSTRAP_URL for item in net.reads)
    assert (net.reads == []) == (place == "bootstrap")


def test_a_public_address_beside_a_private_one_is_not_connected(tmp_path, monkeypatch):
    """One private address in the answer is enough. Nyctr does not connect to the public one beside it."""
    net = Net()
    net.install(monkeypatch)
    net.addresses["data.iana.org"] = [PUBLIC, ipaddress.ip_address("10.0.0.1")]
    found = gather(database(tmp_path))
    assert net.reads == [] and "private network" in found["registration"].reason


def test_an_address_written_as_ipv4_inside_ipv6_is_judged_as_the_inner_address(tmp_path, monkeypatch):
    """A private address hidden inside an IPv6 form is refused the same way."""
    net = Net()
    net.install(monkeypatch)
    net.addresses["data.iana.org"] = [ipaddress.ip_address("::ffff:192.168.0.1")]
    found = gather(database(tmp_path))
    assert net.reads == [] and "private network" in found["registration"].reason


def test_a_second_gathering_within_a_day_does_not_ask_the_registry_again(tmp_path, monkeypatch):
    """The registration is kept for a day. At the day, and not before, it is asked again."""
    net = Net()
    net.install(monkeypatch)
    engine = database(tmp_path)
    assert gather(engine)["registration"].state == "known"
    asked = len(net.reads)
    assert asked == 2  # the list, then the name
    net.wall_at += timedelta(hours=23, minutes=59)
    assert gather(engine)["registration"].value["name"] == "example.com"
    assert len(net.reads) == asked
    gather(engine, "EXAMPLE.COM")  # the same name, however it is typed
    assert len(net.reads) == asked
    net.wall_at += timedelta(minutes=1)  # exactly a day after the first gathering
    assert gather(engine)["registration"].state == "known"
    assert len(net.reads) == asked + 2


def test_the_longer_name_is_asked_when_the_shorter_one_is_missing(tmp_path, monkeypatch):
    """The last two labels are asked, and on 404 the last three."""
    net = Net()
    net.install(monkeypatch)

    def read(url, address, timeout):
        net.reads.append(url)
        if url.endswith("dns.json"):
            return 200, BOOTSTRAP
        if url.endswith("/domain/example.com"):
            return 404, b"{}"
        if url.endswith("/domain/www.example.com"):
            return 200, RDAP
        raise AssertionError(url)

    monkeypatch.setattr(facts, "_read", read)
    found = gather(database(tmp_path), "www.example.com")
    assert found["registration"].value["name"] == "www.example.com"
    assert "for" not in found["registration"].value
    assert net.reads[-2:] == ["https://rdap.example/v1/domain/example.com",
                              "https://rdap.example/v1/domain/www.example.com"]


def test_every_name_that_was_resolved_or_asked_about_is_recorded(tmp_path, monkeypatch):
    """The list, the registry, the name that was asked and the name that was resolved are all written down."""
    net = Net()
    net.install(monkeypatch)

    def read(url, address, timeout):
        net.reads.append(url)
        if url.endswith("dns.json"):
            return 200, BOOTSTRAP
        if url.endswith("/domain/example.com"):
            return 404, b"{}"
        return 200, RDAP

    monkeypatch.setattr(facts, "_read", read)
    engine = database(tmp_path)
    with session_factory(engine)() as db:
        db.add(OwnLookup(name="old.example", at=WHEN - timedelta(hours=24)))
        db.add(OwnLookup(name="fresh.example", at=WHEN - timedelta(hours=23)))
        db.commit()
    gather(engine, "www.example.com")
    with session_factory(engine)() as db:
        names = {row.name for row in db.scalars(select(OwnLookup))}
    assert names == {"data.iana.org", "rdap.example", "example.com", "www.example.com", "fresh.example"}
    assert "old.example" not in names
    sent = " ".join(url if isinstance(url, str) else url["url"] for url in net.reads)
    assert "fresh.example" not in sent and "Jamie" not in sent and "10.0.0" not in sent


def test_a_request_carries_the_name_and_nothing_else(monkeypatch):
    """The connection goes to the address that was checked, and the headers name no person, device or network."""
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"{}")

    monkeypatch.setattr(facts, "_transport", httpx.MockTransport(handler))
    monkeypatch.setattr(facts, "_read", _real_read)
    status, body = facts._read("https://rdap.example/v1/domain/example.com", PUBLIC, 5)
    assert status == 200 and body == b"{}" and len(seen) == 1
    request = seen[0]
    assert request.method == "GET" and request.url.host == "1.1.1.1"
    assert request.headers["host"] == "rdap.example"
    assert request.url.path == "/v1/domain/example.com"
    values = " ".join(request.headers.values()).lower()
    assert "jamie" not in values and "laptop" not in values and "10.0.0" not in values
    assert "authorization" not in {key.lower() for key in request.headers}
    assert request.headers["accept-encoding"] == "identity"


def test_a_redirect_from_the_real_reader_is_one_response_and_not_followed(monkeypatch):
    """The reader returns the redirect and does not open the address it points at."""
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://10.1.2.3/steal"})

    monkeypatch.setattr(facts, "_transport", httpx.MockTransport(handler))
    monkeypatch.setattr(facts, "_read", _real_read)
    status, _body = facts._read("https://rdap.example/domain/example.com", PUBLIC, 5)
    # The client drops the default port. The host is still the address that was checked.
    assert status == 302 and seen == ["https://1.1.1.1/domain/example.com"]


def test_an_oversized_answer_is_stopped_while_it_is_read(monkeypatch):
    """The reader stops past 256 kB instead of handing the rest on."""
    monkeypatch.setattr(facts, "_transport", httpx.MockTransport(
        lambda _request: httpx.Response(200, content=b"x" * (facts.MAX_BYTES + 1))))
    monkeypatch.setattr(facts, "_read", _real_read)
    with pytest.raises(facts._TooBig):
        facts._read("https://rdap.example/domain/example.com", PUBLIC, 5)


def test_a_reader_timeout_is_a_timeout(monkeypatch):
    """A client that runs out of time is reported as a timeout, not as an empty registration."""
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    monkeypatch.setattr(facts, "_transport", httpx.MockTransport(handler))
    monkeypatch.setattr(facts, "_read", _real_read)
    with pytest.raises(TimeoutError):
        facts._read("https://rdap.example/domain/example.com", PUBLIC, 5)


def test_the_resolver_runs_on_another_thread(monkeypatch):
    """The system resolver is called off the gathering's thread, so it can be abandoned."""
    seen = {}

    def fake(host, *_args, **_kwargs):
        seen["thread"] = threading.get_ident()
        seen["host"] = host
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("1.1.1.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    monkeypatch.setattr(facts, "_resolve", _real_resolve)
    assert facts._resolve("example.com", 1) == [PUBLIC]
    assert seen["thread"] != threading.get_ident()
    assert seen["host"] == "example.com."


def test_a_resolver_that_does_not_answer_is_abandoned(monkeypatch):
    """The wait ends when the time is up. The resolver is not given the rest of the gathering."""
    release = threading.Event()

    def fake(*_args, **_kwargs):
        release.wait(5)
        return []

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    monkeypatch.setattr(facts, "_resolve", _real_resolve)
    try:
        with pytest.raises(TimeoutError):
            facts._resolve("example.com", 0.05)
    finally:
        release.set()


def test_a_name_the_resolver_does_not_know_is_no_answer(monkeypatch):
    """An unknown name is the refusal, not an error and not an address."""
    def fake(*_args, **_kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "unknown")

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    monkeypatch.setattr(facts, "_resolve", _real_resolve)
    assert facts._resolve("example.com", 1) is None


def test_a_name_idna_2003_would_change_stays_the_name_it_is(tmp_path, monkeypatch):
    """faß.de is its own registration. It is not looked up as fass.de."""
    assert "faß.de".encode("idna").decode("ascii") == "fass.de"
    assert facts._name("faß.de") == "xn--fa-hia.de"
    assert facts._name("ς.com") == "xn--3xa.com"
    assert facts._name("ς.com") != "ς.com".encode("idna").decode("ascii")
    net = Net()
    net.install(monkeypatch)
    found = gather(database(tmp_path), "faß.de")
    assert found["registration"].state == "unavailable"
    sent = " ".join(item["url"] for item in net.reads)
    assert "fass.de" not in sent
    asked = [host for host, _timeout in net.resolves if host not in {"data.iana.org", "rdap.example"}]
    assert asked == ["xn--fa-hia.de"]
    assert facts._name("foo。com") == "foo.com"
    assert facts._name("cafe\u0301.fr") == "xn--caf-dma.fr"


def test_a_name_that_does_not_map_cleanly_is_refused():
    """A name whose mapping is a different name is not looked up."""
    for domain in ("ｆａｓｓ.de", "ﬁle.com"):
        with pytest.raises(facts.NotAName):
            facts._name(domain)


def test_a_date_that_is_not_a_date_is_left_out(tmp_path, monkeypatch):
    """A registration date has to be a real date. Other text is dropped, and a missing date is not invented."""
    net = Net()
    net.install(monkeypatch)
    net.body = json.dumps({
        "events": [{"eventAction": "registration", "eventDate": "long ago"},
                   {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"}],
        "status": ["active"],
    }).encode()
    engine = database(tmp_path)
    found = gather(engine)
    assert found["registration"].state == "known"
    assert "registered" not in found["registration"].value
    assert found["registration"].value["expires"] == "2030-01-01T00:00:00Z"
    assert "long ago" not in json.dumps(found["registration"].value)
    net.body = json.dumps({"events": [{"eventAction": "registration", "eventDate": "long ago"}]}).encode()
    net.wall_at += facts.KEPT
    again = gather(engine)
    assert again["registration"].state == "unavailable"
    assert "named no registration" in again["registration"].reason


def test_a_registration_of_the_parent_says_which_name_it_describes(tmp_path, monkeypatch):
    """When the registry answers for the parent, the fact says so, and it names that parent."""
    net = Net()
    net.install(monkeypatch)

    def read(url, address, timeout):
        net.reads.append(url)
        if url.endswith("dns.json"):
            return 200, BOOTSTRAP
        if url.endswith("/domain/example.com"):
            return 200, RDAP
        raise AssertionError(url)

    monkeypatch.setattr(facts, "_read", read)
    found = gather(database(tmp_path), "www.example.com")
    assert found["registration"].value["name"] == "example.com"
    assert found["registration"].value["for"] == "parent"


def test_a_bad_port_in_the_reader_is_a_plain_refusal(monkeypatch):
    """The reader refuses a port it cannot use, and it does not raise."""
    monkeypatch.setattr(facts, "_read", _real_read)
    with pytest.raises(facts._GiveUp):
        facts._read("https://rdap.example:99999/domain/example.com", PUBLIC, 1)
    with pytest.raises(facts._GiveUp):
        facts._read("https://rdap.example:abc/domain/example.com", PUBLIC, 1)


def test_a_bad_port_is_unavailable_and_the_lookup_list_is_kept(tmp_path, monkeypatch):
    """A registry address with a bad port is a plain unavailable fact, and the list lookup is kept."""
    net = Net()
    net.install(monkeypatch)
    net.bootstrap = json.dumps({"services": [[
        ["com"],
        ["https://rdap.example:99999/v1/", "https://rdap.example:abc/v1/", "https://rdap.example:25/v1/"],
    ]]}).encode()

    def read(url, address, timeout):
        net.reads.append({"url": url, "address": str(address), "timeout": timeout})
        port = urlsplit(url).port  # the real reader asks for the port, and a bad one raises
        if port not in (None, 443):
            raise AssertionError(port)
        if url.endswith("/rdap/dns.json"):
            return 200, net.bootstrap
        return 200, RDAP

    monkeypatch.setattr(facts, "_read", read)
    engine = database(tmp_path)
    found = gather(engine)
    assert found["registration"].state == "unavailable" and found["registration"].value is None
    assert [item["url"] for item in net.reads] == [facts.BOOTSTRAP_URL]
    with session_factory(engine)() as db:
        names = {row.name for row in db.scalars(select(OwnLookup))}
    assert "data.iana.org" in names
    app = live_app(tmp_path, public_url="http://console.example.test", portal_url="http://portal.example.test")
    with TestClient(app, base_url="http://console.example.test") as client:
        live_signin(client, LIVE_ADMIN)
        answer = client.get("/api/facts", params={"domain": "example.com"})
    assert answer.status_code == 200
    assert kinds(answer.json())["registration"]["state"] == "unavailable"


def test_an_unexpected_error_is_unavailable_and_keeps_the_lookup_list(tmp_path, monkeypatch):
    """A failure inside a call does not become a 500, and names already asked about stay written down."""
    net = Net()
    net.install(monkeypatch)

    def read(url, address, timeout):
        net.reads.append(url)
        if url.endswith("dns.json"):
            return 200, BOOTSTRAP
        raise RuntimeError("Port out of range")

    monkeypatch.setattr(facts, "_read", read)
    engine = database(tmp_path)
    found = gather(engine)
    assert found["registration"].state == "unavailable"
    assert "could not be reached" in found["registration"].reason
    with session_factory(engine)() as db:
        names = {row.name for row in db.scalars(select(OwnLookup))}
    assert "data.iana.org" in names


def test_a_call_is_given_only_the_time_still_left(tmp_path, monkeypatch):
    """After six seconds have been used, the next call gets the two that remain, not another five."""
    net = Net()
    monkeypatch.setattr(facts, "_mono", lambda: net.clock)
    monkeypatch.setattr(facts, "_wall", lambda: net.wall_at)
    seen = []

    def resolve(host, timeout):
        seen.append(("resolve", timeout))
        if host == "data.iana.org":
            net.clock = 6
        return [PUBLIC] if host in {"data.iana.org", "rdap.example"} else None

    def read(url, address, timeout):
        seen.append(("read", timeout))
        return 200, BOOTSTRAP if url.endswith("dns.json") else RDAP

    monkeypatch.setattr(facts, "_resolve", resolve)
    monkeypatch.setattr(facts, "_read", read)
    gather(database(tmp_path))
    assert ("read", 2.0) in seen
    assert all(timeout <= 2.0 for kind, timeout in seen if kind == "read")


def test_a_numeric_host_is_not_given_a_search_domain(monkeypatch):
    """A literal address is not a lookup, and it is not sent to the resolver with a trailing dot."""
    called = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **_kwargs: called.append(args))
    monkeypatch.setattr(facts, "_resolve", _real_resolve)
    assert facts._resolve("1.1.1.1", 1) == [PUBLIC]
    assert called == []


def _stand_in_tls(hostname):
    """A certificate for `hostname` and a client context that trusts only that certificate."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .sign(key, hashes.SHA256()))
    directory = tempfile.TemporaryDirectory()
    cert_path = Path(directory.name) / "cert.pem"
    key_path = Path(directory.name) / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context()
    client.load_verify_locations(cadata=cert_path.read_text())
    return server, client, directory


def _serve_tls(server_ctx, write):
    """Accept one TLS connection on loopback and hand the socket to `write`."""
    raw = socket.socket()
    raw.bind(("127.0.0.1", 0))
    raw.listen(1)
    got = []

    def run():
        raw.settimeout(5)
        try:
            conn, _addr = raw.accept()
        except OSError:
            return
        try:
            tls = server_ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError:
            conn.close()
            return
        tls.settimeout(2)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                piece = tls.recv(4096)
                if not piece:
                    break
                data += piece
        except OSError:
            pass
        got.append(data)
        try:
            write(tls)
        except OSError:
            pass
        try:
            tls.close()
        except OSError:
            pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return raw, thread, got


def test_a_slow_byte_is_cut_off_by_the_clock(monkeypatch):
    """One byte at a time does not get a fresh timeout per byte. The call ends when its own time is up."""
    server_ctx, client_ctx, directory = _stand_in_tls("rdap.example")
    monkeypatch.setattr(facts, "_verify", client_ctx)
    monkeypatch.setattr(facts, "_transport", None)
    monkeypatch.setattr(facts, "_read", _real_read)

    def write(tls):
        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 30\r\nConnection: close\r\n\r\n" + (b"x" * 30)
        end = time.monotonic() + 4
        for byte in payload:
            if time.monotonic() > end:
                break
            tls.send(bytes([byte]))
            time.sleep(0.1)

    raw, thread, _got = _serve_tls(server_ctx, write)
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError):
            facts._read(f"https://rdap.example:{raw.getsockname()[1]}/domain/example.com",
                        ipaddress.ip_address("127.0.0.1"), 0.5)
        assert time.monotonic() - started < 2
    finally:
        raw.close()
        thread.join(2)
        directory.cleanup()


def test_an_untrusted_certificate_is_refused(monkeypatch):
    """The reader checks the certificate. A stand-in signed by no one Nyctr trusts is not read."""
    server_ctx, _client_ctx, directory = _stand_in_tls("rdap.example")
    monkeypatch.setattr(facts, "_transport", None)
    monkeypatch.setattr(facts, "_verify", True)
    monkeypatch.setattr(facts, "_read", _real_read)

    def write(tls):
        body = b"{}"
        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n" + body)

    raw, thread, got = _serve_tls(server_ctx, write)
    try:
        with pytest.raises(facts._GiveUp):
            facts._read(f"https://rdap.example:{raw.getsockname()[1]}/domain/example.com",
                        ipaddress.ip_address("127.0.0.1"), 2)
        assert not any(b"GET " in item for item in got)
    finally:
        raw.close()
        thread.join(2)
        directory.cleanup()


def test_the_environments_proxy_settings_are_not_used(monkeypatch):
    """A proxy named in the environment is not asked. The call goes to the address that was checked."""
    seen = []
    proxy = socket.socket()
    proxy.bind(("127.0.0.1", 0))
    proxy.listen(1)

    def accept():
        proxy.settimeout(3)
        try:
            conn, _addr = proxy.accept()
        except OSError:
            return
        seen.append(True)
        conn.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{proxy.getsockname()[1]}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setattr(facts, "_transport", None)
    monkeypatch.setattr(facts, "_verify", True)
    monkeypatch.setattr(facts, "_read", _real_read)
    try:
        with pytest.raises(facts._GiveUp):
            facts._read(f"https://rdap.example:{closed_port}/domain/example.com",
                        ipaddress.ip_address("127.0.0.1"), 2)
    finally:
        proxy.close()
        thread.join(2)
    assert seen == []


def engine_for(kind, tmp_path, request):
    if kind == "sqlite":
        return database(tmp_path)
    place = postgres_database(request)
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    server, _, name = place["database_url"].rpartition("/")
    opened = create_engine(server + "/postgres", isolation_level="AUTOCOMMIT")
    with opened.connect() as connection:
        connection.execute(text(f"alter database {name} set lock_timeout = '20s'"))
    opened.dispose()
    engine = make_engine(place["database_url"])
    migrate(engine)
    return engine


@pytest.mark.parametrize("kind", ["sqlite", "postgresql"])
def test_a_slow_registry_does_not_lock_the_database(tmp_path, monkeypatch, request, kind):
    """Another write commits while the registry is still answering. It is not told the database is locked."""
    entered, release = threading.Event(), threading.Event()
    errors, elapsed = [], []

    def read(url, address, timeout):
        entered.set()
        release.wait(8)
        if url.endswith("dns.json"):
            return 200, BOOTSTRAP
        return 200, RDAP

    def resolve(host, timeout):
        return [PUBLIC] if host in {"data.iana.org", "rdap.example"} else None

    monkeypatch.setattr(facts, "_read", read)
    monkeypatch.setattr(facts, "_resolve", resolve)
    engine = engine_for(kind, tmp_path, request)
    factory = session_factory(engine)

    def writer():
        if not entered.wait(5):
            errors.append(TimeoutError("the registry was never called"))
            release.set()
            return
        started = time.monotonic()
        try:
            with factory() as db:
                db.add(Setting(key="beside", value={"ok": True}))
                db.commit()
        except Exception as error:  # noqa: BLE001 - the test reports the lock error
            errors.append(error)
        finally:
            elapsed.append(time.monotonic() - started)
            release.set()

    other = threading.Thread(target=writer, daemon=True)
    other.start()
    try:
        with factory() as db:
            found = facts.gather(db, "example.com")
        assert errors == [] and elapsed and elapsed[0] < 3
        assert {item.kind: item.state for item in found}["registration"] == "known"
        with factory() as db:
            assert db.get(Setting, "beside").value == {"ok": True}
    finally:
        release.set()
        other.join(15)
        engine.dispose()
