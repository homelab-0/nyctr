"""Which address a request came from: the rule in `nyctr.peer`, denial paths first."""

import logging
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from nyctr.config import Settings
from nyctr.main import create_app
from nyctr.peer import client_address, seen

PROXY, EDGE = "10.42.0.10", "10.42.0.11"
MEMBER, FORGED, ATTACKER = "198.51.100.21", "192.0.2.99", "198.51.100.20"
NYCTR = Path(__file__).resolve().parents[1] / "nyctr"


def ask(peer, *forwarded, listed=PROXY, hops=1):
    """Build the request Nyctr would get from this TCP peer with these `X-Forwarded-For` lines."""
    settings = SimpleNamespace(proxy_list=listed, proxy_hops=hops)
    return Request({"type": "http", "client": (peer, 40000) if peer else None,
                    "headers": [(b"x-forwarded-for", line.encode()) for line in forwarded],
                    "app": SimpleNamespace(state=SimpleNamespace(settings=settings))})


def test_a_forged_header_from_a_peer_that_is_not_a_listed_proxy_is_ignored():
    """Rule 1: the peer is the client, and nothing it sent is read."""
    answer = seen(ask(ATTACKER, MEMBER))
    assert (answer.address, answer.via_proxy, answer.entry) == (ATTACKER, False, None)
    assert client_address(ask(ATTACKER, f"{MEMBER}, {PROXY}", listed="10.42.0.0/16")) == ATTACKER
    assert client_address(ask(PROXY, MEMBER, listed="")) == PROXY


@pytest.mark.parametrize(("lines", "listed", "peer"), [
    ((f"{FORGED}, {MEMBER}",), PROXY, PROXY),
    # The client's own header line arrives first, the proxy's after it.
    ((FORGED, MEMBER), PROXY, PROXY),
    ((f"{FORGED}, {PROXY}, {MEMBER}",), "10.42.0.0/16", "10.42.9.77"),
])
def test_a_forged_left_entry_behind_a_listed_proxy_is_ignored(lines, listed, peer):
    """Rule 2: only the entry the operator's own proxy wrote is read."""
    assert client_address(ask(peer, *lines, listed=listed)) == MEMBER


def test_a_client_inside_the_trusted_range_that_goes_through_the_proxy_gets_its_own_address():
    """The gap in the alpha.3 notes: its address used to be skipped as a proxy and the forged one believed."""
    inside = "10.42.3.3"
    answer = seen(ask("10.42.9.77", f"{FORGED}, {inside}", listed="10.42.0.0/16"))
    assert (answer.address, answer.via_proxy, answer.entry, answer.entries) == (inside, True, 1, 2)


def test_a_client_that_goes_round_the_edge_gets_no_address():
    """Straight to the inner proxy, a client writes the entry Nyctr would read. A wrong address is worse than none."""
    answer = seen(ask(PROXY, f"{FORGED}, {ATTACKER}", listed=f"{PROXY},{EDGE}", hops=2))
    assert (answer.address, answer.why, answer.entry, answer.unlisted) == (None, "unlisted", 1, ATTACKER)
    # The same with three proxies, whichever of them was skipped.
    for chain in (f"{FORGED}, {ATTACKER}, {EDGE}", f"{FORGED}, {EDGE}, {ATTACKER}"):
        skipped = seen(ask(PROXY, chain, listed=f"{PROXY},{EDGE},10.42.0.12", hops=3))
        assert (skipped.address, skipped.why, skipped.unlisted) == (None, "unlisted", ATTACKER)


def test_an_edge_that_is_not_listed_gives_no_address():
    """With more than one proxy every one of them must be listed, and the answer names the one that is not."""
    answer = seen(ask(PROXY, f"{MEMBER}, {EDGE}", hops=2))
    assert (answer.address, answer.via_proxy, answer.why, answer.entry, answer.entries, answer.unlisted) == (
        None, True, "unlisted", 1, 2, EDGE)


def test_two_proxies_that_are_both_listed_are_counted_with_two_hops():
    """The edge wrote the client, the inner proxy wrote the edge: the second entry from the right."""
    answer = seen(ask(PROXY, f"{FORGED}, {MEMBER}, {EDGE}", listed=f"{PROXY},{EDGE}", hops=2))
    assert (answer.address, answer.why, answer.entry, answer.entries, answer.unlisted) == (
        MEMBER, "forwarded", 2, 3, None)
    # With the default of one hop the same request is the edge's address, not the member's.
    assert client_address(ask(PROXY, f"{FORGED}, {MEMBER}, {EDGE}")) == EDGE


def test_the_limit_that_remains_is_a_direct_client_inside_a_listed_range():
    """Known and documented: a client inside a listed range that skips the edge passes for the edge.

    Nyctr cannot tell it from a proxy by its address. The operator's network
    rules must keep such a client from reaching the inner proxy.
    """
    inside = "10.42.3.3"
    assert client_address(ask("10.42.9.77", f"{FORGED}, {inside}", listed="10.42.0.0/16", hops=2)) == FORGED


@pytest.mark.parametrize(("lines", "hops", "why"), [
    ((MEMBER,), 2, "short"),
    ((f"{MEMBER}, {EDGE}",), 3, "short"),
    ((), 1, "missing"),
    (("",), 1, "missing"),
    (("  ,  ",), 1, "missing"),
    (("not-an-address",), 1, "malformed"),
    (("unknown",), 1, "malformed"),
    (("198.51.100.21.5",), 1, "malformed"),
    (("198.51.100.21:port",), 1, "malformed"),
    (("198.51.100.21:99999",), 1, "malformed"),
    (("198.51.100.21 198.51.100.22",), 1, "malformed"),
    (("[2001:db8:51::20",), 1, "malformed"),
    (("[2001:db8:51::20]51234",), 1, "malformed"),
    (("[198.51.100.21]",), 1, "malformed"),
    (("fe80::1%eth0",), 1, "malformed"),
    # The entry at the counted position is the only one read: no falling back to a neighbour.
    ((f"{MEMBER}, garbage",), 1, "malformed"),
    ((f"{MEMBER},",), 1, "malformed"),
    ((f"garbage, {EDGE}",), 2, "malformed"),
    ((f"{MEMBER}, garbage",), 2, "malformed"),
])
def test_a_missing_short_or_malformed_entry_gives_no_address(lines, hops, why):
    """Rule 3: no address is the answer. Neither the peer nor another entry stands in."""
    answer = seen(ask(PROXY, *lines, listed=f"{PROXY},{EDGE}", hops=hops))
    assert (answer.address, answer.via_proxy, answer.why, answer.unlisted) == (None, True, why, None)
    assert client_address(ask(PROXY, *lines, listed=f"{PROXY},{EDGE}", hops=hops)) is None


def test_a_request_with_no_usable_peer_has_no_address():
    """A server that cannot name its peer gives no address, whatever the headers say."""
    assert client_address(ask(None, MEMBER)) is None
    assert client_address(ask("testclient", MEMBER)) is None
    assert seen(ask(None, MEMBER)).why == "no_peer"


def test_a_peer_with_a_zone_has_no_address_and_the_answer_says_why():
    """A link-local peer matches no list entry and no device. That is said, not passed off as a missing peer."""
    answer = seen(ask("fe80::1%eth0", MEMBER, listed="fe80::/10"))
    assert (answer.address, answer.peer, answer.via_proxy, answer.why) == (None, "fe80::1%eth0", False, "zone")
    assert seen(ask("not-an-address%eth0", MEMBER)).why == "no_peer"


@pytest.mark.parametrize("hops", [0, -1, -2])
def test_a_hop_count_below_one_never_reads_the_leftmost_entry(hops):
    """The settings refuse such a count. The function is safe by itself all the same: no address."""
    answer = seen(ask(PROXY, f"{FORGED}, {MEMBER}, {EDGE}", listed=f"{PROXY},{EDGE}", hops=hops))
    assert (answer.address, answer.via_proxy, answer.why, answer.entry) == (None, True, "hops", None)


def test_the_answer_says_when_the_address_read_is_one_of_the_proxies():
    """With too few hops counted the entry read is a proxy's own. The operator's check can then say so."""
    listed = f"{PROXY},{EDGE}"
    assert seen(ask(PROXY, f"{MEMBER}, {EDGE}", listed=listed)).address_is_proxy is True
    assert seen(ask(PROXY, f"{MEMBER}, {EDGE}", listed=listed, hops=2)).address_is_proxy is False
    assert seen(ask(ATTACKER, MEMBER)).address_is_proxy is False


@pytest.mark.parametrize(("entry", "expected"), [
    ("198.51.100.21", "198.51.100.21"),
    ("198.51.100.21:51234", "198.51.100.21"),
    (" 198.51.100.21 ", "198.51.100.21"),
    ("2001:db8:51::20", "2001:db8:51::20"),
    ("2001:DB8:51:0::20", "2001:db8:51::20"),
    ("[2001:db8:51::20]", "2001:db8:51::20"),
    ("[2001:db8:51::20]:51234", "2001:db8:51::20"),
    ("::ffff:198.51.100.21", "198.51.100.21"),
])
@pytest.mark.parametrize(("listed", "peer"), [(PROXY, PROXY), ("2001:db8:42::/56", "2001:db8:42:1::10")])
def test_the_proxys_entry_is_read_for_both_families_with_and_without_ports_and_brackets(entry, expected,
                                                                                       listed, peer):
    """Addresses come back in one written form, so the same client always counts as the same."""
    answer = seen(ask(peer, f"{FORGED}, {entry}", listed=listed))
    assert (answer.address, answer.via_proxy, answer.why) == (expected, True, "forwarded")


def test_a_peer_is_matched_to_the_list_whichever_way_its_address_is_written():
    """A dual-stack server names an IPv4 proxy as an IPv4-mapped address; it is the same proxy."""
    assert client_address(ask(f"::ffff:{PROXY}", MEMBER)) == MEMBER
    assert client_address(ask(ATTACKER, MEMBER, listed=f" {PROXY} , {EDGE},")) == ATTACKER


@pytest.mark.parametrize("values", [
    {"trusted_proxies": "*"}, {"trusted_proxies": "proxy.example"},
    {"trusted_proxies": "10.42.0.0/33"}, {"trusted_proxies": "10.42.0.10 10.42.0.11"},
    # A list that trusts every address is "believe everyone" written as a range.
    {"trusted_proxies": "0.0.0.0/0"}, {"trusted_proxies": "::/0"}, {"trusted_proxies": "10.42.0.10,::/0"},
    {"trusted_proxies": "0.0.0.0/1,128.0.0.0/1"}, {"trusted_proxies": "::/1,8000::/1"},
    {"trusted_proxies": "0.0.0.0/2,64.0.0.0/2,128.0.0.0/1"}, {"trusted_proxies": "10.42.0.10/0"},
    # The old name is held to the same rule while it is the one in use.
    {"forwarded_allow_ips": "*"}, {"trusted_proxies": " ", "forwarded_allow_ips": "proxy.example"},
    {"forwarded_allow_ips": "0.0.0.0/0"},
    {"proxy_hops": 0}, {"proxy_hops": -1}, {"proxy_hops": 11},
])
def test_a_proxy_setting_nyctr_cannot_honour_stops_it_starting(values):
    """A list that is not addresses and ranges is refused, never read as "believe everyone"."""
    with pytest.raises(ValueError) as refused:
        Settings(mode="demo", database_url="sqlite:///:memory:", **values)
    if "proxy_hops" not in values:
        # The chart's own words for the same refusal.
        assert "must contain only trusted proxy IP addresses or bounded ranges" in str(refused.value)


def test_a_wide_range_short_of_everything_is_still_read_as_written():
    """Outside the chart there is no floor on a range's width, and a host address with a prefix is its range."""
    for listed in ("0.0.0.0/1", "10.0.0.0/8,2001:db8::/32", "10.42.0.99/16"):
        assert Settings(mode="demo", database_url="sqlite:///:memory:", trusted_proxies=listed).proxy_list == listed
    assert client_address(ask("10.42.200.1", MEMBER, listed="10.42.0.99/16")) == MEMBER


OLD_LIST, NEW_LIST = "10.42.0.0/16", "10.99.0.10,2001:db8:42::10"


@pytest.mark.parametrize(("new", "old", "in_force", "old_name"), [
    (None, None, "", False),
    (NEW_LIST, None, NEW_LIST, False),
    # For one release the web server's name is still read when Nyctr's own is unset or empty.
    (None, OLD_LIST, OLD_LIST, True),
    ("", OLD_LIST, OLD_LIST, True),
    # Both set: Nyctr's own name wins, whatever the old one says.
    (NEW_LIST, OLD_LIST, NEW_LIST, False),
    (NEW_LIST, "*", NEW_LIST, False),
])
def test_the_list_of_proxies_is_read_from_nyctrs_own_name_and_for_now_the_old_one(monkeypatch, new, old,
                                                                                 in_force, old_name):
    """`NYCTR_TRUSTED_PROXIES` is the list. Unset under both names, no proxy is believed."""
    for name, value in (("NYCTR_TRUSTED_PROXIES", new), ("FORWARDED_ALLOW_IPS", old)):
        monkeypatch.delenv(name, raising=False)
        if value is not None:
            monkeypatch.setenv(name, value)
    monkeypatch.setenv("NYCTR_PROXY_HOPS", "2")
    settings = Settings(mode="demo", database_url="sqlite:///:memory:")
    assert (settings.proxy_list, settings.old_proxy_name_in_use, settings.proxy_hops) == (in_force, old_name, 2)
    inside_old, inside_new = "10.42.9.77", "10.99.0.10"
    request = ask(inside_old, MEMBER)
    request.app.state.settings = settings
    assert seen(request).via_proxy is (in_force == OLD_LIST)
    request = ask(inside_new, MEMBER)
    request.app.state.settings = settings
    assert seen(request).via_proxy is (in_force == NEW_LIST)


@pytest.mark.parametrize(("values", "warned"), [
    ({"forwarded_allow_ips": OLD_LIST}, 1), ({"trusted_proxies": NEW_LIST}, 0),
    ({"trusted_proxies": NEW_LIST, "forwarded_allow_ips": OLD_LIST}, 0), ({}, 0),
])
def test_starting_on_the_old_name_writes_one_plain_warning(caplog, values, warned):
    """One line at start says the old name is in use and will stop working, and no line otherwise."""
    app = create_app(Settings(mode="demo", database_url="sqlite:///:memory:", worker_enabled=False, **values))
    with caplog.at_level(logging.WARNING, logger="nyctr"), TestClient(app):
        pass
    lines = [x.getMessage() for x in caplog.records if "FORWARDED_ALLOW_IPS" in x.getMessage()]
    assert len(lines) == warned
    assert all("NYCTR_TRUSTED_PROXIES" in line and "stop working" in line for line in lines)


READS = re.compile(
    # The peer, the raw request and what is built from its scheme, through any name that ends like a request.
    r"\b\w*(request|req|conn|connection|websocket)\.(client|scope|base_url|url_for)\b|\.url\.scheme"
    r"|\b\w*(request|req|conn|connection|websocket|scope)\w*\[\s*[\"']client[\"']\s*\]"
    r"|\bscope\b.*[\"']client[\"']|getattr\([^)]*[\"'](client|scope|base_url|url_for)[\"']"
    # The headers a client or a proxy can use to name an address, as text or as a parameter name.
    r"|x[-_]forwarded|x[-_]original[-_]forwarded|forwarded[-_](for|host|proto|port)|[\"']forwarded[\"']"
    r"|x[-_]real[-_]ip|x[-_]client[-_]ip|x[-_]cluster[-_]client[-_]ip|cf[-_]connecting[-_]ip"
    r"|true[-_]client[-_]ip|fastly[-_]client[-_]ip", re.I)
# Inventory kinds, not a request: the one line that reads a "client" entry of a dictionary named scope.
NOT_A_REQUEST = {("links.py", 'for client in scope.get("client", []) if ranges and complete else []:')}


def readers(text: str, name: str = "") -> list[str]:
    """List the lines of one module that read where a request came from."""
    return [f"{name}:{number}: {line.strip()[:80]}" for number, line in enumerate(text.splitlines(), 1)
            if READS.search(line) and (name, line.strip()) not in NOT_A_REQUEST]


def test_only_the_peer_module_reads_where_a_request_came_from():
    """A second reader would bring back the forged address. Ask `peer.client_address` instead.

    Catches the peer of a request, the raw request and the header names, in
    code and in comments, in every module but `peer.py`. It also catches a
    reader of the request's scheme or base address: behind a proxy that ends
    TLS those say `http`, and Nyctr believes no header about them. Cookies and
    addresses Nyctr builds come from the configured origins.

    This is a net for accidents, not for intent. It matches names, so a header
    name put together from pieces, or a request held under an unusual name,
    still gets past it.
    """
    offenders = [line for path in sorted(NYCTR.rglob("*.py")) if path.name != "peer.py"
                 for line in readers(path.read_text(), path.name)]
    assert offenders == []
    assert not re.search(r"proto|scheme", (NYCTR / "peer.py").read_text(), re.I)


@pytest.mark.parametrize("line", [
    'peer = request.client.host', 'host = http_request.client.host', 'client = scope.get("client")',
    'host = scope["client"][0]', 'host = request["client"][0]', 'who = getattr(request, "client")',
    'raw = request.scope', 'origin = str(request.base_url)', 'secure = request.url.scheme == "https"',
    'def login(x_forwarded_for: str = Header("")):', 'value = request.headers.get("X-Forwarded-For")',
    'value = request.headers.get("x-real-ip")', 'value = request.headers["CF-Connecting-IP"]',
    'value = request.headers.get("true-client-ip")', 'value = request.headers.get("forwarded")',
    'name = "x-" + "forwarded-for"', '# read X-Forwarded-Host here',
])
def test_the_net_catches_the_ways_a_second_reader_is_usually_written(line):
    """Each of these was once a way past the test above."""
    assert readers(line) != []


@pytest.mark.parametrize("line", [
    'for client in kinds["client"]:', 'self.client = client', 'path = request.url.path',
    'settings = request.app.state.settings', '"client_ip": row.get("clientIp"),',
    'forwarded_allow_ips: str = Field("", validation_alias="FORWARDED_ALLOW_IPS")',
])
def test_the_net_leaves_ordinary_lines_alone(line):
    """Inventory, outgoing clients and the settings are not readers of where a request came from."""
    assert readers(line) == []
