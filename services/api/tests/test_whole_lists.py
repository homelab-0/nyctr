"""Each integration's word on which gaps leave its lists whole is held to what its adapter reads.

Every gap code an integration can record is provoked at the real adapter against a fabricated
source. A code may be declared in `detail_gaps` exactly when the read that recorded it still
holds every item the source has, of every kind the read does not itself name as unread. So a
declaration that is wrong either way fails here, and so does a code nobody wrote a case for.
"""

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from nyctr import retention
from nyctr.integrations import collect, core, proxmox, registry, unifi

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
TOKEN = "nyctr@pve!reader=0f8fad5b-d9cb-469f-a165-70867728950e"
LOG_KINDS = ["client", "domain"]


def read(monkeypatch, provider, config, key, answer):
    """Collect through the real adapter; return the snapshot, its gaps and the doubt a collection would record."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "source.example")
    monkeypatch.setattr(core, "utc_now", lambda: NOW)
    monkeypatch.setattr(core, "make_http_client", lambda key, **options: httpx.AsyncClient(
        transport=httpx.MockTransport(answer), follow_redirects=False, trust_env=False))
    with core.capture_probe() as evidence:
        snapshot = asyncio.run(collect(provider, "s", config, key))
    return snapshot, set(evidence.gaps), retention.unread(provider, snapshot, evidence.gaps)


def items(snapshot):
    return {(node["kind"], node["source_id"]) for node in snapshot.resources}


def held_to_its_adapter(provider, code, holds, result):
    """The declaration says the lists are whole exactly when nothing the source `holds` is missing from the read."""
    snapshot, gaps, doubt = result
    assert gaps == {code}
    declared = code in registry.find(provider).detail_gaps
    assert (doubt != [retention.EVERY_KIND]) == declared
    hidden = {item for item in holds if item[0] not in doubt} - items(snapshot)
    assert bool(hidden) != declared, (code, sorted(hidden))


def unifi_source(refuse=(), devices=None, sites=None):
    """One site with two devices, a network, a client, a guest and a rule; `refuse` paths answer 404."""
    home = "/proxy/network/integration/v1/sites"
    guest = {"type": "GUEST", "authorized": True}
    lists = {
        home: [{"id": "home", "name": "Home"}] if sites is None else sites,
        f"{home}/home/devices": devices or [{"id": "gw", "name": "Gateway", "features": ["gateway"]},
                                            {"id": "ap", "name": "Upstairs", "features": ["accessPoint"]}],
        f"{home}/home/networks": [{"id": "lan", "name": "LAN", "vlanId": 20, "management": "GATEWAY"}],
        f"{home}/home/clients": [{"id": "laptop", "name": "Laptop"},
                                 {"id": "visitor", "name": "Visitor", "access": guest}],
        f"{home}/home/firewall/policies": [{"id": "rule", "name": "Cameras"}],
        f"{home}/home/hotspot/vouchers": [], f"{home}/home/wifi/broadcasts": [],
    }

    def answer(request):
        path = request.url.path
        if path.removeprefix(f"{home}/home") in refuse:
            return httpx.Response(404)
        if path in lists:
            rows = lists[path]
            return httpx.Response(200, json={"data": rows, "count": len(rows), "offset": 0, "totalCount": len(rows)})
        return httpx.Response(200, json={"id": path.rsplit("/", 1)[1], "access": guest})
    return answer


SWITCH_ONLY = [{"id": "gw", "name": "Gateway", "features": ["switching"]}]
UNIFI = {
    "unifi_networks_details_unavailable": {"refuse": ["/networks/lan"]},
    "unifi_devices_details_unavailable": {"refuse": ["/devices/gw", "/devices/ap"]},
    "unifi_detail_limit": {"limit": ("REQUEST_CEILING", 0)},
    "unifi_gateway_not_identified": {"devices": SWITCH_ONLY},
    "unifi_guest_details_unavailable": {"refuse": ["/clients/visitor"]},
    "unifi_guest_detail_limit": {"limit": ("MAX_GUEST_DETAILS", 0)},
    "unifi_vouchers_unavailable": {"refuse": ["/hotspot/vouchers"]},
    "unifi_wifi_unavailable": {"refuse": ["/wifi/broadcasts"]},
    "unifi_no_visible_sites": {"sites": []},
}


@pytest.mark.parametrize("code", UNIFI)
def test_the_network_integration(monkeypatch, code):
    case = dict(UNIFI[code])
    config = {"base_url": "https://source.example/proxy/network/integration"}
    whole, gaps, doubt = read(monkeypatch, "unifi_network", config, "key", unifi_source(devices=case.get("devices")))
    if "devices" not in case:
        assert (gaps, doubt) == (set(), [])
    if limit := case.pop("limit", None):
        monkeypatch.setattr(unifi, *limit)
    held_to_its_adapter("unifi_network", code, items(whole),
                        read(monkeypatch, "unifi_network", config, "key", unifi_source(**case)))


def proxmox_source(refuse=(), nodes=True):
    pages = {
        "/cluster/resources": [{"type": "qemu", "node": "pve1", "vmid": 101, "name": "photos"},
                               {"type": "lxc", "node": "pve1", "vmid": 204, "name": "indexer"},
                               *([{"type": "node", "node": "pve1", "status": "online"}] if nodes else [])],
        "/cluster/firewall/options": {"enable": 1},
        "/nodes/pve1/network": [{"iface": "vmbr0", "type": "bridge", "active": 1}],
        "/nodes/pve1/qemu/101/config": {"net0": "virtio=00:00:5e:00:53:11,bridge=vmbr0"},
        "/nodes/pve1/qemu/101/firewall/options": {"enable": 1},
        "/nodes/pve1/lxc/204/config": {"net0": "name=eth0,bridge=vmbr0,hwaddr=00:00:5e:00:53:44"},
        "/nodes/pve1/lxc/204/firewall/options": {"enable": 0},
    }

    def answer(request):
        path = request.url.path.removeprefix("/api2/json")
        return httpx.Response(200, json={"data": pages[path]}) if path not in refuse else httpx.Response(501)
    return answer


PROXMOX = {
    "proxmox_firewall_options_unavailable": {"refuse": ["/cluster/firewall/options",
                                                        "/nodes/pve1/qemu/101/firewall/options"]},
    "proxmox_guest_limit": {"limit": 1},
    "proxmox_no_visible_nodes": {"nodes": False},
}


@pytest.mark.parametrize("code", PROXMOX)
def test_the_hypervisor_integration(monkeypatch, code):
    case = dict(PROXMOX[code])
    config = {"base_url": "https://source.example:8006"}
    whole, gaps, doubt = read(monkeypatch, "proxmox", config, TOKEN, proxmox_source())
    assert (gaps, doubt) == (set(), []) and len(whole.resources) == 4
    if limit := case.pop("limit", None):
        monkeypatch.setattr(proxmox, "MAX_GUESTS", limit)
    held_to_its_adapter("proxmox", code, items(whole), read(monkeypatch, "proxmox", config, TOKEN,
                                                           proxmox_source(**case)))


def pihole_source(rows, sign_out=204):
    def answer(request):
        if request.url.path == "/api/auth":
            return (httpx.Response(200, json={"session": {"valid": True, "sid": "c2Vzc2lvbi1pZA==", "validity": 300}})
                    if request.method == "POST" else httpx.Response(sign_out))
        start = int(request.url.params["start"])
        return httpx.Response(200, json={"queries": rows[start:start + 500]})
    return answer


def looked_up(second, address="192.168.1.20"):
    return {"id": second, "time": (NOW - timedelta(seconds=second + 1)).timestamp(), "type": "A",
            "domain": f"d{second}.example", "status": "GRAVITY", "client": {"ip": address, "name": address}}


PIHOLE = {
    "pihole_sign_out_failed": ([looked_up(0), looked_up(1, "192.168.1.99")], 500),
    # More blocked lookups than one collection reads; the oldest is the only one from its device.
    "pihole_query_limit": ([*map(looked_up, range(2000)), looked_up(2000, "192.168.1.99")], 204),
}


@pytest.mark.parametrize("code", PIHOLE)
def test_the_resolver_integration(monkeypatch, code):
    config = {"base_url": "https://source.example"}
    whole, gaps, doubt = read(monkeypatch, "pihole", config, "password", pihole_source([looked_up(0)]))
    assert (gaps, doubt) == (set(), [])
    holds = items(whole) | {("client", "192.168.1.99")}
    held_to_its_adapter("pihole", code, holds, read(monkeypatch, "pihole", config, "password",
                                                    pihole_source(*PIHOLE[code])))


def dns_source(logs=True, without=(), rows=None, pages=1):
    """A profile with every policy section and one blocked lookup from a named device, unless told otherwise."""
    row = {"timestamp": core.iso(NOW - timedelta(minutes=10)), "domain": "blocked.example", "status": "blocked",
           "device": {"id": "TV01", "name": "kitchen-tv"}, "reasons": []}
    profile = {"name": "Office DNS", "settings": {"logs": {} if logs is None else {"enabled": logs}},
               "security": {}, "privacy": {}, "parentalControl": {}, "allowlist": [], "denylist": []}

    def answer(request):
        if request.url.path.endswith("/logs"):
            page = int(request.url.params.get("cursor", "1"))
            return httpx.Response(200, json={
                "data": [row] if rows is None else rows,
                "meta": {"pagination": {"cursor": str(page + 1) if page < pages else None}}})
        return httpx.Response(200, json={"data": {k: v for k, v in profile.items() if k not in without}})
    return answer


DNS = {
    # The profile does not say whether it logs, and the log comes back empty.
    "nextdns_log_settings_unknown": {"logs": None, "rows": []},
    "nextdns_policy_fields_missing": {"without": ["denylist"]},
}


@pytest.mark.parametrize("code", DNS)
def test_the_dns_integration(monkeypatch, code):
    config = {"profile_id": "abc123"}
    whole, gaps, doubt = read(monkeypatch, "nextdns", config, "key", dns_source())
    assert (gaps, doubt) == (set(), []) and {("domain", "blocked.example"), ("client", "TV01")} <= items(whole)
    result = read(monkeypatch, "nextdns", config, "key", dns_source(**DNS[code]))
    held_to_its_adapter("nextdns", code, items(whole), result)
    if code == "nextdns_log_settings_unknown":
        # An empty log may only mean logging is off: what came from lookups was not read, the rest was.
        assert result[2] == LOG_KINDS


@pytest.mark.parametrize("source", [{"logs": False}, {"pages": core.MAX_PAGES + 1}],
                         ids=["logging switched off", "a log read cut short"])
def test_a_log_not_read_in_full_names_what_came_from_lookups_as_unread(monkeypatch, source):
    snapshot, gaps, doubt = read(monkeypatch, "nextdns", {"profile_id": "abc123"}, "key", dns_source(**source))
    assert gaps == set() and doubt == LOG_KINDS
    assert (snapshot.partial_rows is not None) == ("pages" in source)


def test_every_gap_code_an_integration_can_record_has_a_case_here():
    cases = {"unifi_network": UNIFI, "proxmox": PROXMOX, "pihole": PIHOLE, "nextdns": DNS}
    for provider in registry.providers().values():
        assert set(cases[provider.id]) == set(provider.gap_notes), provider.id
        assert provider.detail_gaps <= set(provider.gap_notes), provider.id


def test_an_integration_that_picks_up_dates_what_it_takes_from_lookups_by_the_newest_lookup_not_by_the_read(
        monkeypatch):
    """What a read that picked up counts as still listed is what was looked up inside the window.

    That rests on each such item carrying the time of its newest lookup. One dated by the read
    itself would count as listed for a whole window after its last lookup.
    """
    older, newer = NOW - timedelta(hours=5), NOW - timedelta(minutes=10)
    row = {"domain": "blocked.example", "status": "blocked", "device": {"id": "TV01", "name": "kitchen-tv"},
           "reasons": []}
    dns = dns_source(rows=[{**row, "timestamp": core.iso(newer)}, {**row, "timestamp": core.iso(older)}])
    reads = {
        "nextdns": read(monkeypatch, "nextdns", {"profile_id": "abc123"}, "key", dns)[0],
        "pihole": read(monkeypatch, "pihole", {"base_url": "https://source.example"}, "password", pihole_source(
            [looked_up(10 * 60 - 1), looked_up(5 * 3600 - 1)]))[0],
    }
    assert set(reads) == {provider.id for provider in registry.providers().values() if provider.resumes}
    for provider, snapshot in reads.items():
        dated = {node["observed_at"] for node in snapshot.resources if node["evidence_kind"] == "observed"}
        assert dated == {core.iso(newer)}, provider
