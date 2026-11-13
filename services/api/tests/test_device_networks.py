"""Networks carry their ranges, gear its uplink, and which network a device is on is worked out at read time."""

import asyncio

import httpx
import pytest
from test_integrations import KEY, mock_client, unifi_page

from nyctr.collection import apply_snapshot
from nyctr.integrations import IntegrationError, collect, core
from nyctr.integrations.unifi import REQUEST_CEILING
from nyctr.links import derived_links
from nyctr.models import Integration

BASE = "/v1/sites/home"


def gear(id_, ip, features=("switching",), above=None):
    """One piece of equipment as its list row and its detail read."""
    row = {"id": id_, "name": id_, "features": list(features), "ipAddress": ip}
    return row, {**row, "features": {}, **({"uplink": {"deviceId": above}} if above else {})}


def network(id_, vlan, management, host=None, prefix=24, **extra):
    """One network as its list row and its detail read."""
    row = {"id": id_, "name": id_, "vlanId": vlan, "management": management,
           **({"deviceId": extra.pop("deviceId")} if "deviceId" in extra else {})}
    ipv4 = {"ipv4Configuration": {"hostIpAddress": host, "prefixLength": prefix, **extra}} if host else {}
    return row, {**row, **ipv4}


def home(**changes):
    """One site: a gateway, a switch below it, an access point below that, four networks and four devices."""
    site = {
        "devices": [gear("gw", "10.0.1.1", ("gateway", "switching")), gear("sw", "10.0.1.2", above="gw"),
                    gear("ap", "10.0.1.3", ("accessPoint",), above="sw")],
        "networks": [network("lan", 1, "GATEWAY", "10.0.1.1"),
                     network("iot", 20, "GATEWAY", "10.0.20.1", additionalHostIpSubnets=["10.0.21.1/24"]),
                     network("lab", 30, "SWITCH", "10.0.30.1", deviceId="sw"),
                     network("bare", 40, "UNMANAGED")],
        "clients": [{"id": "laptop", "name": "laptop", "ipAddress": "10.0.1.50", "uplinkDeviceId": "sw"},
                    {"id": "camera", "name": "camera", "ipAddress": "10.0.21.7", "uplinkDeviceId": "ap"},
                    {"id": "roamer", "name": "roamer", "uplinkDeviceId": "ap"},
                    {"id": "stray", "name": "stray", "ipAddress": "172.16.0.9"}],
    }
    return {**site, **changes}


def run(monkeypatch, site, fault=None):
    """Collect the site through the real adapter; `fault` may replace the answer to any request."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "unifi.example")
    lists = {f"{BASE}/{kind}": [row for row, _detail in site[kind]] for kind in ("devices", "networks")}
    lists[f"{BASE}/clients"] = site["clients"]
    details = {f"{BASE}/{kind}/{row['id']}": detail for kind in ("devices", "networks") for row, detail in site[kind]}

    def handler(request):
        """Serve the documented list and detail reads only."""
        path = request.url.path.removeprefix("/proxy/network/integration")
        if fault and (reply := fault(path)) is not None:
            return reply
        if path == "/v1/sites":
            return httpx.Response(200, json=unifi_page([{"id": "home", "name": "Home"}]))
        if path in details:
            return httpx.Response(200, json=details[path])
        return httpx.Response(200, json=unifi_page(lists.get(path, [])))

    calls = mock_client(monkeypatch, handler)
    with core.capture_probe() as evidence:
        snapshot = asyncio.run(collect(
            "unifi_network", "u", {"base_url": "https://unifi.example/proxy/network/integration"}, KEY))
    return snapshot, evidence, calls


def named(snapshot):
    """Index resources by name."""
    return {node["name"]: node for node in snapshot.resources}


def links(edges, kind):
    """The (source, target, evidence) of every link of one kind, by the last part of each identifier."""
    return {(e["source"].rsplit(":", 1)[-1], e["target"].rsplit(":", 1)[-1], e["evidence_kind"])
            for e in edges if e["kind"] == kind}


def test_ranges_the_device_that_runs_a_network_and_uplinks_come_from_the_source(monkeypatch):
    """Each network's range and each piece of gear's uplink are the source's statements, read with GET only."""
    snapshot, evidence, calls = run(monkeypatch, home())
    nodes = named(snapshot)
    assert nodes["lan"]["attributes"]["subnets"] == ["10.0.1.0/24"]
    assert nodes["iot"]["attributes"]["subnets"] == ["10.0.20.0/24", "10.0.21.0/24"]
    assert nodes["iot"]["attributes"]["gateway_ip"] == "10.0.20.1"
    assert [nodes[n]["attributes"]["managed_by"] for n in ("lan", "lab", "bare")] == ["gateway", "switch", "unmanaged"]
    assert "subnets" not in nodes["bare"]["attributes"] and nodes["lan"]["evidence_kind"] == "configured"
    # The device a network names, and the gear above each piece of gear, are the source's statements.
    assert links(snapshot.relationships, "managed_by") == {("lab", "sw", "configured")}
    assert links(snapshot.relationships, "connects_to") >= {("sw", "gw", "observed"), ("ap", "sw", "observed")}
    assert nodes["ap"]["attributes"]["uplink"] == "sw" and "uplink" not in nodes["gw"]["attributes"]
    # Which network a client is on is not a statement of the source, so the snapshot holds none.
    assert not links(snapshot.relationships, "member_of") and evidence.gaps == set()
    assert all(call.method == "GET" for call in calls) and len(calls) == 14


def test_clients_are_placed_at_read_time_only_when_exactly_one_range_holds_their_address(monkeypatch):
    """Placement is inferred with its basis; no address, no range or two ranges places nothing."""
    snapshot, _evidence, _calls = run(monkeypatch, home())
    derived = derived_links(snapshot.resources)
    assert links(derived, "member_of") == {("laptop", "lan", "inferred"), ("camera", "iot", "inferred")}
    assert links(derived, "managed_by") == {("lan", "gw", "inferred"), ("iot", "gw", "inferred")}
    assert all(e["provider"] == "nyctr" and e["attributes"]["basis"].startswith("Worked out by Nyctr") for e in derived)
    placed = next(e for e in derived if e["source"] == "u:client:camera")
    assert "10.0.21.7 is inside 10.0.21.0/24" in placed["attributes"]["basis"]
    # A second network with an overlapping range makes the laptop's network unknown again.
    overlap = home()
    overlap["networks"].append(network("guest", 50, "GATEWAY", "10.0.1.129", 25))
    overlap["clients"].append({"id": "phone", "name": "phone", "ipAddress": "10.0.1.200"})
    snapshot, _evidence, _calls = run(monkeypatch, overlap)
    assert links(derived_links(snapshot.resources), "member_of") == {
        ("laptop", "lan", "inferred"), ("camera", "iot", "inferred")}
    # The same range in another connection or site places nothing here.
    elsewhere = [{**node, "site_id": "other"} if node["kind"] == "network" else node for node in snapshot.resources]
    assert not links(derived_links(elsewhere), "member_of")


def test_nothing_is_placed_while_a_managed_network_of_the_site_has_no_collected_range(monkeypatch):
    """Nested ranges with the inner detail refused: the device must not be claimed for the outer network."""
    nested = home(networks=[network("wide", 1, "GATEWAY", "10.0.0.1", 16), network("inner", 5, "GATEWAY", "10.0.5.1"),
                            network("bare", 40, "UNMANAGED")],
                  clients=[{"id": "cam", "name": "cam", "ipAddress": "10.0.5.9"},
                           {"id": "pc", "name": "pc", "ipAddress": "10.0.9.9"}])
    refuse = lambda path: httpx.Response(403) if path == f"{BASE}/networks/inner" else None  # noqa: E731
    snapshot, evidence, _calls = run(monkeypatch, nested, refuse)
    assert "unifi_networks_details_unavailable" in evidence.gaps
    assert not links(derived_links(snapshot.resources), "member_of")
    # With the inner range read the camera is in two ranges and stays unplaced; the other device is placed.
    # The unmanaged network has no range to miss and never blocks placement.
    snapshot, _evidence, _calls = run(monkeypatch, nested)
    assert links(derived_links(snapshot.resources), "member_of") == {("pc", "wide", "inferred")}


def test_placement_and_gateway_links_stay_inside_one_connection_and_the_latest_collection(monkeypatch):
    """Another connection's ranges, rows missing from the latest collection, and a second gateway place nothing."""
    snapshot, _evidence, _calls = run(monkeypatch, home())
    rows = snapshot.resources

    def changed(name, **attributes):
        """The same inventory with one row's attributes changed."""
        return [{**r, "attributes": {**r["attributes"], **attributes}} if r["name"] == name else r for r in rows]

    # The LAN belongs to another connection: its range no longer places this connection's laptop.
    other = links(derived_links(changed("lan", integration_id="other")), "member_of")
    assert other == {("camera", "iot", "inferred")}
    # A device, or a network, missing from the latest collection takes no part.
    assert links(derived_links(changed("laptop", missing_from_latest_snapshot=True)), "member_of") == {
        ("camera", "iot", "inferred")}
    assert links(derived_links(changed("lan", missing_from_latest_snapshot=True)), "member_of") == {
        ("camera", "iot", "inferred")}
    # Two gateways in the site: which one runs a gateway-managed network is not known.
    second = [{**r, "kind": "gateway"} if r["name"] == "sw" else r for r in rows]
    assert links(derived_links(rows), "managed_by") and not links(derived_links(second), "managed_by")


@pytest.mark.parametrize("kind", ["networks", "devices"])
@pytest.mark.parametrize("reply", [
    lambda path: httpx.Response(403),
    lambda path: httpx.Response(200, content=b'{"id": '),
    lambda path: httpx.Response(200, json={"id": path.rsplit("/", 1)[-1], "uplink": "gw",
                                           "ipv4Configuration": {"hostIpAddress": "10.0.1.1", "prefixLength": "24"}}),
    # The same record answered for every detail read: only the read it belongs to may use it.
    lambda path: httpx.Response(200, json={"id": "lan", "uplink": {"deviceId": "gw"}, "ipv4Configuration": {
        "hostIpAddress": "10.0.1.1", "prefixLength": 24}}),
], ids=["refused", "malformed-json", "malformed-fields", "repeated-record"])
def test_a_refused_malformed_or_repeated_detail_read_is_a_gap_and_keeps_nothing(monkeypatch, kind, reply):
    """The collection still succeeds; what that read would have said stays unknown."""
    snapshot, evidence, calls = run(
        monkeypatch, home(), lambda path: reply(path) if path.startswith(f"{BASE}/{kind}/") else None)
    assert f"unifi_{kind}_details_unavailable" in evidence.gaps and len(snapshot.resources) == 12
    assert all(call.method == "GET" for call in calls)
    nodes = named(snapshot)
    if kind == "devices":
        assert all("uplink" not in nodes[n]["attributes"] for n in ("gw", "sw", "ap"))
        assert not {link for link in links(snapshot.relationships, "connects_to") if link[0] in {"sw", "ap"}}
    else:
        kept = [n for n in ("lan", "iot", "lab", "bare") if "subnets" in nodes[n]["attributes"]]
        repeated = reply(f"{BASE}/networks/iot").status_code == 200 and b'"lan"' in reply(f"{BASE}/networks/iot").content
        assert kept == (["lan"] if repeated else [])
        # A managed network whose range is unknown could hold any address, so nothing is placed.
        assert not links(derived_links(snapshot.resources), "member_of")


@pytest.mark.parametrize("kind", ["networks", "devices"])
@pytest.mark.parametrize("fault, category", [
    (lambda: httpx.Response(429), "rate_limit"),
    (lambda: (_ for _ in ()).throw(httpx.ReadTimeout("slow")), "timeout"),
    (lambda: (_ for _ in ()).throw(httpx.ConnectError("down")), "transport"),
], ids=["rate-limit", "timeout", "broken-connection"])
def test_a_rate_limit_timeout_or_broken_connection_on_a_detail_read_fails_the_collection(
        monkeypatch, kind, fault, category):
    """These are never recorded as "the key cannot read this"."""
    with pytest.raises(IntegrationError) as caught:
        run(monkeypatch, home(), lambda path: fault() if path.startswith(f"{BASE}/{kind}/") else None)
    assert caught.value.category == category


def big(networks, devices, clients, guests=0):
    """A site of the given size with every client on the first network."""
    return {
        "devices": [gear("d0", "10.0.0.1")] + [gear(f"d{n}", f"10.0.0.{n + 1}", above="d0") for n in range(1, devices)],
        "networks": [network(f"n{n}", n + 1, "GATEWAY", f"10.{n}.0.1", 16) for n in range(networks)],
        "clients": [{"id": f"c{n}", "name": f"c{n}", "ipAddress": f"10.0.1.{n}", "uplinkDeviceId": "d0",
                     **({"access": {"type": "GUEST", "authorized": True}} if n < guests else {})}
                    for n in range(clients)],
    }


def test_detail_reads_stay_inside_the_request_budget_and_under_the_hosted_request_limit(monkeypatch):
    """Ten networks, 13 pieces of gear and 67 devices cost 30 requests; a larger site stops reading details."""
    snapshot, evidence, calls = run(monkeypatch, big(10, 13, 67))
    assert len(calls) == 30 and evidence.gaps == set()
    assert len(links(derived_links(snapshot.resources), "member_of")) == 67
    # Guest details and the closing lists are reserved first, so they are still read in full.
    snapshot, evidence, calls = run(monkeypatch, big(40, 60, 50, guests=45))
    assert len(calls) <= REQUEST_CEILING < 100 < core.MAX_REQUESTS and "unifi_detail_limit" in evidence.gaps
    assert sum("/clients/" in call.url.path for call in calls) == 40
    assert {call.url.path.rsplit("/", 2)[-2:][0] for call in calls[-2:]} == {"hotspot", "wifi"}
    read = [node for node in snapshot.resources if node["kind"] == "network" and "subnets" in node["attributes"]]
    assert 0 < len(read) <= 40 and all("uplink" not in n["attributes"] for n in snapshot.resources if n["name"] == "d59")


def test_the_stored_graph_holds_no_placement_and_the_saved_query_returns_devices(app, client, admin_headers, monkeypatch):
    """Placement appears only when the graph is read, labelled inferred, and reaches the saved query."""
    snapshot, _evidence, _calls = run(monkeypatch, home())
    with app.state.session_factory() as db:
        source = Integration(id="u", provider="unifi_network", name="Home network", config={},
                             secret_ref="NYCTR_CONNECTOR_SECRET_U", status="connected")
        db.add(source)
        db.flush()
        apply_snapshot(db, source, snapshot, app.state.settings)
        db.commit()
    graph = client.get("/api/graph", headers=admin_headers).json()
    mine = [edge for edge in graph["edges"] if edge["source"].startswith("u:") and edge["kind"] == "member_of"]
    assert links(mine, "member_of") == {("laptop", "lan", "inferred"), ("camera", "iot", "inferred")}
    assert all(edge["id"].startswith("derived:") and edge["provider"] == "nyctr" for edge in mine)
    assert next(n for n in graph["nodes"] if n["id"] == "u:gateway:gw")["evidence_kind"] == "observed"
    # The saved query "Every network and what is on it": each link says how it is known.
    saved = '{ networks { name vlan: attr(key: "vlan") links(first: 100) { kind evidence basis source { name kind } target { name kind } } } }'
    found = client.post("/api/graph/query", headers=admin_headers, json={"query": saved}).json()["data"]["networks"]
    on = {row["name"]: {(x["source"]["name"], x["target"]["name"], x["evidence"]): x["basis"] for x in row["links"]}
          for row in found}
    assert on["lan"][("laptop", "lan", "inferred")].startswith("Worked out by Nyctr: address 10.0.1.50")
    assert on["lan"][("lan", "gw", "inferred")].startswith("Worked out by Nyctr") and ("camera", "iot", "inferred") in on["iot"]
    assert on["lab"][("lab", "sw", "configured")] is None
    assert not any(name in {"roamer", "stray"} for row in on.values() for name, _target, _evidence in row)
    device = '{ devices(search: "camera") { name network { name } } }'
    assert client.post("/api/graph/query", headers=admin_headers, json={"query": device}).json()["data"]["devices"] == [
        {"name": "camera", "network": {"name": "iot"}}]
