"""The experimental Proxmox reader: parsing, transport contract and inferred cross-source links."""

import asyncio

import httpx
import pytest

from nyctr.analysis import refresh_findings
from nyctr.integrations import IntegrationError, collect, core, validate_config
from nyctr.integrations.proxmox import parse_nic
from nyctr.links import derived_links
from nyctr.models import Finding, Resource

TOKEN = "nyctr@pve!reader=0f8fad5b-d9cb-469f-a165-70867728950e"


@pytest.mark.parametrize("text,expected", [
    ("virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,firewall=1,tag=20",
     {"bridge": "vmbr0", "mac": "bc:24:11:aa:bb:cc", "vlan": 20, "firewall": True, "link_down": False}),
    ("name=eth0,bridge=vmbr1,hwaddr=BC:24:11:00:00:01,ip=dhcp,type=veth",
     {"bridge": "vmbr1", "mac": "bc:24:11:00:00:01", "vlan": None, "firewall": False, "link_down": False}),
    ("e1000=BC:24:11:00:00:02,bridge=vmbr0,tag=9999,link_down=1",
     {"bridge": "vmbr0", "mac": "bc:24:11:00:00:02", "vlan": None, "firewall": False, "link_down": True}),
])
def test_network_card_settings_are_parsed(text, expected):
    """Both VM and container card formats yield bridge, address, tag and firewall flag."""
    assert parse_nic(text) == expected


@pytest.mark.parametrize("text", ["virtio=BC:24:11:AA:BB:CC", "bridge=../../etc", None, 7, "x" * 600])
def test_unusable_card_settings_are_skipped(text):
    """A card with no valid bridge is not placed anywhere."""
    assert parse_nic(text) is None


def test_configuration_requires_an_allowed_https_host(monkeypatch):
    """The Proxmox address passes the same destination checks as other connectors."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "pve.example")
    assert validate_config("proxmox", {"base_url": "https://pve.example:8006"}) == {
        "base_url": "https://pve.example:8006/api2/json"}
    for bad in ["http://pve.example:8006", "https://other.example:8006", "https://pve.example:8006/api2/extjs",
                "https://user:pw@pve.example:8006", "https://127.0.0.1:8006"]:
        with pytest.raises(IntegrationError):
            validate_config("proxmox", {"base_url": bad})
    with pytest.raises(IntegrationError):
        validate_config("proxmox", {"base_url": "https://pve.example:8006", "verify_ssl": False})


def test_a_malformed_token_is_rejected_before_any_request(monkeypatch):
    """A secret that is not an API token never leaves the server."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "pve.example")
    monkeypatch.setattr(core, "make_http_client", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    with pytest.raises(IntegrationError, match="API token"):
        asyncio.run(collect("proxmox", "pve", {"base_url": "https://pve.example:8006"}, "root-password"))


def test_collection_reads_only_and_models_cards_as_configuration(monkeypatch):
    """Nodes, bridges and guests are read with GET and a token header; cards become configured links."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "pve.example")
    pages = {
        "/cluster/resources": [{"type": "node", "node": "pve1", "status": "online"},
                               {"type": "qemu", "node": "pve1", "vmid": 101, "name": "photos", "status": "running"},
                               {"type": "lxc", "node": "pve1", "vmid": 204, "name": "indexer", "status": "running"},
                               {"type": "storage", "node": "pve1", "id": "storage/pve1/local"}],
        "/cluster/firewall/options": {"enable": 1},
        "/nodes/pve1/network": [{"iface": "vmbr0", "type": "bridge", "active": 1, "bridge_vlan_aware": 1,
                                 "cidr": "198.51.100.3/24", "bridge_ports": "enp3s0"},
                                {"iface": "enp3s0", "type": "eth"}],
        "/nodes/pve1/qemu/101/config": {"name": "photos", "net0": "virtio=00:00:5e:00:53:11,bridge=vmbr0,tag=20,firewall=1"},
        "/nodes/pve1/qemu/101/firewall/options": {"enable": 1},
        "/nodes/pve1/lxc/204/config": {"hostname": "indexer", "net0": "name=eth0,bridge=vmbr0,hwaddr=00:00:5e:00:53:44,tag=20"},
    }
    calls = []

    def handler(request):
        calls.append(request)
        assert request.method == "GET" and request.url.host == "pve.example"
        assert request.headers["Authorization"] == "PVEAPIToken=" + TOKEN and "X-Api-Key" not in request.headers
        path = request.url.path.removeprefix("/api2/json")
        return httpx.Response(200, json={"data": pages[path]}) if path in pages else httpx.Response(501)

    def client(key, *, authorization_scheme=""):
        assert authorization_scheme == "PVEAPIToken"
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False,
                                 headers={"Authorization": f"{authorization_scheme}={key}"})

    monkeypatch.setattr(core, "make_http_client", client)
    with core.capture_probe() as evidence:
        snapshot = asyncio.run(collect("proxmox", "pve", {"base_url": "https://pve.example:8006"}, TOKEN))
    kinds = sorted(node["kind"] for node in snapshot.resources)
    assert kinds == ["bridge", "host", "workload", "workload"] and snapshot.blocks == []
    by_name = {node["name"]: node for node in snapshot.resources}
    assert by_name["pve1"]["attributes"]["addresses"] == ["198.51.100.3"]
    assert by_name["photos"]["attributes"]["firewall_enabled"] is True
    # The container's firewall option read failed: its state is unknown, never assumed off.
    assert by_name["indexer"]["attributes"]["firewall_enabled"] is None
    assert by_name["indexer"]["attributes"]["nics"][0]["firewall"] is False
    assert "proxmox_firewall_options_unavailable" in evidence.gaps
    card = next(e for e in snapshot.relationships if e["kind"] == "connects_to" and e["source"] == by_name["photos"]["id"])
    assert card["evidence_kind"] == "configured" and card["attributes"]["vlan"] == 20
    assert all(edge["kind"] in {"hosted_by", "connects_to"} for edge in snapshot.relationships)


def test_cross_source_links_need_a_unique_match():
    """A shared address or tag produces no link; a unique one produces an inferred link with its basis."""
    def row(id_, provider, kind, **attrs):
        return {"id": id_, "provider": provider, "kind": kind, "attributes": attrs, "observed_at": "2026-11-10T00:00:00+00:00"}

    vm = row("vm", "proxmox", "workload", nics=[{"mac": "BC:24:11:00:00:01", "vlan": 20}])
    client = row("c1", "unifi_network", "client", mac="bc:24:11:00:00:01")
    lan = row("n20", "unifi_network", "network", vlan=20)
    links = derived_links([vm, client, lan])
    assert {(e["source"], e["target"], e["kind"], e["evidence_kind"]) for e in links} == {
        ("vm", "c1", "same_device", "inferred"), ("vm", "n20", "member_of", "inferred")}
    twin = row("c2", "unifi_network", "client", mac="bc:24:11:00:00:01")
    other = row("n20b", "unifi_network", "network", vlan=20)
    assert derived_links([vm, client, twin, lan, other]) == []


def test_firewall_finding_opens_from_evidence_and_resolves_when_fixed(app, client, admin_headers):
    """The rule-based finding follows the stored configuration in both directions."""
    assert "auto:workload-firewall:workload-indexer" in {x["id"] for x in client.get("/api/findings").json()}
    with app.state.session_factory() as db:
        row = db.get(Resource, "workload-indexer")
        row.attributes = {**row.attributes, "firewall_enabled": True,
                          "nics": [{**row.attributes["nics"][0], "firewall": True}]}
        refresh_findings(db)
        db.commit()
        assert db.get(Finding, "auto:workload-firewall:workload-indexer").status == "resolved"
