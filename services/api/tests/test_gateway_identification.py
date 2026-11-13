"""Which device is the gateway: the source's own word first, then two labelled deductions, otherwise nobody."""

import httpx
import pytest
from test_device_networks import BASE, gear, home, links, named, network, run

from nyctr.links import derived_links


def unlisted(**changes):
    """A site whose gateway is listed with switching only and holds the LAN's gateway address."""
    return home(**{"devices": [gear("gw", "10.0.1.1"), gear("sw", "10.0.1.2", above="gw"),
                               gear("ap", "10.0.1.3", ("accessPoint",), above="sw")], **changes})


def outside(**changes):
    """The production shape: the gateway reports its internet-side address, all other gear a network one."""
    return home(**{"devices": [gear("gw", "203.0.113.9"), gear("sw", "10.0.1.2", above="gw"),
                               gear("ap", "10.0.30.3", ("accessPoint",), above="sw")], **changes})


def test_gateway_holding_a_gateway_address_is_filed_in_place_with_its_basis(monkeypatch):
    """The one device whose address is a gateway-managed network's gateway address is the gateway."""
    snapshot, evidence, _calls = run(monkeypatch, unlisted())
    nodes = named(snapshot)
    assert [nodes[n]["kind"] for n in ("gw", "sw", "ap")] == ["gateway", "switch", "access_point"]
    # Refiled in place: the identifier is the one earlier collections stored, and the reason is kept.
    assert nodes["gw"]["id"] == "u:switch:gw" and nodes["gw"]["attributes"]["kind_basis"] == "gateway_address"
    assert "kind_basis" not in nodes["sw"]["attributes"] and evidence.gaps == set()
    assert links(derived_links(snapshot.resources), "managed_by") == {("lan", "gw", "inferred"), ("iot", "gw", "inferred")}


def test_gateway_outside_every_range_at_the_top_of_the_gear_is_filed_as_nyctrs_deduction(monkeypatch):
    """Every gateway-managed range collected, one gear outside them all, nothing above it and gear below it."""
    snapshot, evidence, _calls = run(monkeypatch, outside())
    nodes = named(snapshot)
    assert nodes["gw"]["kind"] == "gateway" and nodes["gw"]["id"] == "u:switch:gw"
    # Its own basis: never the same as the source naming it, or as holding a gateway address.
    assert nodes["gw"]["attributes"]["kind_basis"] == "outside_network_ranges"
    assert [nodes[n]["kind"] for n in ("sw", "ap")] == ["switch", "access_point"] and evidence.gaps == set()
    assert links(derived_links(snapshot.resources), "managed_by") == {("lan", "gw", "inferred"), ("iot", "gw", "inferred")}


def _no_uplink_read(path):
    """Refuse the candidate's own detail read, so whether anything is above it is unknown."""
    return httpx.Response(403) if path == f"{BASE}/devices/gw" else None


def _no_range_read(path):
    """Refuse one gateway-managed network's detail read."""
    return httpx.Response(403) if path == f"{BASE}/networks/iot" else None


@pytest.mark.parametrize("change, fault, gap", [
    ({"devices": [gear("gw", "203.0.113.9"), gear("sw", "198.51.100.7", above="gw")]}, None, True),
    ({"devices": [gear("gw", "203.0.113.9"), ({"id": "sw", "name": "sw", "features": ["switching"]}, {"id": "sw"})]},
     None, True),
    ({"devices": [gear("gw", "203.0.113.9", above="sw"), gear("sw", "10.0.1.2")]}, None, True),
    ({"devices": [gear("ap", "203.0.113.9", ("accessPoint",))]}, None, True),
    ({"devices": [gear("gw", "203.0.113.9"), gear("sw", "2001:db8::2", above="gw")]}, None, True),
    ({"devices": [gear("gw", "2001:db8::1"), gear("sw", "10.0.1.2", above="gw")]}, None, True),
    ({"devices": [gear("core", "10.0.1.2"), gear("ap", "10.0.1.3", ("accessPoint",), above="core"),
                  gear("old", "192.168.99.5")]}, None, True),
    ({}, _no_uplink_read, True),
    ({}, _no_range_read, True),
    ({"networks": [network("lan", 1, "GATEWAY", "10.0.1.1"), network("iot", 20, "GATEWAY")]}, None, True),
    ({"devices": [gear("gw", "10.0.1.1"), gear("twin", "10.0.1.1")]}, None, True),
    ({"networks": [network("lab", 30, "SWITCH", "10.0.1.1", deviceId="sw"), network("bare", 40, "UNMANAGED")]},
     None, False),
], ids=["two-gear-outside", "gear-with-no-address", "candidate-has-an-uplink", "one-device-site",
        "other-gear-reports-ipv6", "candidate-reports-ipv6", "unplugged-switch-nothing-attached",
        "candidate-uplink-not-read",
        "gateway-managed-range-refused", "gateway-managed-range-absent", "two-hold-the-gateway-address",
        "no-gateway-managed-network"])
def test_without_sound_evidence_nothing_is_filed_as_a_gateway(monkeypatch, change, fault, gap):
    """Each missing condition files nothing and records the gap; a site with no gateway-managed network has no gap."""
    snapshot, evidence, _calls = run(monkeypatch, outside(**change), fault)
    assert all(node["kind"] != "gateway" and "kind_basis" not in node["attributes"] for node in snapshot.resources)
    assert ("unifi_gateway_not_identified" in evidence.gaps) is gap
    assert not links(derived_links(snapshot.resources), "managed_by")


def test_the_address_match_is_tried_before_position(monkeypatch):
    """A device holding a gateway address is filed on that, even when another sits outside every range."""
    snapshot, _evidence, _calls = run(monkeypatch, unlisted(devices=[
        gear("gw", "10.0.1.1"), gear("modem", "203.0.113.9"), gear("sw", "10.0.1.2", above="modem")]))
    nodes = named(snapshot)
    assert nodes["gw"]["attributes"]["kind_basis"] == "gateway_address" and nodes["modem"]["kind"] == "switch"


def test_a_gateway_the_source_lists_as_one_needs_no_other_evidence(monkeypatch):
    """The feature list still files a gateway, and an address match does not add a second one."""
    snapshot, evidence, _calls = run(monkeypatch, home(devices=[
        gear("gw", "198.51.100.4", ("gateway", "switching")), gear("sw", "10.0.1.1", above="gw")]))
    assert named(snapshot)["gw"]["id"] == "u:gateway:gw" and named(snapshot)["sw"]["kind"] == "switch"
    assert "kind_basis" not in named(snapshot)["gw"]["attributes"] and evidence.gaps == set()


@pytest.mark.parametrize("kind, kept", [("devices", True), ("networks", False)])
def test_a_refused_detail_read_never_turns_into_a_guess(monkeypatch, kind, kept):
    """Without uplinks the address match still holds; without ranges nothing is filed and the gap is recorded."""
    snapshot, evidence, _calls = run(
        monkeypatch, unlisted(), lambda path: httpx.Response(403) if path.startswith(f"{BASE}/{kind}/") else None)
    assert (named(snapshot)["gw"]["kind"] == "gateway") is kept
    assert ("unifi_gateway_not_identified" in evidence.gaps) is not kept
    # The production shape needs the uplinks: with them refused, position files nothing.
    snapshot, evidence, _calls = run(
        monkeypatch, outside(), lambda path: httpx.Response(403) if path.startswith(f"{BASE}/{kind}/") else None)
    assert named(snapshot)["gw"]["kind"] == "switch" and "unifi_gateway_not_identified" in evidence.gaps
