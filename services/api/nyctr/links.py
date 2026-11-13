"""Links Nyctr works out between sources. Always labelled inferred, never stored as provider fact.

Sources do not reference each other, so a virtual machine one source hosts and
the same machine another source sees on the network are joined here by matching
hardware address, VLAN tag or address. A match is a reasoned guess and is shown
as one.

A source may also report a device's address and each network's range without
saying which network the device is on. The device is placed on a network here
when its address falls inside the ranges of exactly one network from the same
connection and site. If a network of that site which a gateway or switch manages
has no collected range, the picture is incomplete and nothing in the site is
placed. A network the source says its gateway manages is linked to that site's
gateway when there is exactly one.

Nothing here names a vendor. Any source whose integration provides `compute`
is matched against any source that provides `inventory`, using the neutral
attributes adapters write (`mac`, `ip`, `vlan`, `nics`, `addresses`, `subnets`,
`managed_by`).
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Any

from .integrations import registry


def _edge(source: str, target: str, kind: str, basis: str, observed_at) -> dict[str, Any]:
    """Build one inferred relationship with a stable identifier and its stated basis."""
    digest = hashlib.sha256(f"{source}|{kind}|{target}".encode()).hexdigest()[:32]
    return {"id": f"derived:{digest}", "source": source, "target": target, "kind": kind, "provider": "nyctr",
            "evidence_kind": "inferred", "observed_at": observed_at,
            "attributes": {"basis": basis, "meaning": "Worked out by Nyctr from matching values; not reported by a source."}}


def _placements(resources: list, get) -> list[dict[str, Any]]:
    """Place clients on networks by address range, and gateway-managed networks on the one gateway."""
    scopes: dict[tuple, dict[str, list]] = {}
    for row in resources:
        attrs = get(row, "attributes") or {}
        if not registry.provides(get(row, "provider"), "inventory") or attrs.get("missing_from_latest_snapshot"):
            continue
        site = row.get("site_id") if isinstance(row, dict) else row.site_id
        scopes.setdefault((attrs.get("integration_id"), site), {}).setdefault(get(row, "kind"), []).append(row)
    edges = []
    for scope in scopes.values():
        ranges = []
        complete = True
        for network in scope.get("network", []):
            attrs = get(network, "attributes") or {}
            known = len(ranges)
            for subnet in attrs.get("subnets") or []:
                try:
                    ranges.append((ipaddress.ip_network(subnet if isinstance(subnet, str) else ""), network))
                except ValueError:
                    continue
            # A managed network has a range. If it was not collected, a device's address could
            # belong there, so "inside one range only" cannot be claimed for this site.
            if attrs.get("managed_by") in {"gateway", "switch"} and len(ranges) == known:
                complete = False
            gateways = scope.get("gateway", [])
            if attrs.get("managed_by") == "gateway" and len(gateways) == 1:
                edges.append(_edge(get(network, "id"), get(gateways[0], "id"), "managed_by",
                                   "Worked out by Nyctr: the source says its gateway manages this network, "
                                   "and this is the only gateway in the site", get(network, "observed_at")))
        for client in scope.get("client", []) if ranges and complete else []:
            try:
                ip = (get(client, "attributes") or {}).get("ip")
                address = ipaddress.ip_address(ip if isinstance(ip, str) else "")
            except ValueError:
                continue
            holding = {get(network, "id"): subnet for subnet, network in ranges
                       if address.version == subnet.version and address in subnet}
            if len(holding) == 1:
                target, subnet = next(iter(holding.items()))
                edges.append(_edge(get(client, "id"), target, "member_of",
                                   f"Worked out by Nyctr: address {address} is inside {subnet}, "
                                   "the range of this network only", get(client, "observed_at")))
    return edges


def derived_links(resources: list) -> list[dict[str, Any]]:
    """Join hosted workloads and hosts to network clients and networks by matching values.

    Accepts ORM rows or dictionaries. Ambiguous matches (a value shared by more
    than one candidate) produce no link.
    """
    def get(row, key):
        return row[key] if isinstance(row, dict) else getattr(row, key)

    by_mac: dict[str, list] = {}
    by_ip: dict[str, list] = {}
    by_vlan: dict[int, list] = {}
    for row in resources:
        attrs = get(row, "attributes") or {}
        if not registry.provides(get(row, "provider"), "inventory"):
            continue
        if get(row, "kind") == "client":
            if isinstance(attrs.get("mac"), str):
                by_mac.setdefault(attrs["mac"].lower(), []).append(row)
            if isinstance(attrs.get("ip"), str):
                by_ip.setdefault(attrs["ip"], []).append(row)
        elif get(row, "kind") == "network":
            if isinstance(attrs.get("vlan"), int):
                by_vlan.setdefault(attrs["vlan"], []).append(row)
    edges: dict[str, dict[str, Any]] = {}
    for row in resources:
        if not registry.provides(get(row, "provider"), "compute"):
            continue
        attrs = get(row, "attributes") or {}
        when = get(row, "observed_at")
        here = registry.name_of(get(row, "provider"))
        if get(row, "kind") == "workload":
            for nic in attrs.get("nics") or []:
                if not isinstance(nic, dict):
                    continue
                clients = by_mac.get(str(nic.get("mac") or "").lower(), [])
                if len(clients) == 1:
                    there = registry.name_of(get(clients[0], "provider"))
                    edge = _edge(get(row, "id"), get(clients[0], "id"), "same_device",
                                 f"Same hardware address in {here} and {there}", when)
                    edges[edge["id"]] = edge
                networks = by_vlan.get(nic.get("vlan"), []) if isinstance(nic.get("vlan"), int) else []
                if len(networks) == 1:
                    edge = _edge(get(row, "id"), get(networks[0], "id"), "member_of",
                                 f"Network card tagged VLAN {nic['vlan']}", when)
                    edges[edge["id"]] = edge
        elif get(row, "kind") == "host":
            for address in attrs.get("addresses") or []:
                clients = by_ip.get(address, []) if isinstance(address, str) else []
                if len(clients) == 1:
                    there = registry.name_of(get(clients[0], "provider"))
                    edge = _edge(get(row, "id"), get(clients[0], "id"), "same_device",
                                 f"Same address in {here} and {there}", when)
                    edges[edge["id"]] = edge
    for edge in _placements(resources, get):
        edges[edge["id"]] = edge
    return list(edges.values())
