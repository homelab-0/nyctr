"""Links Nyctr works out between sources. Always labelled inferred, never stored as provider fact.

Sources do not reference each other, so a virtual machine one source hosts and
the same machine another source sees on the network are joined here by matching
hardware address, VLAN tag or address. A match is a reasoned guess and is shown
as one.

Nothing here names a vendor. Any source whose integration provides `compute`
is matched against any source that provides `inventory`, using the neutral
attributes adapters write (`mac`, `ip`, `vlan`, `nics`, `addresses`).
"""

from __future__ import annotations

import hashlib
from typing import Any

from .integrations import registry


def _edge(source: str, target: str, kind: str, basis: str, observed_at) -> dict[str, Any]:
    """Build one inferred relationship with a stable identifier and its stated basis."""
    digest = hashlib.sha256(f"{source}|{kind}|{target}".encode()).hexdigest()[:32]
    return {"id": f"derived:{digest}", "source": source, "target": target, "kind": kind, "provider": "nyctr",
            "evidence_kind": "inferred", "observed_at": observed_at,
            "attributes": {"basis": basis, "meaning": "Worked out by Nyctr from matching values; not reported by a source."}}


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
    return list(edges.values())
