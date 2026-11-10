"""Proxmox VE inventory and virtual-network reader. Experimental.

Reads nodes, bridges, virtual machines and containers, each guest's network
cards (bridge, VLAN tag, hardware address, per-card firewall flag) and the
firewall switches at cluster and guest level. Written against the documented
`/api2/json` paths and an API token; it has not been run against a cluster by
this project. Everything here is configured evidence: a card attached to a
bridge does not prove that traffic flows.
"""

from __future__ import annotations

import re
from typing import Any

from . import core
from .core import IntegrationError, ReadClient, Snapshot, relationship, resource, source_id

PROVIDER = "proxmox"
MAX_GUESTS = 48
_TOKEN = re.compile(r"[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+=[A-Za-z0-9-]{8,128}")
_MAC = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,120}")


def _list(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Require the documented {"data": [...]} envelope of objects."""
    rows = payload.get("data")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows) or len(rows) > 5000:
        raise IntegrationError("Proxmox returned an invalid list response.")
    return rows


def _object(payload: dict[str, Any]) -> dict[str, Any]:
    """Require the documented {"data": {...}} envelope."""
    data = payload.get("data")
    if not isinstance(data, dict):
        raise IntegrationError("Proxmox returned an invalid object response.")
    return data


def _name(value: Any) -> str:
    """Validate a node, bridge or guest identifier before it is used in a path or an ID."""
    text = str(value) if isinstance(value, (str, int)) and not isinstance(value, bool) else ""
    if not _NAME.fullmatch(text):
        raise IntegrationError("Proxmox returned an invalid identifier.")
    return text


def parse_nic(value: Any) -> dict[str, Any] | None:
    """Parse one `netN` setting such as `virtio=BC:24:11:..,bridge=vmbr0,tag=66,firewall=1`.

    Returns only the fields Nyctr reasons about. A card without a bridge is not
    attached to anything Nyctr can place and is skipped.
    """
    if not isinstance(value, str) or len(value) > 512:
        return None
    fields: dict[str, str] = {}
    mac = None
    for part in value.split(","):
        key, _, item = part.partition("=")
        fields[key.strip()] = item.strip()
        if _MAC.fullmatch(item.strip()) and (key.strip() == "hwaddr" or mac is None):
            mac = item.strip().lower()
    bridge = fields.get("bridge", "")
    if not _NAME.fullmatch(bridge):
        return None
    tag = fields.get("tag", "")
    return {"bridge": bridge, "mac": mac, "vlan": int(tag) if tag.isdigit() and 1 <= int(tag) <= 4094 else None,
            "firewall": fields.get("firewall") == "1", "link_down": fields.get("link_down") == "1"}


async def _optional(reader: ReadClient, path: str, gap: str) -> dict[str, Any] | None:
    """Read a path that some installations do not serve; record the gap instead of failing collection."""
    try:
        return await reader.get(path)
    except IntegrationError as error:
        if core.must_stop(error) or error.category == "authentication":
            raise
        core.record_gap(gap)
        return None


async def collect_proxmox(integration_id: str, config: dict[str, Any], api_key: str) -> Snapshot:
    """Collect nodes, bridges, guests and their network cards as configured evidence."""
    from . import capabilities_for

    if not _TOKEN.fullmatch(api_key or ""):
        raise IntegrationError("The Proxmox secret must be an API token in the form user@realm!name=value.",
                               category="secret")
    snapshot = Snapshot(capabilities=capabilities_for(PROVIDER))
    now = core.iso(core.utc_now())
    async with core.make_http_client(api_key, authorization_scheme="PVEAPIToken") as client:
        reader = ReadClient(client, config["base_url"])
        entries = _list(await reader.get("/cluster/resources"))
        reader.count_records(len(entries))
        nodes = sorted({_name(row["node"]) for row in entries if row.get("type") == "node" and row.get("node")})
        core.record_capability("nodes:read")
        if not nodes:
            core.record_gap("proxmox_no_visible_nodes")
        cluster_fw = await _optional(reader, "/cluster/firewall/options", "proxmox_firewall_options_unavailable")
        cluster_enabled = bool(_object(cluster_fw).get("enable")) if cluster_fw else None
        node_ids: dict[str, str] = {}
        bridge_ids: dict[tuple[str, str], str] = {}
        for node in nodes:
            status = next((row.get("status") for row in entries
                           if row.get("type") == "node" and row.get("node") == node), None)
            host = resource(integration_id, PROVIDER, "host", node, node, now, evidence_kind="observed",
                            attributes={"status": status, "cluster_firewall_enabled": cluster_enabled})
            node_ids[node] = host["id"]
            snapshot.resources.append(host)
            for row in _list(await reader.get(f"/nodes/{node}/network")):
                if row.get("type") not in {"bridge", "OVSBridge"} or not row.get("iface"):
                    continue
                iface = _name(row["iface"])
                bridge = resource(integration_id, PROVIDER, "bridge", f"{node}.{iface}", f"{iface} on {node}", now,
                                  attributes={"iface": iface, "node": node, "active": bool(row.get("active")),
                                              "vlan_aware": bool(row.get("bridge_vlan_aware")),
                                              "ports": str(row.get("bridge_ports") or "")[:200],
                                              "cidr": str(row.get("cidr") or "")[:64]})
                address = str(row.get("cidr") or row.get("address") or "").split("/")[0]
                if address:
                    host["attributes"].setdefault("addresses", []).append(address[:64])
                bridge_ids[(node, iface)] = bridge["id"]
                snapshot.resources.append(bridge)
                snapshot.relationships.append(relationship(
                    integration_id, PROVIDER, bridge["id"], host["id"], "hosted_by", now,
                    attributes={"meaning": "Virtual switch defined on this node."}))
        core.record_capability("bridges:read")
        guests = [row for row in entries if row.get("type") in {"qemu", "lxc"} and row.get("node") in node_ids]
        if len(guests) > MAX_GUESTS:
            core.record_gap("proxmox_guest_limit")
            guests = sorted(guests, key=lambda row: str(row.get("vmid")))[:MAX_GUESTS]
        for row in guests:
            node, kind, vmid = row["node"], row["type"], _name(row.get("vmid"))
            base = f"/nodes/{node}/{kind}/{vmid}"
            settings = _object(await reader.get(base + "/config"))
            options = await _optional(reader, base + "/firewall/options", "proxmox_firewall_options_unavailable")
            guest_fw = bool(_object(options).get("enable")) if options else None
            nics = [nic for key, value in sorted(settings.items())
                    if re.fullmatch(r"net\d{1,2}", key) and (nic := parse_nic(value))]
            label = str(row.get("name") or settings.get("name") or settings.get("hostname") or f"{kind} {vmid}")
            node_resource = resource(
                integration_id, PROVIDER, "workload", f"{kind}.{vmid}", label, now, evidence_kind="observed",
                attributes={"vmid": vmid, "type": "vm" if kind == "qemu" else "container", "node": node,
                            "status": row.get("status"), "nics": nics, "firewall_enabled": guest_fw,
                            "cluster_firewall_enabled": cluster_enabled})
            snapshot.resources.append(node_resource)
            snapshot.relationships.append(relationship(
                integration_id, PROVIDER, node_resource["id"], node_ids[node], "hosted_by", now,
                evidence_kind="observed"))
            for nic in nics:
                target = bridge_ids.get((node, nic["bridge"]))
                if target:
                    snapshot.relationships.append(relationship(
                        integration_id, PROVIDER, node_resource["id"], target, "connects_to", now,
                        attributes={"vlan": nic["vlan"], "firewall": nic["firewall"],
                                    "meaning": "Network card attached to this bridge; not proof of traffic."}))
        core.record_capability("guests:read")
        core.record_capability("guest_network:read")
        if cluster_fw is not None:
            core.record_capability("firewall_options:read")
    snapshot.resources = list({node["id"]: node for node in snapshot.resources}.values())
    snapshot.relationships = list({edge["id"]: edge for edge in snapshot.relationships}.values())
    for node in snapshot.resources:
        source_id(node["source_id"])
    return snapshot
