"""UniFi Network 11.0.97 integration API inventory/configuration reader.

The API contract's client uplinkDeviceId is observed attachment evidence. A
firewall policy or zone association is configured evidence, never a flow log.
"""

from __future__ import annotations

from typing import Any

from . import core
from .core import (
    IntegrationError,
    ReadClient,
    Snapshot,
    offset_pages,
    relationship,
    resource,
    selected,
    source_id,
)

PROVIDER = "unifi_network"


async def collect_unifi(integration_id: str, config: dict[str, Any], api_key: str) -> Snapshot:
    from . import capabilities_for

    snapshot = Snapshot(capabilities=capabilities_for(PROVIDER))
    now = core.iso(core.utc_now())
    async with core.make_http_client(api_key) as client:
        reader = ReadClient(client, config["base_url"])
        sites = await offset_pages(reader, "/v1/sites")
        if config.get("site_id"):
            sites = [site for site in sites if site.get("id") == config["site_id"]]
            if not sites:
                raise IntegrationError("The configured site is not visible to this UniFi API key.")
        if len(sites) > 16:
            raise IntegrationError("More than 16 sites are visible; configure a specific site_id.")
        for site in sites:
            sid = source_id(site.get("id"))
            site_resource = resource(integration_id, PROVIDER, "site", sid, site.get("name", sid), now)
            site_resource["site_id"] = site_resource["id"]
            snapshot.resources.append(site_resource)
            base = f"/v1/sites/{sid}"
            # Sequential, bounded reads avoid saturating small self-hosted gateways.
            devices = await offset_pages(reader, base + "/devices")
            networks = await offset_pages(reader, base + "/networks")
            clients = await offset_pages(reader, base + "/clients")
            policies = await offset_pages(reader, base + "/firewall/policies")
            device_map: dict[str, str] = {}
            network_map: dict[str, str] = {}
            for row in devices:
                remote_id = source_id(row.get("id"))
                features = row.get("features", [])
                if not isinstance(features, list):
                    raise IntegrationError("UniFi returned invalid device capabilities.")
                if not any(feature in features for feature in ("gateway", "accessPoint", "switching")):
                    raise IntegrationError("UniFi returned a device with an unsupported capability classification.")
                kind = "gateway" if "gateway" in features else "access_point" if "accessPoint" in features else "switch"
                node = resource(
                    integration_id, PROVIDER, kind, remote_id, row.get("name", remote_id), now,
                    site_id=site_resource["id"], evidence_kind="observed",
                    attributes=selected(row, ("model", "state", "ipAddress", "macAddress", "firmwareVersion", "firmwareUpdatable", "features")),
                )
                device_map[remote_id] = node["id"]
                snapshot.resources.append(node)
            for row in networks:
                remote_id = source_id(row.get("id"))
                node = resource(
                    integration_id, PROVIDER, "network", remote_id, row.get("name", remote_id), now,
                    site_id=site_resource["id"],
                    attributes=selected(row, ("vlanId", "enabled", "management", "default", "zoneId", "deviceId", "metadata")),
                )
                network_map[remote_id] = node["id"]
                snapshot.resources.append(node)
                managing_device = device_map.get(row.get("deviceId"))
                if managing_device:
                    snapshot.relationships.append(relationship(
                        integration_id, PROVIDER, node["id"], managing_device, "managed_by", now,
                        attributes={"source_field": "network.deviceId"},
                    ))
            for row in clients:
                remote_id = source_id(row.get("id"))
                node = resource(
                    integration_id, PROVIDER, "client", remote_id, row.get("name", remote_id), now,
                    site_id=site_resource["id"], evidence_kind="observed",
                    attributes=selected(row, ("type", "ipAddress", "macAddress", "connectedAt", "uplinkDeviceId")),
                )
                snapshot.resources.append(node)
                uplink = device_map.get(row.get("uplinkDeviceId"))
                if uplink:
                    snapshot.relationships.append(relationship(
                        integration_id, PROVIDER, node["id"], uplink, "connects_to", now,
                        evidence_kind="observed",
                        attributes={"source_field": "client.uplinkDeviceId", "meaning": "Attachment; not proof of end-to-end reachability."},
                    ))
            for row in policies:
                remote_id = source_id(row.get("id"))
                node = resource(
                    integration_id, PROVIDER, "policy", remote_id, row.get("name", remote_id), now,
                    site_id=site_resource["id"],
                    attributes=selected(row, ("enabled", "index", "action", "source", "destination", "ipProtocolScope", "loggingEnabled", "metadata")),
                )
                snapshot.resources.append(node)
                for side in ("source", "destination"):
                    selector = row.get(side, {})
                    if not isinstance(selector, dict):
                        raise IntegrationError("UniFi returned an invalid policy selector.")
                    zone = selector.get("zoneId")
                    for network in networks:
                        if zone and network.get("zoneId") == zone:
                            snapshot.relationships.append(relationship(
                                integration_id, PROVIDER, network_map[network["id"]], node["id"],
                                f"{side}_zone_policy", now,
                                attributes={"source_field": f"policy.{side}.zoneId", "meaning": "Configured zone association; full traffic filters and rule order still apply."},
                            ))
            # Site containment is a collection boundary, not a forwarding path.
            for node in snapshot.resources:
                if node["id"] != site_resource["id"] and node["site_id"] == site_resource["id"]:
                    snapshot.relationships.append(relationship(
                        integration_id, PROVIDER, site_resource["id"], node["id"], "contains", now,
                        attributes={"meaning": "Managed in this site."},
                    ))
    snapshot.resources = list({node["id"]: node for node in snapshot.resources}.values())
    snapshot.relationships = list({edge["id"]: edge for edge in snapshot.relationships}.values())
    return snapshot
