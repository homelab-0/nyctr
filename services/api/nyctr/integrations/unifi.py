"""UniFi Network 11.0.97 integration API inventory/configuration reader.

The API contract's client uplinkDeviceId is observed attachment evidence. A
firewall policy or zone association is configured evidence, never a flow log.
Guest access state and hotspot vouchers are read here; changing them lives in
`actions.py` behind the operator's explicit permission.
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
MAX_GUEST_DETAILS = 40


def _guest_authorization(detail: dict[str, Any]) -> dict[str, Any] | None:
    """Keep the documented guest-authorization fields: method, times and usage counters."""
    access = detail.get("access")
    grant = access.get("authorization") if isinstance(access, dict) else None
    if not isinstance(grant, dict):
        return None
    kept = selected(grant, ("authorizationMethod", "authorizedAt", "expiresAt", "dataUsageLimitMBytes"))
    usage = grant.get("usage")
    if isinstance(usage, dict):
        kept["usage"] = selected(usage, ("bytes", "rxBytes", "txBytes", "durationSec"))
    return kept


async def collect_unifi(integration_id: str, config: dict[str, Any], api_key: str) -> Snapshot:
    """Collect source-backed inventory and configured firewall-policy relationships.

    Use explicit uplink and zone references rather than inferring connectivity
    from addresses. Policy associations never create observed firewall blocks
    or claim a successful end-to-end path.
    """
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
        # Validate the site namespace before calling discovery a verified capability.
        for site in sites:
            source_id(site.get("id"))
        core.record_capability("sites:read")
        if not sites:
            core.record_gap("unifi_no_visible_sites")
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
            guest_details = 0
            for row in clients:
                remote_id = source_id(row.get("id"))
                attributes = selected(row, ("type", "ipAddress", "macAddress", "connectedAt", "uplinkDeviceId"))
                access = row.get("access")
                if isinstance(access, dict) and access.get("type") == "GUEST":
                    attributes["access_type"] = "GUEST"
                    attributes["guest_authorized"] = access.get("authorized") is True
                    if guest_details < MAX_GUEST_DETAILS:
                        guest_details += 1
                        try:
                            grant = _guest_authorization(await reader.get(f"{base}/clients/{remote_id}"))
                        except IntegrationError as error:
                            if error.category in {"tls", "transport", "timeout"}:
                                raise
                            grant = None
                            core.record_gap("unifi_guest_details_unavailable")
                        if grant:
                            attributes["guest_authorization"] = grant
                    else:
                        core.record_gap("unifi_guest_detail_limit")
                node = resource(
                    integration_id, PROVIDER, "client", remote_id, row.get("name", remote_id), now,
                    site_id=site_resource["id"], evidence_kind="observed", attributes=attributes,
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
            try:
                from .actions import unifi_list_vouchers

                for voucher in await unifi_list_vouchers(reader, sid):
                    snapshot.vouchers.append({**voucher, "site": sid})
                core.record_capability("hotspot_vouchers:read")
            except IntegrationError as error:
                if error.category in {"tls", "transport", "timeout"}:
                    raise
                core.record_gap("unifi_vouchers_unavailable")
                snapshot.capabilities = [x for x in snapshot.capabilities if x != "hotspot_vouchers:read"]
            try:
                # Which Wi-Fi names exist and which sit behind UniFi's captive portal. Nyctr
                # reads this to show how guests get on; it never serves that portal itself.
                wifi = []
                for row in await offset_pages(reader, f"{base}/wifi/broadcasts"):
                    hotspot = row.get("hotspotConfiguration")
                    network = row.get("network")
                    wifi.append({
                        "name": str(row.get("name") or "")[:64], "enabled": row.get("enabled") is True,
                        "captive_portal": isinstance(hotspot, dict) and hotspot.get("type") == "CAPTIVE_PORTAL",
                        "network_id": network.get("networkId") if isinstance(network, dict)
                        and isinstance(network.get("networkId"), str) else None})
                site_resource["attributes"] = {**site_resource["attributes"], "wifi": wifi[:64]}
                core.record_capability("wifi_broadcasts:read")
            except IntegrationError as error:
                if error.category in {"tls", "transport", "timeout"}:
                    raise
                core.record_gap("unifi_wifi_unavailable")
                snapshot.capabilities = [x for x in snapshot.capabilities if x != "wifi_broadcasts:read"]
            # Site containment is a collection boundary, not a forwarding path.
            for node in snapshot.resources:
                if node["id"] != site_resource["id"] and node["site_id"] == site_resource["id"]:
                    snapshot.relationships.append(relationship(
                        integration_id, PROVIDER, site_resource["id"], node["id"], "contains", now,
                        attributes={"meaning": "Managed in this site."},
                    ))
    snapshot.resources = list({node["id"]: node for node in snapshot.resources}.values())
    snapshot.relationships = list({edge["id"]: edge for edge in snapshot.relationships}.values())
    if sites:
        for capability in ("devices:read", "networks:read", "clients:read", "firewall_policies:read",
                           "guest_access:read"):
            core.record_capability(capability)
    return snapshot
