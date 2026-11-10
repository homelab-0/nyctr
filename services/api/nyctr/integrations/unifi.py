"""UniFi Network 11.0.97 integration API inventory/configuration reader.

The API contract's client uplinkDeviceId is observed attachment evidence. A
firewall policy or zone association is configured evidence, never a flow log.
Guest access state and hotspot vouchers are read here; changing them lives in
`actions.py` behind the operator's explicit permission.
"""

from __future__ import annotations

import re
from typing import Any

from . import actions, core
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
from .registry import ConfigField, Provider

ID = "unifi_network"
MAX_GUEST_DETAILS = 40
READS = (
    ("sites:read", "Site discovery"),
    ("devices:read", "Network device inventory"),
    ("clients:read", "Connected client inventory"),
    ("networks:read", "Network configuration"),
    ("firewall_policies:read", "Configured firewall policies"),
    ("guest_access:read", "Guest Wi-Fi access state"),
    ("hotspot_vouchers:read", "Guest passes (hotspot vouchers)"),
    ("wifi_broadcasts:read", "Wi-Fi names and which use the captive portal"),
)


_METHODS = {"VOUCHER": "pass", "API": "console"}


def _guest_authorization(detail: dict[str, Any]) -> dict[str, Any] | None:
    """Translate the documented guest authorisation into neutral fields: method, times and usage."""
    access = detail.get("access")
    grant = access.get("authorization") if isinstance(access, dict) else None
    if not isinstance(grant, dict):
        return None
    method = grant.get("authorizationMethod")
    usage = grant.get("usage") if isinstance(grant.get("usage"), dict) else {}
    return {"method": _METHODS.get(method, "other") if isinstance(method, str) else None,
            "authorized_at": grant.get("authorizedAt"), "expires_at": grant.get("expiresAt"),
            "data_limit_mb": grant.get("dataUsageLimitMBytes"),
            "bytes": usage.get("bytes"), "seconds": usage.get("durationSec")}


def _renamed(row: dict[str, Any], names: dict[str, str]) -> dict[str, Any]:
    """Copy documented fields under the neutral names the core reads."""
    return {neutral: row[field] for field, neutral in names.items() if field in row}


def validate(config: dict[str, Any]) -> dict[str, Any]:
    """Accept the documented base path on an allowed host and an optional site."""
    if set(config) - {"base_url", "site_id"}:
        raise IntegrationError("UniFi supports base_url and optional site_id configuration only.")
    parsed, host = core.validated_host(config.get("base_url"), "UniFi")
    path = parsed.path.rstrip("/")
    local = path == "/proxy/network/integration"
    cloud = bool(re.fullmatch(r"/v1/connector/consoles/[A-Za-z0-9:_-]+/proxy/network/integration", path))
    if not local and not (host == "api.ui.com" and cloud):
        raise IntegrationError("Use the documented UniFi Network integration base path.")
    clean = {"base_url": config["base_url"].rstrip("/")}
    if config.get("site_id"):
        site = config["site_id"]
        if not isinstance(site, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", site):
            raise IntegrationError("Invalid UniFi site identifier.")
        clean["site_id"] = site
    return clean


async def collect_unifi(integration_id: str, config: dict[str, Any], api_key: str) -> Snapshot:
    """Collect source-backed inventory and configured firewall-policy relationships.

    Use explicit uplink and zone references rather than inferring connectivity
    from addresses. Policy associations never create observed firewall blocks
    or claim a successful end-to-end path.
    """
    snapshot = Snapshot(capabilities=[read for read, _label in READS], passes=[])
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
        # Detail reads are capped for the whole collection, not per site, so many sites
        # cannot spend the request budget on guests.
        guest_details = 0
        for site in sites:
            sid = source_id(site.get("id"))
            site_resource = resource(integration_id, ID, "site", sid, site.get("name", sid), now)
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
                    integration_id, ID, kind, remote_id, row.get("name", remote_id), now,
                    site_id=site_resource["id"], evidence_kind="observed",
                    attributes={**selected(row, ("model", "state", "firmwareVersion", "firmwareUpdatable", "features")),
                                **_renamed(row, {"ipAddress": "ip", "macAddress": "mac"})},
                )
                device_map[remote_id] = node["id"]
                snapshot.resources.append(node)
            for row in networks:
                remote_id = source_id(row.get("id"))
                node = resource(
                    integration_id, ID, "network", remote_id, row.get("name", remote_id), now,
                    site_id=site_resource["id"],
                    attributes={**selected(row, ("enabled", "management", "default", "zoneId", "deviceId", "metadata")),
                                **_renamed(row, {"vlanId": "vlan"})},
                )
                network_map[remote_id] = node["id"]
                snapshot.resources.append(node)
                managing_device = device_map.get(row.get("deviceId"))
                if managing_device:
                    snapshot.relationships.append(relationship(
                        integration_id, ID, node["id"], managing_device, "managed_by", now,
                        attributes={"source_field": "network.deviceId"},
                    ))
            for row in clients:
                remote_id = source_id(row.get("id"))
                attributes = {**selected(row, ("type",)), **_renamed(row, {
                    "ipAddress": "ip", "macAddress": "mac", "connectedAt": "connected_at",
                    "uplinkDeviceId": "uplink"})}
                access = row.get("access")
                if isinstance(access, dict) and access.get("type") == "GUEST":
                    attributes["guest"] = {"authorized": access.get("authorized") is True}
                    if guest_details < MAX_GUEST_DETAILS:
                        guest_details += 1
                        try:
                            grant = _guest_authorization(await reader.get(f"{base}/clients/{remote_id}"))
                        except IntegrationError as error:
                            if core.must_stop(error):
                                raise
                            grant = None
                            core.record_gap("unifi_guest_details_unavailable")
                        if grant:
                            attributes["guest"].update(grant)
                    else:
                        core.record_gap("unifi_guest_detail_limit")
                node = resource(
                    integration_id, ID, "client", remote_id, row.get("name", remote_id), now,
                    site_id=site_resource["id"], evidence_kind="observed", attributes=attributes,
                )
                snapshot.resources.append(node)
                uplink = device_map.get(row.get("uplinkDeviceId"))
                if uplink:
                    snapshot.relationships.append(relationship(
                        integration_id, ID, node["id"], uplink, "connects_to", now,
                        evidence_kind="observed",
                        attributes={"source_field": "client.uplinkDeviceId", "meaning": "Attachment; not proof of end-to-end reachability."},
                    ))
            for row in policies:
                remote_id = source_id(row.get("id"))
                node = resource(
                    integration_id, ID, "policy", remote_id, row.get("name", remote_id), now,
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
                                integration_id, ID, network_map[network["id"]], node["id"],
                                f"{side}_zone_policy", now,
                                attributes={"source_field": f"policy.{side}.zoneId", "meaning": "Configured zone association; full traffic filters and rule order still apply."},
                            ))
            try:
                vouchers = await actions.unifi_list_vouchers(reader, sid)
                if snapshot.passes is not None:
                    snapshot.passes.extend(vouchers)
                core.record_capability("hotspot_vouchers:read")
            except IntegrationError as error:
                if core.must_stop(error):
                    raise
                core.record_gap("unifi_vouchers_unavailable")
                # Not read for one site means the list is incomplete: leave stored passes alone.
                snapshot.passes = None
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
                if core.must_stop(error):
                    raise
                core.record_gap("unifi_wifi_unavailable")
                snapshot.capabilities = [x for x in snapshot.capabilities if x != "wifi_broadcasts:read"]
            # Site containment is a collection boundary, not a forwarding path.
            for node in snapshot.resources:
                if node["id"] != site_resource["id"] and node["site_id"] == site_resource["id"]:
                    snapshot.relationships.append(relationship(
                        integration_id, ID, site_resource["id"], node["id"], "contains", now,
                        attributes={"meaning": "Managed in this site."},
                    ))
    snapshot.resources = list({node["id"]: node for node in snapshot.resources}.values())
    snapshot.relationships = list({edge["id"]: edge for edge in snapshot.relationships}.values())
    if sites:
        for capability in ("devices:read", "networks:read", "clients:read", "firewall_policies:read",
                           "guest_access:read"):
            core.record_capability(capability)
    return snapshot


PROVIDER = Provider(
    id=ID, name="UniFi Network", letter="U", tone="blue",
    summary="Gateways, switches, access points, clients, networks, firewall rules and guest Wi-Fi.",
    secret_hint="A UniFi Network API key. Read access is enough unless you allow changes.",
    fields=(
        ConfigField("base_url", "Console address", "The integration path on your console, over HTTPS.",
                    "https://unifi.example.net/proxy/network/integration", "url"),
        ConfigField("site_id", "Site", "Leave empty to read every site the key can see (up to 16).",
                    "", "text", False),
    ),
    reads=READS,
    provides=frozenset({"inventory", "guest.devices", "guest.passes", "guest.control"}),
    limitations=(
        ("firewall_events:read", "Observed firewall events",
         "This adapter reads configured policies; a UniFi firewall-event receiver is not implemented."),
        ("reachability:verify", "End-to-end reachability",
         "Inventory and configured policy relationships do not prove a successful network path."),
    ),
    gaps=(
        ("firewall_events", "Firewall-event coverage is not implemented",
         "The current UniFi adapter reads inventory and configured policies. It does not collect observed firewall blocks."),
        ("reachability", "A configured relationship is not a traffic result",
         "Rule associations and device attachment do not prove end-to-end reachability or effective firewall posture."),
        ("user_attribution", "Device inventory does not establish user ownership",
         "Members still require explicit device assignment and reliable event-time attribution before observations can appear in their inbox."),
    ),
    gap_notes={
        "unifi_vouchers_unavailable": (
            "Guest passes could not be read",
            "The hotspot voucher list was not available to this key or site. Guest pass tracking is incomplete."),
        "unifi_wifi_unavailable": (
            "Wi-Fi names could not be read",
            "Nyctr cannot show which Wi-Fi names sit behind UniFi's captive portal."),
        "unifi_guest_details_unavailable": (
            "Guest authorisation details were not returned",
            "Some guest devices are listed without their authorisation time, expiry or usage."),
        "unifi_guest_detail_limit": (
            "More guests than one collection reads in detail",
            "Only the first 40 guest devices carry authorisation details in each collection."),
        "unifi_no_visible_sites": (
            "No sites were visible to the credential",
            "Site discovery returned an empty list. Device, network, client, and policy reads were not exercised."),
    },
    validate=validate, collect=collect_unifi, scope=lambda config: config.get("site_id"),
    issue_pass=actions.unifi_create_voucher, end_pass=actions.unifi_delete_voucher,
    guest_access=actions.unifi_set_guest_access,
)
