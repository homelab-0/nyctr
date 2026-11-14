"""UniFi Network 11.0.97 integration API inventory/configuration reader.

The API contract's client uplinkDeviceId is observed attachment evidence. A
firewall policy or zone association is configured evidence, never a flow log.
Guest access state and hotspot vouchers are read here; changing them lives in
`actions.py` behind the operator's explicit permission.

A network's address range and a device's uplink come from one detail read each.
A device is filed as the gateway on the first of three kinds of evidence: the
source lists it with that feature; its own address is the gateway address the
source gives for a network it says the gateway manages; or, with every
gateway-managed range collected, it is the only equipment whose address is
outside every range, the source reports nothing above it, and other equipment reports
it as its uplink. The last two are
Nyctr's deduction and are recorded as such in `kind_basis`. Nothing else makes
a gateway. Which network a client is on is never stated by this source;
`nyctr.links` works that out at read time.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

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
# The vendor's Site Manager API description limits its cloud pass-through to 100 requests
# a minute for each console. Through that address Nyctr's reads are paced to this many in
# any 60 seconds for one console, whatever they are for. The four held back are for the
# changes Nyctr may make there (a guest pass, letting a guest on), which are not paced.
CLOUD_HOST = "api.ui.com"
CLOUD_PACE = 96
_CLOUD_PATH = re.compile(r"/v1/connector/consoles/([A-Za-z0-9:_-]+)/proxy/network/integration")
# The optional per-network and per-device reads stop while the whole collection is still
# under this many requests, leaving room for the reads that must follow. A collection
# whose lists each fit one page therefore fits one minute of the cloud limit and never waits.
REQUEST_CEILING = 96
_MANAGERS = {"GATEWAY": "gateway", "SWITCH": "switch", "UNMANAGED": "unmanaged"}
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


def _network_addresses(detail: dict[str, Any]) -> dict[str, Any]:
    """Read a network's configured IPv4 gateway address and ranges, rejecting anything malformed."""
    ipv4 = detail.get("ipv4Configuration")
    if ipv4 is None:
        return {}
    extra = ipv4.get("additionalHostIpSubnets", []) if isinstance(ipv4, dict) else None
    if (not isinstance(extra, list) or len(extra) > 64 or type(ipv4.get("prefixLength")) is not int
            or not all(isinstance(item, str) for item in [ipv4.get("hostIpAddress"), *extra])):
        raise IntegrationError("UniFi returned an invalid network address configuration.")
    try:
        hosts = [ipaddress.IPv4Interface(item) for item in
                 [f"{ipv4['hostIpAddress']}/{ipv4['prefixLength']}", *extra]]
    except ValueError:
        raise IntegrationError("UniFi returned an invalid network address configuration.") from None
    return {"gateway_ip": str(hosts[0].ip), "subnets": list(dict.fromkeys(str(host.network) for host in hosts)),
            "gateway_ips": [str(host.ip) for host in hosts]}


def _device_uplink(detail: dict[str, Any]) -> dict[str, Any]:
    """Read the device a piece of gear is attached to; none is the top of the chain, not an error."""
    uplink = detail.get("uplink")
    if uplink is None:
        return {}
    if not isinstance(uplink, dict):
        raise IntegrationError("UniFi returned an invalid device uplink.")
    return {"uplink": source_id(uplink.get("deviceId"))}


def _gateway_by_position(devices: list, routed: list, detail: dict[str, dict[str, Any]]) -> Any:
    """Name the one device that sits outside every network range at the top of the equipment, or nobody.

    Runs only when the range of every gateway-managed network was collected. Every
    piece of equipment must report an IPv4 address, the family the ranges are read
    in; exactly one may be outside every collected range. Its own detail read must
    have reported no uplink device, and at least one other piece of equipment must
    report it as its uplink, so a device nothing hangs off is never the gateway.
    """
    if not routed or any("subnets" not in detail.get(f"networks/{row.get('id')}", {}) for row in routed):
        return None
    ranges = [ipaddress.ip_network(subnet) for key, found in detail.items() if key.startswith("networks/")
              for subnet in found.get("subnets", [])]
    outside = []
    for row in devices:
        try:
            address = ipaddress.IPv4Address(row["ipAddress"] if isinstance(row.get("ipAddress"), str) else "")
        except ValueError:
            return None
        if not any(address in subnet for subnet in ranges):
            outside.append(row.get("id"))
    read = detail.get(f"devices/{outside[0]}") if len(outside) == 1 else None
    below = len(outside) == 1 and any(
        found.get("uplink") == outside[0] for key, found in detail.items() if key.startswith("devices/"))
    return outside[0] if read is not None and "uplink" not in read and below else None


async def _detail(reader: ReadClient, path: str, remote_id: str, parse, gap: str) -> dict[str, Any] | None:
    """Make one optional detail read and return the neutral fields parsed from it, or None.

    A read the key may not make, or an answer that is malformed or about another
    record, keeps nothing and records the gap. A rate limit, timeout, broken
    connection or spent budget still fails the collection.
    """
    try:
        detail = await reader.get(path)
        if detail.get("id") != remote_id:
            raise IntegrationError("UniFi answered a detail read with a different record.")
        return parse(detail)
    except IntegrationError as error:
        if core.must_stop(error):
            raise
        core.record_gap(gap)
        return None


def pace(base_url: str) -> core.Pace | None:
    """Declare the request limit of the address in use: the cloud's for one console, none for the console's own."""
    parsed = urlsplit(base_url)
    cloud = _CLOUD_PATH.fullmatch(parsed.path.rstrip("/"))
    return core.Pace(f"{ID}:{cloud.group(1)}", CLOUD_PACE) if cloud and parsed.hostname == CLOUD_HOST else None


def _shares(needs: list[int], budget: int) -> list[int]:
    """Split the detail reads a collection can still make between its sites.

    Every site gets what it needs up to one level, the highest the budget
    allows, so a small site is read in full and the large ones are cut short
    alike. What is left over goes one read each to the largest sites. No site
    is read in full while another that needs reads gets none.
    """
    budget, level = max(budget, 0), 0
    while level < max(needs, default=0) and sum(min(need, level + 1) for need in needs) <= budget:
        level += 1
    shares = [min(need, level) for need in needs]
    spare = budget - sum(shares)
    for index in sorted(range(len(needs)), key=lambda site: -needs[site]):
        # With too few reads for one each, a read never completes a site while others have none.
        if spare and needs[index] > level + (level == 0):
            shares[index] += 1
            spare -= 1
    return shares


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
    if not local and not (host == CLOUD_HOST and _CLOUD_PATH.fullmatch(path)):
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
        reader = ReadClient(client, config["base_url"], pace(config["base_url"]))
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
        # Every site's lists are read before any detail, so the detail reads that fit can be
        # shared between the sites by what each one needs.
        lists = []
        for site in sites:
            # Sequential, bounded reads avoid saturating small self-hosted gateways.
            lists.append([await offset_pages(reader, f"/v1/sites/{site['id']}/{name}")
                          for name in ("devices", "networks", "clients", "firewall/policies")])
        guests = sum(isinstance(row.get("access"), dict) and row["access"].get("type") == "GUEST"
                     for _devices, _networks, clients, _policies in lists for row in clients)
        # Requests the collection must still be able to make after the optional detail reads:
        # two closing lists for each site and the guest details, capped for the whole collection.
        reserved = 2 * len(sites) + min(guests, MAX_GUEST_DETAILS)
        shares = _shares([len(devices) + len(networks) for devices, networks, _clients, _policies in lists],
                         REQUEST_CEILING - reader.requests - reserved)
        guest_details = 0
        for position, site in enumerate(sites):
            sid = source_id(site.get("id"))
            site_resource = resource(integration_id, ID, "site", sid, site.get("name", sid), now)
            site_resource["site_id"] = site_resource["id"]
            snapshot.resources.append(site_resource)
            base = f"/v1/sites/{sid}"
            devices, networks, clients, policies = lists[position]
            device_map: dict[str, str] = {}
            network_map: dict[str, str] = {}
            detail: dict[str, dict[str, Any]] = {}
            left = shares[position]
            for kind, rows, parse in (("networks", networks, _network_addresses),
                                      ("devices", devices, _device_uplink)):
                for row in rows[:left]:
                    remote_id = source_id(row.get("id"))
                    found = await _detail(
                        reader, f"{base}/{kind}/{remote_id}", remote_id, parse, f"unifi_{kind}_details_unavailable")
                    if found is not None:
                        detail[f"{kind}/{remote_id}"] = found
                if len(rows) > left:
                    # The gap is one fixed code; the site itself says it was cut short and by how much.
                    core.record_gap("unifi_detail_limit")
                    site_resource["attributes"].setdefault("detail_reads_skipped", {})[kind] = len(rows) - left
                left = max(left - len(rows), 0)
            # The gateway's address on each network the source says its gateway manages.
            routed = [row for row in networks if row.get("management") == "GATEWAY"]
            gateway_ips = {ip for row in routed
                           for ip in detail.get(f"networks/{row.get('id')}", {}).get("gateway_ips", [])}
            declared = any(isinstance(row.get("features"), list) and "gateway" in row["features"] for row in devices)
            holders = [row.get("id") for row in devices
                       if isinstance(row.get("ipAddress"), str) and row["ipAddress"] in gateway_ips]
            # One device holding a gateway address is the gateway. None or several is not evidence,
            # and only then is the device's position among the collected ranges considered.
            evident = basis = None
            if not declared and len(holders) == 1:
                evident, basis = holders[0], "gateway_address"
            elif not declared and not holders:
                evident, basis = _gateway_by_position(devices, routed, detail), "outside_network_ranges"
            if routed and not declared and evident is None:
                core.record_gap("unifi_gateway_not_identified")
            uplinks: list[tuple[str, str]] = []
            for row in devices:
                remote_id = source_id(row.get("id"))
                features = row.get("features", [])
                if not isinstance(features, list):
                    raise IntegrationError("UniFi returned invalid device capabilities.")
                if not any(feature in features for feature in ("gateway", "accessPoint", "switching")):
                    raise IntegrationError("UniFi returned a device with an unsupported capability classification.")
                kind = "gateway" if "gateway" in features else "access_point" if "accessPoint" in features else "switch"
                found = detail.get(f"devices/{remote_id}", {})
                node = resource(
                    integration_id, ID, kind, remote_id, row.get("name", remote_id), now,
                    site_id=site_resource["id"], evidence_kind="observed",
                    attributes={**selected(row, ("model", "state", "firmwareVersion", "firmwareUpdatable", "features")),
                                **_renamed(row, {"ipAddress": "ip", "macAddress": "mac"}), **found},
                )
                if remote_id == evident:
                    # The identifier stays the one the feature list gives, so a device already
                    # collected is refiled in place instead of appearing a second time.
                    node["kind"] = "gateway"
                    node["attributes"]["kind_basis"] = basis
                device_map[remote_id] = node["id"]
                snapshot.resources.append(node)
                if "uplink" in found:
                    uplinks.append((remote_id, found["uplink"]))
            for remote_id, above in uplinks:
                if above in device_map and above != remote_id:
                    snapshot.relationships.append(relationship(
                        integration_id, ID, device_map[remote_id], device_map[above], "connects_to", now,
                        evidence_kind="observed",
                        attributes={"source_field": "device.uplink.deviceId", "meaning": "Attachment; not proof of end-to-end reachability."},
                    ))
            for row in networks:
                remote_id = source_id(row.get("id"))
                found = detail.get(f"networks/{remote_id}", {})
                manager = _MANAGERS.get(row.get("management")) if isinstance(row.get("management"), str) else None
                node = resource(
                    integration_id, ID, "network", remote_id, row.get("name", remote_id), now,
                    site_id=site_resource["id"],
                    attributes={**selected(row, ("enabled", "management", "default", "zoneId", "deviceId", "metadata")),
                                **_renamed(row, {"vlanId": "vlan"}), **({"managed_by": manager} if manager else {}),
                                **selected(found, ("gateway_ip", "subnets"))},
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
    id=ID, name="UniFi Network", letter="U", tone="blue", logo="unifi.png",
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
    not_collected=("Firewall connection logs and port scans", "Devices that have left the network"),
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
        "unifi_networks_details_unavailable": (
            "Some network address ranges could not be read",
            "A network's detail was refused or unusable. Devices cannot be placed on a network whose range is unknown."),
        "unifi_devices_details_unavailable": (
            "Some equipment uplinks could not be read",
            "A device's detail was refused or unusable. The Map cannot show what that equipment is attached to."),
        "unifi_detail_limit": (
            "More networks and equipment than one collection reads in detail",
            "Detail reads stop before the collection reaches the source's request limit, and the reads "
            "that fit are shared between the sites. Some address ranges or uplinks are missing; each site "
            "that was cut short says how many. Narrow the connection to one site to read it in full."),
        "unifi_gateway_not_identified": (
            "No device could be shown to be the gateway",
            "The source says a gateway manages some networks, but lists no device as a gateway, no single "
            "device holds a gateway address, and no single device sits outside every network range at the "
            "top of the other equipment. Nyctr files nothing as the gateway rather than guess."),
        "unifi_no_visible_sites": (
            "No sites were visible to the credential",
            "Site discovery returned an empty list. Device, network, client, and policy reads were not exercised."),
    },
    validate=validate, collect=collect_unifi, scope=lambda config: config.get("site_id"),
    issue_pass=actions.unifi_create_voucher, end_pass=actions.unifi_delete_voucher,
    guest_access=actions.unifi_set_guest_access,
)
