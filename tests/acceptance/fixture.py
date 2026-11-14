"""Synthetic UniFi and NextDNS HTTPS contracts for the isolated Docker network.

Read only unless started with changes allowed. The switches below make a source
misbehave on request; README.md says what the console should then show.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import threading
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import count
from pathlib import Path
from urllib.parse import parse_qs, parse_qsl, urlsplit

GOOD_API_KEY = "fake-readonly"
# A second key that may read everything except the Wi-Fi names: one gap on every collection.
LIMITED_API_KEY = "fake-limited"
PRIVATE_ERROR_MARKER = "fixture-private-error-marker"
UNIFI_PREFIX = "/proxy/network/integration/v1"
# Stable for this fixture process so repeated collection does not synthesize new events.
OBSERVED = datetime.now(UTC)
OBSERVED_AT = OBSERVED.isoformat()
# Profile dddddd answers with this many log rows; one collection reads 20 pages of 200.
# Each lookup is repeated on ten rows, so the 4000 rows kept make 400 lookups in the inbox.
OVER_BOUND = 4200
# Longer than the 20 seconds Nyctr waits for an answer.
TIMEOUT_HOLD = 25.0
# Each switch and the values it takes. Empty is off. Set at start by FIXTURE_<NAME>,
# or while running through /control, which is not published (on Linux the host itself can reach it).
SWITCH_FORMS = {
    "refuse": r"[\w/-]{0,80}",  # part of a path: requests for it are refused (HTTP 403)
    "error": r"[\w/-]{0,80}",  # part of a path: requests for it get a server error (HTTP 500)
    "fail": r"|(drop|timeout|limit):[1-9]\d{0,2}",  # the next N requests break, hang or are rate limited
    "retry_after": r"\d{1,4}",  # seconds a rate-limited answer says to wait
    "slow": r"|\d{1,2}(\.\d)?",  # seconds every answer is held back
    "writes": r"|on|fail|pause:\d{1,3}",  # changes: refused (405), accepted, failed, or held N seconds first
}
SWITCHES = {**dict.fromkeys(SWITCH_FORMS, ""), "retry_after": "90"}
LOCK = threading.Lock()
NUMBERS = count(1)
# Allowed names Nyctr added, by list path, so a read reports them back.
ALLOWLISTS: dict[str, list[dict]] = {}


def set_switch(name: str, value: str) -> None:
    """Change one switch, refusing a name or value this fixture does not know."""
    if name not in SWITCH_FORMS or not re.fullmatch(SWITCH_FORMS[name], value):
        raise ValueError("unknown switch or value")
    SWITCHES[name] = value


for _name in SWITCH_FORMS:  # A value this fixture does not know stops it at the start.
    set_switch(_name, os.environ.get(f"FIXTURE_{_name.upper()}") or SWITCHES[_name])


def next_fault() -> str:
    """Use up one planned failure and return its kind, or nothing when none is left."""
    with LOCK:
        kind, _, left = SWITCHES["fail"].partition(":")
        if kind:
            SWITCHES["fail"] = f"{kind}:{int(left) - 1}" if int(left) > 1 else ""
        return kind


def device(id_: str, name: str, feature: str, address: str, number: int) -> dict:
    """One adopted device as the documented list read returns it."""
    return {
        "id": id_,
        "name": name,
        "features": [feature],
        "model": "Acceptance fixture",
        "state": "ONLINE",
        "ipAddress": address,
        "macAddress": f"02:00:00:00:00:{number:02d}",
        "firmwareVersion": "fixture-1.0",
    }


def lan(id_: str, name: str, vlan: int, management: str, **extra: str) -> dict:
    """One network as the documented list read returns it: no address range."""
    return {"id": id_, "name": name, "vlanId": vlan, "enabled": True, "management": management, "default": vlan == 10, **extra}


UNIFI_ROWS = {
    f"{UNIFI_PREFIX}/sites": [{"id": "site-one", "name": "Synthetic lab"},
                              {"id": "site-large", "name": "Example site at real size"}],
    # As a real console can: the gateway is listed with the switching feature only and reports
    # its internet-side address, which is outside every network range of the site.
    f"{UNIFI_PREFIX}/sites/site-one/devices": [
        device("gateway-one", "Synthetic gateway", "switching", "192.0.2.200", 1),
        device("switch-one", "Synthetic switch", "switching", "192.0.2.2", 3),
        device("ap-one", "Synthetic access point", "accessPoint", "192.0.2.3", 4),
    ],
    f"{UNIFI_PREFIX}/sites/site-one/networks": [
        lan("network-one", "Synthetic LAN", 10, "GATEWAY", zoneId="zone-lan"),
        lan("network-two", "Synthetic IoT", 20, "GATEWAY", zoneId="zone-iot"),
        lan("network-three", "Synthetic workshop", 30, "SWITCH", deviceId="switch-one"),
    ],
    # The laptop and camera each sit inside one network's range. The visitor reports no address.
    f"{UNIFI_PREFIX}/sites/site-one/clients": [
        {
            "id": "client-one",
            "name": "Synthetic laptop",
            "type": "WIRED",
            "ipAddress": "192.0.2.20",
            "macAddress": "02:00:00:00:00:02",
            "connectedAt": OBSERVED_AT,
            "uplinkDeviceId": "switch-one",
        },
        {
            "id": "client-two",
            "name": "Synthetic camera",
            "type": "WIRELESS",
            "ipAddress": "198.51.100.20",
            "macAddress": "02:00:00:00:00:05",
            "connectedAt": OBSERVED_AT,
            "uplinkDeviceId": "ap-one",
        },
        {
            "id": "client-three",
            "name": "Synthetic visitor",
            "type": "WIRELESS",
            "macAddress": "02:00:00:00:00:06",
            "connectedAt": OBSERVED_AT,
            "uplinkDeviceId": "ap-one",
        },
    ],
    f"{UNIFI_PREFIX}/sites/site-one/firewall/policies": [
        {
            "id": "policy-one",
            "name": "Synthetic outbound policy",
            "enabled": True,
            "index": 10,
            "action": {"type": "ALLOW"},
            "source": {"zoneId": "zone-lan"},
            "destination": {"zoneId": "zone-external"},
            "loggingEnabled": False,
        }
    ],
    # The 11.0.97 contract serves hotspot vouchers per site; this site has issued none.
    f"{UNIFI_PREFIX}/sites/site-one/hotspot/vouchers": [],
    f"{UNIFI_PREFIX}/sites/site-one/wifi/broadcasts": [
        {"id": "wifi-one", "name": "Synthetic Wi-Fi", "enabled": True, "network": {"type": "NATIVE"}},
    ],
}


LARGE = f"{UNIFI_PREFIX}/sites/site-large"
LARGE_NETWORKS = ("Main", "Staff", "Guests", "Cameras", "Printers", "Media", "Sensors", "Lab", "Voice", "Workshop")
CLIENT_KINDS = ("laptop", "phone", "tablet", "printer", "camera", "television", "speaker", "sensor")


def large_site() -> tuple[dict[str, tuple[str, int]], dict[str, str]]:
    """Add a site at real size and return its address ranges and uplinks.

    Ten networks, 13 pieces of equipment, 67 clients and 230 firewall policies: more
    policies than one page of a list holds, so a collection has to ask for a second.
    Clients 63 to 66 cannot be placed: two report no address and two report one
    outside every range. Five wireless clients on the Guests network are guests of
    the Wi-Fi name that uses a sign-in page; one of them is still waiting.
    """
    def gear(id_: str, name: str, feature: str, address: str, number: int) -> dict:
        return {**device(f"big-{id_}", f"Example {name}", feature, address, number),
                "macAddress": f"02:00:00:00:01:{number:02x}"}

    devices = [gear("gateway", "gateway", "switching", "192.0.2.210", 1)]
    devices += [gear(f"switch-{n}", f"switch {n}", "switching", f"10.90.0.{n + 1}", n + 1) for n in range(1, 5)]
    devices += [gear(f"ap-{n}", f"access point {n}", "accessPoint", f"10.90.0.{n + 10}", n + 5) for n in range(1, 9)]
    above = {"big-switch-1": "big-gateway", **{f"big-switch-{n}": "big-switch-1" for n in range(2, 5)},
             **{f"big-ap-{n}": f"big-switch-{(n - 1) % 4 + 1}" for n in range(1, 9)}}
    networks = [lan(f"big-net-{n}", f"Example {name}", 100 + n, "GATEWAY", zoneId=f"big-zone-{n}")
                for n, name in enumerate(LARGE_NETWORKS)]
    networks[9].update(management="SWITCH", deviceId="big-switch-2")
    clients = []
    for i in range(67):
        wireless = i % 3 != 0
        row = {"id": f"big-client-{i:02d}", "name": f"Example {CLIENT_KINDS[i % 8]} {i:02d}",
               "type": "WIRELESS" if wireless else "WIRED", "ipAddress": f"10.90.{i % 10}.{20 + i}",
               "macAddress": f"02:00:00:00:02:{i:02x}", "connectedAt": OBSERVED_AT,
               "uplinkDeviceId": f"big-ap-{i % 8 + 1}" if wireless else f"big-switch-{i % 4 + 1}"}
        if i >= 65:
            row["ipAddress"] = f"198.18.0.{i}"
        elif i >= 63:
            del row["ipAddress"]
        elif i % 10 == 2 and wireless:
            row["access"] = guest_access(i != 62, "VOUCHER", OBSERVED, 480)
        clients.append(row)
    policies = [{"id": f"big-policy-{p:03d}", "name": f"Example rule {p:03d}", "enabled": p % 9 != 0, "index": 10 * p,
                 "action": {"type": ("ALLOW", "BLOCK")[p % 2]}, "source": {"zoneId": f"big-zone-{p % 10}"},
                 "destination": {"zoneId": f"big-zone-{(3 * p + 1) % 10}" if p % 4 else "big-zone-external"},
                 "loggingEnabled": False} for p in range(1, 231)]
    wifi = [{"id": "big-wifi-main", "name": "Example Wi-Fi", "enabled": True,
             "network": {"type": "SPECIFIC", "networkId": "big-net-0"}},
            {"id": "big-wifi-guests", "name": "Example Guest Wi-Fi", "enabled": True,
             "network": {"type": "SPECIFIC", "networkId": "big-net-2"},
             "hotspotConfiguration": {"type": "CAPTIVE_PORTAL"}}]
    UNIFI_ROWS.update({f"{LARGE}/devices": devices, f"{LARGE}/networks": networks, f"{LARGE}/clients": clients,
                       f"{LARGE}/firewall/policies": policies, f"{LARGE}/hotspot/vouchers": [],
                       f"{LARGE}/wifi/broadcasts": wifi})
    return {f"big-net-{n}": (f"10.90.{n}.1", 24) for n in range(10)}, above


def guest_access(authorized: bool, method: str, since: datetime, minutes: int) -> dict:
    """A guest's access as the read of one client reports it; the list read leaves the authorisation out."""
    grant = {"authorizationMethod": method, "authorizedAt": since.isoformat(),
             "expiresAt": (since + timedelta(minutes=minutes)).isoformat(),
             "usage": {"bytes": 52_000_000, "durationSec": 1800}}
    return {"type": "GUEST", "authorized": authorized, **({"authorization": grant} if authorized else {})}


def unifi_details(site: str, ranges: dict[str, tuple[str, int]], above: dict[str, str]) -> dict[str, dict]:
    """Build the per-record detail reads: a network's address range and a device's uplink."""
    details = {}
    for row in UNIFI_ROWS[f"{site}/networks"]:
        host, prefix = ranges[row["id"]]
        details[f"{site}/networks/{row['id']}"] = {
            **row, "ipv4Configuration": {"autoScaleEnabled": False, "hostIpAddress": host, "prefixLength": prefix}}
    for row in UNIFI_ROWS[f"{site}/devices"]:
        uplink = {"uplink": {"deviceId": above[row["id"]]}} if row["id"] in above else {}
        details[f"{site}/devices/{row['id']}"] = {**row, "features": {}, **uplink}
    return details


UNIFI_DETAILS = {
    **unifi_details(f"{UNIFI_PREFIX}/sites/site-one", {
        "network-one": ("192.0.2.1", 26), "network-two": ("198.51.100.1", 24), "network-three": ("203.0.113.1", 24),
    }, {"switch-one": "gateway-one", "ap-one": "switch-one"}),
    **unifi_details(LARGE, *large_site()),
}
PROFILE_NAMES = {"aaaaaa": "Synthetic DNS", "bbbbbb": "Synthetic DNS without logs",
                 "dddddd": "Synthetic DNS over its bound"}


def profile(profile_id: str) -> dict:
    """Supply all supported policy sections so missing coverage is an explicit test choice."""
    logging_enabled = profile_id != "bbbbbb"
    return {
        "data": {
            "name": PROFILE_NAMES[profile_id],
            "settings": {"logs": {"enabled": logging_enabled, "retention": 86400}},
            "security": {"threatIntelligenceFeeds": True},
            "privacy": {"blocklists": [{"id": "synthetic-list"}]},
            "parentalControl": {},
            "allowlist": ALLOWLISTS.get(f"/profiles/{profile_id}/allowlist", []),
            "denylist": [],
        }
    }


def blocked_lookup(domain: str, seconds_ago: int = 0, **source: object) -> dict:
    """One blocked lookup as the log read returns it."""
    return {"timestamp": (OBSERVED - timedelta(seconds=seconds_ago)).isoformat(), "domain": domain,
            "status": "blocked", "reasons": [{"id": "synthetic-list", "name": "Synthetic test list"}], **source}


def change(method: str, path: str, sent: dict) -> tuple[int, dict]:
    """Make one of the changes Nyctr can make and remember it, so the next read reports it back."""
    head, _, last = path.rpartition("/")
    if method == "POST" and last == "vouchers" and path in UNIFI_ROWS:
        number = next(NUMBERS)
        voucher = {"id": f"voucher-{number}", "code": f"{4200000000 + number}", "name": sent.get("name"),
                   "timeLimitMinutes": sent.get("timeLimitMinutes"), "authorizedGuestCount": 0,
                   "authorizedGuestLimit": sent.get("authorizedGuestLimit"), "expired": False,
                   "dataUsageLimitMBytes": sent.get("dataUsageLimitMBytes"), "createdAt": datetime.now(UTC).isoformat()}
        UNIFI_ROWS[path].append(voucher)
        return 201, {"vouchers": [voucher]}
    if method == "POST" and last == "allowlist" and head[10:] in PROFILE_NAMES and isinstance(sent.get("id"), str):
        ALLOWLISTS.setdefault(path, []).append({"id": sent["id"], "active": True})
        return 200, {}
    listed = UNIFI_ROWS.get(head) if head.endswith("/vouchers") else ALLOWLISTS.get(head)
    if method == "DELETE" and listed is not None and any(row["id"] == last for row in listed):
        listed[:] = [row for row in listed if row["id"] != last]
        return 200, {}
    guest = head.rpartition("/")
    row = next((row for row in UNIFI_ROWS.get(guest[0], []) if row["id"] == guest[2] and "access" in row), None)
    if method == "POST" and last == "actions" and row and guest[0].endswith("/clients"):
        if sent.get("action") == "AUTHORIZE_GUEST_ACCESS":
            row["access"] = guest_access(True, "API", datetime.now(UTC), int(sent.get("timeLimitMinutes") or 60))
        else:  # Cutting a guest off also disconnects it, so it is no longer among the connected clients.
            UNIFI_ROWS[guest[0]].remove(row)
        return 200, {}
    return 404, {"errors": [{"code": "unknown_fixture_change"}]}


def response_for(target: str, api_key: str | None, method: str = "GET", sent: bytes = b"") -> tuple[int, bytes]:
    """Return source data, a normal credential rejection, a malformed contract, or a switched fault.

    No request URL, credential, or outside data is reflected in the response.
    Lists are paged as documented: 25 rows unless asked, 200 at most, no external URLs.
    Status 0 means no answer at all: the caller closes the connection.
    """
    # The gateway source's cloud address serves the same reads under a console path.
    parsed = urlsplit(re.sub(r"^/v1/connector/consoles/[\w:-]+(?=/proxy/)", "", target))
    if parsed.path == "/healthz":
        return 200, b'{"status":"ok","fixture":"nyctr-acceptance"}'
    if api_key not in {GOOD_API_KEY, LIMITED_API_KEY}:
        return 401, json.dumps(
            {"errors": [{"code": "unauthorized", "detail": PRIVATE_ERROR_MARKER}]}
        ).encode()
    if parsed.path == "/control":
        try:
            for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                set_switch(name, value)
        except ValueError:
            return 400, b'{"errors":[{"code":"unknown_switch"}]}'
        return 200, json.dumps(SWITCHES).encode()
    time.sleep(float(SWITCHES["slow"] or 0))
    fault = next_fault()
    if fault == "limit":
        return 429, b'{"errors":[{"code":"rate_limited"}]}'
    if fault:
        time.sleep(TIMEOUT_HOLD if fault == "timeout" else 0)
        return 0, b""
    limited = api_key == LIMITED_API_KEY and parsed.path.endswith("/wifi/broadcasts")
    if limited or (SWITCHES["refuse"] and SWITCHES["refuse"] in parsed.path):
        return 403, b'{"errors":[{"code":"forbidden"}]}'
    if SWITCHES["error"] and SWITCHES["error"] in parsed.path:
        return 500, b'{"errors":[{"code":"fixture_server_error"}]}'
    clients, _, client = parsed.path.rpartition("/")
    if method != "GET":
        mode = SWITCHES["writes"]
        if mode in {"", "fail"}:
            return (500, b'{"errors":[{"code":"fixture_change_failed"}]}') if mode else (
                405, b'{"errors":[{"code":"read_only_fixture"}]}')
        time.sleep(float(mode[6:] or 0) if mode.startswith("pause:") else 0)
        try:
            body = json.loads(sent or b"{}")
        except ValueError:
            body = None
        status, payload = change(method, parsed.path, body) if isinstance(body, dict) else (400, {})
    elif parsed.path in UNIFI_ROWS:
        query = parse_qs(parsed.query)
        try:
            offset = int(query.get("offset", ["0"])[0])
            limit = int(query.get("limit", ["25"])[0])
        except (ValueError, IndexError):
            return 400, b'{"errors":[{"code":"invalid_pagination"}]}'
        if offset < 0 or not 1 <= limit <= 200:
            return 400, b'{"errors":[{"code":"invalid_pagination"}]}'
        rows = UNIFI_ROWS[parsed.path]
        # The list says only whether a guest is let on; how and until when is in the read of that client.
        page = [{**row, "access": {key: row["access"][key] for key in ("type", "authorized")}} if "access" in row
                else row for row in rows[offset : offset + limit]]
        payload = {"data": page, "offset": offset, "limit": limit, "count": len(page), "totalCount": len(rows)}
        status = 200
    elif parsed.path in UNIFI_DETAILS:
        status, payload = 200, UNIFI_DETAILS[parsed.path]
    elif clients.endswith("/clients") and any(row["id"] == client for row in UNIFI_ROWS.get(clients, [])):
        status, payload = 200, next(row for row in UNIFI_ROWS[clients] if row["id"] == client)
    elif parsed.path[10:] in PROFILE_NAMES:
        status, payload = 200, profile(parsed.path[10:])
    elif parsed.path.endswith("/allowlist") and parsed.path[10:16] in PROFILE_NAMES:
        status, payload = 200, {"data": ALLOWLISTS.get(parsed.path, [])}
    elif parsed.path == "/profiles/aaaaaa/logs":
        device = {"id": "dns-client-one", "name": "Synthetic DNS client", "model": "fixture"}
        payload = {"data": [blocked_lookup("photos.example.test", device=device, clientIp="192.0.2.20")],
                   "meta": {"pagination": {"cursor": None}}}
        status = 200
    elif parsed.path == "/profiles/dddddd/logs":
        # Newest first, 200 to a page, with a cursor for as long as older lookups remain.
        cursor = parse_qs(parsed.query).get("cursor", ["0"])[0]
        start = int(cursor) if cursor.isdigit() else 0
        rows = [blocked_lookup(f"lookup-{i // 10 % 40:02d}.example.test", i // 10)
                for i in range(start, min(start + 200, OVER_BOUND))]
        more = str(start + 200) if start + 200 < OVER_BOUND else None
        status, payload = 200, {"data": rows, "meta": {"pagination": {"cursor": more}}}
    elif parsed.path == "/profiles/bbbbbb/logs":
        # The production collector must stop when the profile explicitly disables logging.
        return 409, b'{"errors":[{"code":"logging_disabled"}]}'
    elif parsed.path == "/profiles/cccccc":
        return 200, b'{"fixture-private-error-marker":'
    else:
        return 404, b'{"errors":[{"code":"unknown_fixture_route"}]}'
    return status, json.dumps(payload, separators=(",", ":")).encode()


class FixtureHandler(BaseHTTPRequestHandler):
    """Expose the synthetic sources without printing credentials or request contents."""

    server_version = "NyctrAcceptance"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def send_fixture_response(self, status: int, body: bytes) -> None:
        """Send a bounded JSON body and close denied methods without parsing their contents."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if status == 429:
            self.send_header("Retry-After", SWITCHES["retry_after"])
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:
        """Serve an allowlisted fixture path using the same API-key header as the real collectors.

        A change is read and applied only when the fixture was started with changes allowed;
        otherwise it is refused without its contents being read.
        """
        sent = b""
        if self.command != "GET" and SWITCHES["writes"] and (self.headers.get("Content-Length") or "").isdigit():
            sent = self.rfile.read(min(int(self.headers["Content-Length"]), 65536))
        status, body = response_for(self.path, self.headers.get("X-Api-Key"), self.command, sent)
        if status:
            self.send_fixture_response(status, body)
        self.close_connection = True

    do_POST = do_PUT = do_PATCH = do_DELETE = do_GET

    def log_message(self, format: str, *args) -> None:
        """Suppress standard access logs so request headers and paths never enter test output."""


def make_server(directory: Path, host: str = "0.0.0.0", port: int = 443) -> ThreadingHTTPServer:
    """Wrap the local server in the generated CA-signed leaf; clients still verify TLS normally."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(directory / "fixture.pem", directory / "fixture-key.pem")
    server = ThreadingHTTPServer((host, port), FixtureHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> None:
    """Start the internal HTTPS provider; Compose publishes no port for this service."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert-directory", type=Path, default=Path("/acceptance-certs"))
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--set", nargs="*", metavar="NAME=VALUE",
                        help="change switches on the running fixture and print them all, then exit")
    args = parser.parse_args()
    if args.set is not None:
        context = ssl.create_default_context(cafile=str(args.cert_directory / "combined-ca.pem"))
        request = urllib.request.Request("https://fixture/control?" + "&".join(args.set),
                                         headers={"X-Api-Key": GOOD_API_KEY})
        try:
            print(urllib.request.urlopen(request, context=context, timeout=5).read().decode())
        except OSError:
            raise SystemExit("Not set: unknown switch or value, or the fixture is not running.") from None
        return
    server = make_server(args.cert_directory, port=args.port)
    print("Synthetic acceptance provider listening with certificate verification enabled.")
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
