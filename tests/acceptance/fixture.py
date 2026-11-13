"""Synthetic GET-only UniFi and NextDNS HTTPS contracts for the isolated Docker network."""

from __future__ import annotations

import argparse
import json
import ssl
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

GOOD_API_KEY = "fake-readonly"
PRIVATE_ERROR_MARKER = "fixture-private-error-marker"
UNIFI_PREFIX = "/proxy/network/integration/v1"
# Stable for this fixture process so repeated collection does not synthesize new events.
OBSERVED_AT = datetime.now(UTC).isoformat()



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
    f"{UNIFI_PREFIX}/sites": [{"id": "site-one", "name": "Synthetic lab"}],
    f"{UNIFI_PREFIX}/sites/site-one/devices": [
        device("gateway-one", "Synthetic gateway", "gateway", "192.0.2.1", 1),
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


def unifi_details() -> dict[str, dict]:
    """Build the per-record detail reads: a network's address range and a device's uplink."""
    site = f"{UNIFI_PREFIX}/sites/site-one"
    ranges = {"network-one": ("192.0.2.1", 26), "network-two": ("198.51.100.1", 24), "network-three": ("203.0.113.1", 24)}
    above = {"switch-one": "gateway-one", "ap-one": "switch-one"}
    details = {}
    for row in UNIFI_ROWS[f"{site}/networks"]:
        host, prefix = ranges[row["id"]]
        details[f"{site}/networks/{row['id']}"] = {
            **row, "ipv4Configuration": {"autoScaleEnabled": False, "hostIpAddress": host, "prefixLength": prefix}}
    for row in UNIFI_ROWS[f"{site}/devices"]:
        uplink = {"uplink": {"deviceId": above[row["id"]]}} if row["id"] in above else {}
        details[f"{site}/devices/{row['id']}"] = {**row, "features": {}, **uplink}
    return details


UNIFI_DETAILS = unifi_details()


def profile(logging_enabled: bool) -> dict:
    """Supply all supported policy sections so missing coverage is an explicit test choice."""
    return {
        "data": {
            "name": "Synthetic DNS" if logging_enabled else "Synthetic DNS without logs",
            "settings": {"logs": {"enabled": logging_enabled, "retention": 86400}},
            "security": {"threatIntelligenceFeeds": True},
            "privacy": {"blocklists": [{"id": "synthetic-list"}]},
            "parentalControl": {},
            "allowlist": [],
            "denylist": [],
        }
    }


def response_for(target: str, api_key: str | None) -> tuple[int, bytes]:
    """Return fixed source data, a normal credential rejection, or a malformed contract.

    No request URL, credential, or outside data is reflected in the response.
    Pagination responds to documented offset/limit inputs without external URLs.
    """
    parsed = urlsplit(target)
    if parsed.path == "/healthz":
        return 200, b'{"status":"ok","fixture":"nyctr-acceptance"}'
    if api_key != GOOD_API_KEY:
        return 401, json.dumps(
            {"errors": [{"code": "unauthorized", "detail": PRIVATE_ERROR_MARKER}]}
        ).encode()
    if parsed.path in UNIFI_ROWS:
        query = parse_qs(parsed.query)
        try:
            offset = int(query.get("offset", ["0"])[0])
            limit = int(query.get("limit", ["200"])[0])
        except (ValueError, IndexError):
            return 400, b'{"errors":[{"code":"invalid_pagination"}]}'
        if offset < 0 or not 1 <= limit <= 1000:
            return 400, b'{"errors":[{"code":"invalid_pagination"}]}'
        rows = UNIFI_ROWS[parsed.path]
        page = rows[offset : offset + limit]
        payload = {"data": page, "offset": offset, "count": len(page), "totalCount": len(rows)}
    elif parsed.path in UNIFI_DETAILS:
        payload = UNIFI_DETAILS[parsed.path]
    elif parsed.path == "/profiles/aaaaaa":
        payload = profile(True)
    elif parsed.path == "/profiles/bbbbbb":
        payload = profile(False)
    elif parsed.path == "/profiles/aaaaaa/logs":
        payload = {
            "data": [
                {
                    "timestamp": OBSERVED_AT,
                    "domain": "photos.example.test",
                    "status": "blocked",
                    "reasons": [{"id": "synthetic-list", "name": "Synthetic test list"}],
                    "device": {"id": "dns-client-one", "name": "Synthetic DNS client", "model": "fixture"},
                    "clientIp": "192.0.2.20",
                }
            ],
            "meta": {"pagination": {"cursor": None}},
        }
    elif parsed.path == "/profiles/bbbbbb/logs":
        # The production collector must stop when the profile explicitly disables logging.
        return 409, b'{"errors":[{"code":"logging_disabled"}]}'
    elif parsed.path == "/profiles/cccccc":
        return 200, b'{"fixture-private-error-marker":'
    else:
        return 404, b'{"errors":[{"code":"unknown_fixture_route"}]}'
    return 200, json.dumps(payload, separators=(",", ":")).encode()


class FixtureHandler(BaseHTTPRequestHandler):
    """Expose synthetic reads only, without printing credentials or request contents."""

    server_version = "NyctrAcceptance"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def send_fixture_response(self, status: int, body: bytes) -> None:
        """Send a bounded JSON body and close denied methods without parsing their contents."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:
        """Serve an allowlisted fixture path using the same API-key header as the real collectors."""
        status, body = response_for(self.path, self.headers.get("X-Api-Key"))
        self.send_fixture_response(status, body)

    def do_POST(self) -> None:
        """Reject writes even inside the disposable fixture environment."""
        self.send_fixture_response(405, b'{"errors":[{"code":"read_only_fixture"}]}')

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST

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
    args = parser.parse_args()
    server = make_server(args.cert_directory, port=args.port)
    print("Synthetic acceptance provider listening with certificate verification enabled.")
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
