"""Exercise the isolated Docker acceptance app using only loopback HTTP and synthetic credentials."""

from __future__ import annotations

import argparse
import http.cookiejar
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

EMAIL = "tester@nyctr.test"
PASSWORD = "nyctr-acceptance-only"
GOOD_SECRET_REF = "NYCTR_CONNECTOR_SECRET_ACCEPTANCE"
BAD_SECRET_REF = "NYCTR_CONNECTOR_SECRET_REJECTED"
PRIVATE_VALUES = ("fake-readonly", "fake-rejected", "fixture-private-error-marker")

CONNECTIONS = {
    "unifi": {
        "name": "Acceptance - UniFi Network",
        "provider": "unifi_network",
        "config": {"base_url": "https://fixture/proxy/network/integration", "site_id": "site-one"},
        "secret_ref": GOOD_SECRET_REF,
    },
    "nextdns": {
        "name": "Acceptance - NextDNS",
        "provider": "nextdns",
        "config": {"profile_id": "aaaaaa", "lookback_hours": 24},
        "secret_ref": GOOD_SECRET_REF,
    },
    "rejected": {
        "name": "Acceptance - rejected credential",
        "provider": "unifi_network",
        "config": {"base_url": "https://fixture/proxy/network/integration", "site_id": "site-one"},
        "secret_ref": BAD_SECRET_REF,
    },
    "tls": {
        "name": "Acceptance - invalid TLS hostname",
        "provider": "unifi_network",
        "config": {"base_url": "https://untrusted-fixture/proxy/network/integration", "site_id": "site-one"},
        "secret_ref": GOOD_SECRET_REF,
    },
    "disabled": {
        "name": "Acceptance - logging disabled",
        "provider": "nextdns",
        "config": {"profile_id": "bbbbbb", "lookback_hours": 24},
        "secret_ref": GOOD_SECRET_REF,
    },
    "malformed": {
        "name": "Acceptance - malformed response",
        "provider": "nextdns",
        "config": {"profile_id": "cccccc", "lookback_hours": 24},
        "secret_ref": GOOD_SECRET_REF,
    },
}


class AcceptanceFailure(Exception):
    """A fixed, safe test failure that excludes response bodies, tokens, and credentials."""


def require(condition: bool, message: str) -> None:
    """Fail with an application-owned assertion message instead of printing source data."""
    if not condition:
        raise AcceptanceFailure(message)


def loopback_url(value: str) -> str:
    """Reject remote origins, credentials, and URL suffixes before any login can be sent."""
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        local = hostname.lower() == "localhost"
        if not local:
            local = ipaddress.ip_address(hostname).is_loopback
        port = parsed.port
    except ValueError:
        raise AcceptanceFailure("The acceptance URL must be an HTTP(S) loopback origin.") from None
    require(
        local
        and parsed.scheme in {"http", "https"}
        and parsed.netloc
        and parsed.username is None
        and parsed.password is None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
        and not any(character.isspace() for character in value)
        and (port is None or 1 <= port <= 65535),
        "The acceptance URL must be an HTTP(S) loopback origin without credentials or a path.",
    )
    return value.rstrip("/")


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """Prevent a local response from forwarding a test login or session to a different origin."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        """Leave redirects as HTTP errors without following or displaying their destinations."""
        return None


class Client:
    """Use a private cookie jar and explicit CSRF token with no environment proxy inheritance."""

    def __init__(self, origin: str):
        """Validate the destination before constructing a local-only authenticated HTTP client."""
        self.origin = loopback_url(origin)
        self.csrf = ""
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirects(),
            urllib.request.HTTPCookieProcessor(self.cookies),
        )

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body=None,
        expected: int = 200,
        timeout: float = 110,
        csrf: bool = True,
    ) -> bytes:
        """Read one bounded same-origin response and censor all failure bodies from output."""
        require(path.startswith("/") and not path.startswith("//"), "Invalid local acceptance request path.")
        headers = {"Accept": "application/json", "Origin": self.origin}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if method not in {"GET", "HEAD"} and csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        request = urllib.request.Request(self.origin + path, data=data, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            response = error
        except (urllib.error.URLError, OSError):
            raise AcceptanceFailure(
                "Could not reach the local acceptance app; inspect test-container health."
            ) from None
        with response:
            require(
                response.status == expected,
                f"Acceptance API returned HTTP {response.status}; expected HTTP {expected}. Response details suppressed.",
            )
            payload = response.read(2 * 1024 * 1024 + 1)
            require(len(payload) <= 2 * 1024 * 1024, "Acceptance response exceeded the expected size limit.")
        return payload

    def json(self, path: str, **options):
        """Decode a test API response without echoing malformed data or authentication material."""
        try:
            return json.loads(self.request(path, **options))
        except (ValueError, UnicodeError):
            raise AcceptanceFailure("Acceptance API returned an unexpected response format.") from None

    def login(self) -> None:
        """Authenticate only the known disposable administrator; arbitrary credentials are not accepted."""
        user = self.json("/api/auth/login", method="POST", body={"email": EMAIL, "password": PASSWORD})
        require(
            user.get("email") == EMAIL and user.get("role") == "admin" and user.get("mode") == "live",
            "The acceptance app did not return the expected synthetic live administrator.",
        )
        require(
            isinstance(user.get("csrf_token"), str) and bool(user["csrf_token"]),
            "The acceptance login did not establish CSRF protection.",
        )
        self.csrf = user["csrf_token"]


def wait_for_app(client: Client) -> None:
    """Allow a bounded application restart without retrying credentials or printing network errors."""
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            health = client.json("/api/health", timeout=3)
            if health.get("status") == "ok":
                return
        except AcceptanceFailure:
            pass
        time.sleep(1)
    raise AcceptanceFailure("The local acceptance app was not healthy within 60 seconds.")


def saved_connections(client: Client, *, create: bool) -> dict[str, dict]:
    """Create or reuse only exact synthetic connections; never rewrite unexpected saved configuration."""
    existing = client.json("/api/integrations")
    require(isinstance(existing, list), "The integration list did not match the acceptance contract.")
    result = {}
    for scenario, specification in CONNECTIONS.items():
        matches = [row for row in existing if row.get("name") == specification["name"]]
        require(len(matches) <= 1, "Duplicate acceptance connection names exist; use a fresh test volume.")
        if not matches:
            require(create, "A saved acceptance connection was lost; persistence verification failed.")
            row = client.json("/api/integrations", method="POST", body=specification, expected=201)
        else:
            row = matches[0]
        require(
            all(row.get(key) == value for key, value in specification.items()),
            "A named acceptance connection has unexpected configuration; refusing to modify it.",
        )
        result[scenario] = row
    return result


def source_path(connection: dict, action: str) -> str:
    """Build a saved-integration operation path without allowing source IDs to introduce URL syntax."""
    return f"/api/integrations/{quote(connection['id'], safe='')}/{action}"


def evidence_snapshot(client: Client) -> str:
    """Capture inventory, graph, and fresh block state for a strict no-import comparison."""
    graph = client.json("/api/graph")
    state = {
        "resources": sorted(client.json("/api/resources"), key=lambda row: row["id"]),
        "nodes": sorted(graph["nodes"], key=lambda row: row["id"]),
        "edges": sorted(graph["edges"], key=lambda row: row["id"]),
        "blocks": sorted(client.json("/api/blocks"), key=lambda row: row["id"]),
    }
    return json.dumps(state, sort_keys=True)


def collection_health(client: Client) -> dict:
    """Capture persisted collection health separately from an ephemeral diagnostic result."""
    return {
        row["id"]: {key: row.get(key) for key in ("status", "last_sync", "last_error", "capabilities")}
        for row in client.json("/api/integrations")
    }


def assert_sanitized(value) -> None:
    """Reject reflected test credentials and fixture error markers without displaying their values."""
    serialized = json.dumps(value)
    require(
        not any(marker in serialized for marker in PRIVATE_VALUES),
        "A diagnostic or audit response exposed private fixture material.",
    )


def verify_diagnostics(client: Client, connections: dict[str, dict]) -> None:
    """Exercise successful reads and realistic negative cases without importing any evidence."""
    before = evidence_snapshot(client)
    health = collection_health(client)
    client.json(source_path(connections["unifi"], "diagnostics"), method="POST", csrf=False, expected=403)
    expected_outcomes = {
        "unifi": "verified",
        "nextdns": "verified",
        "rejected": "failed",
        "tls": "failed",
        "disabled": "partial",
        "malformed": "failed",
    }
    expected_counts = {
        "unifi": {"resources": 11, "relationships": 17, "observations": 0},
        "nextdns": {"resources": 8, "relationships": 7, "observations": 1},
        "disabled": {"resources": 6, "relationships": 5, "observations": 0},
    }
    for scenario, connection in connections.items():
        report = client.json(source_path(connection, "diagnostics"), method="POST")
        assert_sanitized(report)
        require(
            report.get("integration_id") == connection["id"] and report.get("read_only") is True,
            "Diagnostics did not retain the requested read-only connection scope.",
        )
        require(
            report.get("outcome") == expected_outcomes[scenario],
            f"The {scenario} diagnostic returned an unexpected outcome.",
        )
        require(
            report.get("snapshot_counts") == expected_counts.get(scenario),
            f"The {scenario} diagnostic reported unexpected in-memory counts.",
        )
        checks = {item["id"]: item for item in report["checks"]}
        capabilities = {item["id"]: item for item in report["capabilities"]}
        require(
            capabilities["device_identity:verify"]["implementation"] == "not_implemented"
            and capabilities["device_identity:verify"]["verification"] == "unavailable",
            "Source labels were incorrectly presented as verified user identity.",
        )
        if scenario in {"unifi", "nextdns"}:
            require(
                all(check["status"] == "passed" for check in checks.values()),
                "A successful fixture did not verify its supported connection checks.",
            )
            require(
                all(
                    capability["verification"] == "verified"
                    for capability in capabilities.values()
                    if capability["implementation"] == "implemented"
                ),
                "A successful fixture left a supported capability unverified.",
            )
        if scenario == "rejected":
            require(
                checks["authentication"]["status"] == "failed"
                and checks["authentication"]["category"] == "authentication"
                and checks["tls"]["status"] == "passed",
                "Provider rejection was not distinguished from transport or TLS failure.",
            )
        if scenario == "tls":
            require(
                checks["tls"]["status"] == "failed"
                and checks["tls"]["category"] == "tls"
                and checks["authentication"]["status"] == "unknown",
                "The invalid fixture hostname did not fail verified TLS before authentication.",
            )
        if scenario == "disabled":
            require(
                capabilities["blocked_dns_logs:read"]["verification"] == "unavailable"
                and any(gap["id"] == "logging_disabled" for gap in report["evidence_gaps"]),
                "Disabled logging was not preserved as an explicit evidence gap.",
            )
        if scenario == "malformed":
            require(
                checks["provider_contract"]["status"] == "failed"
                and checks["provider_contract"]["category"] == "provider_contract"
                and checks["authentication"]["status"] == "unknown",
                "Malformed provider data was incorrectly treated as verified evidence.",
            )
        require(
            evidence_snapshot(client) == before, "Diagnostics imported or changed inventory/observations."
        )
        require(collection_health(client) == health, "Diagnostics changed persisted collection health.")
        print(f"PASS diagnostic: {scenario}; inventory and collection health unchanged")
    audit = client.json("/api/audit")
    assert_sanitized(audit)
    events = [event for event in audit if event.get("action") == "integration.diagnosed"]
    require(
        len(events) >= len(CONNECTIONS)
        and all(event["details"].get("imported") is False for event in events),
        "Diagnostics audit records did not preserve the no-import boundary.",
    )


def collect_fixtures(client: Client, connections: dict[str, dict]) -> None:
    """Import only the two positive fixtures through the ordinary administrator collection API."""
    for scenario, count, observations in (("unifi", 11, 0), ("nextdns", 8, 1)):
        result = client.json(source_path(connections[scenario], "sync"), method="POST")
        require(
            result
            == {"ok": True, "resource_count": count, "observation_count": observations, "partial": False},
            f"Explicit {scenario} collection returned unexpected counts.",
        )
        print(f"PASS explicit collection: {scenario}")


def verify_placement(client: Client, graph: dict) -> None:
    """Check the gateway, each network's range, gear uplinks and where each device is placed.

    The source never says which network a device is on. Nyctr works that out when
    the graph is read, so those links must be labelled inferred and say so.
    """
    name = {node["id"]: node["name"] for node in graph["nodes"]}
    kinds = {node["name"]: node["kind"] for node in graph["nodes"] if node["kind"] != "site"}
    require(
        kinds.get("Synthetic gateway") == "gateway"
        and [kind for kind in kinds.values() if kind == "gateway"] == ["gateway"]
        and kinds.get("Synthetic switch") == "switch",
        "The device outside every network range, with nothing above it, was not filed as the only gateway.",
    )
    require(
        [node["attributes"].get("kind_basis") for node in graph["nodes"] if node["kind"] == "gateway"]
        == ["outside_network_ranges"],
        "The gateway was not marked as Nyctr's deduction from where it sits.",
    )
    ranges = {node["name"]: node["attributes"].get("subnets") for node in graph["nodes"] if node["kind"] == "network"}
    require(
        ranges
        == {"Synthetic LAN": ["192.0.2.0/26"], "Synthetic IoT": ["198.51.100.0/24"], "Synthetic workshop": ["203.0.113.0/24"]}
        and all(node["evidence_kind"] == "configured" for node in graph["nodes"] if node["kind"] == "network"),
        "A network lost the address range the source configured for it.",
    )

    def found(kind: str) -> set[tuple[str, str, str]]:
        return {(name[e["source"]], name[e["target"]], e["evidence_kind"]) for e in graph["edges"] if e["kind"] == kind}

    require(
        {("Synthetic switch", "Synthetic gateway", "observed"), ("Synthetic access point", "Synthetic switch", "observed")}
        <= found("connects_to"),
        "Equipment was not linked to the equipment above it as observed.",
    )
    placed = [edge for edge in graph["edges"] if edge["kind"] == "member_of"]
    require(
        found("member_of")
        == {("Synthetic laptop", "Synthetic LAN", "inferred"), ("Synthetic camera", "Synthetic IoT", "inferred")}
        and all(
            edge["id"].startswith("derived:") and edge["attributes"]["basis"].startswith("Worked out by Nyctr")
            for edge in placed
        ),
        "A device was not placed on its network, or the placement was shown as the source's statement.",
    )
    require(
        found("managed_by")
        == {
            ("Synthetic workshop", "Synthetic switch", "configured"),
            ("Synthetic LAN", "Synthetic gateway", "inferred"),
            ("Synthetic IoT", "Synthetic gateway", "inferred"),
        },
        "Networks were not linked to the device that runs them with the right evidence.",
    )
    saved = "{ networks { name links(first: 100) { kind evidence basis source { name } target { name } } } }"
    answer = client.json("/api/graph/query", method="POST", body={"query": saved})
    on = {
        row["name"]: {link["source"]["name"]: (link["evidence"], link["basis"] or "") for link in row["links"]}
        for row in answer["data"]["networks"]
    }
    require(
        all(
            on[network].get(device, ("", ""))[0] == "inferred"
            and on[network][device][1].startswith("Worked out by Nyctr")
            for network, device in (("Synthetic LAN", "Synthetic laptop"), ("Synthetic IoT", "Synthetic camera"))
        )
        and not any("Synthetic visitor" in names for names in on.values()),
        "The saved query for every network and what is on it did not return the placed devices as worked out by Nyctr.",
    )
    print("PASS placement: one gateway, ranges, uplinks, two devices placed as inferred, one not reported")


def verify_persisted_evidence(client: Client, connections: dict[str, dict]) -> None:
    """Check the saved graph and unassigned block using read endpoints only, including after restart."""
    resources = client.json("/api/resources")
    graph = client.json("/api/graph")
    blocks = client.json("/api/blocks")
    require(
        len(resources) == 19 and len(graph["nodes"]) == 19 and len(graph["edges"]) == 28,
        "The synthetic graph was lost, duplicated, or mixed with other data; expected 19 resources and 28 relationships.",
    )
    verify_placement(client, graph)
    for scenario, expected in (("unifi", 11), ("nextdns", 8)):
        source_id = connections[scenario]["id"]
        require(
            sum(row["attributes"].get("integration_id") == source_id for row in resources) == expected,
            "Source resource namespaces did not survive collection or restart.",
        )
    require(len(blocks) == 1, "Expected one fresh synthetic DNS block; stale blocks expire after 24 hours.")
    block = blocks[0]
    require(
        block["domain"] == "photos.example.test"
        and block["source"] == "nextdns"
        and block["device_id"] is None
        and block["attribution"] == "unverified"
        and block["risk_score"] is None,
        "The synthetic DNS block lost its unknown-risk or unassigned identity boundary.",
    )
    require(
        datetime.fromisoformat(block["expires_at"].replace("Z", "+00:00")) > datetime.now(UTC),
        "The synthetic observation expired; restart the fixture and collect again for a fresh inbox.",
    )
    clients = [row for row in resources if row["kind"] == "client"]
    require(
        len(clients) == 4
        and all(row["classification"] == "unassigned" and row["owner_id"] is None for row in clients),
        "Fixture devices were incorrectly assigned to a user.",
    )
    require(
        any(edge["kind"] == "connects_to" and edge["evidence_kind"] == "observed" for edge in graph["edges"])
        and any(
            edge["kind"] == "source_zone_policy" and edge["evidence_kind"] == "configured"
            for edge in graph["edges"]
        ),
        "The graph lost the distinction between observed attachment and configured policy.",
    )
    health = collection_health(client)
    require(
        all(
            health[connections[key]["id"]]["status"] == "connected"
            and health[connections[key]["id"]]["last_sync"] is not None
            for key in ("unifi", "nextdns")
        ),
        "Successful collection health did not persist.",
    )
    print(
        "PASS persisted evidence: 19 resources, 28 relationships, 1 unassigned DNS block; risk remains unknown"
    )


def main() -> int:
    """Run synthetic acceptance checks, or read-only persistence verification after an app restart."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.environ.get("NYCTR_ACCEPTANCE_URL", "http://localhost:8091"))
    parser.add_argument(
        "--verify-persistence",
        action="store_true",
        help="Verify existing synthetic connections and evidence without diagnostics or collection",
    )
    args = parser.parse_args()
    try:
        client = Client(args.url)
        wait_for_app(client)
        config = client.json("/api/auth/config")
        require(
            config.get("mode") == "live"
            and config.get("local_enabled") is True
            and config.get("oidc_enabled") is False,
            "This is not the isolated live-mode acceptance configuration.",
        )
        require(b'id="root"' in client.request("/"), "The production web application was not served.")
        client.json("/api/integrations", expected=401)
        client.login()
        connections = saved_connections(client, create=not args.verify_persistence)
        if not args.verify_persistence:
            verify_diagnostics(client, connections)
            collect_fixtures(client, connections)
        verify_persisted_evidence(client, connections)
        print(
            "PASS acceptance checks; containers remain available for browser testing on the configured loopback URL"
        )
        return 0
    except AcceptanceFailure as error:
        print(f"FAIL: {error}", file=sys.stderr)
    except (KeyError, TypeError, ValueError, OSError):
        print(
            "FAIL: An acceptance response did not match the synthetic test contract. Details suppressed.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
