"""Focused fixture/certificate tests; all sockets are loopback and provider transport is synthetic."""

from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import check as acceptance_check
import fixture
import httpx
from create_certs import create_certificates
from cryptography import x509
from fixture import GOOD_API_KEY, LIMITED_API_KEY, UNIFI_PREFIX, make_server, response_for

# Run from a checkout with the documented API development dependencies installed.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api"))
from nyctr.integrations import (
    actions,  # noqa: E402
    collect,  # noqa: E402
    core,  # noqa: E402
)

UNIFI = {"base_url": "https://fixture/proxy/network/integration", "site_id": "site-one"}
LARGE = {**UNIFI, "site_id": "site-large"}
NEXTDNS = {"profile_id": "aaaaaa", "lookback_hours": 24}


class FixtureTLSCase(unittest.TestCase):
    """Verify the real test trust chain, valid aliases, and intentional hostname failure."""

    @classmethod
    def setUpClass(cls):
        """Start one ephemeral CA-signed server on an OS-selected loopback port."""
        cls.temporary = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temporary.name)
        create_certificates(cls.directory)
        cls.server = make_server(cls.directory, host="127.0.0.1", port=0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        """Stop the isolated server and remove its disposable certificate material."""
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)
        cls.temporary.cleanup()

    def request(self, hostname: str, path: str, key: str = GOOD_API_KEY, method: str = "GET",
                body: bytes = b"", length: int = 0):
        """Verify hostname and chain while connecting only to the local fixture test socket."""
        context = ssl.create_default_context(cafile=str(self.directory / "combined-ca.pem"))
        with socket.create_connection(self.server.server_address, timeout=5) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as secured:
                secured.sendall(
                    (
                        f"{method} {path} HTTP/1.1\r\nHost: {hostname}\r\n"
                        f"X-Api-Key: {key}\r\nContent-Length: {length or len(body)}\r\nConnection: close\r\n\r\n"
                    ).encode() + body
                )
                response = http.client.HTTPResponse(secured)
                response.begin()
                self.retry_after = response.getheader("Retry-After")
                return response.status, response.read()

    def test_valid_names_and_normal_api_rejection(self):
        """Both intended aliases verify normally, and bad credentials produce an ordinary 401."""
        for hostname, path in (("fixture", f"{UNIFI_PREFIX}/sites"), ("api.nextdns.io", "/profiles/aaaaaa")):
            status, body = self.request(hostname, path)
            self.assertEqual(status, 200)
            self.assertIn("data", json.loads(body))
        self.assertEqual(self.request("fixture", f"{UNIFI_PREFIX}/sites", "fake-rejected")[0], 401)

    def test_untrusted_alias_fails_hostname_validation(self):
        """A trusted CA cannot make an unlisted hostname valid for the fixture leaf."""
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.request("untrusted-fixture", f"{UNIFI_PREFIX}/sites")

    def test_public_trust_alone_rejects_the_fixture_ca(self):
        """The disposable CA is trusted only through the explicit test bundle."""
        context = ssl.create_default_context()
        with socket.create_connection(self.server.server_address, timeout=5) as connection:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(connection, server_hostname="fixture")

    def test_write_methods_are_rejected(self):
        """The synthetic provider does not accept mutations even with its known test key."""
        self.assertEqual(self.request("fixture", f"{UNIFI_PREFIX}/sites", method="POST")[0], 405)

    def test_a_change_is_read_only_when_changes_are_on(self):
        """Refused without waiting for contents that never come on the default start; read and made once on."""
        path = "/profiles/aaaaaa/allowlist"
        self.assertEqual(self.request("api.nextdns.io", path, method="POST", length=40)[0], 405)
        self.addCleanup(fixture.ALLOWLISTS.clear)
        with patch.dict(fixture.SWITCHES, {"writes": "on"}):
            sent = b'{"id":"photos.example.test"}'
            self.assertEqual(self.request("api.nextdns.io", path, method="POST", body=sent)[0], 200)
        self.assertEqual(fixture.ALLOWLISTS[path], [{"id": "photos.example.test", "active": True}])

    def test_switched_faults_reach_the_wire_and_pass(self):
        """A planned rate limit states its wait, a planned break sends nothing, and both are used up."""
        with patch.dict(fixture.SWITCHES, {"fail": "limit:1", "retry_after": "150", "slow": "0.1"}):
            self.assertEqual(self.request("fixture", f"{UNIFI_PREFIX}/sites")[0], 429)
            self.assertEqual(self.retry_after, "150")
            self.assertEqual(self.request("fixture", f"{UNIFI_PREFIX}/sites")[0], 200)
            for kind in ("drop", "timeout"):
                fixture.set_switch("fail", f"{kind}:1")
                with patch.object(fixture, "TIMEOUT_HOLD", 0.1), self.assertRaises(http.client.HTTPException):
                    self.request("fixture", f"{UNIFI_PREFIX}/sites")
                self.assertEqual(self.request("api.nextdns.io", "/profiles/aaaaaa")[0], 200)

    def test_certificate_volume_is_reused_and_contains_no_ca_key(self):
        """A restart reuses trust rather than rotating a running fixture's certificate authority."""
        original = (self.directory / "fixture.pem").read_bytes()
        create_certificates(self.directory)
        self.assertEqual((self.directory / "fixture.pem").read_bytes(), original)
        self.assertEqual((self.directory / "fixture-key.pem").stat().st_mode & 0o777, 0o644)
        certificate = x509.load_pem_x509_certificate(original)
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(set(names.get_values_for_type(x509.DNSName)), {"fixture", "api.nextdns.io", "api.ui.com"})
        self.assertEqual(
            {path.name for path in self.directory.iterdir()},
            {"ca.pem", "fixture.pem", "fixture-key.pem", "combined-ca.pem"},
        )


class FixtureContractCase(unittest.TestCase):
    """Ensure synthetic responses remain compatible with the unchanged production parsers."""

    def through_fixture(self, call):
        """Run real adapter code with a transport double: reads only, unless changes are switched on."""

        def respond(request):
            """Translate one documented request into a fixture response without a network call."""
            if not fixture.SWITCHES["writes"]:
                self.assertEqual(request.method, "GET")
            self.assertIn(request.url.host, {"fixture", "api.nextdns.io", "api.ui.com"})
            target = request.url.raw_path.decode()
            status, body = response_for(target, request.headers.get("X-Api-Key"), request.method, request.content)
            if not status:
                raise httpx.ConnectError("The fixture sent no answer.")
            return httpx.Response(status, content=body, headers={"Content-Type": "application/json"})

        def client(api_key):
            """Preserve the production API-key header while replacing only transport for parser tests."""
            return httpx.AsyncClient(transport=httpx.MockTransport(respond), headers={"X-Api-Key": api_key})

        with (
            patch.dict("os.environ", {"NYCTR_CONNECTOR_HOSTS": "fixture,api.ui.com"}),
            patch.object(core, "make_http_client", client),
        ):
            return asyncio.run(call)

    def collect_fixture(self, provider, config, key=GOOD_API_KEY):
        """Collect with the real collector and keep what it recorded as not read."""
        with core.capture_probe() as self.evidence:
            return self.through_fixture(collect(provider, "acceptance-test", config, key))

    def test_large_site_is_real_size_and_reads_cleanly(self):
        """Ten networks, 13 pieces of equipment, 67 clients and 230 policies in two pages, with nothing left unread."""
        snapshot = self.collect_fixture("unifi_network", LARGE)
        kinds = [node["kind"] for node in snapshot.resources]
        self.assertEqual({kind: kinds.count(kind) for kind in set(kinds)}, {
            "site": 1, "gateway": 1, "switch": 4, "access_point": 8, "network": 10, "client": 67, "policy": 230})
        self.assertEqual(self.evidence.gaps, set())
        # The gateway's lists give 25 rows unless asked and never more than 200, so the policies take two reads.
        listed = [json.loads(response_for(f"{fixture.LARGE}/{rows}", GOOD_API_KEY)[1])
                  for rows in ("firewall/policies", "firewall/policies?limit=200", "clients?limit=200")]
        self.assertEqual([(page["count"], page["totalCount"]) for page in listed], [(25, 230), (200, 230), (67, 67)])
        self.assertEqual(response_for(f"{fixture.LARGE}/clients?limit=201", GOOD_API_KEY)[0], 400)
        # Only the read of one client says how and until when a guest was let on.
        self.assertNotIn("authorization", json.dumps(listed[2]))
        self.assertIn("authorization", json.loads(response_for(f"{fixture.LARGE}/clients/big-client-02", GOOD_API_KEY)[1])["access"])
        cloud = {**LARGE, "base_url": "https://api.ui.com/v1/connector/consoles/example-console/proxy/network/integration"}
        self.assertEqual(len(self.collect_fixture("unifi_network", cloud).resources), len(snapshot.resources))
        gateway = next(node for node in snapshot.resources if node["kind"] == "gateway")
        self.assertEqual((gateway["name"], gateway["attributes"]["kind_basis"]),
                         ("Example gateway", "outside_network_ranges"))
        self.assertEqual(sum(edge["attributes"].get("source_field") == "device.uplink.deviceId"
                             for edge in snapshot.relationships), 12)
        ranges = [ipaddress.ip_network(subnet) for node in snapshot.resources
                  for subnet in node["attributes"].get("subnets", [])]
        self.assertEqual(len(ranges), 10)
        clients = [node["attributes"] for node in snapshot.resources if node["kind"] == "client"]
        placed = [sum(ipaddress.ip_address(row["ip"]) in subnet for subnet in ranges) for row in clients if "ip" in row]
        self.assertEqual((placed.count(1), placed.count(0), len(clients) - len(placed)), (63, 2, 2))
        # Guests of the one Wi-Fi name behind a sign-in page: four let on by a pass, one waiting.
        guests = [row["guest"] for row in clients if "guest" in row]
        self.assertEqual(sorted(guest.get("method") or "waiting" for guest in guests), ["pass"] * 4 + ["waiting"])
        wifi = snapshot.resources[0]["attributes"]["wifi"]
        self.assertEqual([(row["name"], row["network_id"]) for row in wifi if row["captive_portal"]],
                         [("Example Guest Wi-Fi", "big-net-2")])

    def test_refused_and_failed_optional_reads_are_gaps_with_their_cause(self):
        """The limited key and the two path switches each leave one gap, told apart by cause."""
        self.collect_fixture("unifi_network", UNIFI, LIMITED_API_KEY)
        self.assertEqual(self.evidence.gap_causes, {"unifi_wifi_unavailable": {"refused"}})
        with patch.dict(fixture.SWITCHES, {"refuse": "hotspot/vouchers", "error": "networks/network-two"}):
            snapshot = self.collect_fixture("unifi_network", UNIFI)
        self.assertEqual(len(snapshot.resources), 11)
        self.assertEqual(self.evidence.gap_causes, {"unifi_vouchers_unavailable": {"refused"},
                                                    "unifi_networks_details_unavailable": {"source_error"}})

    def test_profile_over_its_bound_is_a_partial_collection(self):
        """More log rows than one collection reads: the newest 4000 are kept and it says so."""
        snapshot = self.collect_fixture("nextdns", {"profile_id": "dddddd", "lookback_hours": 24})
        self.assertEqual((snapshot.partial_rows, len(snapshot.blocks)), (4000, 400))
        self.assertGreater(fixture.OVER_BOUND, core.MAX_PAGES * core.PAGE_SIZE)

    def test_a_planned_failure_fails_a_collection_then_passes(self):
        """A rate limit and a broken connection each fail one collection in the category Nyctr retries."""
        for fault, category in (("limit:1", "rate_limit"), ("drop:1", "transport")):
            with patch.dict(fixture.SWITCHES, {"fail": fault}):
                with self.assertRaises(core.IntegrationError) as error:
                    self.collect_fixture("nextdns", NEXTDNS)
                self.assertEqual(error.exception.category, category)
                self.assertEqual(len(self.collect_fixture("nextdns", NEXTDNS).blocks), 1)

    def test_changes_are_accepted_remembered_and_reported_back_when_allowed(self):
        """Every change Nyctr can make, through the real action code, then read back from the fixture."""
        self.assertEqual(response_for("/control?writes=maybe", GOOD_API_KEY)[0], 400)
        self.addCleanup(fixture.set_switch, "writes", "")
        self.assertEqual(json.loads(response_for("/control?writes=on", GOOD_API_KEY)[1])["writes"], "on")
        run, key = self.through_fixture, GOOD_API_KEY
        self.assertEqual(run(actions.nextdns_allow(NEXTDNS, key, "photos.example.test", allowed=True))["owned"], True)
        self.assertEqual(json.loads(response_for("/profiles/aaaaaa", key)[1])["data"]["allowlist"],
                         [{"id": "photos.example.test", "active": True}])
        self.assertEqual(run(actions.nextdns_disallow(NEXTDNS, key, "photos.example.test", allowed=True)),
                         {"removed": True, "verified": True})
        issued = run(actions.unifi_create_voucher(LARGE, key, "site-large", name="Example pass", minutes=60,
                                                  guest_limit=2, data_limit_mb=None, allowed=True))
        self.assertEqual([row["id"] for row in self.collect_fixture("unifi_network", LARGE).passes], [issued["id"]])
        run(actions.unifi_delete_voucher(LARGE, key, "site-large", issued["id"], allowed=True))
        self.assertEqual(self.collect_fixture("unifi_network", LARGE).passes, [])
        clients = fixture.UNIFI_ROWS[f"{fixture.LARGE}/clients"]
        self.addCleanup(clients.__setitem__, slice(None), [dict(row) for row in clients])
        # A guest let on is read back. One cut off is disconnected and no longer listed, so nothing can be read back.
        for allow, read_back in ((True, {"authorized": True, "verified": True}), (False, {"authorized": None, "verified": False})):
            done = run(actions.unifi_set_guest_access(LARGE, key, "site-large", "big-client-62", allow,
                                                      minutes=30, allowed=True))
            self.assertEqual(done, read_back)
        self.assertEqual(len(clients), 66)
        fixture.set_switch("writes", "fail")
        with self.assertRaises(core.IntegrationError):
            run(actions.nextdns_allow(NEXTDNS, key, "photos.example.test", allowed=True))
        self.assertEqual(json.loads(response_for("/profiles/aaaaaa/allowlist", key)[1]), {"data": []})

    def test_unifi_graph_counts_match_acceptance_assertions(self):
        """The gateway, gear, networks, clients, and policy produce the expected evidence-aware graph."""
        snapshot = self.collect_fixture("unifi_network", UNIFI)
        self.assertEqual(
            (len(snapshot.resources), len(snapshot.relationships), len(snapshot.blocks)), (11, 17, 0)
        )
        self.assertIn("source_zone_policy", {edge["kind"] for edge in snapshot.relationships})
        # The gateway is listed with switching only and reports an address outside every range.
        # It is filed because it is the only such gear and has nothing above it, and is marked so.
        self.assertEqual(
            [(node["name"], node["attributes"]["kind_basis"]) for node in snapshot.resources if node["kind"] == "gateway"],
            [("Synthetic gateway", "outside_network_ranges")],
        )
        # Which network a device is on is never something the source said, so it is never collected.
        self.assertNotIn("member_of", {edge["kind"] for edge in snapshot.relationships})

    def test_nextdns_block_stays_unassigned_with_unknown_risk(self):
        """A provider device label must not become a user identity or a fabricated risk score."""
        snapshot = self.collect_fixture("nextdns", NEXTDNS)
        self.assertEqual(
            (len(snapshot.resources), len(snapshot.relationships), len(snapshot.blocks)), (8, 7, 1)
        )
        self.assertIsNone(snapshot.blocks[0]["device_id"])
        self.assertIsNone(snapshot.blocks[0]["risk_score"])
        self.assertEqual(snapshot.blocks[0]["attribution"], "unverified")

    def test_disabled_logs_do_not_query_the_rejecting_log_endpoint(self):
        """The disabled profile succeeds without calling its intentionally failing logs route."""
        snapshot = self.collect_fixture("nextdns", {"profile_id": "bbbbbb", "lookback_hours": 24})
        self.assertEqual(
            (len(snapshot.resources), len(snapshot.relationships), len(snapshot.blocks)), (6, 5, 0)
        )
        self.assertIn("blocked_dns_logs:disabled_at_source", snapshot.capabilities)

    def test_malformed_fixture_fails_normal_contract_parsing(self):
        """Invalid JSON triggers the ordinary provider-contract failure without reflecting its contents."""
        with self.assertRaises(core.IntegrationError) as error:
            self.collect_fixture("nextdns", {"profile_id": "cccccc", "lookback_hours": 24})
        self.assertEqual(error.exception.category, "provider_contract")
        self.assertNotIn("fixture-private-error-marker", str(error.exception))


class ReadOnlyDefaultCase(unittest.TestCase):
    """The compose file is the whole control over whether a start may change the fake sources."""

    def test_compose_allows_no_change_unless_asked(self):
        """Both sides stay empty, which is read only, unless NYCTR_ACCEPTANCE_WRITES is set at the start."""
        compose = (Path(__file__).parent / "compose.yaml").read_text()
        self.assertEqual(re.findall(r"(?:FIXTURE_WRITES=|NYCTR_PROVIDER_WRITES: )(.*)", compose),
                         ["${NYCTR_ACCEPTANCE_WRITES:+on}", "${NYCTR_ACCEPTANCE_WRITES:-}"])


class AcceptanceURLCase(unittest.TestCase):
    """Keep the stdlib acceptance client from targeting a homelab or public deployment."""

    def test_loopback_origins_are_accepted(self):
        """Default and alternative loopback ports remain usable for isolated local Docker runs."""
        for url in ("http://localhost:8091", "http://127.0.0.1:19091/", "http://[::1]:8091"):
            self.assertEqual(acceptance_check.loopback_url(url), url.rstrip("/"))

    def test_remote_and_credential_bearing_urls_are_rejected(self):
        """Reject network destinations and URL suffixes before sending the synthetic login."""
        for url in (
            "https://nyctr.example.test",
            "http://192.168.1.10:8091",
            "http://127.0.0.1.example.test",
            "http://tester:secret@localhost:8091",
            "http://localhost:8091/api",
            "http://localhost:8091?next=x",
            "file:///tmp/nyctr",
            "http://[::1]:99999",
            "http://localhost:8091#token",
        ):
            with self.subTest(url=url), self.assertRaises(acceptance_check.AcceptanceFailure):
                acceptance_check.loopback_url(url)


if __name__ == "__main__":
    unittest.main()
