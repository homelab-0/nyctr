"""Focused fixture/certificate tests; all sockets are loopback and provider transport is synthetic."""

from __future__ import annotations

import asyncio
import http.client
import json
import socket
import ssl
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import check as acceptance_check
import httpx
from create_certs import create_certificates
from cryptography import x509
from fixture import GOOD_API_KEY, UNIFI_PREFIX, make_server, response_for

# Run from a checkout with the documented API development dependencies installed.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "services" / "api"))
from nyctr.integrations import (
    collect,  # noqa: E402
    core,  # noqa: E402
)


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

    def request(self, hostname: str, path: str, key: str = GOOD_API_KEY, method: str = "GET"):
        """Verify hostname and chain while connecting only to the local fixture test socket."""
        context = ssl.create_default_context(cafile=str(self.directory / "combined-ca.pem"))
        with socket.create_connection(self.server.server_address, timeout=5) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as secured:
                secured.sendall(
                    (
                        f"{method} {path} HTTP/1.1\r\nHost: {hostname}\r\n"
                        f"X-Api-Key: {key}\r\nConnection: close\r\n\r\n"
                    ).encode()
                )
                response = http.client.HTTPResponse(secured)
                response.begin()
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

    def test_certificate_volume_is_reused_and_contains_no_ca_key(self):
        """A restart reuses trust rather than rotating a running fixture's certificate authority."""
        original = (self.directory / "fixture.pem").read_bytes()
        create_certificates(self.directory)
        self.assertEqual((self.directory / "fixture.pem").read_bytes(), original)
        self.assertEqual((self.directory / "fixture-key.pem").stat().st_mode & 0o777, 0o644)
        certificate = x509.load_pem_x509_certificate(original)
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(set(names.get_values_for_type(x509.DNSName)), {"fixture", "api.nextdns.io"})
        self.assertEqual(
            {path.name for path in self.directory.iterdir()},
            {"ca.pem", "fixture.pem", "fixture-key.pem", "combined-ca.pem"},
        )


class FixtureContractCase(unittest.TestCase):
    """Ensure synthetic responses remain compatible with the unchanged production parsers."""

    def collect_fixture(self, provider, config):
        """Use the real collector with a transport double that permits synthetic GET requests only."""

        def respond(request):
            """Translate one documented request into a fixed fixture response without a network call."""
            self.assertEqual(request.method, "GET")
            self.assertIn(request.url.host, {"fixture", "api.nextdns.io"})
            target = request.url.raw_path.decode()
            status, body = response_for(target, request.headers.get("X-Api-Key"))
            return httpx.Response(status, content=body, headers={"Content-Type": "application/json"})

        def client(api_key):
            """Preserve the production API-key header while replacing only transport for parser tests."""
            return httpx.AsyncClient(transport=httpx.MockTransport(respond), headers={"X-Api-Key": api_key})

        with (
            patch.dict("os.environ", {"NYCTR_CONNECTOR_HOSTS": "fixture"}),
            patch.object(core, "make_http_client", client),
        ):
            return asyncio.run(collect(provider, "acceptance-test", config, GOOD_API_KEY))

    def test_unifi_graph_counts_match_acceptance_assertions(self):
        """The gateway, gear, networks, clients, and policy produce the expected evidence-aware graph."""
        snapshot = self.collect_fixture(
            "unifi_network", {"base_url": "https://fixture/proxy/network/integration", "site_id": "site-one"}
        )
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
        snapshot = self.collect_fixture("nextdns", {"profile_id": "aaaaaa", "lookback_hours": 24})
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
