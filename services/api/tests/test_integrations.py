"""Meaningful provider boundary tests: real schemas, no real network calls."""

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from nyctr.integrations import IntegrationError, capabilities_for, collect, core, validate_config

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
KEY = "test-secret-must-not-leak"


def mock_client(monkeypatch, handler):
    """Replace external I/O with a clock-fixed transport enforcing GET and API-key use."""
    calls = []

    def wrapped(request):
        """Record each request and enforce the adapter transport contract before replying."""
        calls.append(request)
        assert request.method == "GET"
        assert request.headers["X-Api-Key"] == KEY
        return handler(request)

    monkeypatch.setattr(core, "utc_now", lambda: NOW)
    monkeypatch.setattr(core, "make_http_client", lambda key: httpx.AsyncClient(
        transport=httpx.MockTransport(wrapped), headers={"X-Api-Key": key},
        follow_redirects=False, trust_env=False,
    ))
    return calls


def profile():
    """Return a synthetic profile with enabled logs and representative policy evidence."""
    return {"data": {
        "name": "Home DNS", "settings": {"logs": {"enabled": True}},
        "privacy": {"blocklists": [{"id": "example-list"}]},
        "allowlist": [{"id": "allowed.example", "active": True}],
    }}


def blocked(**overrides):
    """Build a fresh blocked-query fixture with explicit source time and list reason."""
    return {
        "timestamp": core.iso(NOW - timedelta(minutes=10)),
        "domain": "blocked.example", "status": "blocked",
        "clientIp": "203.0.113.10",
        "reasons": [{"id": "blocklist:example-list", "name": "Example blocklist"}],
        **overrides,
    }


def run_nextdns():
    """Run the public adapter entry point with fixed synthetic profile credentials."""
    return asyncio.run(collect("nextdns", "integration-one", {"profile_id": "abc123"}, KEY))


def test_nextdns_collects_evidence_without_inferring_identity_or_risk(monkeypatch):
    """Keep duplicate block evidence stable, secret-free, unattributed, and unscored."""
    event = blocked()
    def handler(request):
        """Serve repeated blocks and an allowed query to test status filtering and deduplication."""
        if request.url.path == "/profiles/abc123":
            return httpx.Response(200, json=profile())
        assert request.url.path == "/profiles/abc123/logs"
        assert request.url.params["status"] == "blocked"
        return httpx.Response(200, json={"data": [event, event, blocked(status="allowed")]})
    calls = mock_client(monkeypatch, handler)
    snapshot = run_nextdns()
    assert len(snapshot.blocks) == 1
    block = snapshot.blocks[0]
    assert block["device_id"] is None
    assert block["attribution"] == "unattributed"
    assert block["risk_score"] is None
    assert block["reason"] == "Example blocklist"
    assert block["expires_at"] == core.iso(NOW - timedelta(minutes=10) + timedelta(hours=24))
    assert all(node["owner_id"] is None for node in snapshot.resources)
    assert all(request.url.host == "api.nextdns.io" for request in calls)
    assert KEY not in json.dumps(snapshot.__dict__)
    assert run_nextdns().blocks[0]["id"] == block["id"]


def test_reported_device_metadata_is_not_a_trusted_personal_device(monkeypatch):
    """Ensure provider labels alone cannot establish device ownership or member visibility."""
    def handler(request):
        """Return an apparently personal device label without authenticated ownership evidence."""
        return httpx.Response(200, json=profile() if request.url.path.endswith("abc123") else {
            "data": [blocked(device={"id": "PHONE1", "name": "Jamie's phone", "model": "Phone"})]
        })
    mock_client(monkeypatch, handler)
    snapshot = run_nextdns()
    device = next(item for item in snapshot.resources if item["kind"] == "client")
    assert device["classification"] == "unassigned"
    assert device["owner_id"] is None
    assert device["attributes"]["identity_verified"] is False
    assert snapshot.blocks[0]["device_id"] is None
    assert snapshot.blocks[0]["attribution"] == "unverified"


def test_stale_source_records_are_not_rejuvenated(monkeypatch):
    """Exclude old provider events instead of treating collection time as event time."""
    def handler(request):
        """Return an otherwise valid block whose source timestamp is outside the lookback."""
        return httpx.Response(200, json=profile() if request.url.path.endswith("abc123") else {
            "data": [blocked(timestamp=core.iso(NOW - timedelta(days=7)))]
        })
    mock_client(monkeypatch, handler)
    assert run_nextdns().blocks == []


def test_disabled_logs_do_not_claim_observation_coverage(monkeypatch):
    """Report source-disabled logging without fetching or claiming blocked-query data."""
    response = profile()
    response["data"]["settings"]["logs"]["enabled"] = False
    calls = mock_client(monkeypatch, lambda request: httpx.Response(200, json=response))
    result = run_nextdns()
    assert len(calls) == 1
    assert result.blocks == []
    assert "blocked_dns_logs:read" not in result.capabilities
    assert "blocked_dns_logs:disabled_at_source" in result.capabilities


@pytest.mark.parametrize("payload", [
    {"errors": [{"detail": KEY}]},
    {"data": [KEY]},
])
def test_api_errors_even_with_http_200_are_sanitized(monkeypatch, payload):
    """Reject malformed or provider-error payloads without reflecting embedded secrets."""
    mock_client(monkeypatch, lambda request: httpx.Response(200, json=payload))
    with pytest.raises(IntegrationError) as error:
        run_nextdns()
    assert KEY not in str(error.value)


def test_redirects_never_forward_credentials(monkeypatch):
    """Stop at a redirect before any credential-bearing request reaches another origin."""
    calls = mock_client(monkeypatch, lambda request: httpx.Response(302, headers={"Location": "https://attacker.example/collect"}))
    with pytest.raises(IntegrationError, match="redirect"):
        run_nextdns()
    assert len(calls) == 1
    assert calls[0].url.host == "api.nextdns.io"


def test_repeated_cursor_is_rejected_without_importing_partial_snapshot(monkeypatch):
    """Fail collection when a source repeats its cursor rather than accepting partial logs."""
    def handler(request):
        """Repeat a pagination cursor to model an incomplete or broken provider log feed."""
        return httpx.Response(200, json=profile() if request.url.path.endswith("abc123") else {
            "data": [blocked()], "meta": {"pagination": {"cursor": "same"}}
        })
    calls = mock_client(monkeypatch, handler)
    with pytest.raises(IntegrationError, match="repeated"):
        run_nextdns()
    assert len(calls) == 3


def test_non_string_cursor_is_rejected(monkeypatch):
    """Reject structured pagination values that could be mistaken for request destinations."""
    def handler(request):
        """Supply an attacker URL inside an invalid cursor object."""
        return httpx.Response(200, json=profile() if request.url.path.endswith("abc123") else {
            "data": [], "meta": {"pagination": {"cursor": {"url": "https://attacker.example"}}}
        })
    mock_client(monkeypatch, handler)
    with pytest.raises(IntegrationError, match="cursor"):
        run_nextdns()


def test_response_size_budget_is_enforced(monkeypatch):
    """Bound downloaded response size before parsing unexpectedly large provider content."""
    monkeypatch.setattr(core, "MAX_BODY_BYTES", 32)
    mock_client(monkeypatch, lambda request: httpx.Response(200, content=b" " * 100))
    with pytest.raises(IntegrationError, match="size limit"):
        run_nextdns()


def test_record_budget_is_enforced(monkeypatch):
    """Fail the snapshot when valid-looking rows exceed its shared resource budget."""
    monkeypatch.setattr(core, "MAX_RECORDS", 1)
    def handler(request):
        """Return two distinct valid events against an intentionally reduced record limit."""
        return httpx.Response(200, json=profile() if request.url.path.endswith("abc123") else {
            "data": [blocked(), blocked(domain="another.example")]
        })
    mock_client(monkeypatch, handler)
    with pytest.raises(IntegrationError, match="record budget"):
        run_nextdns()


def test_pagination_cursor_is_only_a_query_value_never_an_external_url(monkeypatch):
    """Keep URL-shaped cursors on the fixed NextDNS origin as opaque query values."""
    cursor = "https://attacker.example/steal"
    def handler(request):
        """Require the second request to carry the opaque cursor without navigating to it."""
        if request.url.path.endswith("abc123"):
            return httpx.Response(200, json=profile())
        if "cursor" not in request.url.params:
            return httpx.Response(200, json={"data": [], "meta": {"pagination": {"cursor": cursor}}})
        assert request.url.params["cursor"] == cursor
        return httpx.Response(200, json={"data": []})
    calls = mock_client(monkeypatch, handler)
    run_nextdns()
    assert all(request.url.host == "api.nextdns.io" for request in calls)


def log_pages(pages, fault=None):
    """Serve a newest-first blocked log of full pages; `fault` maps a page number to its reply.

    Row k of the whole log is k seconds older than the newest and has its own
    name, so a test can tell exactly which rows were kept. A cursor is offered
    after every page but the last.
    """
    def handler(request):
        """Answer the profile read, then one log page per cursor."""
        if request.url.path.endswith("abc123"):
            return httpx.Response(200, json=profile())
        assert request.url.params["sort"] == "desc"
        assert request.url.params["limit"] == str(core.PAGE_SIZE)
        page = int(request.url.params.get("cursor", "page-1").removeprefix("page-"))
        if fault and page in fault:
            return fault[page]
        first = (page - 1) * core.PAGE_SIZE
        rows = [blocked(timestamp=core.iso(NOW - timedelta(seconds=k + 1)), domain=f"d{k}.example")
                for k in range(first, first + core.PAGE_SIZE)]
        cursor = f"page-{page + 1}" if page < pages else None
        return httpx.Response(200, json={"data": rows, "meta": {"pagination": {"cursor": cursor}}})
    return handler


def test_busy_log_keeps_the_most_recent_rows_within_the_unchanged_bound(monkeypatch):
    """More blocked lookups than one collection may read: keep the newest, succeed, and say so."""
    assert (core.MAX_PAGES, core.PAGE_SIZE) == (20, 200)
    calls = mock_client(monkeypatch, log_pages(pages=core.MAX_PAGES + 10))
    snapshot = run_nextdns()
    kept = core.MAX_PAGES * core.PAGE_SIZE
    # One profile read and no more than the page bound of log reads, exactly as before.
    assert len(calls) == 1 + core.MAX_PAGES
    assert snapshot.partial_rows == kept
    assert {block["domain"] for block in snapshot.blocks} == {f"d{k}.example" for k in range(kept)}
    assert min(block["observed_at"] for block in snapshot.blocks) == core.iso(NOW - timedelta(seconds=kept))


def test_log_that_ends_on_the_last_allowed_page_is_complete(monkeypatch):
    """A window that fits the bound exactly is a complete read, not a partial one."""
    calls = mock_client(monkeypatch, log_pages(pages=core.MAX_PAGES))
    snapshot = run_nextdns()
    assert len(calls) == 1 + core.MAX_PAGES
    assert snapshot.partial_rows is None
    assert len(snapshot.blocks) == core.MAX_PAGES * core.PAGE_SIZE


@pytest.mark.parametrize("page", [3, core.MAX_PAGES])
@pytest.mark.parametrize(("reply", "message"), [
    (lambda: httpx.Response(401), "denied access"),
    (lambda: httpx.Response(403), "denied access"),
    (lambda: httpx.Response(200, json={"data": ["not a row"]}), "invalid list"),
    (lambda: httpx.Response(200, content=b"{not json"), "invalid JSON"),
    (lambda: httpx.Response(200, json={"data": [blocked()], "meta": {"pagination": {"cursor": 7}}}), "invalid or repeated"),
    (lambda: httpx.Response(200, json={"data": [blocked()], "meta": {"pagination": {"cursor": "page-2"}}}),
     "invalid or repeated"),
    (lambda: httpx.Response(200, content=b" " * (core.MAX_BODY_BYTES + 1)), "size limit"),
])
def test_a_fault_on_a_later_page_still_fails_and_returns_nothing(monkeypatch, page, reply, message):
    """Keeping recent rows applies only to the page bound: every other fault discards what was read.

    Each fault is tried mid-log and on the last allowed page, where the bound
    must not turn it into a partial success.
    """
    calls = mock_client(monkeypatch, log_pages(pages=core.MAX_PAGES + 10, fault={page: reply()}))
    with pytest.raises(IntegrationError, match=message) as error:
        run_nextdns()
    assert len(calls) == 1 + page
    assert KEY not in str(error.value)


@pytest.mark.parametrize("url", [
    "http://unifi.example/proxy/network/integration",
    "https://user:password@unifi.example/proxy/network/integration",
    "https://unifi.example/proxy/network/integration?key=secret",
    "https://unifi.example/proxy/network/integration#fragment",
    "https://other.example/proxy/network/integration",
    "https://127.0.0.1/proxy/network/integration",
    "https://169.254.169.254/proxy/network/integration",
    "https://[::1]/proxy/network/integration",
    "https://unifi.example/arbitrary/key-destination",
])
def test_unifi_destination_boundaries(monkeypatch, url):
    """Reject insecure, credential-bearing, unapproved, and metadata-targeting endpoints."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "unifi.example,127.0.0.1,169.254.169.254,::1")
    with pytest.raises(IntegrationError):
        validate_config("unifi_network", {"base_url": url})


def test_expected_private_gateway_requires_explicit_allowlist(monkeypatch):
    """Permit an intended private console only with explicit server-side host approval."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "10.20.65.1")
    config = validate_config("unifi_network", {"base_url": "https://10.20.65.1/proxy/network/integration/"})
    assert config["base_url"] == "https://10.20.65.1/proxy/network/integration"


def test_nextdns_does_not_accept_credential_destinations_or_inline_secrets():
    """Prevent NextDNS configuration from overriding its fixed origin or storing a key."""
    for config in ({"profile_id": "abc123", "base_url": "https://attacker.example"}, {"profile_id": "abc123", "api_key": KEY}):
        with pytest.raises(IntegrationError):
            validate_config("nextdns", config)


def unifi_page(rows):
    """Wrap fixture rows in the documented UniFi offset-pagination response shape."""
    return {"data": rows, "count": len(rows), "offset": 0, "totalCount": len(rows)}


def test_unifi_models_real_uplink_and_policy_evidence_not_access_results(monkeypatch):
    """Keep source attachment and configured zone policy distinct from traffic outcomes."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "unifi.example")
    pages = {
        "/v1/sites": [{"id": "site-one", "name": "Lab"}],
        "/v1/sites/site-one/devices": [{"id": "gw-one", "name": "Gateway", "features": ["gateway", "switching"]}],
        "/v1/sites/site-one/networks": [{"id": "net-one", "name": "LAN", "vlanId": 66, "zoneId": "internal"}],
        "/v1/sites/site-one/clients": [{"id": "client-one", "name": "Laptop", "uplinkDeviceId": "gw-one", "ipAddress": "10.20.66.10", "type": "WIRED"}],
        "/v1/sites/site-one/firewall/policies": [{"id": "rule-one", "name": "Block management", "action": {"type": "BLOCK"}, "source": {"zoneId": "internal"}, "destination": {"zoneId": "external"}, "index": 10}],
        "/v1/sites/site-one/hotspot/vouchers": [],
        "/v1/sites/site-one/wifi/broadcasts": [
            {"id": "w1", "name": "Home", "enabled": True, "network": {"type": "NATIVE"}},
            {"id": "w2", "name": "Home Guest", "enabled": True, "hotspotConfiguration": {"type": "CAPTIVE_PORTAL"},
             "network": {"type": "SPECIFIC", "networkId": "network-one"}},
        ],
    }
    def handler(request):
        """Route source-contract fixtures only through the approved UniFi integration path."""
        assert request.url.host == "unifi.example"
        path = request.url.path.removeprefix("/proxy/network/integration")
        return httpx.Response(200, json=unifi_page(pages[path])) if path in pages else httpx.Response(404)
    mock_client(monkeypatch, handler)
    snapshot = asyncio.run(collect("unifi_network", "u-one", {"base_url": "https://unifi.example/proxy/network/integration"}, KEY))
    assert len(snapshot.resources) == 5
    assert snapshot.blocks == []
    uplink = next(edge for edge in snapshot.relationships if edge["kind"] == "connects_to")
    assert uplink["source"] == "u-one:client:client-one"
    assert uplink["target"] == "u-one:gateway:gw-one"
    assert uplink["evidence_kind"] == "observed"
    policy = next(node for node in snapshot.resources if node["kind"] == "policy")
    assert policy["evidence_kind"] == "configured"
    assert any(edge["kind"] == "source_zone_policy" for edge in snapshot.relationships)
    assert all(node["owner_id"] is None for node in snapshot.resources)
    assert all(edge["kind"] not in {"allows", "denies", "reachable"} for edge in snapshot.relationships)
    # Wi-Fi names are kept on the site with whether UniFi's captive portal gates them.
    site = next(node for node in snapshot.resources if node["kind"] == "site")
    assert site["attributes"]["wifi"] == [
        {"name": "Home", "enabled": True, "captive_portal": False, "network_id": None},
        {"name": "Home Guest", "enabled": True, "captive_portal": True, "network_id": "network-one"}]


def unifi_guests(monkeypatch, sites, guests_per_site, *, detail_status=200, voucher_status=200):
    """Serve a synthetic UniFi with guest clients on every site and count the detail reads."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "unifi.example")

    def handler(request):
        """Answer the documented list paths, one guest detail path and the optional reads."""
        path = request.url.path.removeprefix("/proxy/network/integration")
        if path == "/v1/sites":
            return httpx.Response(200, json=unifi_page([{"id": f"site-{n}", "name": f"Site {n}"} for n in range(sites)]))
        site, _, rest = path.removeprefix("/v1/sites/").partition("/")
        if rest == "clients":
            return httpx.Response(200, json=unifi_page([
                {"id": f"{site}-guest-{n}", "name": f"Guest {n}", "access": {"type": "GUEST", "authorized": True}}
                for n in range(guests_per_site)]))
        if rest.startswith("clients/"):
            return httpx.Response(detail_status, json={"id": rest.removeprefix("clients/"), "access": {
                "type": "GUEST", "authorized": True,
                "authorization": {"authorizationMethod": "VOUCHER", "authorizedAt": "2026-07-02T11:00:00Z"}}})
        if rest == "hotspot/vouchers":
            return httpx.Response(voucher_status, json=unifi_page([]))
        return httpx.Response(200, json=unifi_page([]))

    calls = mock_client(monkeypatch, handler)
    return calls, lambda: asyncio.run(collect(
        "unifi_network", "u-one", {"base_url": "https://unifi.example/proxy/network/integration"}, KEY))


def test_guest_detail_reads_are_capped_for_the_whole_collection(monkeypatch):
    """The cap on per-guest reads is one total, so several busy sites cannot spend the request budget."""
    calls, run = unifi_guests(monkeypatch, sites=3, guests_per_site=30)
    snapshot = run()
    details = [c for c in calls if "/clients/" in c.url.path]
    assert len(details) == 40
    guests = [r for r in snapshot.resources if r["kind"] == "client"]
    assert len(guests) == 90 and sum(g["attributes"]["guest"].get("method") == "pass" for g in guests) == 40
    assert len(calls) <= core.MAX_REQUESTS


def test_a_spent_request_budget_fails_the_collection_instead_of_posing_as_a_missing_feature(monkeypatch):
    """Running out of requests during an optional read is a failure, not "the key cannot read this"."""
    monkeypatch.setattr(core, "MAX_REQUESTS", 8)
    _calls, run = unifi_guests(monkeypatch, sites=1, guests_per_site=10)
    with pytest.raises(core.BudgetExceeded, match="request budget"):
        run()


@pytest.mark.parametrize("status, stops", [(429, True), (403, False), (404, False), (503, False)])
def test_optional_reads_stop_on_a_rate_limit_but_record_a_gap_when_unavailable(monkeypatch, status, stops):
    """A rate limit must end the collection; a read this key or site lacks is only a gap."""
    _calls, run = unifi_guests(monkeypatch, sites=1, guests_per_site=1, voucher_status=status)
    if stops:
        with pytest.raises(IntegrationError) as caught:
            run()
        assert caught.value.category == "rate_limit"
    else:
        snapshot = run()
        assert "hotspot_vouchers:read" not in snapshot.capabilities and len(snapshot.resources) == 2


@pytest.mark.parametrize("status, headers, category, transient, wait", [
    (503, {}, "provider_contract", True, None), (500, {}, "provider_contract", True, None),
    (404, {}, "provider_contract", False, None), (429, {"Retry-After": "120"}, "rate_limit", False, 120),
    (429, {"Retry-After": "86400"}, "rate_limit", False, 3600),
    (429, {"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}, "rate_limit", False, None),
    (429, {}, "rate_limit", False, None)])
def test_a_server_error_may_pass_and_a_rate_limit_keeps_its_wait_in_seconds(
        monkeypatch, status, headers, category, transient, wait):
    """A 5xx keeps its category and plain message; only Retry-After in seconds is read, capped at an hour."""
    mock_client(monkeypatch, lambda request: httpx.Response(status, headers=headers, text="secret-bearing body"))
    with pytest.raises(IntegrationError) as caught:
        run_nextdns()
    error = caught.value
    assert (error.category, error.transient, error.retry_after) == (category, transient, wait)
    assert "secret" not in str(error) and (status != 503 or str(error) == "Provider returned HTTP 503.")


def test_repeated_offset_page_is_rejected(monkeypatch):
    """Detect repeated inventory pages even when their offset metadata changes."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "unifi.example")
    def handler(request):
        """Echo the requested offset while repeating the same resource to simulate source drift."""
        return httpx.Response(200, json={"data": [{"id": "site-one", "name": "Lab"}], "count": 1, "offset": int(request.url.params["offset"]), "totalCount": 3})
    calls = mock_client(monkeypatch, handler)
    with pytest.raises(IntegrationError, match="repeated"):
        asyncio.run(collect("unifi_network", "u-one", {"base_url": "https://unifi.example/proxy/network/integration"}, KEY))
    assert len(calls) == 2


def test_transport_configuration_requires_tls_and_disables_redirects_and_environment_proxy(monkeypatch):
    """Verify the production client protects credentials regardless of host proxy settings."""
    monkeypatch.delenv("NYCTR_CONNECTOR_CA_BUNDLE", raising=False)
    kwargs_seen = {}
    def fake_client(**kwargs):
        """Capture constructor options without constructing a network-capable client."""
        kwargs_seen.update(kwargs)
        return object()
    monkeypatch.setattr(core.httpx, "AsyncClient", fake_client)
    core.make_http_client(KEY)
    assert kwargs_seen["verify"] is True
    assert kwargs_seen["follow_redirects"] is False
    assert kwargs_seen["trust_env"] is False
    assert kwargs_seen["headers"]["X-Api-Key"] == KEY


def test_unsupported_fabric_contract_is_not_advertised_as_full_coverage():
    """Keep unsupported Fabric policy capabilities unadvertised and unconfigurable."""
    assert capabilities_for("unifi_fabric") == []
    with pytest.raises(IntegrationError, match="not implemented"):
        validate_config("unifi_fabric", {})


def test_max_length_domains_fit_postgresql_identifiers_and_keep_source_evidence(monkeypatch):
    # A valid 253-character DNS name exceeds VARCHAR(255) once namespaced.
    """Preserve full DNS evidence while bounding deterministic IDs for PostgreSQL storage."""
    domain = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 61])
    assert len(domain) == 253
    def handler(request):
        """Serve a maximum-length DNS name through the actual profile/log collection flow."""
        return httpx.Response(200, json=profile() if request.url.path.endswith("abc123") else {
            "data": [blocked(domain=domain)]
        })
    mock_client(monkeypatch, handler)
    result = run_nextdns()
    node = next(item for item in result.resources if item["kind"] == "domain")
    assert len(node["id"]) <= 255
    assert node["source_id"] == domain
    assert node["name"] == domain
    assert result.blocks[0]["domain"] == domain
    assert node["id"] == next(
        item["id"] for item in run_nextdns().resources if item["kind"] == "domain"
    )
    assert any(edge["target"] == node["id"] for edge in result.relationships)


def test_long_source_ids_use_distinct_stable_hashes_with_bounded_namespace():
    """Distinguish long source IDs and retain originals while enforcing storage limits."""
    namespace = "i" * 128
    source_a, source_b = "x" * 254 + "a", "x" * 254 + "b"
    id_a = core.object_id(namespace, "dns_profile", source_a)
    id_b = core.object_id(namespace, "dns_profile", source_b)
    assert len(id_a) <= 255 and len(id_b) <= 255
    assert id_a != id_b
    assert id_a == core.object_id(namespace, "dns_profile", source_a)
    node = core.resource(namespace, "nextdns", "dns_profile", source_a, "n" * 500, core.iso(NOW))
    assert node["source_id"] == source_a
    assert len(node["name"]) == 255
    assert node["id"] == id_a
    with pytest.raises(IntegrationError, match="namespace"):
        core.object_id("i" * 129, "domain", "example.com")
