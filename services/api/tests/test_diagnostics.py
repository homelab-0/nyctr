"""Diagnostics exercise real adapter parsing while keeping all provider traffic synthetic."""

import asyncio
import ssl
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import timedelta
from threading import Event

import httpx
import pytest
from sqlalchemy import select
from test_collection import live_client, setup_integration

from nyctr.integrations import IntegrationError, Snapshot, core
from nyctr.models import (
    AccessRequest,
    Audit,
    DeviceGrant,
    Finding,
    Integration,
    Observation,
    Relationship,
    Resource,
    User,
    utc,
    utcnow,
)

KEY = "DIAGNOSTIC_SECRET_SENTINEL"
SOURCE_TEXT = "UNTRUSTED_PROVIDER_SENTINEL"


@pytest.fixture
def saved(tmp_path, monkeypatch):
    """Create a live integration with a server secret and an authenticated administrator."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", KEY)
    with live_client(tmp_path) as client:
        headers, integration_id = setup_integration(client)
        yield client, headers, integration_id


def provider_transport(monkeypatch, handler):
    """Record synthetic credential-bearing requests and enforce the real GET-only adapter boundary."""
    calls = []

    def receive(request):
        """Reject mutations and unexpected credentials before dispatching a fabricated response."""
        assert request.method == "GET"
        assert request.headers["X-Api-Key"] == KEY
        calls.append(request)
        return handler(request)

    def make_client(api_key):
        """Supply an isolated HTTP transport without changing provider origins or adapter parsing."""
        return httpx.AsyncClient(transport=httpx.MockTransport(receive),
                                headers={"X-Api-Key": api_key}, follow_redirects=False, trust_env=False)

    monkeypatch.setattr(core, "make_http_client", make_client)
    return calls


def profile(*, logging=True):
    """Expose every supported policy section and an explicit logging setting in a synthetic profile."""
    return {"data": {"name": SOURCE_TEXT, "settings": {"logs": {"enabled": logging}},
                     "security": {}, "privacy": {}, "parentalControl": {}, "allowlist": [], "denylist": []}}


def nextdns_response(request):
    """Return a complete profile and a fresh private-looking block that must never be reflected."""
    if request.url.path == "/profiles/abc123":
        return httpx.Response(200, json=profile())
    assert request.url.path == "/profiles/abc123/logs"
    return httpx.Response(200, json={"data": [{
        "timestamp": core.iso(utcnow() - timedelta(minutes=1)), "domain": "private-browsing.example",
        "status": "blocked", "device": {"id": "source-phone", "name": SOURCE_TEXT},
        "reasons": [{"name": SOURCE_TEXT}],
    }]})


def run_probe(saved):
    """Run the protected endpoint and return a completed report, including diagnosed source failures."""
    client, headers, integration_id = saved
    response = client.post(f"/api/integrations/{integration_id}/diagnostics", headers=headers)
    assert response.status_code == 200, response.text
    assert KEY not in response.text and SOURCE_TEXT not in response.text
    assert "private-browsing.example" not in response.text
    return response.json()


def checks(report):
    """Index fixed check identifiers without depending on their display order or wording."""
    return {item["id"]: item for item in report["checks"]}


def capabilities(report):
    """Index capability verification independently from whether the adapter implements it."""
    return {item["id"]: item for item in report["capabilities"]}


def evidence_rows(client):
    """Snapshot every evidence/request table so probes cannot silently import or modify source data."""
    with client.app.state.session_factory() as db:
        return {model.__tablename__: list(db.execute(select(model.__table__)).mappings())
                for model in (Resource, Relationship, Observation, DeviceGrant, Finding, AccessRequest)}


def test_diagnostics_are_admin_only_csrf_protected_and_disabled_in_demo(client, monkeypatch):
    """Reject unauthenticated, member, CSRF-less, and demo probes before any provider call."""
    calls = provider_transport(monkeypatch, nextdns_response)
    path = "/api/integrations/demo-nextdns/diagnostics"
    assert client.post(path).status_code == 401
    member = client.post("/api/auth/login", json={"email": "jamie@nyctr.demo", "password": "nyctr-demo"}).json()
    assert client.post(path, headers={"X-CSRF-Token": member["csrf_token"]}).status_code == 403
    admin = client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "nyctr-demo"}).json()
    assert client.post(path).status_code == 403
    assert client.post(path, headers={"X-CSRF-Token": admin["csrf_token"]}).status_code == 409
    assert calls == []


def test_live_member_and_missing_integration_never_contact_provider(saved, monkeypatch):
    """Apply authorization in live mode and keep nonexistent integration probes side-effect free."""
    client, headers, integration_id = saved
    calls = provider_transport(monkeypatch, nextdns_response)
    assert client.post("/api/integrations/missing/diagnostics", headers=headers).status_code == 404
    with client.app.state.session_factory() as db:
        db.scalar(select(User)).role = "member"
        db.commit()
    assert client.post(f"/api/integrations/{integration_id}/diagnostics", headers=headers).status_code == 403
    assert calls == []


def test_verified_reads_do_not_persist_snapshot_or_replace_collection_health(saved, monkeypatch):
    """A successful diagnostic preserves existing evidence and collection state while auditing safe counts."""
    client, _, integration_id = saved
    calls = provider_transport(monkeypatch, nextdns_response)
    with client.app.state.session_factory() as db:
        integration = db.get(Integration, integration_id)
        integration.status = "error"
        integration.last_error = "Previous collection failed"
        integration.last_sync = utcnow() - timedelta(days=1)
        db.add(Resource(id="existing", integration_id=integration_id, name="Existing evidence", kind="dns_profile",
                        provider="nextdns", source_id="existing", observed_at=utcnow(), evidence_kind="configured"))
        db.add(Observation(id="existing-event", integration_id=integration_id, device_id=None, device_name="Unknown",
                           domain="existing.example", source="nextdns", reason="Existing reason",
                           observed_at=utcnow(), expires_at=utcnow() + timedelta(hours=1), evidence_kind="observed",
                           attribution="unattributed", risk_score=None, risk_explanation="Unassessed"))
        db.commit()
    before_evidence = evidence_rows(client)
    before_health = client.get("/api/integrations").json()
    report = run_probe(saved)
    assert report["outcome"] == "verified" and report["read_only"] is True
    assert report["checked_at"] and report["duration_ms"] >= 0
    assert all(check["status"] == "passed" for check in report["checks"])
    assert report["snapshot_counts"]["observations"] == 1
    assert report["snapshot_counts"]["resources"] > 1
    assert capabilities(report)["blocked_dns_logs:read"]["verification"] == "verified"
    assert capabilities(report)["device_identity:verify"]["implementation"] == "not_implemented"
    assert {gap["id"] for gap in report["evidence_gaps"]} >= {"upstream_identity", "dns_scope"}
    assert evidence_rows(client) == before_evidence
    assert client.get("/api/integrations").json() == before_health
    audit = client.get("/api/audit")
    assert KEY not in audit.text and SOURCE_TEXT not in audit.text
    event = next(row for row in audit.json() if row["action"] == "integration.diagnosed")
    assert event["details"]["imported"] is False
    assert event["details"]["name"] == client.get("/api/integrations").json()[0]["name"]
    assert event["details"]["snapshot_counts"] == report["snapshot_counts"]
    assert len(calls) == 2


@pytest.mark.parametrize("change", ["configuration", "restricted_reference", "missing_secret", "invalid_secret"])
def test_preflight_failures_never_call_provider_or_claim_connectivity(saved, monkeypatch, change):
    """Reject bad saved configuration and unsafe or unavailable secrets without inferring network success."""
    client, _, integration_id = saved
    calls = provider_transport(monkeypatch, nextdns_response)
    with client.app.state.session_factory() as db:
        integration = db.get(Integration, integration_id)
        if change == "configuration":
            integration.config = {"profile_id": "invalid", "api_key": KEY}
        elif change == "restricted_reference":
            integration.secret_ref = "NYCTR_BOOTSTRAP_ADMIN_PASSWORD"
        db.commit()
    if change == "missing_secret":
        monkeypatch.delenv("NYCTR_CONNECTOR_SECRET_DNS")
    elif change == "invalid_secret":
        monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "bad\r\ncredential")
    report = run_probe(saved)
    stage = "configuration" if change == "configuration" else "secret"
    assert checks(report)[stage]["status"] == "failed"
    assert all(checks(report)[id_]["status"] == "unknown" for id_ in ("connectivity", "tls", "authentication"))
    assert report["outcome"] == "failed" and report["snapshot_counts"] is None
    assert calls == []
    assert client.get("/api/integrations").json()[0]["status"] == "configured"


@pytest.mark.parametrize("status,category", [(401, "authentication"), (403, "authentication"),
                                            (429, "rate_limit"), (500, "provider_contract")])
def test_http_failures_confirm_transport_but_not_successful_reads(saved, monkeypatch, status, category):
    """An HTTPS error response proves transport only; provider status and body never manufacture coverage."""
    provider_transport(monkeypatch, lambda request: httpx.Response(status, json={"error": KEY + SOURCE_TEXT}))
    before = evidence_rows(saved[0])
    report = run_probe(saved)
    rows = checks(report)
    assert rows["connectivity"]["status"] == rows["tls"]["status"] == "passed"
    stage = "authentication" if category == "authentication" else "provider_contract"
    assert rows[stage]["status"] == "failed" and rows[stage]["category"] == category
    if category != "authentication":
        assert rows["authentication"]["status"] == "unknown"
    assert report["outcome"] == "failed" and report["snapshot_counts"] is None
    assert all(item["verification"] == "unknown" for item in report["capabilities"]
               if item["implementation"] == "implemented")
    assert evidence_rows(saved[0]) == before


def test_provider_error_inside_http_200_does_not_verify_authentication(saved, monkeypatch):
    """A provider error envelope must remain a failed contract even when HTTP itself succeeds."""
    provider_transport(monkeypatch, lambda request: httpx.Response(200, json={"errors": [{"detail": KEY}]}))
    report = run_probe(saved)
    assert checks(report)["tls"]["status"] == "passed"
    assert checks(report)["authentication"]["status"] == "unknown"
    assert checks(report)["provider_contract"]["status"] == "failed"
    assert report["snapshot_counts"] is None


def test_malformed_payload_preserves_transport_evidence_without_reflection(saved, monkeypatch):
    """Invalid JSON cannot leak source text or be interpreted as accepted authentication or data."""
    provider_transport(monkeypatch, lambda request: httpx.Response(200, content=(KEY + SOURCE_TEXT).encode()))
    report = run_probe(saved)
    assert checks(report)["connectivity"]["status"] == "passed"
    assert checks(report)["authentication"]["status"] == "unknown"
    assert checks(report)["provider_contract"]["category"] == "provider_contract"


@pytest.mark.parametrize("failure", ["connection", "tls", "timeout"])
def test_typed_transport_failures_keep_unproven_stages_unknown(saved, monkeypatch, failure):
    """Classify typed transport failures without parsing secret-bearing exception strings."""
    def fail(request):
        """Simulate distinct transport causes while making every exception message unsafe to expose."""
        if failure == "tls":
            try:
                raise ssl.SSLCertVerificationError(KEY)
            except ssl.SSLError as exc:
                raise httpx.ConnectError(SOURCE_TEXT, request=request) from exc
        if failure == "timeout":
            raise httpx.ConnectTimeout(KEY, request=request)
        raise httpx.ConnectError(KEY, request=request)

    provider_transport(monkeypatch, fail)
    report = run_probe(saved)
    rows = checks(report)
    assert rows["authentication"]["status"] == "unknown"
    if failure == "tls":
        assert rows["tls"]["status"] == "failed" and rows["tls"]["category"] == "tls"
        assert rows["connectivity"]["status"] == "unknown"
    else:
        assert rows["connectivity"]["status"] == "failed"
        assert rows["connectivity"]["category"] == ("timeout" if failure == "timeout" else "transport")
        assert rows["tls"]["status"] == "unknown"
    assert report["snapshot_counts"] is None


def test_invalid_ca_bundle_fails_without_claiming_a_connection(saved, monkeypatch, tmp_path):
    """The production client must reject an unavailable trust bundle before provider I/O."""
    monkeypatch.setenv("NYCTR_CONNECTOR_CA_BUNDLE", str(tmp_path / "missing-ca.pem"))
    report = run_probe(saved)
    assert checks(report)["tls"]["status"] == "failed"
    assert checks(report)["connectivity"]["status"] == "unknown"
    assert report["snapshot_counts"] is None


def test_disabled_nextdns_logging_is_explicitly_unavailable(saved, monkeypatch):
    """Disabled source logging yields partial coverage and no false no-blocks conclusion."""
    calls = provider_transport(monkeypatch, lambda request: httpx.Response(200, json=profile(logging=False)))
    report = run_probe(saved)
    assert report["outcome"] == "partial"
    capability = capabilities(report)["blocked_dns_logs:read"]
    assert capability["implementation"] == "implemented" and capability["verification"] == "unavailable"
    assert report["snapshot_counts"]["observations"] == 0
    assert "logging_disabled" in {gap["id"] for gap in report["evidence_gaps"]}
    assert len(calls) == 1


def test_missing_policy_fields_and_unknown_logging_are_not_verified(saved, monkeypatch):
    """Successful log reads cannot fill absent policy or source-logging configuration evidence."""
    def partial(request):
        """Expose a minimal profile and an empty but valid log feed."""
        return httpx.Response(200, json={"data": {"name": SOURCE_TEXT}} if request.url.path.endswith("abc123")
                              else {"data": []})

    provider_transport(monkeypatch, partial)
    report = run_probe(saved)
    assert report["outcome"] == "partial"
    assert capabilities(report)["dns_policies:read"]["verification"] == "unknown"
    assert capabilities(report)["blocked_dns_logs:read"]["verification"] == "verified"
    assert {gap["id"] for gap in report["evidence_gaps"]} >= {
        "nextdns_policy_fields_missing", "nextdns_log_settings_unknown", "no_recent_events",
    }


def test_failure_after_profile_preserves_partial_verification_but_discards_counts(saved, monkeypatch):
    """A later denied log read does not erase verified profile reads or imply a completed snapshot."""
    def partial(request):
        """Allow profile configuration but deny the separate log permission."""
        return httpx.Response(200, json=profile()) if request.url.path.endswith("abc123") else httpx.Response(403)

    provider_transport(monkeypatch, partial)
    report = run_probe(saved)
    assert report["outcome"] == "partial" and report["snapshot_counts"] is None
    assert checks(report)["authentication"]["status"] == "failed"
    assert capabilities(report)["profile:read"]["verification"] == "verified"
    assert capabilities(report)["blocked_dns_logs:read"]["verification"] == "unknown"
    assert "log_coverage_unknown" in {gap["id"] for gap in report["evidence_gaps"]}


@pytest.mark.parametrize("has_site", [True, False])
def test_unifi_verifies_only_exercised_reads_and_never_claims_firewall_events(saved, monkeypatch, has_site):
    """Empty discovery cannot verify uncalled inventory endpoints, and configuration is never an event feed."""
    client, headers, _ = saved
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "unifi.example")
    response = client.post("/api/integrations", headers=headers, json={"provider": "unifi_network", "name": "Lab",
        "config": {"base_url": "https://unifi.example/proxy/network/integration"},
        "secret_ref": "NYCTR_CONNECTOR_SECRET_DNS"})
    integration_id = response.json()["id"]

    def unifi(request):
        """Expose one synthetic site, or none, and valid empty inventories for its supported reads."""
        rows = [{"id": "site-one", "name": SOURCE_TEXT}] if has_site and request.url.path.endswith("/sites") else []
        return httpx.Response(200, json={"data": rows, "offset": 0, "count": len(rows), "totalCount": len(rows)})

    calls = provider_transport(monkeypatch, unifi)
    report = run_probe((client, headers, integration_id))
    items = capabilities(report)
    assert report["outcome"] == ("verified" if has_site else "partial")
    assert items["sites:read"]["verification"] == "verified"
    assert items["devices:read"]["verification"] == ("verified" if has_site else "unknown")
    assert items["firewall_events:read"]["implementation"] == "not_implemented"
    assert items["firewall_events:read"]["verification"] == "unavailable"
    assert "firewall_events" in {gap["id"] for gap in report["evidence_gaps"]}
    assert report["snapshot_counts"]["observations"] == 0
    assert items["hotspot_vouchers:read"]["verification"] == ("verified" if has_site else "unknown")
    assert items["wifi_broadcasts:read"]["verification"] == ("verified" if has_site else "unknown")
    # Sites, devices, networks, clients, firewall policies, hotspot vouchers and Wi-Fi names.
    assert len(calls) == (7 if has_site else 1)


@pytest.mark.parametrize("known", [True, False])
def test_exception_text_is_never_serialized_even_for_integration_errors(saved, monkeypatch, known):
    """Categorized adapter failures and unexpected exceptions both discard potentially sensitive text."""
    async def fail(*args):
        """Raise maliciously detailed exception text rather than a provider response."""
        if known:
            raise IntegrationError(KEY + SOURCE_TEXT, category="provider_contract")
        raise RuntimeError(KEY + SOURCE_TEXT)

    monkeypatch.setattr("nyctr.integrations.collect", fail)
    report = run_probe(saved)
    assert checks(report)["provider_contract"]["category"] == ("provider_contract" if known else "internal")
    assert all(checks(report)[stage]["status"] == "unknown" for stage in ("connectivity", "tls", "authentication"))
    assert saved[0].get("/api/integrations").json()[0]["status"] == "configured"


def test_probe_deadline_releases_lease_and_returns_unknown_coverage(saved, monkeypatch):
    """A timed-out probe must stop work, restore integration state, and expose no invented snapshot counts."""
    async def delayed(*args):
        """Wait longer than the patched diagnostic deadline without contacting a provider."""
        await asyncio.sleep(1)
        return Snapshot()

    monkeypatch.setattr("nyctr.integrations.collect", delayed)
    monkeypatch.setattr("nyctr.diagnostics.DIAGNOSTICS_TIMEOUT_SECONDS", 0.01)
    report = run_probe(saved)
    assert checks(report)["connectivity"]["category"] == "timeout"
    assert report["snapshot_counts"] is None
    assert saved[0].get("/api/integrations").json()[0]["status"] == "configured"


def test_existing_collection_lease_rejects_probe_without_provider_io(saved, monkeypatch):
    """A live collection's lease excludes diagnostics and is not cleared by the rejected request."""
    client, headers, integration_id = saved
    calls = provider_transport(monkeypatch, nextdns_response)
    with client.app.state.session_factory() as db:
        integration = db.get(Integration, integration_id)
        integration.status = "syncing"
        integration.sync_started_at = utcnow()
        db.commit()
    response = client.post(f"/api/integrations/{integration_id}/diagnostics", headers=headers)
    assert response.status_code == 409 and calls == []
    assert client.get("/api/integrations").json()[0]["status"] == "syncing"


def test_running_probe_excludes_both_second_probe_and_collection(saved, monkeypatch):
    """Concurrent HTTP requests must share the existing integration lease across both operation types."""
    client, headers, integration_id = saved
    started, release = Event(), Event()

    async def blocked(*args):
        """Hold a diagnostic inside collection long enough to exercise competing requests."""
        started.set()
        while not release.is_set():
            await asyncio.sleep(0.005)
        return Snapshot()

    monkeypatch.setattr("nyctr.integrations.collect", blocked)
    path = f"/api/integrations/{integration_id}"
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(client.post, path + "/diagnostics", headers=headers)
        try:
            assert started.wait(timeout=5)
            assert client.post(path + "/diagnostics", headers=headers).status_code == 409
            assert client.post(path + "/sync", headers=headers).status_code == 409
        finally:
            release.set()
        assert future.result(timeout=5).status_code == 200
    assert client.get("/api/integrations").json()[0]["status"] == "configured"


def test_cancelled_probe_restores_prior_collection_health(saved, monkeypatch):
    """Cancelling the ASGI request must cancel its provider task and restore existing collection health."""
    client, headers, integration_id = saved
    with client.app.state.session_factory() as db:
        integration = db.get(Integration, integration_id)
        integration.status = "error"
        integration.last_sync = utcnow() - timedelta(days=1)
        integration.last_error = "Earlier collection failed"
        db.commit()
    prior_health = client.get("/api/integrations").json()
    prior_audit = client.get("/api/audit").json()

    async def interrupt_request():
        """Cancel an authenticated in-process HTTP request after its collector has obtained the lease."""
        started, cancelled = asyncio.Event(), asyncio.Event()

        async def waiting_provider(*args):
            """Hold provider work until cancellation and acknowledge that cancellation reached the task."""
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        monkeypatch.setattr("nyctr.integrations.collect", waiting_provider)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=client.app),
                                     base_url="http://testserver", cookies=client.cookies) as async_client:
            task = asyncio.create_task(async_client.post(
                f"/api/integrations/{integration_id}/diagnostics", headers=headers))
            try:
                await asyncio.wait_for(started.wait(), timeout=5)
                with client.app.state.session_factory() as db:
                    assert db.get(Integration, integration_id).status == "syncing"
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert cancelled.is_set()
            finally:
                if not task.done():
                    task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task

    asyncio.run(interrupt_request())
    assert client.get("/api/integrations").json() == prior_health
    assert client.get("/api/audit").json() == prior_audit
    with client.app.state.session_factory() as db:
        assert db.get(Integration, integration_id).sync_started_at is None


@pytest.mark.parametrize("prior_status", ["configured", "connected", "partial", "error"])
def test_expired_diagnostic_cannot_clear_a_replacement_lease(saved, monkeypatch, prior_status):
    """Reclaim an expired probe and fence the original cleanup from the replacement's active lease.

    The replacement finds only an abandoned "syncing" lease, so it must rebuild
    the earlier status: a source whose last collection was partial stays partial,
    and one whose last collection was complete is not turned into a partial one.
    """
    client, headers, integration_id = saved
    with client.app.state.session_factory() as db:
        integration = db.get(Integration, integration_id)
        integration.status = prior_status
        integration.last_sync = None if prior_status == "configured" else utcnow() - timedelta(days=1)
        integration.last_error = "Earlier collection failed" if prior_status == "error" else None
        if prior_status != "configured":
            # An older partial read, then the collection that left the current status.
            db.add(Audit(action="integration.collected", target_id=integration_id, created_at=utcnow() - timedelta(days=2),
                         details={"resources": 1, "observations": 30, "partial": True, "rows_kept": 30}))
            last_partial = prior_status in {"partial", "error"}
            db.add(Audit(action="integration.collected", target_id=integration_id, created_at=utcnow() - timedelta(days=1),
                         details={"resources": 1, "observations": 30, "partial": last_partial,
                                  **({"rows_kept": 30} if last_partial else {})}))
        db.commit()
    prior_health = client.get("/api/integrations").json()
    lease_clock = [utcnow()]
    started = [Event(), Event()]
    release = [Event(), Event()]
    calls = []

    def lease_time():
        """Advance only lease time so expiration is deterministic without a five-minute test delay."""
        return lease_clock[0]

    async def held_provider(*args):
        """Pause each of two real HTTP probes independently after its successful lease claim."""
        index = len(calls)
        calls.append(index)
        started[index].set()
        while not release[index].is_set():
            await asyncio.sleep(0.005)
        return Snapshot()

    monkeypatch.setattr("nyctr.main.utcnow", lease_time)
    monkeypatch.setattr("nyctr.integrations.collect", held_provider)
    path = f"/api/integrations/{integration_id}"
    with ThreadPoolExecutor(max_workers=2) as pool:
        original = pool.submit(client.post, path + "/diagnostics", headers=headers)
        replacement = None
        try:
            assert started[0].wait(timeout=5)
            lease_clock[0] += timedelta(minutes=6)
            replacement = pool.submit(client.post, path + "/diagnostics", headers=headers)
            assert started[1].wait(timeout=5)
            release[0].set()
            assert original.result(timeout=5).status_code == 200
            with client.app.state.session_factory() as db:
                integration = db.get(Integration, integration_id)
                assert integration.status == "syncing"
                assert utc(integration.sync_started_at) == lease_clock[0]
            assert client.post(path + "/diagnostics", headers=headers).status_code == 409
            assert client.post(path + "/sync", headers=headers).status_code == 409
        finally:
            for signal in release:
                signal.set()
        assert replacement is not None and replacement.result(timeout=5).status_code == 200
    with client.app.state.session_factory() as db:
        integration = db.get(Integration, integration_id)
        assert integration.status == prior_status
        assert integration.sync_started_at is None
    assert client.get("/api/integrations").json() == prior_health
    assert len(calls) == 2


def test_probe_context_isolation_prevents_previous_success_from_verifying_a_failed_probe(saved, monkeypatch):
    """A later failed probe must not inherit capabilities or HTTPS evidence from an earlier success."""
    provider_transport(monkeypatch, nextdns_response)
    assert run_probe(saved)["outcome"] == "verified"
    provider_transport(monkeypatch, lambda request: httpx.Response(401))
    report = run_probe(saved)
    assert report["outcome"] == "failed"
    assert all(item["verification"] == "unknown" for item in report["capabilities"]
               if item["implementation"] == "implemented")
