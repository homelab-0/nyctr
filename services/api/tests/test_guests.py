"""Guest Wi-Fi: visibility, passes, the written cut-off rule and provider write gating."""

import asyncio
import json
from datetime import timedelta

import httpx
import pytest
from conftest import live_app, live_signin
from fastapi.testclient import TestClient
from sqlalchemy import select

from nyctr.guests import enforce, evaluate_rule
from nyctr.integrations import IntegrationError, actions, core
from nyctr.models import Finding, GuestAction, Integration, Observation, Resource, utcnow
from nyctr.policy import GuestRule, put_rule


def guest(client, name):
    """Fetch one guest device from the administrator overview by name."""
    return next(x for x in client.get("/api/guests").json()["devices"] if x["name"] == name)


def test_members_cannot_see_or_control_guests(client, member_headers):
    """Guest tracking and control are administrator-only, including the demo trigger."""
    assert client.get("/api/guests").status_code == 403
    for path, body in [("guests/passes", {"name": "Friend", "minutes": 60}),
                       ("guests/actions", {"device_id": "guest-priya", "action": "cut"}),
                       ("guests/passes/pass-spare/end", {}), ("demo/guest-activity", {"device_id": "guest-hvac"})]:
        assert client.post("/api/" + path, headers=member_headers, json=body).status_code == 403
    assert not [x for x in client.get("/api/blocks").json() if x["device_id"].startswith("guest-")]


def test_overview_separates_what_is_known_inferred_and_not_collected(client, admin_headers):
    """States come from actions, the pass link is an inferred guess, and no lookups means unknown risk."""
    data = client.get("/api/guests").json()
    assert data["writes"] == "simulated" and data["rule"]["enabled"] is True
    assert any("port scans" in x for x in data["not_collected"])
    by_name = {x["name"]: x for x in data["devices"]}
    assert by_name["Pixel 8"]["state"] == "cut" and by_name["Pixel 8"]["lookups"]["threat"] == 3
    assert by_name["Pixel 8"]["risk"]["band"] == "high"
    assert by_name["Priya's iPhone"]["state"] == "online"
    assert by_name["Priya's iPhone"]["pass"] == {"id": "pass-priya", "name": "Priya (weekend)", "evidence": "inferred"}
    assert by_name["Priya's iPhone"]["access_point"]["name"] == "Upstairs access point"
    assert [t["text"] for t in by_name["Priya's iPhone"]["timeline"] if t["kind"] == "moved"] == [
        "Moved to Upstairs access point", "Seen on Basement access point"]
    assert by_name["HVAC-Laptop"]["risk"] == {"score": None, "band": "unknown", "factors": [
        {"label": "No blocked lookups are tied to this device. That does not prove it is safe.", "points": None}]}
    spare = next(x for x in data["passes"] if x["id"] == "pass-spare")
    assert spare["state"] == "unused" and spare["code"] == "77102-33864"


def test_issue_and_end_a_pass_in_demo_is_simulated(client, admin_headers):
    """Demo passes get a local code and never claim to exist in UniFi."""
    made = client.post("/api/guests/passes", headers=admin_headers,
                       json={"name": "Plumber", "minutes": 120, "guest_limit": 1})
    assert made.status_code == 201 and made.json()["execution"] == "simulated"
    assert len(made.json()["code"]) == 11 and made.json()["state"] == "unused"
    ended = client.post(f"/api/guests/passes/{made.json()['id']}/end", headers=admin_headers)
    assert ended.json()["state"] == "ended"
    assert client.post(f"/api/guests/passes/{made.json()['id']}/end", headers=admin_headers).status_code == 409
    assert client.post("/api/guests/passes", headers=admin_headers,
                       json={"name": "Too short", "minutes": 5}).status_code == 422


def test_the_written_rule_cuts_a_guest_and_an_administrator_decides_what_next(client, admin_headers):
    """Counted threat lookups trigger the cut-off; restore and lock are explicit administrator actions."""
    assert guest(client, "HVAC-Laptop")["state"] == "online"
    after = client.post("/api/demo/guest-activity", headers=admin_headers, json={"device_id": "guest-hvac"})
    hvac = next(x for x in after.json()["devices"] if x["id"] == "guest-hvac")
    assert hvac["state"] == "cut" and hvac["authorized"] is False and hvac["lookups"]["threat"] == 3
    assert hvac["timeline"][0]["text"] == "The cut-off rule cut this device off (simulated)"
    findings = {x["id"]: x for x in client.get("/api/findings").json()}
    assert findings["auto:guest-cut:guest-hvac"]["severity"] == "high"
    attention = client.get("/api/attention").json()
    assert attention[0]["kind"] == "guest" and {a["id"] for a in attention[:2]} == {"guest-hvac", "guest-pixel"}
    restored = client.post("/api/guests/actions", headers=admin_headers,
                           json={"device_id": "guest-hvac", "action": "restore", "reason": "Known contractor"})
    assert restored.json()["state"] == "online" and restored.json()["authorized"] is True
    assert {x["id"]: x["status"] for x in client.get("/api/findings").json()}["auto:guest-cut:guest-hvac"] == "resolved"
    # The same lookups must not cut the device again after an administrator let it back on.
    locked = client.post("/api/guests/actions", headers=admin_headers,
                         json={"device_id": "guest-pixel", "action": "lock"})
    assert locked.json()["state"] == "locked"
    assert client.post("/api/guests/actions", headers=admin_headers,
                       json={"device_id": "laptop-jamie", "action": "cut"}).status_code == 404


def test_rule_does_not_fire_when_switched_off_or_below_its_count(client, app, admin_headers):
    """No rule, no automatic action; fewer hits than written, no action either."""
    assert client.put("/api/rules/guest", headers=admin_headers,
                      json={"enabled": True, "hits": 10, "minutes": 5}).status_code == 200
    client.post("/api/demo/guest-activity", headers=admin_headers, json={"device_id": "guest-hvac"})
    assert guest(client, "HVAC-Laptop")["state"] == "online"
    client.put("/api/rules/guest", headers=admin_headers, json={"enabled": False})
    with app.state.session_factory() as db:
        assert evaluate_rule(db, app.state.settings) == []
    assert client.put("/api/rules/guest", headers=admin_headers,
                      json={"enabled": True, "hits": 0}).status_code == 422


def live_guest(app, *, lookups=3):
    """Insert a UniFi site, one authorised guest device and recent threat lookups into a live database."""
    now = utcnow()
    with app.state.session_factory() as db:
        db.add(Integration(id="unifi", provider="unifi_network", name="UniFi", status="connected",
                           config={"base_url": "https://unifi.example/proxy/network/integration"},
                           secret_ref="NYCTR_CONNECTOR_SECRET_UNIFI"))
        db.add(Integration(id="dns", provider="nextdns", name="DNS", config={"profile_id": "abc123"},
                           secret_ref="NYCTR_CONNECTOR_SECRET_DNS", status="connected"))
        db.flush()
        for id_, kind, source, attrs in [
            ("unifi:site:s1", "site", "s1", {}),
            ("unifi:client:g1", "client", "g1", {"access_type": "GUEST", "guest_authorized": True}),
        ]:
            db.add(Resource(id=id_, integration_id="unifi", name="Visitor phone" if kind == "client" else "Home",
                            kind=kind, provider="unifi_network", source_id=source, site_id="unifi:site:s1",
                            observed_at=now, evidence_kind="observed", classification="unassigned",
                            attributes=attrs))
        for index in range(lookups):
            when = now - timedelta(seconds=30 * index)
            db.add(Observation(id=f"dns:block:{index}", integration_id="dns", device_id="unifi:client:g1",
                               device_name="Visitor phone", domain=f"bad{index}.example", source="nextdns",
                               reason="Threat Intelligence Feeds", reason_codes=["threat-intelligence-feeds"],
                               observed_at=when, expires_at=when + timedelta(hours=24), evidence_kind="observed",
                               attribution="inferred", risk_score=None, risk_explanation=""))
        put_rule(db, "guest_rule", GuestRule(enabled=True, hits=3, minutes=5), "test")
        db.commit()


def run_rule(app):
    """Evaluate and enforce the guest rule once, as collection does."""
    async def go():
        with app.state.session_factory() as db:
            return await enforce(db, app.state.settings, evaluate_rule(db, app.state.settings))
    return asyncio.run(go())


def test_live_read_only_rule_match_is_reported_not_enforced(tmp_path):
    """Without write permission a rule match is recorded as not applied and the device stays online."""
    app = live_app(tmp_path)
    with TestClient(app) as client:
        live_guest(app)
        headers = live_signin(client)
        assert run_rule(app) == 1
        device = guest(client, "Visitor phone")
        assert device["state"] == "online" and device["authorized"] is True
        with app.state.session_factory() as db:
            assert db.scalar(select(GuestAction)).execution == "not_applied"
            assert db.get(Finding, "auto:guest-unenforced:unifi:client:g1").severity == "high"
        assert run_rule(app) == 0  # The same lookups are not reported twice.
        assert client.post("/api/guests/passes", headers=headers,
                           json={"name": "Friend", "minutes": 60}).status_code == 409
        assert client.post("/api/guests/actions", headers=headers,
                           json={"device_id": "unifi:client:g1", "action": "cut"}).status_code == 409
        assert client.post("/api/demo/guest-activity", headers=headers,
                           json={"device_id": "unifi:client:g1"}).status_code == 404


def test_live_writes_use_only_the_documented_unifi_calls(tmp_path, monkeypatch):
    """With permission, the rule unauthorises the guest, and a pass is created with the documented body."""
    calls = []

    def handler(request):
        path = request.url.path.removeprefix("/proxy/network/integration")
        body = json.loads(request.content) if request.content else None
        calls.append((request.method, path, body))
        assert request.headers["X-Api-Key"] == "unifi-secret" and request.url.host == "unifi.example"
        if path.endswith("/actions"):
            return httpx.Response(200, json={"action": body["action"]})
        if path.endswith("/clients/g1"):
            return httpx.Response(200, json={"id": "g1", "access": {"type": "GUEST", "authorized": False}})
        if path.endswith("/hotspot/vouchers"):
            return httpx.Response(201, json={"vouchers": [{"id": "v1", "code": "1234567890", "name": body["name"],
                                                           "timeLimitMinutes": body["timeLimitMinutes"]}]})
        return httpx.Response(404)

    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "unifi-secret")
    monkeypatch.setattr(core, "make_http_client", lambda key, **_: httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"X-Api-Key": key}, follow_redirects=False))
    app = live_app(tmp_path, provider_writes="unifi_network")
    with TestClient(app) as client:
        live_guest(app)
        headers = live_signin(client)
        assert run_rule(app) == 1
        assert calls[0] == ("POST", "/v1/sites/s1/clients/g1/actions", {"action": "UNAUTHORIZE_GUEST_ACCESS"})
        assert calls[1][:2] == ("GET", "/v1/sites/s1/clients/g1")
        assert guest(client, "Visitor phone")["state"] == "cut"
        # Locking a device that is already cut needs no provider call.
        before = len(calls)
        locked = client.post("/api/guests/actions", headers=headers,
                             json={"device_id": "unifi:client:g1", "action": "lock"})
        assert locked.json()["state"] == "locked" and len(calls) == before
        made = client.post("/api/guests/passes", headers=headers,
                           json={"name": "Friend", "minutes": 90, "guest_limit": 2})
        assert made.status_code == 201 and made.json()["execution"] == "applied" and made.json()["code"] == "1234567890"
        assert calls[-1] == ("POST", "/v1/sites/s1/hotspot/vouchers",
                             {"count": 1, "name": "Friend", "timeLimitMinutes": 90, "authorizedGuestLimit": 2})


@pytest.mark.parametrize("call", [
    lambda: actions.nextdns_allow({"profile_id": "abc123"}, "k", "example.com", allowed=False),
    lambda: actions.nextdns_disallow({"profile_id": "abc123"}, "k", "example.com", allowed=False),
    lambda: actions.unifi_guest_action({"base_url": "https://x"}, "k", "s", "c", "UNAUTHORIZE_GUEST_ACCESS", allowed=False),
    lambda: actions.unifi_create_voucher({"base_url": "https://x"}, "k", "s", name="n", minutes=60,
                                         guest_limit=1, data_limit_mb=None, allowed=False),
    lambda: actions.unifi_delete_voucher({"base_url": "https://x"}, "k", "s", "v", allowed=False),
])
def test_every_action_refuses_before_any_network_call_without_permission(monkeypatch, call):
    """The action layer fails closed on its own, whatever the caller forgot to check."""
    def no_network(*_args, **_kwargs):
        raise AssertionError("A provider client was created without write permission")
    monkeypatch.setattr(core, "make_http_client", no_network)
    with pytest.raises(actions.WritesDisabled):
        asyncio.run(call())


@pytest.mark.parametrize("domain", ["https://example.com/x", "*.example.com", "10.0.0.1", "exa mple.com", ""])
def test_only_plain_domain_names_can_be_allowed(monkeypatch, domain):
    """URLs, wildcards and addresses are rejected before anything is sent."""
    monkeypatch.setattr(core, "make_http_client", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    with pytest.raises(IntegrationError):
        asyncio.run(actions.nextdns_allow({"profile_id": "abc123"}, "k", domain, allowed=True))
