"""Access decisions, leases and their denial paths."""

import json
from datetime import timedelta

import httpx
import pytest
from conftest import LIVE_MEMBER, live_app, live_signin, seed_live_member, signin
from fastapi.testclient import TestClient
from sqlalchemy import select

from nyctr.collection import apply_snapshot
from nyctr.integrations import Snapshot, core
from nyctr.models import Audit, Integration, Lease, Observation, utcnow

GALLERY = {"block_id": "block-gallery", "reason": "Need to open a picture gallery", "duration_minutes": 240}


def put_rule(client, headers, **values):
    """Write the access rule as the administrator."""
    body = {"enabled": True, "max_score": 25, "max_minutes": 60, "per_day": 4, **values}
    assert client.put("/api/rules/access", headers=headers, json=body).status_code == 200


def test_low_risk_privacy_block_opens_under_the_written_rule(client, app, member_headers):
    """The rule, not the score alone, opens access; the time is capped and the result is marked simulated."""
    response = client.post("/api/requests", headers=member_headers, json=GALLERY)
    row = response.json()
    assert response.status_code == 201 and row["status"] == "auto_approved" and row["decided_by"] == "rule"
    assert row["risk_score"] == 16 and row["risk_category"] == "privacy_list" and row["duration_minutes"] == 60
    lease = next(x for x in client.get("/api/leases").json() if x["request_id"] == row["id"])
    assert lease["status"] == "active" and lease["execution"] == "simulated" and lease["kind"] == "temporary"
    assert "Everyone using" in lease["scope"]
    with app.state.session_factory() as db:
        event = db.scalar(select(Audit).where(Audit.action == "access.opened", Audit.target_id == lease["id"]))
        assert event.details["decided_by"] == "rule" and event.actor_id is None


@pytest.mark.parametrize("block,expect", [
    ("block-verify", "above the automatic limit"),   # newly registered: score 72
    ("block-tablet", "an administrator's rule"),      # administrator denylist
])
def test_risky_or_deliberate_blocks_always_wait_for_a_person(client, member_headers, block, expect):
    """Security and policy blocks are scored, explained and left pending."""
    row = client.post("/api/requests", headers=member_headers,
                      json={"block_id": block, "reason": "I need this page", "duration_minutes": 60}).json()
    assert row["status"] == "pending" and row["risk_score"] > 30
    assert expect in row["decision_note"] or "person decides" in row["decision_note"]
    assert not [x for x in client.get("/api/leases").json() if x["request_id"] == row["id"]]


def test_unknown_reason_fails_closed(client, app, member_headers):
    """A block Nyctr cannot score never opens automatically, whatever the rule allows."""
    with app.state.session_factory() as db:
        source = db.get(Observation, "block-gallery")
        source.reason, source.reason_codes = "Something the adapter has never seen", []
        db.commit()
    row = client.post("/api/requests", headers=member_headers, json=GALLERY).json()
    assert row["status"] == "pending" and row["risk_score"] is None and row["risk_category"] == "unknown"
    assert "could not score" in row["decision_note"]


def test_rule_switch_daily_cap_and_prior_denial_each_stop_automatic_access(client, app, member_headers):
    """Turning the rule off, exhausting the daily cap, or an earlier denial each leave a request pending."""
    admin_headers = signin(client)
    put_rule(client, admin_headers, per_day=2)  # one automatic opening is already seeded today
    signin(client, member=True)
    member = {"X-CSRF-Token": client.get("/api/auth/me").json()["csrf_token"]}
    first = client.post("/api/requests", headers=member, json=GALLERY).json()
    assert first["status"] == "auto_approved"
    second = client.post("/api/requests", headers=member, json={**GALLERY, "block_id": "block-fonts"}).json()
    assert second["status"] == "pending" and "limit of 2" in second["decision_note"]
    admin_headers = signin(client)
    assert client.post(f"/api/requests/{second['id']}/review", headers=admin_headers,
                       json={"decision": "denied", "note": "Not this one"}).status_code == 200
    put_rule(client, admin_headers, per_day=10)
    with app.state.session_factory() as db:
        now = utcnow()
        db.add(Observation(id="block-fonts-again", integration_id="demo-nextdns", device_id="laptop-jamie",
                           device_name="Jamie's MacBook", domain="fonts.partner-metrics.example", source="nextdns",
                           reason="HaGeZi Multi PRO++", reason_codes=["blocklist:x"], observed_at=now,
                           expires_at=now + timedelta(hours=1), evidence_kind="observed", attribution="assigned",
                           risk_score=None, risk_explanation=""))
        db.commit()
    put_rule(client, admin_headers, enabled=False)
    member = signin(client, member=True)
    again = client.post("/api/requests", headers=member,
                        json={**GALLERY, "block_id": "block-fonts-again"}).json()
    assert again["status"] == "pending" and "switched off" in again["decision_note"]
    admin_headers = signin(client)
    put_rule(client, admin_headers, enabled=True, per_day=10)
    with app.state.session_factory() as db:
        db.get(Observation, "block-fonts-again").id = "block-fonts-third"
        db.commit()
    member = signin(client, member=True)
    third = client.post("/api/requests", headers=member, json={**GALLERY, "block_id": "block-fonts-third"}).json()
    assert third["status"] == "pending" and "said no" in third["decision_note"]


def test_members_cannot_read_or_change_rules_leases_or_suggestions(client, member_headers):
    """Only administrators see or widen what Nyctr does on its own."""
    for path in ("rules", "suggestions", "device-links", "users", "attention", "guests"):
        assert client.get("/api/" + path).status_code == 403
    assert client.put("/api/rules/access", headers=member_headers, json={"enabled": True}).status_code == 403
    assert client.put("/api/rules/guest", headers=member_headers, json={"enabled": True}).status_code == 403
    assert client.post("/api/leases/lease-recipes/end", headers=member_headers).status_code == 403
    assert client.post("/api/suggestions", headers=member_headers,
                       json={"domain": "img.newsletter-cdn.example", "action": "make_permanent"}).status_code == 403
    own = client.get("/api/leases").json()
    assert own and all(x["requester_id"] == "user-jamie" for x in own)
    assert all("requester_name" not in x for x in own)


def test_rule_values_are_bounded(client, admin_headers):
    """The automatic limit can never be raised into the medium band or beyond four hours."""
    assert client.put("/api/rules/access", headers=admin_headers,
                      json={"enabled": True, "max_score": 61}).status_code == 422
    assert client.put("/api/rules/access", headers=admin_headers,
                      json={"enabled": True, "max_minutes": 600}).status_code == 422
    assert client.put("/api/rules/access", headers=admin_headers,
                      json={"enabled": True, "anything": 1}).status_code == 422


def test_administrator_approval_opens_a_lease_and_expiry_closes_it(client, app, member_headers):
    """Approval creates a temporary lease; once its time is up reconciliation ends it."""
    row = client.post("/api/requests", headers=member_headers,
                      json={"block_id": "block-verify", "reason": "Bank asked me to verify", "duration_minutes": 30}).json()
    admin_headers = signin(client)
    done = client.post(f"/api/requests/{row['id']}/review", headers=admin_headers,
                       json={"decision": "approved", "note": "Checked with Jamie", "minutes": 45})
    assert done.status_code == 200 and done.json()["status"] == "approved"
    assert client.post(f"/api/requests/{row['id']}/review", headers=admin_headers,
                       json={"decision": "approved", "note": "Again"}).status_code == 409
    lease = next(x for x in client.get("/api/leases").json() if x["request_id"] == row["id"])
    assert lease["decided_by"] == "user-admin" and lease["status"] == "active"
    with app.state.session_factory() as db:
        db.get(Lease, lease["id"]).expires_at = utcnow() - timedelta(seconds=5)
        db.commit()
    after = next(x for x in client.get("/api/leases").json() if x["id"] == lease["id"])
    assert after["status"] == "ended" and after["ended_reason"] == "expired"
    assert client.post(f"/api/leases/{lease['id']}/end", headers=admin_headers).status_code == 409


def test_approval_needs_current_evidence_but_refusing_does_not(client, app, member_headers):
    """A request whose blocked lookup has expired cannot be approved; it can still be refused.

    Approving changes a provider, so stale evidence must not turn into access.
    The request and its history stay, and no lease is created.
    """
    made = [client.post("/api/requests", headers=member_headers, json={
        "block_id": block, "reason": "Need it for work", "duration_minutes": 30}).json()
        for block in ("block-verify", "block-stream")]
    admin_headers = signin(client)
    with app.state.session_factory() as db:
        for block in ("block-verify", "block-stream"):
            db.get(Observation, block).expires_at = utcnow() - timedelta(minutes=1)
        db.commit()
    before = len(client.get("/api/leases").json())
    stale = client.post(f"/api/requests/{made[0]['id']}/review", headers=admin_headers,
                        json={"decision": "approved", "note": "Looks fine"})
    assert stale.status_code == 409 and "no longer current" in stale.json()["detail"]
    assert len(client.get("/api/leases").json()) == before
    still = next(x for x in client.get("/api/requests").json() if x["id"] == made[0]["id"])
    assert still["status"] == "pending"
    # Reading the inbox removes expired evidence entirely; the answer must stay the same.
    client.get("/api/blocks")
    assert client.post(f"/api/requests/{made[0]['id']}/review", headers=admin_headers,
                       json={"decision": "approved", "note": "Looks fine"}).status_code == 409
    denied = client.post(f"/api/requests/{made[1]['id']}/review", headers=admin_headers,
                         json={"decision": "denied", "note": "Not for work"})
    assert denied.status_code == 200 and denied.json()["status"] == "denied"


def test_suggestions_come_from_rule_openings_and_need_an_administrator(client, admin_headers):
    """Repeated automatic openings are suggested; nothing becomes permanent until an administrator says so."""
    items = client.get("/api/suggestions").json()
    news = next(x for x in items if x["domain"] == "img.newsletter-cdn.example")
    assert news["times"] == 2 and news["people"] == ["Jamie Rivera"]
    made = client.post("/api/suggestions", headers=admin_headers,
                       json={"domain": news["domain"], "action": "make_permanent"}).json()
    assert made["kind"] == "permanent" and made["expires_at"] is None and made["decided_by"] == "user-admin"
    assert news["domain"] not in {x["domain"] for x in client.get("/api/suggestions").json()}
    assert client.post("/api/suggestions", headers=admin_headers,
                       json={"domain": "assets.supplier-catalogue.example", "action": "dismiss"}).json() == {"ok": True}
    assert client.get("/api/suggestions").json() == []
    assert client.post("/api/suggestions", headers=admin_headers,
                       json={"domain": "never-seen.example", "action": "dismiss"}).status_code == 404


def test_this_device_is_recognised_only_among_the_callers_devices(client, app, member_headers):
    """Recognition returns a device the member already holds; an address never grants a new one."""
    seen = client.get("/api/me/device").json()
    assert seen == {"device_id": "laptop-jamie", "name": "Jamie's MacBook", "simulated": True}
    found = client.post("/api/blocks/find", headers=member_headers, json={"domain": "proofing-studio.example"}).json()
    assert [x["id"] for x in found] == ["block-gallery"]
    hidden = client.post("/api/blocks/find", headers=member_headers, json={"domain": "downloads.filemirror.example"})
    assert hidden.json() == []


def test_live_address_match_requires_an_existing_grant(tmp_path):
    """In live mode the connecting address is matched, but only to devices assigned to the caller."""
    app = live_app(tmp_path)
    with TestClient(app, client=("10.0.0.9", 50000)) as client:
        seed_live_member(app)
        live_signin(client, LIVE_MEMBER)
        assert client.get("/api/me/device").json()["device_id"] == "unifi:client:laptop"
    with TestClient(app, client=("10.0.0.77", 50000)) as other:
        live_signin(other, LIVE_MEMBER)
        assert other.get("/api/me/device").json() == {"device_id": None, "name": None, "simulated": False}


def test_live_without_write_permission_never_claims_access(tmp_path):
    """With provider writes off the rule cannot open anything, and an approval is recorded as not applied."""
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        admin_headers = live_signin(client)
        put_rule(client, admin_headers)
        assert client.get("/api/rules").json()["writes"] == {"access": "disabled", "guests": "disabled"}
        member = live_signin(client, LIVE_MEMBER)
        row = client.post("/api/requests", headers=member,
                          json={"block_id": "dns:block:one", "reason": "Need the gallery", "duration_minutes": 60}).json()
        assert row["status"] == "pending" and row["risk_score"] == 16
        assert "not allowed to change Office DNS" in row["decision_note"]
        admin_headers = live_signin(client)
        client.post(f"/api/requests/{row['id']}/review", headers=admin_headers,
                    json={"decision": "approved", "note": "Fine by me"})
        lease = client.get("/api/leases").json()[0]
        assert lease["execution"] == "not_applied" and lease["owned"] is False


def nextdns_mock(monkeypatch, allowlist, *, fail_delete=False):
    """Serve a fake NextDNS allowlist and record every call."""
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        assert request.headers["X-Api-Key"] == "dns-secret" and request.url.host == "api.nextdns.io"
        if request.method == "GET":
            return httpx.Response(200, json={"data": [{"id": d, "active": True} for d in allowlist]})
        if request.method == "POST":
            allowlist.append(json.loads(request.content)["id"])
            return httpx.Response(200, json={"data": {}})
        if fail_delete:
            return httpx.Response(500)
        allowlist.remove(request.url.path.rsplit("/", 1)[1])
        return httpx.Response(204)

    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "dns-secret")
    monkeypatch.setattr(core, "make_http_client", lambda key, **_: httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"X-Api-Key": key}, follow_redirects=False,
        trust_env=False))
    return calls


def open_live(client, app):
    """Let the written rule open the seeded member's request in a live app with NextDNS writes allowed."""
    admin_headers = live_signin(client)
    put_rule(client, admin_headers)
    member = live_signin(client, LIVE_MEMBER)
    row = client.post("/api/requests", headers=member,
                      json={"block_id": "dns:block:one", "reason": "Need the gallery", "duration_minutes": 60}).json()
    return row, live_signin(client)


def test_enabled_writes_add_verify_and_remove_only_what_nyctr_created(tmp_path, monkeypatch):
    """The allowlist entry is added and verified, then removed at expiry because Nyctr created it."""
    allowlist: list[str] = []
    calls = nextdns_mock(monkeypatch, allowlist)
    app = live_app(tmp_path, provider_writes="nextdns")
    with TestClient(app) as client:
        seed_live_member(app)
        row, admin_headers = open_live(client, app)
        assert row["status"] == "auto_approved" and allowlist == ["click.proofing-studio.example"]
        lease = client.get("/api/leases").json()[0]
        assert lease["execution"] == "applied" and lease["owned"] is True
        assert [c[0] for c in calls] == ["GET", "POST", "GET"]
        with app.state.session_factory() as db:
            db.get(Lease, lease["id"]).expires_at = utcnow() - timedelta(seconds=1)
            db.commit()
        assert client.get("/api/leases").json()[0]["status"] == "ended" and allowlist == []


def test_a_preexisting_entry_is_never_removed(tmp_path, monkeypatch):
    """If the domain was already allowed, the lease is not owned and expiry leaves the provider alone."""
    allowlist = ["click.proofing-studio.example"]
    calls = nextdns_mock(monkeypatch, allowlist)
    app = live_app(tmp_path, provider_writes="nextdns")
    with TestClient(app) as client:
        seed_live_member(app)
        row, admin_headers = open_live(client, app)
        lease = client.get("/api/leases").json()[0]
        assert lease["execution"] == "applied" and lease["owned"] is False
        assert client.post(f"/api/leases/{lease['id']}/end", headers=admin_headers).status_code == 200
        assert allowlist == ["click.proofing-studio.example"] and all(method == "GET" for method, _ in calls)


def test_a_failed_close_stays_open_visible_and_retried(tmp_path, monkeypatch):
    """When the provider refuses the removal the lease stays active with an error, never silently ended."""
    allowlist: list[str] = []
    nextdns_mock(monkeypatch, allowlist, fail_delete=True)
    app = live_app(tmp_path, provider_writes="nextdns")
    with TestClient(app) as client:
        seed_live_member(app)
        _row, admin_headers = open_live(client, app)
        lease = client.get("/api/leases").json()[0]
        assert client.post(f"/api/leases/{lease['id']}/end", headers=admin_headers).status_code == 502
        after = client.get("/api/leases").json()[0]
        assert after["status"] == "active" and "HTTP 500" in after["last_error"]
        assert allowlist == ["click.proofing-studio.example"]
        assert any(x["kind"] == "lease" for x in client.get("/api/attention").json())


def test_a_provider_failure_while_opening_leaves_the_request_pending(tmp_path, monkeypatch):
    """A failed add stores no lease and tells the member a person will decide."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "dns-secret")
    monkeypatch.setattr(core, "make_http_client", lambda key, **_: httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(503)), follow_redirects=False))
    app = live_app(tmp_path, provider_writes="nextdns")
    with TestClient(app) as client:
        seed_live_member(app)
        row, _admin = open_live(client, app)
        assert row["status"] == "pending" and "could not change Office DNS" in row["decision_note"]
        assert client.get("/api/leases").json() == []


def test_device_links_apply_only_to_later_lookups(client, app, admin_headers):
    """Linking a DNS label attributes later events to the device and never backdates earlier ones."""
    labels = client.get("/api/device-links").json()
    label = next(x for x in labels if x["source_id"] == "dns-label-jamie")
    assert label["device_id"] is None and label["suggested_device_id"] is None
    assert client.put("/api/device-links", headers=admin_headers,
                      json={"source_id": "dns-label-jamie", "device_id": "dns-home"}).status_code == 422
    assert client.put("/api/device-links", headers=admin_headers,
                      json={"source_id": "laptop-jamie", "device_id": "laptop-jamie"}).status_code == 404
    assert client.put("/api/device-links", headers=admin_headers,
                      json={"source_id": "dns-label-jamie", "device_id": "laptop-jamie"}).status_code == 200
    now = utcnow()

    def block(id_, when):
        return {"id": id_, "device_id": None, "source_device_id": "dns-label-jamie", "reason_codes": [],
                "device_name": "Jamies-MacBook-Pro", "domain": "later.example", "source": "nextdns",
                "reason": "Blocklist", "observed_at": when.isoformat(),
                "expires_at": (when + timedelta(hours=24)).isoformat(), "evidence_kind": "observed",
                "attribution": "unverified", "risk_score": None, "risk_explanation": ""}

    with app.state.session_factory() as db:
        integration = db.get(Integration, "demo-nextdns")
        capabilities = list(integration.capabilities)
        apply_snapshot(db, integration, Snapshot(
            blocks=[block("demo-nextdns:block:before", now - timedelta(hours=2)),
                    block("demo-nextdns:block:after", now + timedelta(seconds=1))],
            capabilities=capabilities), app.state.settings)
        db.commit()
        assert db.get(Observation, "demo-nextdns:block:before").attribution == "unverified"
        after = db.get(Observation, "demo-nextdns:block:after")
        assert after.device_id == "laptop-jamie" and after.attribution == "assigned"
    signin(client, member=True)
    visible = {x["id"] for x in client.get("/api/blocks").json()}
    assert "demo-nextdns:block:after" in visible and "demo-nextdns:block:before" not in visible
