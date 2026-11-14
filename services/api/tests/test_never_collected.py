"""Nyctr changes nothing at a source it has never collected from, so a source cannot move under a change."""

import dataclasses

import pytest
from conftest import LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from test_access import put_rule
from test_guests import live_guest

from nyctr.integrations import registry
from nyctr.models import AccessRequest, GuestAction, GuestPass, Integration, Lease, Resource, utcnow

EXCEPTIONS, GUESTS = ("approval", "rule", "permanent"), ("pass", "admit", "cut", "lock")
TOLD = "has not collected from"


class StandIn:
    """Records every provider change it is asked for, and does it."""

    def __init__(self, during=lambda: None):
        self.calls, self.during = [], during

    async def allow_domain(self, config, key, domain, *, allowed):
        self.calls.append(("allow", domain))
        self.during()
        return {"owned": True}

    async def disallow_domain(self, config, key, domain, *, allowed):
        self.calls.append(("disallow", domain))

    async def issue_pass(self, config, key, site, **_kwargs):
        self.calls.append(("issue",))
        return {"id": "voucher-1", "code": "1234567890"}

    async def guest_access(self, config, key, site, device, allow, **_kwargs):
        self.calls.append(("guest", allow))


def world(tmp_path, monkeypatch, kind, collected):
    """A live app whose source for this kind of change has, or has never, collected; provider calls go to a
    stand-in. Returns the client, admin headers, the app and the stand-in."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "dns-secret")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "unifi-secret")
    app = live_app(tmp_path, provider_writes="nextdns,unifi_network")
    client = TestClient(app).__enter__()
    (live_guest if kind in GUESTS else seed_live_member)(app)
    with app.state.session_factory() as db:
        if kind == "permanent":
            db.add(Lease(integration_id="dns", domain="often.example.org", decided_by="rule", status="ended",
                         execution="applied", owned=True, ended_at=utcnow()))
        if kind == "admit":
            db.get(Resource, "unifi:client:g1").attributes = {"guest": {"authorized": False}}
        db.get(Integration, "unifi" if kind in GUESTS else "dns").last_sync = utcnow() if collected else None
        db.commit()
    stand_in = StandIn()
    monkeypatch.setattr("nyctr.access._opener", lambda integration: stand_in)
    real, find, get = registry.find("unifi_network"), registry.find, registry.get
    fake = dataclasses.replace(real, issue_pass=stand_in.issue_pass, guest_access=stand_in.guest_access)
    monkeypatch.setattr(registry, "find", lambda provider: fake if provider == "unifi_network" else find(provider))
    monkeypatch.setattr(registry, "get", lambda provider: fake if provider == "unifi_network" else get(provider))
    return client, live_signin(client), app, stand_in


def change(client, headers, kind):
    """Start one kind of provider change; return the status code and the plain sentence (or new status)."""
    if kind in ("approval", "rule"):
        if kind == "rule":
            put_rule(client, headers)
        row = client.post("/api/requests", headers=live_signin(client, LIVE_MEMBER), json={
            "block_id": "dns:block:one", "reason": "Need the gallery", "duration_minutes": 60}).json()
        if kind == "rule":
            return row["status"], row["decision_note"]
        response = client.post(f"/api/requests/{row['id']}/review", headers=live_signin(client),
                               json={"decision": "approved", "note": "Fine for work"})
    elif kind == "permanent":
        response = client.post("/api/suggestions", headers=headers,
                               json={"domain": "often.example.org", "action": "make_permanent"})
    elif kind == "pass":
        response = client.post("/api/guests/passes", headers=headers, json={"name": "Friend", "minutes": 90})
    else:
        response = client.post("/api/guests/actions", headers=headers,
                               json={"device_id": "unifi:client:g1", "action": kind})
    return response.status_code, response.json().get("detail", "")


def stored(app):
    with app.state.session_factory() as db:
        return [db.scalar(select(func.count()).select_from(model).where(*where)) for model, where in (
            (Lease, (Lease.status == "active",)), (GuestPass, ()), (GuestAction, ()),
            (AccessRequest, (AccessRequest.status != "pending",)))]


@pytest.mark.parametrize("kind", EXCEPTIONS + GUESTS)
def test_no_change_is_made_at_a_source_never_collected_from(tmp_path, monkeypatch, kind):
    """Refused in plain words before any provider call: nothing sent, nothing stored."""
    client, headers, app, stand_in = world(tmp_path, monkeypatch, kind, collected=False)
    status, told = change(client, headers, kind)
    assert status in (409, "pending") and TOLD in told, (status, told)
    assert stand_in.calls == [] and stored(app) == [0, 0, 0, 0]


@pytest.mark.parametrize("kind", EXCEPTIONS + GUESTS)
def test_the_same_change_goes_ahead_once_the_source_has_collected(tmp_path, monkeypatch, kind):
    client, headers, app, stand_in = world(tmp_path, monkeypatch, kind, collected=True)
    status, told = change(client, headers, kind)
    assert status in (200, 201, "auto_approved") and TOLD not in told, (status, told)
    assert len(stand_in.calls) == 1


def test_a_source_cannot_be_moved_under_a_change_so_an_undo_never_goes_to_the_wrong_place(tmp_path, monkeypatch):
    """The scenario of a source moved from one place to another while a change is in flight, with the undo at
    the first place failing, cannot be set up: before its first collection nothing is changed there, and after
    it, where it reads cannot change, including during the call."""
    client, headers, app, stand_in = world(tmp_path, monkeypatch, "permanent", collected=False)
    move = {"name": "Office DNS", "secret_ref": "NYCTR_CONNECTOR_SECRET_DNS", "config": {"profile_id": "fed789"}}
    assert change(client, headers, "permanent")[0] == 409 and stand_in.calls == []
    with app.state.session_factory() as db:
        db.get(Integration, "dns").last_sync = utcnow()
        db.commit()
    refused = []
    stand_in.during = lambda: refused.append(TestClient(app, cookies=dict(client.cookies)).put(
        "/api/integrations/dns", headers=headers, json=move).status_code)
    assert change(client, headers, "permanent")[0] == 200
    assert refused == [409] and stand_in.calls == [("allow", "often.example.org")]
    with app.state.session_factory() as db:
        assert db.get(Integration, "dns").config["profile_id"] == "abc123"
