"""A source removed while Nyctr is changing it: what Nyctr just created there is taken back, or the failure kept."""

import dataclasses
import sqlite3
from datetime import timedelta

import pytest
from conftest import LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_access import put_rule
from test_guests import live_guest, run_rule

from nyctr.integrations import IntegrationError, registry
from nyctr.models import Audit, GuestAction, GuestPass, Integration, Lease, Observation, Resource, utcnow


class StandIn:
    """A provider whose write pauses mid-call while the source is removed, and whose undo can fail."""

    def __init__(self, during, fail_undo, owned=True, on_undo=lambda: None):
        self.during, self.fail_undo, self.owned, self.on_undo, self.undone = during, fail_undo, owned, on_undo, []

    async def allow_domain(self, config, key, domain, *, allowed):
        self.during()
        return {"owned": self.owned}

    async def disallow_domain(self, config, key, domain, *, allowed):
        self.undone.append((config, domain, allowed))
        self.on_undo()
        if self.fail_undo:
            raise IntegrationError("The source did not answer.")

    async def issue_pass(self, config, key, site, **_kwargs):
        self.during()
        return {"id": "voucher-1", "code": "1234567890"}

    async def end_pass(self, config, key, site, voucher, *, allowed):
        self.undone.append((config, voucher, allowed))
        if self.fail_undo:
            raise IntegrationError("The source did not answer.")


def removal_during(app, client, headers, id_, name):
    """Return a callable that removes the source from a second browser, and the statuses it got."""
    done = []

    def run():
        other = TestClient(app, cookies=dict(client.cookies))
        done.append(other.request("DELETE", f"/api/integrations/{id_}", headers=headers,
                                  json={"name": name}).status_code)
    return run, done


def undo_records(app):
    with app.state.session_factory() as db:
        return [(r.action, r.details["execution"]) for r in db.scalars(select(Audit).where(
            Audit.action.in_(("access.open_undone", "guest.pass_undone"))))]


@pytest.mark.parametrize("fail_undo", [False, True])
def test_an_exception_added_while_its_source_is_removed_is_taken_back(tmp_path, monkeypatch, fail_undo):
    """The stand-in adds the exception; the source is removed during that call. Nyctr takes the exception back
    at the place the call used, or, when that fails, keeps it open with its error and says so."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "dns-secret")
    app = live_app(tmp_path, provider_writes="nextdns")
    with TestClient(app) as client:
        seed_live_member(app)
        with app.state.session_factory() as db:
            db.add(Lease(integration_id="dns", domain="often.example.org", decided_by="rule", status="ended",
                         execution="applied", owned=True, ended_at=utcnow()))
            db.commit()
        headers = live_signin(client)
        during, removed = removal_during(app, client, headers, "dns", "Home DNS")
        stand_in = StandIn(during, fail_undo)
        monkeypatch.setattr("nyctr.access._opener", lambda integration: stand_in)
        response = client.post("/api/suggestions", headers=headers,
                               json={"domain": "often.example.org", "action": "make_permanent"})
        assert removed == [200]
        assert response.status_code == 409, response.text
        assert stand_in.undone == [({"profile_id": "abc123"}, "often.example.org", True)]
        assert undo_records(app) == [("access.open_undone", "failed" if fail_undo else "applied")]
        with app.state.session_factory() as db:
            assert db.get(Integration, "dns") is None
            active = list(db.scalars(select(Lease).where(Lease.status == "active")))
        if fail_undo:
            assert "could not take it back out" in response.json()["detail"]
            assert [(lease.domain, lease.owned, bool(lease.last_error)) for lease in active] == [
                ("often.example.org", True, True)]
            assert [lease["domain"] for lease in client.get("/api/leases").json() if lease["status"] == "active"] \
                == ["often.example.org"]
        else:
            assert "took that exception back out. Nothing was opened." in response.json()["detail"]
            assert active == []


@pytest.mark.parametrize("fail_undo", [False, True])
def test_a_pass_issued_while_its_source_is_removed_is_ended_again(tmp_path, monkeypatch, fail_undo):
    """The stand-in issues the pass; the source is removed during that call. Nyctr ends the pass at the place
    the call used, or, when that fails, keeps it listed as live and records the failure."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "unifi-secret")
    app = live_app(tmp_path, provider_writes="unifi_network")
    with TestClient(app) as client:
        live_guest(app)
        headers = live_signin(client)
        during, removed = removal_during(app, client, headers, "unifi", "UniFi")
        stand_in = StandIn(during, fail_undo)
        monkeypatch.setattr(registry, "get", lambda provider: stand_in)
        response = client.post("/api/guests/passes", headers=headers, json={"name": "Friend", "minutes": 90})
        assert removed == [200]
        assert response.status_code == 409, response.text
        assert stand_in.undone == [({"base_url": "https://unifi.example/proxy/network/integration"}, "voucher-1",
                                    True)]
        assert undo_records(app) == [("guest.pass_undone", "failed" if fail_undo else "applied")]
        with app.state.session_factory() as db:
            passes = [(p.voucher_id, p.execution, p.ended_at) for p in db.scalars(select(GuestPass))]
        if fail_undo:
            assert "could not end that pass" in response.json()["detail"]
            assert passes == [("voucher-1", "applied", None)]
        else:
            assert "ended that pass again. No pass was issued." in response.json()["detail"]
            assert passes == []


def make_permanent(tmp_path, monkeypatch, during_edit=None, **stand_in):
    """Make often.example.org permanent at the DNS source through the stand-in, with `during_edit` (new settings)
    saved by a second browser while the call is in flight. Return the app, the answer and the stand-in."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "dns-secret")
    app = live_app(tmp_path, provider_writes="nextdns")
    client = TestClient(app).__enter__()
    seed_live_member(app)
    with app.state.session_factory() as db:
        db.add(Lease(integration_id="dns", domain="often.example.org", decided_by="rule", status="ended",
                     execution="applied", owned=True, ended_at=utcnow()))
        db.commit()
    headers = live_signin(client)

    def edit():
        other = TestClient(app, cookies=dict(client.cookies))
        body = {"name": "Home DNS", "secret_ref": "NYCTR_CONNECTOR_SECRET_DNS", "config": during_edit}
        answer = other.put("/api/integrations/dns", headers=headers, json=body)
        assert answer.status_code == 200, answer.text
    removal, removed = removal_during(app, client, headers, "dns", "Home DNS")
    found = StandIn(edit if during_edit else removal, False, **stand_in)
    monkeypatch.setattr("nyctr.access._opener", lambda integration: found)
    response = client.post("/api/suggestions", headers=headers,
                           json={"domain": "often.example.org", "action": "make_permanent"})
    return app, client, response, found


def test_a_number_changed_during_the_call_does_not_move_the_source(tmp_path, monkeypatch):
    """Hours of lookups say what is read, not where: the exception stays open and nothing is taken back."""
    app, client, response, stand_in = make_permanent(tmp_path, monkeypatch,
                                                     {"profile_id": "abc123", "lookback_hours": 12})
    assert response.status_code == 200, response.text
    assert stand_in.undone == [] and undo_records(app) == []
    with app.state.session_factory() as db:
        assert db.get(Integration, "dns").config["lookback_hours"] == 12
        assert [lease.domain for lease in db.scalars(select(Lease).where(Lease.status == "active"))] == [
            "often.example.org"]


def test_a_source_moved_during_the_call_is_undone_at_the_old_place_with_nothing_held(tmp_path, monkeypatch):
    """Before its first collection a source may still be moved. Changed between the call and storing the
    exception: the undo goes to the place the call used, and while it is in flight the source row (indeed the
    whole database, on SQLite) is free for anything else, such as a collection taking its lease."""
    free = []

    def take_the_row():
        with sqlite3.connect(f"{tmp_path}/live.db", timeout=0.2) as other:
            other.execute("UPDATE integrations SET name = name WHERE id = 'dns'")
        free.append(True)
    app, client, response, stand_in = make_permanent(tmp_path, monkeypatch, {"profile_id": "fed789"},
                                                     on_undo=take_the_row)
    assert response.status_code == 409 and "took that exception back out" in response.json()["detail"]
    assert stand_in.undone == [({"profile_id": "abc123"}, "often.example.org", True)] and free == [True]
    assert undo_records(app) == [("access.open_undone", "applied")]
    with app.state.session_factory() as db:
        assert db.get(Integration, "dns").config["profile_id"] == "fed789"
        assert not list(db.scalars(select(Lease).where(Lease.status == "active")))


def test_an_undo_never_removes_an_entry_nyctr_did_not_add(tmp_path, monkeypatch):
    """The exception was already at the source: the source is removed during the call and nothing is taken out."""
    app, client, response, stand_in = make_permanent(tmp_path, monkeypatch, owned=False)
    assert response.status_code == 409 and "Nyctr left it as it was" in response.json()["detail"]
    assert stand_in.undone == [] and undo_records(app) == [("access.open_undone", "not_applied")]


@pytest.mark.parametrize("path", ["approval", "rule"])
def test_the_approval_and_the_access_rule_take_back_and_say_so(tmp_path, monkeypatch, path):
    """The source is found removed once the call returns. The request stays waiting, with its assessment, and the
    take-back is recorded. (On SQLite these paths hold a write across the call, so the removal itself is stood in
    for; the real race is run by hand on PostgreSQL.)"""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "dns-secret")
    app = live_app(tmp_path, provider_writes="nextdns")
    with TestClient(app) as client:
        seed_live_member(app)
        headers = live_signin(client)
        if path == "rule":
            put_rule(client, headers)
        stand_in = StandIn(lambda: None, False)
        monkeypatch.setattr("nyctr.access._opener", lambda integration: stand_in)
        monkeypatch.setattr("nyctr.access.source_held", lambda db, integration_id: False)
        row = client.post("/api/requests", headers=live_signin(client, LIVE_MEMBER), json={
            "block_id": "dns:block:one", "reason": "Need the gallery", "duration_minutes": 60}).json()
        if path == "approval":
            response = client.post(f"/api/requests/{row['id']}/review", headers=live_signin(client),
                                   json={"decision": "approved", "note": "Fine for work"})
            assert response.status_code == 409 and "took that exception back out" in response.json()["detail"]
        else:
            assert "took that exception back out" in row["decision_note"] and row["risk_score"] is not None
        assert client.get("/api/requests").json()[0]["status"] == "pending"
        assert len(stand_in.undone) == 1 and undo_records(app) == [("access.open_undone", "applied")]


def test_an_exception_left_at_a_removed_source_is_not_retried_and_can_be_marked_removed_by_hand(tmp_path,
                                                                                               monkeypatch):
    """Nothing can reach it: reading the list after it is due neither calls nor records a failure, and its
    message is kept. An administrator who removed it there marks it so; that is recorded."""
    app = live_app(tmp_path, provider_writes="nextdns")
    with TestClient(app) as client:
        seed_live_member(app)
        stand_in = StandIn(lambda: None, False)
        monkeypatch.setattr("nyctr.access._opener", lambda integration: stand_in)
        told = "Remove the exception for kept.example.org at that source by hand."
        with app.state.session_factory() as db:
            db.add_all([Lease(id="kept", integration_id="removed", domain="kept.example.org", execution="applied",
                              owned=True, last_error=told, expires_at=utcnow() - timedelta(minutes=1)),
                        Lease(id="here", integration_id="dns", domain="here.example.org", execution="applied",
                              owned=True)])
            db.commit()
        headers = live_signin(client)
        for _ in range(2):
            kept = next(lease for lease in client.get("/api/leases").json() if lease["id"] == "kept")
        assert (kept["status"], kept["last_error"], kept["source_removed"]) == ("active", told, True)
        ended = client.post("/api/leases/kept/end", headers=headers, json={})
        assert ended.status_code == 409 and "mark it as removed by hand" in ended.json()["detail"]
        assert client.post("/api/leases/here/end", headers=headers, json={"by_hand": True}).status_code == 409
        assert client.post("/api/leases/kept/end", headers=headers, json={"by_hand": True}).status_code == 200
        assert stand_in.undone == []
        with app.state.session_factory() as db:
            assert db.get(Lease, "kept").ended_reason == "removed_by_hand"
            assert [(a.action, a.details.get("reason")) for a in db.scalars(select(Audit).where(
                Audit.action.like("access.close%")))] == [("access.closed", "removed_by_hand")]


def guest_stand_in(monkeypatch, during):
    """Let the network source's own guest call pause while `during` runs, recording each call."""
    calls, real, find = [], registry.find("unifi_network"), registry.find

    async def guest_access(config, key, site, device, allow, **_kwargs):
        calls.append((device, allow))
        during(len(calls))
    fake = dataclasses.replace(real, guest_access=guest_access)
    monkeypatch.setattr(registry, "find", lambda provider: fake if provider == "unifi_network" else find(provider))
    return calls


@pytest.mark.parametrize("action", ["cut", "lock", "admit"])
def test_a_guest_action_whose_source_is_removed_during_the_call_is_recorded_and_told(tmp_path, monkeypatch,
                                                                                     action):
    """What was done at the source is recorded with the source's name; the device row (gone) is left alone, a cut
    is not undone, and the administrator is told in plain words."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "unifi-secret")
    app = live_app(tmp_path, provider_writes="unifi_network")
    with TestClient(app) as client:
        live_guest(app)
        if action == "admit":
            with app.state.session_factory() as db:
                db.get(Resource, "unifi:client:g1").attributes = {"guest": {"authorized": False}}
                db.commit()
        headers = live_signin(client)
        removal, removed = removal_during(app, client, headers, "unifi", "UniFi")
        calls = guest_stand_in(monkeypatch, lambda _n: removal())
        response = client.post("/api/guests/actions", headers=headers,
                               json={"device_id": "unifi:client:g1", "action": action})
        assert removed == [200] and len(calls) == 1
        assert response.status_code == 409, response.text
        assert response.json()["detail"].startswith("UniFi was removed while Nyctr was changing Visitor phone's")
        with app.state.session_factory() as db:
            assert not list(db.scalars(select(GuestAction)))
            record = db.scalar(select(Audit).where(Audit.action == f"guest.{action}"))
        assert (record.target_id, record.details["execution"], record.details["source"],
                record.details["source_removed"]) == ("unifi:client:g1", "applied", "UniFi", True)


def test_the_cut_off_rule_goes_on_with_the_next_guest_when_one_source_is_removed_mid_pass(tmp_path, monkeypatch):
    """Two guests due at two sources; the first one's source is removed during its cut. That cut is recorded,
    and the second guest is still cut off in the same pass."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "unifi-secret")
    app = live_app(tmp_path, provider_writes="unifi_network")
    with TestClient(app) as client:
        live_guest(app)
        now = utcnow()
        with app.state.session_factory() as db:
            db.add(Integration(id="unifi2", provider="unifi_network", name="Barn", status="connected",
                               config={"base_url": "https://barn.example"}, secret_ref="NYCTR_CONNECTOR_SECRET_UNIFI"))
            db.flush()
            for id_, kind in (("unifi2:site:s2", "site"), ("unifi2:client:g2", "client")):
                db.add(Resource(id=id_, integration_id="unifi2", name="Zed tablet", kind=kind, provider="unifi_network",
                                source_id=id_, site_id="unifi2:site:s2", observed_at=now, evidence_kind="observed",
                                attributes={"guest": {"authorized": True}} if kind == "client" else {}))
            for index in range(3):
                db.add(Observation(id=f"dns:block:z{index}", integration_id="dns", device_id="unifi2:client:g2",
                                   device_name="Zed tablet", domain=f"worse{index}.example", source="nextdns",
                                   reason="Threat Intelligence Feeds", reason_codes=["threat-intelligence-feeds"],
                                   observed_at=now, expires_at=now + timedelta(hours=1), evidence_kind="observed",
                                   attribution="inferred", risk_score=None, risk_explanation=""))
            db.commit()
        removal, removed = removal_during(app, client, live_signin(client), "unifi", "UniFi")
        calls = guest_stand_in(monkeypatch, lambda n: removal() if n == 1 else None)
        assert run_rule(app) == 2 and removed == [200]
        assert [device for device, _ in calls] == ["g1", "unifi2:client:g2"]
        with app.state.session_factory() as db:
            assert [(a.device_id, a.execution) for a in db.scalars(select(GuestAction))] == [
                ("unifi2:client:g2", "applied")]
            assert db.scalar(select(Audit).where(Audit.target_id == "unifi:client:g1")).details["source_removed"]
