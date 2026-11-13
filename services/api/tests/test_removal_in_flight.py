"""A source removed while Nyctr is changing it: what Nyctr just created there is taken back, or the failure kept."""

import pytest
from conftest import live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_guests import live_guest

from nyctr.integrations import IntegrationError, registry
from nyctr.models import Audit, GuestPass, Integration, Lease, utcnow


class StandIn:
    """A provider whose write pauses mid-call while the source is removed, and whose undo can fail."""

    def __init__(self, during, fail_undo):
        self.during, self.fail_undo, self.undone = during, fail_undo, []

    async def allow_domain(self, config, key, domain, *, allowed):
        self.during()
        return {"owned": True}

    async def disallow_domain(self, config, key, domain, *, allowed):
        self.undone.append((config, domain, allowed))
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
