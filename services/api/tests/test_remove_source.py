"""Removing a saved source: its collected data goes, history stays, and nothing of Nyctr's is left at the source."""

from datetime import timedelta

import httpx
import pytest
from conftest import LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from nyctr import access
from nyctr.collection import apply_snapshot
from nyctr.integrations import Snapshot
from nyctr.models import (
    AccessRequest,
    Audit,
    DeviceGrant,
    DeviceLink,
    Finding,
    GuestAction,
    GuestPass,
    Insight,
    Integration,
    Lease,
    Observation,
    Relationship,
    Resource,
    Sighting,
    utcnow,
)

TABLES = (Integration, Resource, Relationship, Observation, DeviceGrant, DeviceLink, Sighting, GuestAction,
          GuestPass, Lease, AccessRequest, Finding, Insight, Audit)


def item(id_, integration_id, kind, name, provider="fabricated", **extra):
    return Resource(id=id_, integration_id=integration_id, name=name, kind=kind, provider=provider,
                    source_id=id_, observed_at=utcnow(), evidence_kind="observed", **extra)


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Two fabricated sources: a network source with Sam's assigned laptop, and a DNS source whose label for that
    laptop is linked to it. Each carries history that must survive a removal and data that must not."""
    # Removal never talks to a source: any outgoing provider request fails the test.
    async def no_request(*_args, **_kwargs):
        raise AssertionError("removal sent a request to a source")
    monkeypatch.setattr(httpx.AsyncClient, "send", no_request)
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        now, ended = utcnow(), utcnow() - timedelta(hours=1)
        with app.state.session_factory() as db:
            db.add_all([item("unifi:network:lan", "unifi", "network", "LAN"),
                        item("unifi:policy:block", "unifi", "policy", "Block cameras"),
                        item("dns:client:label", "dns", "client", "sams-laptop")])
            db.flush()
            db.add_all([
                DeviceLink(source_id="dns:client:label", device_id="unifi:client:laptop", created_by="owner"),
                Relationship(id="unifi:rel:one", integration_id="unifi", source="unifi:client:laptop",
                             target="unifi:network:lan", kind="member_of", provider="fabricated",
                             evidence_kind="observed", observed_at=now),
                Sighting(device_id="unifi:client:laptop", uplink_id="unifi:network:lan", first_seen=now, last_seen=now),
                Finding(id="auto:unifi-only", title="Only the network", severity="low", summary="",
                        resource_ids=["unifi:client:laptop"]),
                Finding(id="auto:both", title="Both", severity="low", summary="",
                        resource_ids=["unifi:client:laptop", "dns:client:label"]),
                Insight(finding_id="auto:unifi-only", evidence_hash="x", provider="none"),
                AccessRequest(id="request", block_id="dns:block:one", domain="click.example.org", device_name="Laptop",
                              requester_id="sam", reason="Work", duration_minutes=30, integration_id="dns"),
                Lease(integration_id="unifi", domain="ended.example.org", status="ended", execution="applied",
                      owned=True, ended_at=ended),
                GuestPass(integration_id="unifi", code="11111-22222", name="Ended", minutes=60, issued_by="owner",
                          ended_at=ended),
                GuestPass(integration_id="unifi", code="33333-44444", name="Read from the source", minutes=60),
            ])
            db.commit()
        yield app, client, live_signin(client)


def snapshot(app):
    """Count every row of every table, so a refusal can be shown to have changed nothing."""
    with app.state.session_factory() as db:
        return {model.__name__: db.scalar(select(func.count()).select_from(model)) for model in TABLES}


def remove(client, headers, id_="unifi", name="UniFi"):
    return client.request("DELETE", f"/api/integrations/{id_}", headers=headers, json={"name": name})


def test_preview_counts_what_goes_and_what_stays(world):
    """The confirmation is built from these counts."""
    _, client, _ = world
    preview = client.get("/api/integrations/unifi/removal").json()
    assert preview["name"] == "UniFi"
    assert preview["remove"] == {"devices": 1, "networks": 1, "rules": 1, "other_items": 0, "lookups": 0,
                                 "assignments": 1, "links": 1}
    assert preview["keep"] == {"requests": 0, "exceptions": 1, "passes": 1}
    assert preview["held"] == {"exceptions": 0, "passes": 0, "cut_off": 0, "locked_out": 0}
    assert (preview["let_on"], preview["notice"]) == (0, None)


def test_preview_says_guests_nyctr_let_on_stay_on_but_do_not_hold_removal_back(world):
    """Their grant ends by itself at the source, so removal goes ahead, but the administrator is told first that
    Nyctr can no longer cut them off. A grant already run out, or one only simulated, is not counted."""
    app, client, headers = world
    soon, gone = (utcnow() + timedelta(hours=4)).isoformat(), (utcnow() - timedelta(hours=1)).isoformat()
    with app.state.session_factory() as db:
        for name, ends, execution in (("on", soon, "applied"), ("over", gone, "applied"), ("sim", soon, "simulated")):
            db.add(item(f"unifi:client:{name}", "unifi", "client", name,
                        attributes={"guest": {"authorized": True, "expires_at": ends}}))
            db.flush()
            db.add(GuestAction(device_id=f"unifi:client:{name}", action="admit", actor="owner", execution=execution))
        db.commit()
    preview = client.get("/api/integrations/unifi/removal").json()
    assert preview["let_on"] == 1 and preview["refusal"] is None
    assert preview["notice"] == ("1 guest Nyctr let on stays let on at this source until its time ends. "
                                 "After removal, Nyctr can no longer cut it off.")
    assert remove(client, headers).status_code == 200


def test_removal_takes_only_this_sources_data_and_keeps_history(world):
    """After removal nothing collected from the source shows anywhere, the other source is untouched, and requests,
    ended exceptions, ended passes and the audit history remain, naming the source."""
    app, client, headers = world
    member = TestClient(app)
    live_signin(member, LIVE_MEMBER)
    assert [d["id"] for d in member.get("/api/devices").json()] == ["unifi:client:laptop"]
    assert [b["id"] for b in member.get("/api/blocks").json()["rows"]] == ["dns:block:one"]
    response = remove(client, headers)
    assert response.status_code == 200, response.text
    with app.state.session_factory() as db:
        assert db.get(Integration, "unifi") is None and db.get(Integration, "dns") is not None
        assert set(db.scalars(select(Resource.id))) == {"dns:client:label"}
        assert not list(db.scalars(select(DeviceGrant))) and not list(db.scalars(select(DeviceLink)))
        assert not list(db.scalars(select(Relationship))) and not list(db.scalars(select(Sighting)))
        # The DNS source's lookup stays, no longer tied to the removed laptop.
        lookup = db.get(Observation, "dns:block:one")
        assert (lookup.device_id, lookup.attribution) == (None, "unverified")
        assert db.get(Finding, "auto:unifi-only") is None and db.get(Insight, "auto:unifi-only") is None
        assert db.get(Finding, "auto:both").resource_ids == ["dns:client:label"]
        assert [p.name for p in db.scalars(select(GuestPass))] == ["Ended"]
        assert [lease.status for lease in db.scalars(select(Lease))] == ["ended"]
        record = db.scalar(select(Audit).where(Audit.action == "integration.removed"))
        assert record.target_id == "unifi" and record.actor_id is not None
        assert record.details == {"name": "UniFi", "provider": "unifi_network", "removed": {
            "devices": 1, "networks": 1, "rules": 1, "other_items": 0, "lookups": 0, "assignments": 1, "links": 1}}
    # A member who had the laptop sees it gone, with no error.
    assert member.get("/api/devices").status_code == 200 and member.get("/api/devices").json() == []
    assert member.get("/api/blocks").json()["rows"] == []
    assert [r["id"] for r in member.get("/api/requests").json()] == ["request"]
    assert [i["id"] for i in client.get("/api/integrations").json()] == ["dns"]
    # Removing the DNS source too keeps the request, still naming the source as it was.
    assert remove(client, headers, "dns", "Office DNS").status_code == 200
    assert [(r["id"], r["source_name"]) for r in client.get("/api/requests").json()] == [("request", "Office DNS")]
    assert {e["target_id"] for e in client.get("/api/audit").json() if e["action"] == "integration.removed"} == {
        "unifi", "dns"}


def held(app, kind):
    """Give Nyctr something of its own at the network source, of the given kind."""
    with app.state.session_factory() as db:
        if kind == "exception":
            db.add(Lease(integration_id="unifi", domain="held.example.org", execution="applied", owned=True))
        elif kind == "pass":
            db.add(GuestPass(integration_id="unifi", code="55555-66666", name="Visitor", minutes=60,
                             issued_by="owner", execution="applied"))
        else:
            db.add(GuestAction(device_id="unifi:client:laptop", action="cut" if kind == "cut" else "lock",
                               actor="owner", execution="applied"))
        db.commit()


@pytest.mark.parametrize("kind, told", [("exception", "1 open exception (end under Open now)"),
                                        ("pass", "1 guest pass it issued (end under Guests)"),
                                        ("cut", "1 guest cut off (let back on under Guests)"),
                                        ("lock", "1 guest locked out (unlock under Guests)")])
def test_removal_waits_while_nyctr_still_has_something_of_its_own_at_the_source(world, kind, told):
    """Nyctr could never end it afterwards, so removal is refused with the count and where to end it."""
    app, client, headers = world
    held(app, kind)
    before = snapshot(app)
    response = remove(client, headers)
    assert response.status_code == 409 and told in response.json()["detail"], response.text
    assert snapshot(app) == before


def test_entries_nyctr_did_not_create_do_not_block_removal_and_are_not_sent_anywhere(world):
    """An exception that already existed, one never applied and a pass read from the source do not hold it back.
    Nothing is sent to the source (the fixture fails any request); Nyctr's own records of them simply end."""
    app, client, headers = world
    with app.state.session_factory() as db:
        db.add_all([Lease(integration_id="unifi", domain="theirs.example.org", execution="applied", owned=False),
                    Lease(integration_id="unifi", domain="never.example.org", execution="not_applied", owned=True)])
        db.commit()
    assert client.get("/api/integrations/unifi/removal").json()["held"]["exceptions"] == 0
    assert remove(client, headers).status_code == 200
    with app.state.session_factory() as db:
        ended = {lease.domain: lease.ended_reason for lease in db.scalars(select(Lease))}
        assert ended == {"ended.example.org": None, "theirs.example.org": "source_removed",
                         "never.example.org": "source_removed"}


@pytest.mark.parametrize("case, status", [("member", 403), ("signed out", 401), ("no token", 403),
                                          ("wrong token", 403), ("unknown source", 404), ("wrong name", 422),
                                          ("collecting", 409)])
def test_refused_removals_change_nothing(world, case, status):
    """Each denial path leaves every table exactly as it was."""
    app, client, headers = world
    id_, name = "unifi", "UniFi"
    if case == "member":
        headers = live_signin(client, LIVE_MEMBER)
    elif case == "signed out":
        client.cookies.clear()
    elif case in ("no token", "wrong token"):
        headers = {} if case == "no token" else {"X-CSRF-Token": "not-this-session"}
    elif case == "unknown source":
        id_ = "missing"
    elif case == "wrong name":
        name = "Unifi"
    else:
        with app.state.session_factory() as db:
            row = db.get(Integration, "unifi")
            row.status, row.sync_started_at = "syncing", utcnow()
            db.commit()
    before = snapshot(app)
    assert remove(client, headers, id_, name).status_code == status
    assert snapshot(app) == before


def test_demo_sources_cannot_be_removed(client, admin_headers):
    before = client.get("/api/integrations").json()
    response = client.request("DELETE", f"/api/integrations/{before[0]['id']}", headers=admin_headers,
                              json={"name": before[0]["name"]})
    assert response.status_code == 409 and client.get("/api/integrations").json() == before


def test_a_failure_part_way_leaves_everything_as_it_was(world, monkeypatch):
    """Removal is one transaction: a failure after the deletes, before the commit, rolls all of them back."""
    app, _, _ = world
    client = TestClient(app, raise_server_exceptions=False)
    headers = live_signin(client)
    before = snapshot(app)

    def fail(*_args, **_kwargs):
        raise RuntimeError("fabricated failure")
    monkeypatch.setattr("nyctr.main.audit", fail)
    assert remove(client, headers).status_code == 500
    assert snapshot(app) == before


def test_a_new_source_for_the_same_place_starts_from_nothing(world):
    """Removing and adding a source is how it is pointed somewhere else: the same identifiers bring back no
    assignment, label link or lookup for the member who had them."""
    app, client, headers = world
    assert remove(client, headers).status_code == 200
    now = utcnow()
    with app.state.session_factory() as db:
        db.add(Integration(id="unifi-again", provider="unifi_network", name="UniFi", status="configured",
                           config={}, secret_ref="NYCTR_CONNECTOR_SECRET_UNIFI"))
        db.commit()
        laptop = {"id": "unifi-again:client:laptop", "name": "Sam's laptop", "kind": "client",
                  "provider": "unifi_network", "source_id": "laptop", "observed_at": now.isoformat(),
                  "evidence_kind": "observed", "attributes": {"ip": "10.0.0.9"}}
        apply_snapshot(db, db.get(Integration, "unifi-again"), Snapshot(resources=[laptop]), app.state.settings)
        block = {"id": "dns:block:later", "device_id": None, "source_device_id": "dns:client:label",
                 "device_name": "sams-laptop", "domain": "later.example.org", "source": "nextdns",
                 "reason": "Blocklist", "reason_codes": [], "observed_at": (now + timedelta(seconds=1)).isoformat(),
                 "expires_at": (now + timedelta(hours=24)).isoformat(), "evidence_kind": "observed",
                 "attribution": "unverified", "risk_score": None, "risk_explanation": ""}
        apply_snapshot(db, db.get(Integration, "dns"), Snapshot(blocks=[block]), app.state.settings)
        db.commit()
        assert db.get(Resource, "unifi-again:client:laptop").classification == "unassigned"
        assert db.get(Observation, "dns:block:later").device_id is None
    member = TestClient(app)
    live_signin(member, LIVE_MEMBER)
    assert member.get("/api/devices").json() == [] and member.get("/api/blocks").json()["rows"] == []


def test_a_link_to_a_device_removed_before_it_is_stored_is_refused_in_plain_words(world, monkeypatch):
    """A label link whose device goes with its source between the read and the commit stores nothing: 404."""
    app, client, headers = world
    with app.state.session_factory() as db:
        db.add_all([item("dns:client:spare-label", "dns", "client", "spare", provider="nextdns"),
                    item("unifi:client:spare", "unifi", "client", "Spare", provider="unifi_network")])
        db.commit()
    real = access.audit

    def remove_device_first(db, *args, **details):
        with app.state.session_factory() as other:
            other.delete(other.get(Resource, "unifi:client:spare"))
            other.commit()
        return real(db, *args, **details)
    monkeypatch.setattr("nyctr.access.audit", remove_device_first)
    response = client.put("/api/device-links", headers=headers,
                          json={"source_id": "dns:client:spare-label", "device_id": "unifi:client:spare"})
    assert response.status_code == 404 and "no longer in your inventory" in response.json()["detail"]
    with app.state.session_factory() as db:
        assert db.get(DeviceLink, "dns:client:spare-label") is None
