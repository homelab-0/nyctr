"""Editing a saved source: same validation as a new one, with every refusal leaving the row untouched."""

import asyncio
import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_collection import live_client

from nyctr.collection import collect_integration
from nyctr.diagnostics import DiagnosticReport
from nyctr.integrations import Snapshot
from nyctr.main import _settled_status
from nyctr.models import Audit, DeviceLink, GuestPass, Integration, Lease, Resource, User, utcnow

KEY = "EDIT_SECRET_SENTINEL"
ADDRESS = "https://resolver.example.net"
SAVED = {"name": "Resolver", "config": {"base_url": ADDRESS, "lookback_hours": 24},
         "secret_ref": "NYCTR_CONNECTOR_SECRET_RESOLVER"}


@pytest.fixture
def source(tmp_path, monkeypatch):
    """Save one live source with an address setting, already collected once, and sign its administrator in."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "resolver.example.net,second.example.net")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_RESOLVER", KEY)
    with live_client(tmp_path) as client:
        logged = client.post("/api/auth/login", json={"email": "owner@example.net",
                                                      "password": "secure password for tests"})
        headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
        created = client.post("/api/integrations", headers=headers, json={"provider": "pihole", **SAVED})
        assert created.status_code == 201, created.text
        id_ = created.json()["id"]
        with client.app.state.session_factory() as db:
            row = db.get(Integration, id_)
            row.status, row.last_sync = "partial", utcnow()
            db.add(Resource(id=f"{id_}:client:one", integration_id=id_, name="Tablet", kind="client",
                            provider="pihole", source_id="one", observed_at=utcnow(), evidence_kind="observed"))
            db.commit()
        yield client, headers, id_


def stored(client, id_):
    """Read the saved row straight from the database, bypassing the API under test."""
    with client.app.state.session_factory() as db:
        row = db.get(Integration, id_)
        return {"name": row.name, "config": row.config, "secret_ref": row.secret_ref, "status": row.status,
                "last_sync": row.last_sync, "last_error": row.last_error}


def edit(client, headers, id_, **changes):
    """Send the whole edit form, as the console does, with some fields changed."""
    return client.put(f"/api/integrations/{id_}", headers=headers, json={**SAVED, **changes})


def assert_untouched(client, id_):
    """A refused edit must leave name, settings, secret name and status exactly as saved."""
    row = stored(client, id_)
    assert {key: row[key] for key in SAVED} == {**SAVED, "config": {"base_url": ADDRESS + "/api", "lookback_hours": 24}}
    assert row["status"] == "partial"
    with client.app.state.session_factory() as db:
        assert db.scalar(select(Audit).where(Audit.action == "integration.updated")) is None


def test_name_and_reading_setting_change_keeps_status_and_collected_data(source):
    """A new name or a shorter window is saved without sending the source back for testing."""
    client, headers, id_ = source
    response = edit(client, headers, id_, name="Kitchen resolver", config={"base_url": ADDRESS, "lookback_hours": 6})
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["name"], body["config"]["lookback_hours"], body["status"]) == ("Kitchen resolver", 6, "partial")
    assert body["provider"] == "pihole" and body["last_sync"] is not None
    assert KEY not in response.text
    assert stored(client, id_)["config"] == {"base_url": ADDRESS + "/api", "lookback_hours": 6}


@pytest.mark.parametrize("changes", [
    {"config": {"base_url": "https://second.example.net", "lookback_hours": 24}},
    {"secret_ref": "NYCTR_CONNECTOR_SECRET_SECOND"},
])
def test_new_address_or_secret_name_needs_testing_again_and_keeps_what_was_collected(source, changes):
    """Where or as whom Nyctr reads changed: the source is untested again, its earlier evidence stays."""
    client, headers, id_ = source
    with client.app.state.session_factory() as db:
        db.get(Integration, id_).last_error = "An earlier failure at the old address."
        db.commit()
    response = edit(client, headers, id_, **changes)
    assert response.status_code == 200, response.text
    row = stored(client, id_)
    assert row["status"] == "configured" and row["last_error"] is None
    assert row["last_sync"] is not None
    assert [item["name"] for item in client.get("/api/resources").json()] == ["Tablet"]
    with client.app.state.session_factory() as db:
        # An abandoned lease on this source must settle back to "needs a test", not "connected".
        assert _settled_status(db, db.get(Integration, id_)) == "configured"


def test_unchanged_form_saves_nothing_and_writes_no_audit_record(source):
    """Pressing save without a change is not an edit."""
    client, headers, id_ = source
    assert edit(client, headers, id_).status_code == 200
    assert_untouched(client, id_)


def test_edit_is_audited_by_field_name_without_address_or_secret_name(source):
    """The audit history says who changed which fields of which source, and none of the values."""
    client, headers, id_ = source
    assert edit(client, headers, id_, name="Kitchen resolver", secret_ref="NYCTR_CONNECTOR_SECRET_SECOND",
                config={"base_url": "https://second.example.net", "lookback_hours": 24}).status_code == 200
    with client.app.state.session_factory() as db:
        record = db.scalar(select(Audit).where(Audit.action == "integration.updated"))
        admin = db.scalar(select(User).where(User.email == "owner@example.net"))
        assert (record.actor_id, record.target_id) == (admin.id, id_)
        assert record.details == {"provider": "pihole", "retest": True,
                                  "fields": ["name", "config.base_url", "secret_ref"]}
    listed = next(item for item in client.get("/api/audit").json() if item["action"] == "integration.updated")
    for value in ("example.net", "NYCTR_CONNECTOR_SECRET", "Kitchen", KEY):
        assert value not in str(listed)


def test_member_cannot_edit_a_source(source):
    """A member is refused with 403 and nothing changes."""
    client, headers, id_ = source
    with client.app.state.session_factory() as db:
        db.scalar(select(User)).role = "member"
        db.commit()
    assert edit(client, headers, id_, name="Mine now").status_code == 403
    assert_untouched(client, id_)


def test_signed_out_edit_is_refused(source):
    """Without a session the edit is refused with 401 and nothing changes."""
    client, headers, id_ = source
    client.cookies.clear()
    assert edit(client, headers, id_, name="Mine now").status_code == 401
    assert_untouched(client, id_)


@pytest.mark.parametrize("headers", [{}, {"X-CSRF-Token": "not-this-session"}])
def test_missing_or_wrong_csrf_token_is_refused(source, headers):
    """A signed-in administrator's browser cannot be made to edit a source from another site."""
    client, _, id_ = source
    assert edit(client, headers, id_, name="Mine now").status_code == 403
    assert_untouched(client, id_)


def test_unknown_source_is_not_found(source):
    """Editing a source that does not exist returns 404 and creates nothing."""
    client, headers, id_ = source
    assert edit(client, headers, "missing").status_code == 404
    assert len(client.get("/api/integrations").json()) == 1


def test_address_off_the_allow_list_is_refused_without_echoing_server_configuration(source):
    """The server's host allow-list applies to an edit, and the refusal repeats neither list nor address."""
    client, headers, id_ = source
    response = edit(client, headers, id_, config={"base_url": "https://elsewhere.example.org"})
    assert response.status_code == 422
    assert response.json()["detail"].startswith("Not saved.") and "allowlist" in response.json()["detail"]
    for value in ("resolver.example.net", "second.example.net", "elsewhere.example.org", SAVED["secret_ref"], KEY):
        assert value not in response.text
    assert_untouched(client, id_)


@pytest.mark.parametrize("config", [
    {"base_url": ADDRESS, "lookback_hours": 500},
    {"base_url": ADDRESS, "api_key": KEY},
    {"base_url": "http://resolver.example.net"},
])
def test_invalid_setting_is_refused_by_the_integrations_own_check(source, config):
    """The integration's validator decides, exactly as for a new source, and says which rule failed."""
    client, headers, id_ = source
    response = edit(client, headers, id_, config=config)
    assert response.status_code == 422 and response.json()["detail"].startswith("Not saved.")
    assert KEY not in response.text
    assert_untouched(client, id_)


@pytest.mark.parametrize("body", [
    {**SAVED, "provider": "nextdns"},
    {**SAVED, "secret_ref": "NYCTR_BOOTSTRAP_ADMIN_PASSWORD"},
    {**SAVED, "name": ""},
])
def test_kind_of_source_and_unsafe_secret_names_cannot_be_set(source, body):
    """The kind of source is not editable, and a secret name outside the connector prefix is refused."""
    client, headers, id_ = source
    assert client.put(f"/api/integrations/{id_}", headers=headers, json=body).status_code == 422
    assert_untouched(client, id_)
    assert stored(client, id_) and client.get("/api/integrations").json()[0]["provider"] == "pihole"


def test_demo_sources_cannot_be_edited(client, admin_headers):
    """Demo mode refuses the edit with 409 and keeps its seeded source."""
    before = client.get("/api/integrations").json()
    response = client.put(f"/api/integrations/{before[0]['id']}", headers=admin_headers,
                          json={"name": "Changed", "config": before[0]["config"],
                                "secret_ref": "NYCTR_CONNECTOR_SECRET_DEMO"})
    assert response.status_code == 409
    assert client.get("/api/integrations").json() == before


def test_edit_during_a_running_collection_is_refused_in_plain_words(source):
    """While a collection or a test holds the source, an edit is refused and the lease is left alone."""
    client, headers, id_ = source
    with client.app.state.session_factory() as db:
        row = db.get(Integration, id_)
        row.status, row.sync_started_at = "syncing", utcnow()
        db.commit()
    response = edit(client, headers, id_, config={"base_url": "https://second.example.net"})
    assert response.status_code == 409
    assert response.json()["detail"] == ("This source is being collected or tested right now. "
                                         "Try again when that has finished.")
    row = stored(client, id_)
    assert (row["status"], row["config"]["base_url"], row["name"]) == ("syncing", ADDRESS + "/api", "Resolver")


NEW_ADDRESS = {"config": {"base_url": "https://second.example.net"}, "secret_ref": "NYCTR_CONNECTOR_SECRET_SECOND"}


def edit_once(client, headers, id_):
    """Return a callable that saves a new address and secret name the first time it runs, as a second browser would."""
    done = []

    def run():
        if not done:
            done.append(True)
            other = TestClient(client.app, cookies=dict(client.cookies))
            assert edit(other, headers, id_, **NEW_ADDRESS).status_code == 200
        return bool(done)
    return run


def collect_with_an_edit_before_the_lease(source, monkeypatch):
    """Run one collection in which an edit lands after the settings were read and before the lease is taken.

    Collection resolves the secret between those two steps, so the edit is made from there.
    """
    client, headers, id_ = source
    land_edit, used = edit_once(client, headers, id_), []

    class Environment:
        @staticmethod
        def get(name, default=None):
            land_edit()
            return os.environ.get(name, default)

    async def collect(provider, integration_id, config, api_key):
        used.append((config["base_url"], api_key))
        return Snapshot(resources=[{"id": f"{integration_id}:client:two", "name": config["base_url"], "kind": "client",
                                    "provider": provider, "source_id": "two", "evidence_kind": "observed",
                                    "attributes": {}}])
    monkeypatch.setattr("nyctr.collection.os", type("os", (), {"environ": Environment}))
    monkeypatch.setattr("nyctr.integrations.collect", collect)
    app = client.app
    result = asyncio.run(collect_integration(app.state.session_factory, app.state.settings, id_, None))
    return result, used


def test_collection_never_runs_on_settings_an_edit_replaced_before_its_lease(source, monkeypatch):
    """The collection reads with the saved address and secret, so nothing from the old ones is stored as current."""
    client, _, id_ = source
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_SECOND", "SECOND_SECRET_SENTINEL")
    (snapshot, error), used = collect_with_an_edit_before_the_lease(source, monkeypatch)
    assert error is None and snapshot is not None
    assert used == [("https://second.example.net/api", "SECOND_SECRET_SENTINEL")]
    names = {item["name"] for item in client.get("/api/resources").json()}
    assert "https://second.example.net/api" in names and ADDRESS + "/api" not in names
    # A finished read of the new address is the test the edit asked for.
    assert stored(client, id_)["status"] == "connected"


def test_collection_stops_and_source_still_needs_a_test_when_the_new_secret_is_not_set(source, monkeypatch):
    """With no value for the new secret name nothing is read, the lease is given back and the edit's mark stays."""
    client, _, id_ = source
    (snapshot, error), used = collect_with_an_edit_before_the_lease(source, monkeypatch)
    assert (snapshot, error, used) == (None, "secret", [])
    row = stored(client, id_)
    assert row["status"] == "configured" and row["secret_ref"] == NEW_ADDRESS["secret_ref"]
    assert [item["name"] for item in client.get("/api/resources").json()] == ["Tablet"]


def test_diagnostics_never_probe_or_restore_what_an_edit_replaced_before_the_lease(source, monkeypatch):
    """A test that started just before an edit probes the saved settings and leaves the source needing a test."""
    client, headers, id_ = source
    land_edit, probed = edit_once(client, headers, id_), []

    def clock():
        land_edit()
        return utcnow()

    async def diagnose(provider, integration_id, config, secret_ref):
        probed.append((config["base_url"], secret_ref))
        return DiagnosticReport(integration_id=integration_id, provider=provider, checked_at=utcnow(), duration_ms=1,
                                outcome="verified", summary="Fabricated.", checks=[], capabilities=[],
                                evidence_gaps=[], snapshot_counts=None)
    # The route reads the clock between loading the source and taking the lease.
    monkeypatch.setattr("nyctr.main.utcnow", clock)
    monkeypatch.setattr("nyctr.main.diagnose_integration", diagnose)
    assert client.post(f"/api/integrations/{id_}/diagnostics", headers=headers).status_code == 200
    assert probed == [("https://second.example.net/api", NEW_ADDRESS["secret_ref"])]
    row = stored(client, id_)
    assert row["status"] == "configured" and row["config"]["base_url"] == "https://second.example.net/api"


def add(client, row):
    """Store one fabricated row and return its id."""
    with client.app.state.session_factory() as db:
        db.add(row)
        db.commit()
        return getattr(row, "id", None)


@pytest.mark.parametrize("kind, told", [("exception", "1 open exception (end under Open now)"),
                                        ("pass", "1 guest pass it issued (end under Guests)")])
def test_address_or_secret_change_waits_until_nyctrs_own_entries_at_the_source_are_ended(source, kind, told):
    """Ending Nyctr's own exception or pass later would go to the new address, so the change is refused first."""
    client, headers, id_ = source
    if kind == "exception":
        held = add(client, Lease(integration_id=id_, domain="held.example.org", execution="applied", owned=True))
    else:
        held = add(client, GuestPass(integration_id=id_, code="12345-67890", name="Visitor", minutes=60,
                                     issued_by="owner", execution="applied"))
    for changes in ({"config": {"base_url": "https://second.example.net"}}, NEW_ADDRESS["secret_ref"]):
        changes = changes if isinstance(changes, dict) else {"secret_ref": changes}
        response = edit(client, headers, id_, **changes)
        assert response.status_code == 409 and told in response.json()["detail"], response.text
        assert_untouched(client, id_)
    assert edit(client, headers, id_, name="Renamed", config={"base_url": ADDRESS, "lookback_hours": 6}).status_code == 200
    with client.app.state.session_factory() as db:
        if kind == "exception":
            db.get(Lease, held).status = "ended"
        else:
            db.get(GuestPass, held).ended_at = utcnow()
        db.commit()
    assert edit(client, headers, id_, **NEW_ADDRESS).status_code == 200
    assert stored(client, id_)["status"] == "configured"


def test_entries_nyctr_did_not_create_do_not_hold_back_a_change(source):
    """An exception that already existed, one never applied, and a pass read from the source are not Nyctr's."""
    client, headers, id_ = source
    add(client, Lease(integration_id=id_, domain="theirs.example.org", execution="applied", owned=False))
    add(client, Lease(integration_id=id_, domain="by-hand.example.org", execution="not_applied", owned=False))
    add(client, GuestPass(integration_id=id_, code="22222-33333", name="Made at the source", minutes=60,
                          issued_by=None, execution="applied"))
    assert edit(client, headers, id_, **NEW_ADDRESS).status_code == 200


def test_address_or_secret_change_waits_until_assignments_and_label_links_are_removed(source):
    """An assignment or label link made for one network must not carry over to whatever the source reads next."""
    client, headers, id_ = source
    other = add(client, Integration(provider="pihole", name="Other", config={}, secret_ref=""))
    for owner in (id_, other):
        add(client, Resource(id=f"{owner}:client:phone", integration_id=owner, name="Phone", kind="client",
                             provider="pihole", source_id="phone", observed_at=utcnow(), evidence_kind="observed"))

    def set_assignment(owner, classification):
        with client.app.state.session_factory() as db:
            db.get(Resource, f"{owner}:client:phone").classification = classification
            db.commit()

    def refused(told):
        for changes in ({"config": {"base_url": "https://second.example.net"}},
                        {"secret_ref": NEW_ADDRESS["secret_ref"]}):
            response = edit(client, headers, id_, **changes)
            assert response.status_code == 409, response.text
            assert told in response.json()["detail"] and "another network's blocked lookups" in response.text
            assert_untouched(client, id_)
    set_assignment(other, "personal")
    set_assignment(id_, "shared")
    refused("1 device assigned to people (unassign under Setup)")
    set_assignment(id_, "unassigned")
    add(client, DeviceLink(source_id=f"{id_}:client:one", device_id=f"{other}:client:phone", created_by="owner"))
    refused("1 linked device label (unlink under Setup)")
    assert edit(client, headers, id_, config={"base_url": ADDRESS, "lookback_hours": 6}).status_code == 200
    with client.app.state.session_factory() as db:
        db.delete(db.get(DeviceLink, f"{id_}:client:one"))
        db.commit()
    # The other source still has an assigned device; that is not this source's concern.
    assert edit(client, headers, id_, **NEW_ADDRESS).status_code == 200


def test_overlapping_edits_are_compared_with_the_settings_they_replace(source, monkeypatch):
    """A rename that started before another edit and a collection of it must not quietly restore old settings."""
    client, headers, id_ = source
    land_edit, landed = edit_once(client, headers, id_), []
    from nyctr.integrations import validate_config

    def validate(provider, config):
        # The first edit has loaded the source and not yet locked it: the second lands, then is collected.
        if not landed:
            landed.append(True)
            land_edit()
            with client.app.state.session_factory() as db:
                db.get(Integration, id_).status = "connected"
                db.commit()
        return validate_config(provider, config)
    monkeypatch.setattr("nyctr.integrations.validate_config", validate)
    assert edit(client, headers, id_, name="Renamed").status_code == 200
    row = stored(client, id_)
    assert (row["name"], row["config"]["base_url"], row["status"]) == ("Renamed", ADDRESS + "/api", "configured")
    with client.app.state.session_factory() as db:
        records = list(db.scalars(select(Audit).where(Audit.action == "integration.updated")
                                  .order_by(Audit.created_at)))
        assert [record.details["retest"] for record in records] == [True, True]
        assert records[1].details["fields"] == ["name", "config.base_url", "secret_ref"]


def test_stored_data_stays_marked_as_older_than_the_change_until_a_collection_succeeds(source, monkeypatch):
    """A failed collection after an address change turns the status to error but replaces nothing."""
    client, headers, id_ = source
    app, answers = client.app, [RuntimeError("unreachable"), Snapshot()]

    async def collect(provider, integration_id, config, api_key):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer
    monkeypatch.setattr("nyctr.integrations.collect", collect)

    def listed():
        row = client.get("/api/integrations").json()[0]
        return row["status"], row["predates_change"]
    assert listed() == ("partial", False)
    assert edit(client, headers, id_, config={"base_url": "https://second.example.net"}).status_code == 200
    assert listed() == ("configured", True)
    for expected in (("error", True), ("connected", False)):
        asyncio.run(collect_integration(app.state.session_factory, app.state.settings, id_, None))
        assert listed() == expected
