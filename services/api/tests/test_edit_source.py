"""Editing a saved source: name and numeric settings at any time, where it reads only until its first collection."""

import asyncio
import os
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_collection import live_client

from nyctr.collection import collect_integration
from nyctr.diagnostics import DiagnosticReport
from nyctr.integrations import Snapshot
from nyctr.main import MOVED_SOURCE, _settled_status
from nyctr.models import Audit, Integration, Resource, User, utcnow

KEY = "EDIT_SECRET_SENTINEL"
ADDRESS = "https://resolver.example.net"
SAVED = {"name": "Resolver", "config": {"base_url": ADDRESS, "lookback_hours": 24},
         "secret_ref": "NYCTR_CONNECTOR_SECRET_RESOLVER"}


@pytest.fixture(params=[True])
def source(request, tmp_path, monkeypatch):
    """Save one live source with an address setting and sign its administrator in.

    By default it has already stored a partial collection; `new_source` has never collected.
    """
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "resolver.example.net,second.example.net")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_RESOLVER", KEY)
    with live_client(tmp_path) as client:
        logged = client.post("/api/auth/login", json={"email": "owner@example.net",
                                                      "password": "secure password for tests"})
        headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
        created = client.post("/api/integrations", headers=headers, json={"provider": "pihole", **SAVED})
        assert created.status_code == 201, created.text
        id_ = created.json()["id"]
        if request.param:
            with client.app.state.session_factory() as db:
                row = db.get(Integration, id_)
                row.status, row.last_sync = "partial", utcnow()
                db.add(Resource(id=f"{id_}:client:one", integration_id=id_, name="Tablet", kind="client",
                                provider="pihole", source_id="one", observed_at=utcnow(), evidence_kind="observed"))
                db.commit()
        yield client, headers, id_


new_source = pytest.mark.parametrize("source", [False], indirect=True)


def stored(client, id_):
    """Read the saved row straight from the database, bypassing the API under test."""
    with client.app.state.session_factory() as db:
        row = db.get(Integration, id_)
        return {"name": row.name, "config": row.config, "secret_ref": row.secret_ref, "status": row.status,
                "last_sync": row.last_sync, "last_error": row.last_error, "sync_started_at": row.sync_started_at}


def edit(client, headers, id_, **changes):
    """Send the whole edit form, as the console does, with some fields changed."""
    return client.put(f"/api/integrations/{id_}", headers=headers, json={**SAVED, **changes})


def audit_trail(client):
    """Return every audit record, so a refusal can be shown to have written none."""
    with client.app.state.session_factory() as db:
        return [(record.action, record.target_id, record.details) for record in db.scalars(select(Audit))]


def assert_refused_untouched(client, id_, response, status, before):
    """A refused edit returns `status` and leaves the row and the audit history exactly as they were."""
    assert response.status_code == status, response.text
    row = stored(client, id_)
    assert {key: row[key] for key in SAVED} == {**SAVED, "config": {"base_url": ADDRESS + "/api", "lookback_hours": 24}}
    assert row["status"] == ("partial" if row["last_sync"] else "configured")
    assert audit_trail(client) == before


NEW_ADDRESS = {"config": {"base_url": "https://second.example.net"}, "secret_ref": "NYCTR_CONNECTOR_SECRET_SECOND"}
MOVES = [{"config": {"base_url": "https://second.example.net", "lookback_hours": 24}},
         {"secret_ref": "NYCTR_CONNECTOR_SECRET_SECOND"},
         {"name": "Kitchen resolver", **NEW_ADDRESS}]


def test_name_and_numeric_setting_change_keeps_status_and_collected_data(source):
    """After collecting, a new name or a shorter window is saved and the source keeps its status."""
    client, headers, id_ = source
    response = edit(client, headers, id_, name="Kitchen resolver", config={"base_url": ADDRESS, "lookback_hours": 6})
    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["name"], body["config"]["lookback_hours"], body["status"]) == ("Kitchen resolver", 6, "partial")
    assert body["provider"] == "pihole" and body["last_sync"] is not None and KEY not in response.text
    assert stored(client, id_)["config"] == {"base_url": ADDRESS + "/api", "lookback_hours": 6}
    assert [item["name"] for item in client.get("/api/resources").json()] == ["Tablet"]


@new_source
@pytest.mark.parametrize("changes", MOVES)
def test_where_a_new_source_reads_can_be_corrected_and_it_needs_a_test(source, changes):
    """Before the first collection every field can change; moving it sends it back to "needs a test"."""
    client, headers, id_ = source
    with client.app.state.session_factory() as db:
        row = db.get(Integration, id_)
        row.status, row.last_error = "error", "An earlier failure at the old address."
        db.commit()
    response = edit(client, headers, id_, **changes)
    assert response.status_code == 200, response.text
    row = stored(client, id_)
    assert (row["status"], row["last_error"], row["last_sync"]) == ("configured", None, None)
    with client.app.state.session_factory() as db:
        # An abandoned lease on this source settles back to "needs a test".
        assert _settled_status(db, db.get(Integration, id_)) == "configured"


@pytest.mark.parametrize("changes", MOVES)
def test_where_it_reads_cannot_change_after_the_first_collection(source, changes):
    """A source that has stored a collection, even a partial one, is never moved; a new source is added instead."""
    client, headers, id_ = source
    before = audit_trail(client)
    response = edit(client, headers, id_, **changes)
    assert_refused_untouched(client, id_, response, 409, before)
    assert response.json()["detail"] == MOVED_SOURCE
    for value in ("example.net", "NYCTR_CONNECTOR_SECRET", KEY):
        assert value not in response.text


def test_unchanged_form_saves_nothing_and_writes_no_audit_record(source):
    """Pressing save without a change is not an edit."""
    client, headers, id_ = source
    before = audit_trail(client)
    assert_refused_untouched(client, id_, edit(client, headers, id_), 200, before)


@new_source
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


@pytest.mark.parametrize("who, status", [("member", 403), ("signed out", 401), ("no token", 403),
                                         ("wrong token", 403), ("unknown source", 404)])
def test_refused_edits_leave_the_row_and_audit_history_untouched(source, who, status):
    """A member, a signed-out browser, a request without this session's token and an unknown source are refused."""
    client, headers, id_ = source
    before, target = audit_trail(client), id_
    if who == "member":
        with client.app.state.session_factory() as db:
            db.scalar(select(User)).role = "member"
            db.commit()
    elif who == "signed out":
        client.cookies.clear()
    elif who == "unknown source":
        target = "missing"
    else:
        headers = {} if who == "no token" else {"X-CSRF-Token": "not-this-session"}
    assert_refused_untouched(client, id_, edit(client, headers, target, name="Mine now"), status, before)


@new_source
def test_address_off_the_allow_list_is_refused_without_echoing_server_configuration(source):
    """The server's host allow-list applies to an edit, and the refusal repeats neither list nor address."""
    client, headers, id_ = source
    before = audit_trail(client)
    response = edit(client, headers, id_, config={"base_url": "https://elsewhere.example.org"})
    assert_refused_untouched(client, id_, response, 422, before)
    assert response.json()["detail"].startswith("Not saved.") and "allowlist" in response.json()["detail"]
    for value in ("resolver.example.net", "second.example.net", "elsewhere.example.org", SAVED["secret_ref"], KEY):
        assert value not in response.text


@pytest.mark.parametrize("source", [False, True], indirect=True)
@pytest.mark.parametrize("config", [
    {"base_url": ADDRESS, "lookback_hours": 500},
    {"base_url": ADDRESS, "api_key": KEY},
    {"base_url": "http://resolver.example.net"},
])
def test_invalid_setting_is_refused_by_the_integrations_own_check(source, config):
    """The integration's validator decides, exactly as for a new source, and says which rule failed."""
    client, headers, id_ = source
    before = audit_trail(client)
    response = edit(client, headers, id_, config=config)
    assert_refused_untouched(client, id_, response, 422, before)
    assert response.json()["detail"].startswith("Not saved.") and KEY not in response.text


@pytest.mark.parametrize("body", [
    {**SAVED, "provider": "nextdns"},
    {**SAVED, "secret_ref": "NYCTR_BOOTSTRAP_ADMIN_PASSWORD"},
    {**SAVED, "name": ""},
])
def test_kind_of_source_and_unsafe_secret_names_cannot_be_set(source, body):
    """The kind of source is not editable, and a secret name outside the connector prefix is refused."""
    client, headers, id_ = source
    before = audit_trail(client)
    assert_refused_untouched(client, id_, client.put(f"/api/integrations/{id_}", headers=headers, json=body), 422, before)
    assert client.get("/api/integrations").json()[0]["provider"] == "pihole"


def test_demo_sources_cannot_be_edited(client, admin_headers):
    """Demo mode refuses the edit with 409 and keeps its seeded source and audit history."""
    before = client.get("/api/integrations").json()
    trail = audit_trail(client)
    response = client.put(f"/api/integrations/{before[0]['id']}", headers=admin_headers,
                          json={"name": "Changed", "config": before[0]["config"],
                                "secret_ref": "NYCTR_CONNECTOR_SECRET_DEMO"})
    assert response.status_code == 409
    assert client.get("/api/integrations").json() == before and audit_trail(client) == trail


def hold_lease(client, id_, started):
    """Mark the source as being read since `started`, as a collection or a diagnostic does."""
    with client.app.state.session_factory() as db:
        row = db.get(Integration, id_)
        row.status, row.sync_started_at = "syncing", started
        db.commit()


def edit_once(client, headers, id_, **changes):
    """Return a callable that saves an edit the first time it runs, as a second browser would, and its responses."""
    responses = []

    def run():
        if not responses:
            responses.append(None)  # The edit itself may call back here; it runs once.
            other = TestClient(client.app, cookies=dict(client.cookies))
            responses[0] = edit(other, headers, id_, **(changes or NEW_ADDRESS))
        return responses[0]
    return run


def fake_collect(monkeypatch, used, during=None, fail=False):
    """Stand in for the provider read: record what it was asked to read, and run `during` while it is in flight."""
    async def collect(provider, integration_id, config, api_key):
        used.append((config["base_url"], api_key))
        if during:
            during()
        if fail:
            raise RuntimeError("unreachable")
        return Snapshot(resources=[{"id": f"{integration_id}:client:two", "name": config["base_url"], "kind": "client",
                                    "provider": provider, "source_id": "two", "evidence_kind": "observed",
                                    "attributes": {}}])
    monkeypatch.setattr("nyctr.integrations.collect", collect)


def run_collection(client, id_):
    app = client.app
    return asyncio.run(collect_integration(app.state.session_factory, app.state.settings, id_, None))


def collect_with_an_edit_before_the_lease(source, monkeypatch):
    """Run one collection in which an edit lands after the settings were read and before the lease is taken.

    Collection resolves the secret between those two steps, so the edit is made from there.
    """
    client, headers, id_ = source
    land_edit, used = edit_once(client, headers, id_), []

    class Environment:
        @staticmethod
        def get(name, default=None):
            assert land_edit().status_code == 200
            return os.environ.get(name, default)

    monkeypatch.setattr("nyctr.collection.os", type("os", (), {"environ": Environment}))
    fake_collect(monkeypatch, used)
    return run_collection(client, id_), used


@new_source
@pytest.mark.parametrize("secret_set", [True, False])
def test_edit_first_then_first_collection_reads_the_edited_settings(source, monkeypatch, secret_set):
    """Edit wins the race: the collection re-reads the source under its lease and reads the new address, or,
    with no value for the new secret name, reads nothing and gives the lease back as "configured"."""
    client, _, id_ = source
    if secret_set:
        monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_SECOND", "SECOND_SECRET_SENTINEL")
    (snapshot, error), used = collect_with_an_edit_before_the_lease(source, monkeypatch)
    names = [item["name"] for item in client.get("/api/resources").json()]
    row = stored(client, id_)
    if secret_set:
        assert error is None and used == [("https://second.example.net/api", "SECOND_SECRET_SENTINEL")]
        assert (names, row["status"]) == (["https://second.example.net/api"], "connected")
    else:
        assert (snapshot, error, used, names) == (None, "secret", [], [])
        assert (row["status"], row["secret_ref"], row["last_sync"]) == ("configured", NEW_ADDRESS["secret_ref"], None)


@new_source
def test_first_collection_first_then_the_edit_is_refused(source, monkeypatch):
    """Collection wins the race: an edit during it is refused, and once it has stored, moving the source is too."""
    client, headers, id_ = source
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_RESOLVER", KEY)
    used, during = [], edit_once(client, headers, id_)
    fake_collect(monkeypatch, used, during=during)
    snapshot, error = run_collection(client, id_)
    assert error is None and used == [(ADDRESS + "/api", KEY)]
    assert during().json()["detail"] == ("This source is being collected or tested right now. "
                                         "Try again when that has finished.")
    row = stored(client, id_)
    assert (row["status"], row["config"]["base_url"]) == ("connected", ADDRESS + "/api") and row["last_sync"]
    before = audit_trail(client)
    assert not [entry for entry in before if entry[0] == "integration.updated"]
    response = edit(client, headers, id_, **NEW_ADDRESS)
    assert response.status_code == 409 and response.json()["detail"] == MOVED_SOURCE
    assert stored(client, id_)["config"]["base_url"] == ADDRESS + "/api" and audit_trail(client) == before


@new_source
@pytest.mark.parametrize("fail", [False, True])
def test_a_read_that_outlived_its_lease_stores_nothing_after_the_source_moved(source, monkeypatch, fail):
    """A lease older than five minutes no longer holds the source. If an edit moves it meanwhile, the old read
    stores nothing and records no failure, so the source is still uncollected and still needs a test."""
    client, headers, id_ = source
    responses = []

    def stall_then_edit():
        hold_lease(client, id_, utcnow() - timedelta(minutes=6))
        responses.append(edit_once(client, headers, id_)())
    fake_collect(monkeypatch, [], during=stall_then_edit, fail=fail)
    assert run_collection(client, id_) == (None, "replaced")
    assert responses[0].status_code == 200
    row = stored(client, id_)
    assert (row["status"], row["last_sync"], row["last_error"], row["sync_started_at"]) == ("configured", None,
                                                                                            None, None)
    assert row["config"]["base_url"] == "https://second.example.net/api"
    assert client.get("/api/resources").json() == []
    assert not [entry for entry in audit_trail(client) if entry[0].startswith("integration.collect")]


@new_source
def test_diagnostics_never_probe_or_restore_what_an_edit_replaced_before_the_lease(source, monkeypatch):
    """A test that started just before an edit probes the saved settings and leaves the source needing a test."""
    client, headers, id_ = source
    with client.app.state.session_factory() as db:
        db.get(Integration, id_).status = "error"
        db.commit()
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


@new_source
def test_overlapping_edits_are_compared_with_the_settings_they_replace(source, monkeypatch):
    """A rename that loaded the source before another edit moved it is applied after it, and audited as what it
    really did: it puts back the old address and secret name, so the source still needs a test."""
    client, headers, id_ = source
    land_edit = edit_once(client, headers, id_)
    from nyctr.integrations import validate_config

    def validate(provider, config):
        # The rename has loaded the source and not yet locked it: the other edit lands now.
        land_edit()
        return validate_config(provider, config)
    monkeypatch.setattr("nyctr.integrations.validate_config", validate)
    assert edit(client, headers, id_, name="Renamed").status_code == 200
    assert land_edit().status_code == 200
    row = stored(client, id_)
    assert (row["name"], row["config"]["base_url"], row["status"]) == ("Renamed", ADDRESS + "/api", "configured")
    with client.app.state.session_factory() as db:
        records = list(db.scalars(select(Audit).where(Audit.action == "integration.updated")
                                  .order_by(Audit.created_at)))
        assert [(record.details["fields"], record.details["retest"]) for record in records] == [
            (["config.base_url", "secret_ref"], True), (["name", "config.base_url", "secret_ref"], True)]
