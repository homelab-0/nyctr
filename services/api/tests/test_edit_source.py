"""Editing a saved source: same validation as a new one, with every refusal leaving the row untouched."""

import pytest
from sqlalchemy import select
from test_collection import live_client

from nyctr.main import _settled_status
from nyctr.models import Audit, Integration, Resource, User, utcnow

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
