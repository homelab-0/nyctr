"""The collection schedule: who may set it, which value is in force, and when a run is due."""

import asyncio
from datetime import datetime, timedelta

from conftest import LIVE_ADMIN, LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import select

from nyctr import schedule, worker
from nyctr.integrations import Snapshot
from nyctr.models import Audit, Integration, User, utc, utcnow


def fake_sources(monkeypatch):
    """Answer every collection with an empty fabricated snapshot and record which source was asked."""
    asked = []

    async def collect(provider, integration_id, config, api_key):
        asked.append(integration_id)
        await asyncio.sleep(0)  # Give a second copy the chance to run in the middle of this one.
        return Snapshot()

    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "fabricated-key")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "fabricated-key")
    monkeypatch.setattr("nyctr.integrations.collect", collect)
    return asked


def next_at(client):
    """Read the next collection time the API reports."""
    return utc(datetime.fromisoformat(client.get("/api/collection").json()["next_at"].replace("Z", "+00:00")))


def tick(app, now):
    """Run one upkeep pass of this copy of Nyctr at a chosen time."""
    return asyncio.run(worker.collection_pass(app.state.session_factory, app.state.settings, now))


def test_the_starting_value_is_the_deployment_interval_or_fifteen_minutes_and_demo_never_collects(
        client, admin_headers, tmp_path):
    """Before anyone saves a schedule: demo is off, live uses the deployment value, else 15 minutes."""
    demo = client.get("/api/collection").json()
    assert demo["enabled"] is False and demo["source"] == "demo" and demo["next_at"] is None
    assert client.put("/api/collection", headers=admin_headers,
                      json={"enabled": True, "minutes": 15}).status_code == 409
    for folder, given, seconds, source in (("a", {}, 900, "default"),
                                           ("b", {"collect_interval_seconds": 0}, 900, "default"),
                                           ("c", {"collect_interval_seconds": 7200}, 7200, "deployment")):
        (tmp_path / folder).mkdir()
        with TestClient(live_app(tmp_path / folder, **given)) as live:
            live_signin(live)
            body = live.get("/api/collection").json()
            assert (body["enabled"], body["interval_seconds"], body["source"]) == (True, seconds, source)
            assert body["choices"] == [5, 15, 30, 60, 180, 360, 720, 1440]


def test_a_saved_schedule_wins_over_the_deployment_value_and_is_audited_with_old_and_new(tmp_path):
    """The Console's value replaces the deployment one, and the audit says who changed what."""
    app = live_app(tmp_path, collect_interval_seconds=7200)
    with TestClient(app) as client:
        headers = live_signin(client)
        saved = client.put("/api/collection", headers=headers, json={"enabled": True, "minutes": 60})
        assert saved.status_code == 200
        assert (saved.json()["interval_seconds"], saved.json()["source"]) == (3600, "console")
        off = client.put("/api/collection", headers=headers, json={"enabled": False, "minutes": 60}).json()
        assert off["enabled"] is False and off["next_at"] is None
        with app.state.session_factory() as db:
            owner = db.scalar(select(User).where(User.email == LIVE_ADMIN[0]))
            first, second = db.scalars(select(Audit).where(Audit.action == "collection.schedule_changed")
                                       .order_by(Audit.created_at))
        assert first.actor_id == second.actor_id == owner.id
        assert first.details == {"old": {"enabled": True, "interval_seconds": 7200, "source": "deployment"},
                                 "new": {"enabled": True, "interval_seconds": 3600}}
        assert second.details == {"old": {"enabled": True, "interval_seconds": 3600, "source": "console"},
                                  "new": {"enabled": False, "interval_seconds": 3600}}


def test_only_a_signed_in_administrator_can_save_a_schedule_from_the_list(tmp_path):
    """Signed out is 401, a member 403, a missing request token 403, and a value off the list 422."""
    app = live_app(tmp_path)
    good = {"enabled": True, "minutes": 30}
    with TestClient(app) as client:
        seed_live_member(app)
        assert client.get("/api/collection").status_code == 401
        assert client.put("/api/collection", json=good).status_code == 401
        member = live_signin(client, LIVE_MEMBER)
        assert client.put("/api/collection", headers=member, json=good).status_code == 403
        admin = live_signin(client)
        assert client.put("/api/collection", json=good).status_code == 403
        for bad in ({"enabled": True, "minutes": 1}, {"enabled": True, "minutes": 45},
                    {"enabled": True, "minutes": 2880}, {"enabled": True, "minutes": "15"},
                    {"enabled": True}, {"minutes": 15}, {"enabled": True, "minutes": 15, "source": "x"}):
            assert client.put("/api/collection", headers=admin, json=bad).status_code == 422, bad
        with app.state.session_factory() as db:
            assert db.scalar(select(Audit).where(Audit.action == "collection.schedule_changed")) is None
        assert client.get("/api/collection").json()["source"] == "default"


def test_a_member_reads_only_what_the_portal_needs_and_an_administrator_the_full_schedule(tmp_path):
    """Signed out reads nothing; a member gets on or off, the interval and the next time; an administrator all."""
    app = live_app(tmp_path, collect_interval_seconds=7200)
    with TestClient(app) as client:
        seed_live_member(app)
        assert client.get("/api/collection").status_code == 401
        live_signin(client, LIVE_MEMBER)
        seen = client.get("/api/collection").json()
        assert set(seen) == {"enabled", "interval_seconds", "next_at"}
        assert (seen["enabled"], seen["interval_seconds"]) == (True, 7200) and seen["next_at"]
        client.post("/api/auth/logout", headers=live_signin(client))
        assert client.get("/api/collection").status_code == 401
        live_signin(client)
        full = client.get("/api/collection").json()
        assert set(full) == {"enabled", "interval_seconds", "next_at", "source", "choices"}
        assert full["source"] == "deployment" and full["next_at"]


def test_an_administrator_on_the_member_portal_address_reads_as_a_member(tmp_path):
    """On the portal address every account has member rights, so the narrow answer applies there too."""
    app = live_app(tmp_path, portal_url="http://portal.testserver")
    with TestClient(app, base_url="http://portal.testserver") as client:
        headers = live_signin(client)
        assert set(client.get("/api/collection").json()) == {"enabled", "interval_seconds", "next_at"}
        assert client.put("/api/collection", headers=headers,
                          json={"enabled": False, "minutes": 15}).status_code == 403


def test_a_saved_change_applies_at_the_next_upkeep_pass_without_a_restart(tmp_path, monkeypatch):
    """Runs follow the stored schedule on a clock: due, not due again, shortened, switched off."""
    asked = fake_sources(monkeypatch)
    app = live_app(tmp_path)
    start = utcnow()
    with TestClient(app) as client:
        seed_live_member(app)
        headers = live_signin(client)
        assert tick(app, start) is True and sorted(asked) == ["dns", "unifi"]
        assert tick(app, start + timedelta(minutes=14, seconds=30)) is False
        assert tick(app, start + timedelta(minutes=15)) is True and len(asked) == 4
        client.put("/api/collection", headers=headers, json={"enabled": True, "minutes": 5})
        assert tick(app, start + timedelta(minutes=19, seconds=30)) is False
        assert tick(app, start + timedelta(minutes=20)) is True and len(asked) == 6
        client.put("/api/collection", headers=headers, json={"enabled": False, "minutes": 5})
        assert tick(app, start + timedelta(days=2)) is False and len(asked) == 6
        client.put("/api/collection", headers=headers, json={"enabled": True, "minutes": 1440})
        assert tick(app, start + timedelta(days=2)) is True and len(asked) == 8


def test_a_source_failing_for_an_unknown_reason_is_not_retried_before_the_next_scheduled_time(tmp_path, monkeypatch):
    """The run is recorded before sources are contacted, and a fault that may not pass gets no retry."""
    fake_sources(monkeypatch)
    attempts = []

    async def fail(provider, integration_id, config, api_key):
        attempts.append(integration_id)
        raise RuntimeError("fabricated outage")

    monkeypatch.setattr("nyctr.integrations.collect", fail)
    app = live_app(tmp_path)
    start = utcnow()
    with TestClient(app):
        seed_live_member(app)
        assert tick(app, start) is True and len(attempts) == 2
        assert tick(app, start + timedelta(seconds=30)) is False and len(attempts) == 2


def test_after_a_restart_the_next_collection_is_counted_from_the_last_one(tmp_path, monkeypatch):
    """A new process reads the last run from the database instead of starting its own clock."""
    asked = fake_sources(monkeypatch)
    start = utcnow() - timedelta(minutes=10)
    first = live_app(tmp_path)
    with TestClient(first):
        seed_live_member(first)
        assert tick(first, start) is True
    restarted = live_app(tmp_path)
    with TestClient(restarted) as client:
        live_signin(client)
        due = next_at(client)
        assert due == start + timedelta(minutes=15)
        assert tick(restarted, start + timedelta(minutes=10)) is False and len(asked) == 2
        assert tick(restarted, due) is True and len(asked) == 4


def test_two_copies_on_one_database_run_a_scheduled_collection_once(tmp_path, monkeypatch):
    """Both copies see the run as due at the same moment; one claims it and each source is read once."""
    asked = fake_sources(monkeypatch)
    one, two = live_app(tmp_path), live_app(tmp_path)
    start = utcnow()
    with TestClient(one) as client, TestClient(two):
        seed_live_member(one)
        headers = live_signin(client)

        async def both(now):
            return await asyncio.gather(*(worker.collection_pass(copy.state.session_factory, copy.state.settings, now)
                                          for copy in (one, two)))

        assert sorted(asyncio.run(both(start))) == [False, True]
        assert sorted(asked) == ["dns", "unifi"]
        # The stored schedule, not a per-process timer, decides the next run for both copies.
        client.put("/api/collection", headers=headers, json={"enabled": True, "minutes": 30})
        assert asyncio.run(both(start + timedelta(minutes=20))) == [False, False]
        assert sorted(asyncio.run(both(start + timedelta(minutes=30)))) == [False, True]
        assert sorted(asked) == ["dns", "dns", "unifi", "unifi"]
        with one.state.session_factory() as db:
            assert {row.status for row in db.scalars(select(Integration))} == {"connected"}
            assert db.scalar(select(Audit).where(Audit.action == "integration.collection_failed")) is None


def test_the_collection_lease_still_refuses_a_second_collection_of_one_source(tmp_path, monkeypatch):
    """While a scheduled collection of a source is running, another copy asking for it is told it is busy."""
    from nyctr.collection import collect_integration

    fake_sources(monkeypatch)
    one, two = live_app(tmp_path), live_app(tmp_path)
    results = []

    async def slow(provider, integration_id, config, api_key):
        results.append(await collect_integration(two.state.session_factory, two.state.settings, "dns", None))
        return Snapshot()

    monkeypatch.setattr("nyctr.integrations.collect", slow)
    with TestClient(one), TestClient(two):
        seed_live_member(one)
        with one.state.session_factory() as db:
            assert schedule.claim_run(db, schedule.in_force(db, one.state.settings)) is True
        asyncio.run(collect_integration(one.state.session_factory, one.state.settings, "dns", None))
    assert results == [(None, "busy")]
