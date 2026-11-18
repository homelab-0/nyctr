"""A statement is opened only while the account and the device still qualify.

The rows are inserted here and finished by the real decision and lease path.
This file does not mount a second copy of the route. An event request, and a
row whose basis is empty, still open. A web session is not that permission.
"""

import asyncio
import json
import threading
from datetime import timedelta
from types import SimpleNamespace

import httpx
from conftest import live_signin, signin
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, text
from test_access import put_rule
from test_analysis_claim import stand_in
from test_analysis_counts import database_url, demo, plant
from test_presence import home
from test_tiers import BOTH

from nyctr import access
from nyctr.collection import holder_id
from nyctr.deps import statement_current
from nyctr.integrations import core
from nyctr.models import (
    AccessRequest,
    DeviceGrant,
    DevicePresence,
    Integration,
    Lease,
    LoginSession,
    Notice,
    Observation,
    Resource,
    Setting,
    User,
    utcnow,
)
from nyctr.worker import end_at_source

WAITING = access.STATEMENT_WAITING
PRIVACY = ["blocklist:hagezi-multi-pro-plusplus"]
# Long enough for the checks made while a request is paused, short enough that a missed release ends.
PAUSE_LIMIT = 30


def wait_for_release(event, what, limit=PAUSE_LIMIT):
    """Block until the test releases the pause. A missed release ends the wait."""
    if not event.wait(limit):
        raise TimeoutError(f"{what} was not released within {limit} seconds")


def release_paused(thread, event):
    """Let the paused request continue, and wait until that thread has stopped."""
    event.set()
    thread.join(PAUSE_LIMIT)


def allow_statements(app, headers):
    """Turn the statement switch on. Off, a statement waits before the device is read again."""
    with TestClient(app) as client:
        put_rule(client, headers(client), per_day=20, daily_total=100, allow_statement=True)


def file_row(db, key, *, basis="statement", device_id="laptop-jamie", requester="user-jamie",
             domain=None, device_name="Jamie's MacBook"):
    """One analysing request on a fresh copy of the gallery block."""
    domain = domain or f"{key}.example"
    plant(db, key, domain=domain, device_id=device_id or "laptop-jamie", device_name=device_name)
    db.add(AccessRequest(
        id=key, block_id=key, domain=domain, device_name=device_name, requester_id=requester,
        reason="A fabricated statement", duration_minutes=60, status="analysing", basis=basis,
        device_id=device_id))
    return domain


def empty_basis(app, request_id):
    """A row migrated before the column: the basis is SQL NULL, not the event default."""
    with app.state.session_factory() as db:
        db.execute(text("UPDATE access_requests SET basis = NULL WHERE id = :id"), {"id": request_id})
        db.commit()
        found = db.execute(text("SELECT basis FROM access_requests WHERE id = :id"), {"id": request_id}).scalar()
    assert found is None


def set_active(app, user_id, active):
    """Commit the account flag from a session of its own."""
    with app.state.session_factory() as db:
        db.get(User, user_id).active = active
        db.commit()


def drop_sessions(app):
    """Remove every web session. The opening must not need one."""
    with app.state.session_factory() as db:
        db.execute(delete(LoginSession))
        db.commit()


def take_laptop(app):
    """Remove Jamie's grant and tie, and give the laptop to someone else."""
    with app.state.session_factory() as db:
        db.execute(delete(DeviceGrant).where(
            DeviceGrant.device_id == "laptop-jamie", DeviceGrant.user_id == "user-jamie"))
        db.execute(delete(DevicePresence).where(
            DevicePresence.device_id == "laptop-jamie", DevicePresence.user_id == "user-jamie"))
        db.get(Resource, "laptop-jamie").owner_id = "user-admin"
        db.commit()


def give_laptop(app):
    """Give Jamie the laptop again, the way an assignment does."""
    now = utcnow()
    with app.state.session_factory() as db:
        laptop = db.get(Resource, "laptop-jamie")
        laptop.owner_id = "user-jamie"
        laptop.classification = "personal"
        db.execute(delete(DeviceGrant).where(
            DeviceGrant.device_id == "laptop-jamie", DeviceGrant.user_id == "user-jamie"))
        db.add(DeviceGrant(device_id="laptop-jamie", user_id="user-jamie", valid_from=now - timedelta(days=1)))
        db.commit()


def tie_only(app):
    """A live tie and no grant. Jamie still owns the laptop."""
    now = utcnow()
    with app.state.session_factory() as db:
        db.execute(delete(DeviceGrant).where(
            DeviceGrant.device_id == "laptop-jamie", DeviceGrant.user_id == "user-jamie"))
        db.add(DevicePresence(
            kind="tie", user_id="user-jamie", device_id="laptop-jamie", basis="live",
            first_at=now, last_at=now, reach_from=now - timedelta(hours=1)))
        db.commit()


def finish(app):
    """The pass that finishes every request still being analysed."""
    asyncio.run(access.finish_due(app.state.session_factory, app.state.settings))


def saved(app, request_id):
    """The request, the leases filed for it, and its notices."""
    with app.state.session_factory() as db:
        row = db.get(AccessRequest, request_id)
        leases = list(db.scalars(select(Lease).where(Lease.request_id == request_id)))
        notes = list(db.scalars(select(Notice).where(Notice.subject == request_id)))
        return row, leases, notes


def assert_waiting(app, request_id):
    """The statement is still pending, with one notice and no lease."""
    row, leases, notes = saved(app, request_id)
    assert row.status == "pending" and row.decision_note == WAITING, (row.status, row.decision_note)
    assert leases == []
    assert len(notes) == 1 and notes[0].kind == "request_waiting"
    return row


def assert_opened(app, request_id, *, execution, basis):
    """The rule opened one owned lease and left the basis alone."""
    row, leases, _notes = saved(app, request_id)
    assert row.status == "auto_approved" and row.decided_by == "rule", (row.status, row.decision_note)
    assert row.basis == basis and row.decision_note != WAITING
    assert len(leases) == 1 and leases[0].status == "active" and leases[0].owned is True
    assert leases[0].execution == execution
    return row


class HeldAllowlist:
    """A fabricated allowlist. One call can wait after it has already changed the list."""

    def __init__(self, monkeypatch, hold=None):
        self.listed, self.calls, self.hold = [], [], hold
        self.reached, self.go = threading.Event(), threading.Event()
        monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "dns-secret")
        monkeypatch.setattr(core, "make_http_client", lambda key, **_: httpx.AsyncClient(
            transport=httpx.MockTransport(self.answer), headers={"X-Api-Key": key}, trust_env=False))

    async def answer(self, request):
        call = len(self.calls)
        name = request.url.path.rsplit("/", 1)[1]
        self.calls.append(request.method)
        if request.method == "POST":
            self.listed.append(json.loads(request.content)["id"])
        elif request.method == "DELETE" and name in self.listed:
            self.listed.remove(name)
        response = httpx.Response(200, json={"data": [{"id": item, "active": True} for item in self.listed]})
        if self.hold == call:
            self.reached.set()
            await asyncio.to_thread(wait_for_release, self.go, "the paused provider call")
        return response


def live_world(tmp_path, monkeypatch, request, database):
    """A live app whose fabricated DNS source may be changed, with the laptop assigned to Sam."""
    app, _gateway = home(tmp_path, monkeypatch, provider_writes="nextdns",
                         database_url=database_url(database, tmp_path, request))
    now = utcnow()
    with app.state.session_factory() as db:
        db.add(Integration(
            id="dns", provider="nextdns", name="Office DNS", config={"profile_id": "abc123"},
            secret_ref="NYCTR_CONNECTOR_SECRET_DNS", status="connected", last_sync=now))
        laptop = db.get(Resource, "gw:client:laptop")
        laptop.owner_id = "sam"
        laptop.classification = "personal"
        db.add(DeviceGrant(device_id="gw:client:laptop", user_id="sam", valid_from=now - timedelta(days=1)))
        db.commit()
    allow_statements(app, live_signin)
    return app


def plant_live(app, domain):
    """One fresh block and one analysing statement for it, on Sam's laptop."""
    now = utcnow()
    block_id = f"dns:block:{domain}"
    with app.state.session_factory() as db:
        db.add(Observation(
            id=block_id, integration_id="dns", device_id="gw:client:laptop", device_name="Laptop",
            domain=domain, source="nextdns", reason="HaGeZi Multi PRO++", reason_codes=list(PRIVACY),
            observed_at=now - timedelta(minutes=2), expires_at=now + timedelta(hours=20),
            evidence_kind="observed", attribution="assigned", risk_score=None, risk_explanation=""))
        db.add(AccessRequest(
            id=domain, block_id=block_id, domain=domain, device_name="Laptop", requester_id="sam",
            reason="A fabricated statement", duration_minutes=60, status="analysing", basis="statement",
            device_id="gw:client:laptop"))
        db.commit()


def run_one(app, request_id):
    """Finish this request on its own thread, so the test can commit while the provider call waits."""
    box = {}

    def run():
        try:
            asyncio.run(access.finish_one(
                app.state.session_factory, app.state.settings, request_id, holder_id(app.state.session_factory)))
            box["done"] = True
        except Exception as exc:  # The assertion reports it. A hung call is the join below.
            box["error"] = repr(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, box


def due_leases(app, domain):
    """Lease ids a tick would end: open, owned by the clock, for this domain."""
    with app.state.session_factory() as db:
        return list(db.scalars(select(Lease.id).where(
            Lease.domain == domain, Lease.status.in_(access.OPEN), Lease.expires_at.is_not(None),
            Lease.expires_at <= utcnow())))


def domain_rows(app, domain):
    """The statement, every lease of this domain, and the statement's notices."""
    with app.state.session_factory() as db:
        row = db.scalar(select(AccessRequest).where(AccessRequest.domain == domain))
        leases = list(db.scalars(select(Lease).where(Lease.domain == domain)))
        notes = [] if row is None else list(db.scalars(select(Notice).where(Notice.subject == row.id)))
        return row, leases, notes


@BOTH
def test_a_current_assignment_or_live_tie_still_opens_after_the_session_is_gone(
        tmp_path, database, request, monkeypatch):
    """An assignment or a live tie is enough. Deleting the web session does not stop the opening."""
    app = demo(tmp_path, database_url(database, tmp_path, request))
    stand_in(monkeypatch)
    allow_statements(app, signin)
    with app.state.session_factory() as db:
        assigned = file_row(db, "assigned")
        db.commit()
    drop_sessions(app)
    finish(app)
    assert_opened(app, "assigned", execution="simulated", basis="statement")
    with app.state.session_factory() as db:
        assert db.get(AccessRequest, "assigned").domain == assigned
        assert list(db.scalars(select(LoginSession))) == []

    tie_only(app)
    with app.state.session_factory() as db:
        tied = file_row(db, "tied")
        db.commit()
    drop_sessions(app)
    finish(app)
    row = assert_opened(app, "tied", execution="simulated", basis="statement")
    assert row.domain == tied and row.device_id == "laptop-jamie"
    finish(app)
    assert len(saved(app, "assigned")[1]) == 1 and len(saved(app, "tied")[1]) == 1


@BOTH
def test_a_lost_device_or_inactive_account_waits_and_older_rows_still_open(
        tmp_path, database, request, monkeypatch):
    """A revoked device or a disabled account waits. An event, and an empty basis, still open.

    The account is read again in the session that already holds it. A second pass adds no lease
    and no second notice. Two finishes at once leave one notice.
    """
    app = demo(tmp_path, database_url(database, tmp_path, request))
    stand_in(monkeypatch)
    allow_statements(app, signin)
    with app.state.session_factory() as db:
        file_row(db, "revoked", domain="zz-revoked.example")
        file_row(db, "event", basis="event", device_id=None, domain="zz-event.example")
        file_row(db, "blank", basis="event", device_id=None, domain="zz-blank.example")
        db.commit()
    empty_basis(app, "blank")
    take_laptop(app)

    async def both():
        factory, settings = app.state.session_factory, app.state.settings
        holder = holder_id(factory)
        await asyncio.gather(
            access.finish_one(factory, settings, "revoked", holder),
            access.finish_one(factory, settings, "revoked", holder))

    asyncio.run(both())
    assert_waiting(app, "revoked")
    finish(app)
    assert_opened(app, "event", execution="simulated", basis="event")
    assert_opened(app, "blank", execution="simulated", basis=None)
    finish(app)
    assert_waiting(app, "revoked")
    assert len(saved(app, "event")[1]) == 1 and len(saved(app, "blank")[1]) == 1

    give_laptop(app)
    with app.state.session_factory() as db:
        file_row(db, "inactive", domain="zz-inactive.example")
        file_row(db, "event-off", basis="event", device_id=None, domain="zz-event-off.example")
        file_row(db, "blank-off", basis="event", device_id=None, domain="zz-blank-off.example")
        db.commit()
    empty_basis(app, "blank-off")
    with app.state.session_factory() as held:
        cached = held.get(User, "user-jamie")
        assert cached.active is True
        statement = held.get(AccessRequest, "inactive")
        event_row = held.get(AccessRequest, "event-off")
        blank_row = held.get(AccessRequest, "blank-off")
        assert event_row.basis == "event" and blank_row.basis is None
        held.commit()
        set_active(app, "user-jamie", False)
        assert statement_current(held, statement) is False
        assert cached.active is False
        assert statement_current(held, event_row) is True
        assert statement_current(held, blank_row) is True
        held.add(User(id="gone", email="gone@example.net", name="Gone", role="member"))
        held.commit()
        with app.state.session_factory() as other:
            other.delete(other.get(User, "gone"))
            other.commit()
        missing = AccessRequest(
            basis="statement", device_id="laptop-jamie", requester_id="gone", domain="zz-gone.example",
            block_id="gone", device_name="Jamie's MacBook", reason="A fabricated statement", duration_minutes=60)
        assert statement_current(held, missing) is False
        assert held.get(User, "gone") is None
    finish(app)
    assert_waiting(app, "inactive")
    assert_opened(app, "event-off", execution="simulated", basis="event")
    assert_opened(app, "blank-off", execution="simulated", basis=None)
    finish(app)
    assert_waiting(app, "inactive")
    assert len(saved(app, "inactive")[1]) == 0


@BOTH
def test_disabling_the_account_during_the_add_is_removed_on_upkeep(
        tmp_path, database, request, monkeypatch):
    """A disable committed while the add is in flight waits, and upkeep removes only that entry."""
    app = live_world(tmp_path, monkeypatch, request, database)
    stand_in(monkeypatch)
    source = HeldAllowlist(monkeypatch, hold=2)
    domain = "zz-disabled.example"
    plant_live(app, domain)
    thread, box = run_one(app, domain)
    try:
        assert source.reached.wait(20), {"calls": source.calls, "box": box}
        assert source.calls == ["GET", "GET", "POST"] and source.listed == [domain], source.calls
        set_active(app, "sam", False)
    finally:
        release_paused(thread, source.go)
    assert not thread.is_alive(), box
    assert box.get("error") is None, box
    assert box.get("done") is True
    row, leases, notes = domain_rows(app, domain)
    assert row.status == "pending" and row.decision_note == WAITING, (row.status, row.decision_note)
    assert row.basis == "statement" and row.device_id == "gw:client:laptop" and row.requester_id == "sam"
    assert len(notes) == 1 and notes[0].kind == "request_waiting"
    assert not any(lease.status == "active" for lease in leases), [lease.status for lease in leases]
    compensation = [lease for lease in leases
                    if lease.status == "unconfirmed" and lease.owned and lease.request_id is None]
    assert len(compensation) == 1 and compensation[0].execution == "not_applied"
    assert due_leases(app, domain) == [compensation[0].id]
    asyncio.run(end_at_source(app.state.session_factory, app.state.settings, [compensation[0].id]))
    assert source.listed == [] and source.calls.count("POST") == 1 and source.calls.count("DELETE") == 1
    before = list(source.calls)
    finish(app)
    row, leases, notes = domain_rows(app, domain)
    assert row.status == "pending" and len(notes) == 1 and source.calls == before
    assert not any(lease.status == "active" for lease in leases)


@BOTH
def test_an_entry_already_there_stays_when_the_account_is_disabled(
        tmp_path, database, request, monkeypatch):
    """A disable during the read does not remove an entry this opening did not add."""
    app = live_world(tmp_path, monkeypatch, request, database)
    stand_in(monkeypatch)
    source = HeldAllowlist(monkeypatch, hold=1)
    domain = "zz-kept.example"
    source.listed.append(domain)
    plant_live(app, domain)
    thread, box = run_one(app, domain)
    try:
        assert source.reached.wait(20), {"calls": source.calls, "box": box}
        assert source.calls == ["GET", "GET"] and source.listed == [domain] and "POST" not in source.calls
        set_active(app, "sam", False)
    finally:
        release_paused(thread, source.go)
    assert not thread.is_alive(), box
    assert box.get("error") is None, box
    row, leases, notes = domain_rows(app, domain)
    assert row.status == "pending" and row.decision_note == WAITING, (row.status, row.decision_note)
    assert len(notes) == 1 and notes[0].kind == "request_waiting"
    assert leases == [] and "DELETE" not in source.calls and source.calls.count("POST") == 0
    before = list(source.calls)
    finish(app)
    row, leases, notes = domain_rows(app, domain)
    assert row.status == "pending" and len(notes) == 1 and leases == [] and source.calls == before
    assert source.listed == [domain]


@BOTH
def test_an_active_account_still_opens_after_the_session_is_gone(tmp_path, database, request, monkeypatch):
    """An active account with an assignment opens through the provider after the sign-in is gone."""
    app = live_world(tmp_path, monkeypatch, request, database)
    stand_in(monkeypatch)
    source = HeldAllowlist(monkeypatch, hold=None)
    domain = "zz-open.example"
    plant_live(app, domain)
    drop_sessions(app)
    with app.state.session_factory() as db:
        assert db.get(User, "sam").active is True
    finish(app)
    row, leases, _notes = domain_rows(app, domain)
    assert row.status == "auto_approved" and row.decided_by == "rule", (row.status, row.decision_note)
    assert row.basis == "statement" and row.device_id == "gw:client:laptop"
    assert len(leases) == 1 and leases[0].status == "active" and leases[0].execution == "applied"
    assert leases[0].owned is True and leases[0].request_id == row.id
    assert source.listed == [domain] and source.calls.count("POST") == 1 and "DELETE" not in source.calls
    before = list(source.calls)
    finish(app)
    again, leases, _notes = domain_rows(app, domain)
    assert again.status == "auto_approved" and len(leases) == 1 and source.calls == before


def add_client(db, id_, name, ip, *, owner="user-jamie"):
    """One personal device Jamie may use, with a current grant."""
    now = utcnow()
    db.add(Resource(
        id=id_, integration_id="demo-unifi", name=name, kind="client", provider="unifi_network",
        source_id=id_, site_id="site-home", observed_at=now, evidence_kind="observed",
        classification="personal", owner_id=owner, attributes={"ip": ip, "demo": True}))
    db.flush()
    db.add(DeviceGrant(device_id=id_, user_id=owner, valid_from=now - timedelta(days=1)))


def page(app, address=None):
    """What This device answers for a member, from one address when one is given."""
    kwargs = {"client": (address, 50000)} if address else {}
    with TestClient(app, **kwargs) as client:
        signin(client, member=True)
        return client.get("/api/me/device").json()


@BOTH
def test_the_demo_page_uses_the_same_device_order_as_the_stand_in(tmp_path, database, request):
    """The page and the shared choice agree: a permitted stored address, then name, then id."""
    app = demo(tmp_path, database_url(database, tmp_path, request))
    with TestClient(app):
        pass
    with app.state.session_factory() as db:
        add_client(db, "phone-jamie", "AAA phone", "192.0.2.77")
        db.commit()
    seen = page(app)
    assert (seen["device_id"], seen["name"], seen["simulated"], seen["how"]) == (
        "phone-jamie", "AAA phone", True, "assigned")
    laptop = page(app, "192.0.2.42")
    assert (laptop["device_id"], laptop["name"], laptop["simulated"], laptop["how"]) == (
        "laptop-jamie", "Jamie's MacBook", False, "assigned")
    tablet = page(app, "192.0.2.51")
    assert (tablet["device_id"], tablet["name"], tablet["simulated"]) == (
        "tablet-family", "Front desk tablet", False)
    other = page(app, "192.0.2.28")
    assert (other["device_id"], other["simulated"]) == ("phone-jamie", True)
    with app.state.session_factory() as db:
        stolen = db.get(Resource, "old-laptop")
        stolen.name = "000 stolen"
        stolen.attributes = {**(stolen.attributes or {}), "ip": "192.0.2.42"}
        add_client(db, "device-b", "000 same", "192.0.2.81")
        add_client(db, "device-a", "000 same", "192.0.2.82")
        db.commit()
    still = page(app, "192.0.2.42")
    assert (still["device_id"], still["simulated"]) == ("laptop-jamie", False)
    ordered = page(app)
    assert (ordered["device_id"], ordered["name"], ordered["simulated"]) == ("device-a", "000 same", True)
    with app.state.session_factory() as db:
        user = db.get(User, "user-jamie")
        chosen, simulated = access.stand_in_device(db, user, SimpleNamespace(address=None))
        matched, matched_simulated = access.stand_in_device(db, user, SimpleNamespace(address="192.0.2.42"))
        assert (chosen.id, simulated) == ("device-a", True)
        assert (matched.id, matched_simulated) == ("laptop-jamie", False)


def pause_after_claim(monkeypatch):
    """Stop once, when the entry claim has been taken and before the caller can add the address."""
    real, reached, go, once = access.hold_entry, threading.Event(), threading.Event(), {"done": False}

    async def hold(db, settings, integration, domain):
        claim = await real(db, settings, integration, domain)
        if not once["done"]:
            once["done"] = True
            reached.set()
            await asyncio.to_thread(wait_for_release, go, "the paused entry claim")
        return claim

    monkeypatch.setattr(access, "hold_entry", hold)
    return reached, go


def take_sam_laptop(app):
    """Remove Sam's grant and tie, and give the laptop to someone else."""
    with app.state.session_factory() as db:
        db.execute(delete(DeviceGrant).where(
            DeviceGrant.device_id == "gw:client:laptop", DeviceGrant.user_id == "sam"))
        db.execute(delete(DevicePresence).where(
            DevicePresence.device_id == "gw:client:laptop", DevicePresence.user_id == "sam"))
        laptop = db.get(Resource, "gw:client:laptop")
        laptop.owner_id = "kim"
        laptop.classification = "personal"
        db.commit()


def entry_claims(app):
    """Claims still held on a source entry or an automatic opening."""
    with app.state.session_factory() as db:
        return list(db.scalars(select(Setting.key).where(Setting.key.startswith("ending:"))))


@BOTH
def test_revoking_the_device_during_the_entry_wait_sends_nothing(
        tmp_path, database, request, monkeypatch):
    """A grant removed while the entry claim is held never reaches the provider add.

    The claim is given back, with no lease and one notice. A later event for the
    same address can take that claim. An empty basis on another address still
    opens. A second pass does not add a notice.
    """
    app = live_world(tmp_path, monkeypatch, request, database)
    stand_in(monkeypatch)
    source = HeldAllowlist(monkeypatch, hold=None)
    reached, go = pause_after_claim(monkeypatch)
    domain = "zz-held.example"
    plant_live(app, domain)
    thread, box = run_one(app, domain)
    try:
        assert reached.wait(20), {"calls": source.calls, "box": box}
        assert source.calls == ["GET"] and "POST" not in source.calls, source.calls
        take_sam_laptop(app)
    finally:
        release_paused(thread, go)
    assert not thread.is_alive(), box
    assert box.get("error") is None, box
    assert box.get("done") is True
    row, leases, notes = domain_rows(app, domain)
    assert row.status == "pending" and row.decision_note == WAITING, (row.status, row.decision_note)
    assert row.basis == "statement" and row.device_id == "gw:client:laptop"
    assert len(notes) == 1 and notes[0].kind == "request_waiting"
    assert leases == [] and source.calls == ["GET"] and entry_claims(app) == []
    finish(app)
    row, leases, notes = domain_rows(app, domain)
    assert row.status == "pending" and len(notes) == 1 and leases == [] and source.calls == ["GET"]

    with app.state.session_factory() as db:
        db.add(AccessRequest(
            id="zz-held-event", block_id=f"dns:block:{domain}", domain=domain, device_name="Laptop",
            requester_id="sam", reason="An ordinary event", duration_minutes=60, status="analysing",
            basis="event", device_id=None))
        db.commit()
    plant_live(app, "zz-blank.example")
    empty_basis(app, "zz-blank.example")
    finish(app)
    event, event_leases, _event_notes = saved(app, "zz-held-event")
    blank, blank_leases, _blank_notes = saved(app, "zz-blank.example")
    assert event.status == "auto_approved" and event.basis == "event", (event.status, event.decision_note)
    assert len(event_leases) == 1 and event_leases[0].status == "active"
    assert event_leases[0].execution == "applied" and event_leases[0].owned is True
    assert blank.status == "auto_approved" and blank.basis is None, (blank.status, blank.decision_note)
    assert len(blank_leases) == 1 and blank_leases[0].status == "active" and blank_leases[0].owned is True
    assert source.calls.count("POST") == 2 and "DELETE" not in source.calls
    assert set(source.listed) == {domain, "zz-blank.example"}
    row, leases, notes = saved(app, domain)
    assert row.status == "pending" and len(notes) == 1 and leases == []
    finish(app)
    row, leases, notes = saved(app, domain)
    assert row.status == "pending" and len(notes) == 1 and leases == []
    assert source.calls.count("POST") == 2 and "DELETE" not in source.calls
