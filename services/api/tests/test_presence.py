"""Signing in on a device ties the person to it. Denial paths first, then the tie, then who sees what."""

import ast
import asyncio
import dataclasses
import inspect
import itertools
import threading
import time
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from conftest import LIVE_ADMIN, LIVE_MEMBER, live_app, live_signin
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event, select
from sqlalchemy import text as sql
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from test_collection_store import POSTGRES, postgres_database

from nyctr import access, collection, peer, presence, removal, retention
from nyctr.deps import observation_permitted, observations_permitted
from nyctr.integrations import IntegrationError, core, registry, unifi
from nyctr.models import Audit, DevicePresence, Integration, Observation, Resource, Setting, User, utc, utcnow
from nyctr.security import hash_password
from nyctr.worker import Upkeep

KIM = ("kim@example.net", "a third secure password")
LAPTOP, PHONE, TABLET, PRINTER, SHARED = (f"192.0.2.{n}" for n in (10, 11, 12, 20, 30))
# name: (address, classification, owner)
DEVICES = {"laptop": (LAPTOP, "unassigned", None), "phone": (PHONE, "unassigned", None),
           "tablet": (TABLET, "personal", "kim"), "printer": (PRINTER, "infrastructure", None),
           "shared": (SHARED, "shared", None)}
NOTHING = {"device_id": None, "name": None, "simulated": False, "how": None}


def home(tmp_path, monkeypatch, switched_on=True, **settings):
    """A live installation whose gateway source collected one network and five devices.

    Returns the app and the fabricated client list its gateway answers from: which device
    holds which address now, how often it was read and for which site, and whether it answers at all.
    """
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_GW", "fabricated-key")
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "gateway.example")
    gateway = {"holds": {name: row[0] for name, row in DEVICES.items()}, "reads": 0, "down": False, "sites": []}

    async def client_at(integration_id, config, key, address, site):
        gateway["reads"] += 1
        gateway["sites"].append(site)
        if gateway["down"]:
            raise IntegrationError("The source did not answer in time.", category="timeout")
        if "answer" in gateway:
            return gateway["answer"]
        return [{"id": f"{integration_id}:client:{name}", "mac": "00:00:5e:00:53:01"}
                for name, held in gateway["holds"].items() if held == address]

    provider = registry.get("unifi_network")
    monkeypatch.setitem(registry.providers(), provider.id, dataclasses.replace(provider, client_at=client_at))
    monkeypatch.setattr(presence, "_answers", {})
    app = live_app(tmp_path, **settings)
    with TestClient(app), app.state.session_factory() as db:
        now = utcnow()
        db.add(Integration(id="gw", provider=provider.id, name="Gateway", status="connected", last_sync=now,
                           config={"base_url": "https://gateway.example/proxy/network/integration"},
                           secret_ref="NYCTR_CONNECTOR_SECRET_GW"))
        for id_, (email, password) in {"sam": LIVE_MEMBER, "kim": KIM}.items():
            db.add(User(id=id_, email=email, name=id_.title(), role="member", password_hash=hash_password(password)))
        db.flush()
        db.add(Resource(id="gw:network:lan", integration_id="gw", name="LAN", kind="network", provider=provider.id,
                        source_id="lan", observed_at=now, evidence_kind="configured",
                        classification="infrastructure", attributes={"subnets": ["192.0.2.0/24"]}))
        for name, (address, classification, owner) in DEVICES.items():
            db.add(Resource(id=f"gw:client:{name}", integration_id="gw", name=name.title(), kind="client",
                            provider=provider.id, source_id=name, observed_at=now, evidence_kind="observed",
                            classification=classification, owner_id=owner, attributes={"ip": address}))
        db.add(Setting(key=presence.KEY, value={"enabled": switched_on, "reach_back_hours": 2}))
        db.commit()
    return app, gateway


@contextmanager
def browser(app, address, who=LIVE_MEMBER, **options):
    """A person signed in from an address, as a browser on the device that holds it."""
    with TestClient(app, client=(address, 50000), **options) as client:
        client.headers.update(live_signin(client, who))
        yield client


def stored(app, kind="tie"):
    """Every tie or conflict on record, oldest first."""
    with app.state.session_factory() as db:
        return list(db.scalars(select(DevicePresence).where(DevicePresence.kind == kind)
                               .order_by(DevicePresence.first_at)))


def change(app, model, id_, **values):
    """Set stored values directly, the way time or an administrator would have."""
    with app.state.session_factory() as db:
        row = db.get(model, id_)
        for key, value in values.items():
            setattr(row, key, value)
        db.commit()


def refused(app, address, code, says, **options):
    """Open the portal from an address and require no tie, no device and a sentence that says why."""
    with browser(app, address, **options) as client:
        told = client.get("/api/me/device").json()
    assert {key: told[key] for key in NOTHING} == NOTHING and told["reason"] == code and says in told["message"], told
    assert stored(app) == []
    return told


# --- Every way a tie is not made ---------------------------------------------------------------------------------


def test_no_session_gets_no_answer_and_no_address_gets_no_tie(tmp_path, monkeypatch):
    """Without a session the route refuses. A request whose address Nyctr cannot tell is tied to nothing."""
    app, gateway = home(tmp_path, monkeypatch)
    with TestClient(app, client=(LAPTOP, 50000)) as client:
        assert client.get("/api/me/device").status_code == 401
    refused(app, "testclient", "no_address", "could not tell which address")
    assert gateway["reads"] == 0


def test_the_switch_is_off_until_an_administrator_turns_it_on(tmp_path, monkeypatch):
    """Off: the gateway is never asked and nothing is tied, however clearly the device holds the address."""
    app, gateway = home(tmp_path, monkeypatch, switched_on=False)
    refused(app, LAPTOP, "off", "not set to recognise")
    assert gateway["reads"] == 0
    with TestClient(app), app.state.session_factory() as db:
        assert presence.settings(db).enabled is False
        db.delete(db.get(Setting, presence.KEY))
        db.commit()
        assert presence.settings(db).enabled is False  # never written is off too


@pytest.mark.parametrize("address, holds, code, says", [
    ("198.51.100.7", {}, "outside", "did not come from your network"),
    ("2001:db8::10", {}, "ipv6", "over IPv6"),
    ("192.0.2.99", {}, "nobody", "lists no device"),
    (LAPTOP, {"phone": LAPTOP}, "several", "more than one device"),
    (LAPTOP, {"laptop": None, "newcomer": LAPTOP}, "not_collected", "has not read this device"),
    (PRINTER, {}, "infrastructure", "not a personal device"),
])
def test_an_address_that_names_no_one_device_of_a_person_is_tied_to_nothing(tmp_path, monkeypatch, address, holds,
                                                                             code, says):
    """Outside every collected network, over IPv6, held by nobody, claimed by two, not yet collected, or infrastructure."""
    app, gateway = home(tmp_path, monkeypatch)
    gateway["holds"].update(holds)
    refused(app, address, code, says)
    assert gateway["reads"] == (0 if code in {"outside", "ipv6"} else 1)


def test_a_request_over_ipv6_is_refused_by_rule_even_where_a_network_lists_its_range(tmp_path, monkeypatch):
    """IPv6 is never tied, whatever a source collects. IPv4 carried inside IPv6 is the IPv4 address and is tied as one."""
    app, gateway = home(tmp_path, monkeypatch)
    change(app, Resource, "gw:network:lan", attributes={"subnets": ["192.0.2.0/24", "2001:db8::/64"]})
    change(app, Resource, "gw:client:phone", attributes={"ip": "2001:db8::10"})
    gateway["holds"]["phone"] = "2001:db8::10"
    refused(app, "2001:db8::10", "ipv6", "over IPv6")
    assert gateway["reads"] == 0
    with browser(app, "::ffff:" + LAPTOP) as client:
        assert client.get("/api/me/device").json()["device_id"] == "gw:client:laptop"


def two_sites(app, cabin):
    """Give the gateway two sites: what it collected so far is the home site's, and a cabin has a network and a boat."""
    with app.state.session_factory() as db:
        made = {"integration_id": "gw", "provider": "unifi_network", "observed_at": utcnow()}
        for row in db.scalars(select(Resource).where(Resource.kind.in_(("network", "client")))):
            row.site_id = "gw:site:home"
        for name in ("home", "cabin"):
            db.add(Resource(id=f"gw:site:{name}", name=name.title(), kind="site", source_id=name,
                            site_id=f"gw:site:{name}", evidence_kind="observed", attributes={}, **made))
        db.add(Resource(id="gw:network:cabin", name="Cabin", kind="network", source_id="cabin-lan",
                        site_id="gw:site:cabin", evidence_kind="configured", attributes={"subnets": [cabin]}, **made))
        db.add(Resource(id="gw:client:boat", name="Boat", kind="client", source_id="boat", site_id="gw:site:cabin",
                        evidence_kind="observed", attributes={"ip": "198.51.100.7"}, **made))
        db.commit()


def test_an_address_two_sites_both_use_is_tied_to_nothing(tmp_path, monkeypatch):
    """Home does not list the device yet, the cabin lists another at that address: nobody is asked, nobody is tied."""
    app, gateway = home(tmp_path, monkeypatch)
    two_sites(app, cabin="192.0.2.0/24")
    gateway["holds"].update(phone=None, boat=PHONE)
    refused(app, PHONE, "two_networks", "More than one of your networks")
    assert gateway["reads"] == 0


def test_an_address_is_asked_of_the_site_whose_network_holds_it(tmp_path, monkeypatch):
    """Each site's own client list answers for its own range, and so does its own stored inventory."""
    app, gateway = home(tmp_path, monkeypatch)
    two_sites(app, cabin="198.51.100.0/24")
    gateway["holds"]["boat"] = "198.51.100.7"
    with browser(app, "198.51.100.7") as sam, browser(app, LAPTOP, KIM) as kim:
        assert sam.get("/api/me/device").json()["device_id"] == "gw:client:boat"
        assert kim.get("/api/me/device").json()["device_id"] == "gw:client:laptop"
    assert gateway["sites"] == ["cabin", "home"]
    # The gateway is silent and the cabin's stored boat still shows the phone's address: only home's inventory counts.
    gateway["down"] = True
    change(app, Resource, "gw:client:boat", attributes={"ip": PHONE})
    with browser(app, PHONE, KIM) as kim:
        assert kim.get("/api/me/device").json()["device_id"] == "gw:client:phone"
    assert [(tie.device_id, tie.basis) for tie in stored(app)][-1] == ("gw:client:phone", "stored")


@pytest.mark.parametrize("answer", ["gw:network:lan", "other:client:laptop", "gw:client:nobody"])
def test_a_holder_that_is_no_client_of_the_source_that_answered_is_tied_to_nothing(tmp_path, monkeypatch, answer):
    """The gateway names something that is not a device, another source's device, or one Nyctr has not read."""
    app, gateway = home(tmp_path, monkeypatch)
    with app.state.session_factory() as db:
        db.add(Integration(id="other", provider="unifi_network", name="Other", status="connected", config={}))
        db.flush()
        db.add(Resource(id="other:client:laptop", integration_id="other", name="Other laptop", kind="client",
                        provider="unifi_network", source_id="laptop", observed_at=utcnow(), evidence_kind="observed",
                        attributes={"ip": LAPTOP}))
        db.commit()
    gateway["answer"] = [{"id": answer, "mac": None}]
    refused(app, LAPTOP, "not_collected", "has not read this device")


def test_the_stored_inventory_leaves_out_a_device_that_has_left(tmp_path, monkeypatch):
    """The gateway is silent and the laptop is marked as gone from its latest whole read: its old address names nobody."""
    app, gateway = home(tmp_path, monkeypatch)
    gateway["down"] = True
    change(app, Resource, "gw:client:laptop", attributes={"ip": LAPTOP, retention.MISSING: True})
    refused(app, LAPTOP, "nobody", "lists no device")


def test_a_busy_database_is_a_reason_not_an_error_and_the_work_is_off_the_servers_loop(tmp_path, monkeypatch):
    """A tie that cannot be written just now is not made, and the member is asked to open the page again."""
    app, _gateway = home(tmp_path, monkeypatch)

    def locked(*_args, **_more):
        raise OperationalError("INSERT INTO device_presence", {}, Exception("database is locked"))

    monkeypatch.setattr(presence, "_record", locked)
    refused(app, LAPTOP, "busy", "Open this page again")
    # A blocking wait for the database must hold up this request only: neither runs on the loop.
    assert not inspect.iscoroutinefunction(access.this_device) and not inspect.iscoroutinefunction(presence.recognise)


# The tests that run two writers against each other run on both engines. The PostgreSQL case needs a server
# named in NYCTR_TEST_POSTGRES (its address, ending in /) and makes and drops a database of its own.
BOTH_ENGINES = pytest.mark.parametrize("engine", ["sqlite", "postgresql"])
# How long, in seconds, a test gives the second writer before it asks whether that one is still waiting.
# On PostgreSQL a waiter waits for as long as it takes, so the bound is generous: a slow run must not make
# a request that had nothing to wait for look like one that waited. SQLite itself gives up on a lock after
# five seconds, so there the bound has to stay well inside that, or the waiter would fail before its turn.
WAIT = {"sqlite": 0.5, "postgresql": 5.0}
# The hard bounds, so that a fault in the locks fails a test within seconds and never hangs the run. On
# PostgreSQL no wait for a lock outlasts LOCK_SECONDS: the test's database is set to give up then. And however
# a test ends, every thread it started is waited for, FINISH seconds at most, before a browser closes.
LOCK_SECONDS = 20
FINISH = 30.0


@contextmanager
def others_finish():
    """Give a test the list it puts its threads in, and wait for each of them when the test leaves, however it leaves.

    A browser that closes while a request of its own is still under way never returns, so nothing may
    be left running when one does. A thread still alive after FINISH seconds fails the test.
    """
    started = []
    try:
        yield started
    finally:
        for other in started:
            other.join(FINISH)
    assert not any(other.is_alive() for other in started), "a second writer never finished"


def on(engine, request):
    """Where this case keeps its database, as a `home` setting: nothing for SQLite in the test's own folder."""
    if engine == "sqlite":
        return {}
    place = postgres_database(request)
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    server, _, name = place["database_url"].rpartition("/")
    admin = create_engine(server + "/postgres", isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:  # every connection the test opens from here on gives up on a lock in time
        connection.execute(sql(f"alter database {name} set lock_timeout = '{LOCK_SECONDS}s'"))
    admin.dispose()
    return place


def switch_off(app):
    """Have an administrator switch recognition off, through the route's own function, and say what it answered."""
    with app.state.session_factory() as db:
        admin = db.scalars(select(User).where(User.role == "admin")).first()
        return presence.switch(presence.Recognition(enabled=False, reach_back_hours=2), admin, db)


@BOTH_ENGINES
def test_recognition_switched_off_while_the_network_is_being_asked_ties_nobody(tmp_path, monkeypatch, request, engine):
    """The sign-in passed the check while recognition was on. Switched off before the tie is written, none is made."""
    app, gateway = home(tmp_path, monkeypatch, **on(engine, request))
    provider, asked = registry.get("unifi_network"), []

    async def client_at(integration_id, *_rest):
        asked.append(switch_off(app))  # the administrator's change lands while the lookup is out
        return [{"id": f"{integration_id}:client:laptop", "mac": None}]

    monkeypatch.setitem(registry.providers(), provider.id, dataclasses.replace(provider, client_at=client_at))
    refused(app, LAPTOP, "off", "not set to recognise")
    assert asked == [{"enabled": False, "reach_back_hours": 2}] and gateway["reads"] == 0


@BOTH_ENGINES
def test_switching_recognition_off_waits_for_a_tie_being_written_and_then_ends_it(tmp_path, monkeypatch, request,
                                                                                  engine):
    """Whichever comes first, no tie is in force once recognition is off: the switch and the write take one lock."""
    app, _gateway = home(tmp_path, monkeypatch, **on(engine, request))
    write, others, answers, waiting = presence._record, [], [], []

    def record(*args):
        # The tie is about to be written. An administrator switches off now, on another connection.
        other = threading.Thread(target=lambda: answers.append(switch_off(app)), daemon=True)
        others.append(other)
        other.start()
        other.join(WAIT[engine])  # with the lock it is still waiting when this gives up, however long that takes
        waiting.append(other.is_alive())
        return write(*args)

    monkeypatch.setattr(presence, "_record", record)
    with browser(app, LAPTOP) as sam:
        with others_finish() as started:
            others = started
            sam.get("/api/me/device")
        assert waiting == [True] and answers == [{"enabled": False, "reach_back_hours": 2}]
        assert sam.get("/api/devices").json() == []
    tie, = stored(app)
    assert tie.ended_at is not None
    with app.state.session_factory() as db:
        assert db.scalars(select(Audit).where(Audit.action == "presence.setting_changed")).all()[-1].details[
            "ties_ended"] == 1


@BOTH_ENGINES
def test_two_people_signing_in_on_one_unshared_device_at_the_same_moment_are_not_both_tied(tmp_path, monkeypatch,
                                                                                           request, engine):
    """Sam has read that nobody is tied to the laptop and is about to write. Kim's request arrives just then."""
    app, _gateway = home(tmp_path, monkeypatch, **on(engine, request))
    write, others, answers, waiting = presence._record, [], [], []

    with browser(app, LAPTOP) as sam, browser(app, LAPTOP, KIM) as kim:
        def record(*args):
            if not others:  # Sam's write, the first: Kim asks now, on another thread and another connection
                other = threading.Thread(target=lambda: answers.append(kim.get("/api/me/device").json()),
                                         daemon=True)
                others.append(other)
                other.start()
                other.join(WAIT[engine])  # under the lock Kim is still waiting when this gives up
                waiting.append(other.is_alive())
            return write(*args)

        monkeypatch.setattr(presence, "_record", record)
        with others_finish() as started:
            others = started
            assert sam.get("/api/me/device").json()["device_id"] == "gw:client:laptop"
        assert waiting == [True] and answers[0]["reason"] == "other_person" and answers[0]["device_id"] is None
        assert kim.get("/api/devices").json() == [] and len(sam.get("/api/devices").json()) == 1
    assert [(tie.user_id, tie.ended_at) for tie in stored(app)] == [("sam", None)]
    assert [(row.user_id, row.device_id) for row in stored(app, "conflict")] == [("kim", "gw:client:laptop")]


# Everything that writes a tie, each as the console, the portal or the worker does it.
WRITERS = {
    "switch": lambda who: who["chief"].put("/api/presence", json={"enabled": True, "reach_back_hours": 1}),
    "assign": lambda who: assigned(who["deputy"], "laptop", "shared", "sam"),
    "sign_in": lambda who: who["again"].get("/api/me/device"),
    "forget": lambda who: who["sam"].delete(f"/api/presence/{who['tie']}"),
    "keep": lambda who: presence.keep(who["app"].state.session_factory, utcnow()),
}


@contextmanager
def stopped_before_it_writes(second, wait, at=1):
    """Stop the next writer after its reads and just before it sends its first change, and run `second` then.

    That is the moment a writer holds what it read and has changed nothing yet, so a second writer that
    is not made to wait would have its work overwritten. `second` runs on another thread and connection.
    With `at=2` the writer is stopped before it sends its second lot of changes, holding what the first took.

    Yields what happened: whether `second` was still waiting when the first went on, and what it raised.
    """
    seen = {"armed": at, "waiting": [], "raised": []}

    def run():
        try:
            second()
        except Exception as error:  # noqa: BLE001 - reported to the test, which fails on it
            seen["raised"].append(error)

    def before_flush(session, *_rest):
        if seen["armed"] and (session.dirty or session.new or session.deleted):
            seen["armed"] -= 1
        else:
            return
        if not seen["armed"]:
            other = threading.Thread(target=run, daemon=True)
            seen["started"].append(other)
            other.start()
            other.join(wait)  # under the locks it is still waiting, however long this machine takes
            seen["waiting"].append(other.is_alive())

    event.listen(Session, "before_flush", before_flush)
    try:
        with others_finish() as started:
            seen["started"] = started
            yield seen
    finally:
        event.remove(Session, "before_flush", before_flush)
    assert started, "the writer was never stopped, so the second never ran"


@BOTH_ENGINES
@pytest.mark.parametrize("first, second", list(itertools.permutations(WRITERS, 2)),
                         ids=[f"{first} then {second}" for first, second in itertools.permutations(WRITERS, 2)])
def test_no_writer_of_a_tie_overtakes_another_between_its_read_and_its_write(tmp_path, monkeypatch, request, engine,
                                                                              first, second):
    """Each writer takes the setting's row, the device's row and the ties, in that order, before it reads a tie.

    So the second of any two waits for the first to commit, and what it then writes rests on what the
    first wrote: nothing an assignment set is put back by a change of the setting read earlier, and so on.
    """
    app, _gateway = home(tmp_path, monkeypatch, **on(engine, request))
    blocked(app, recent=("laptop", 10))
    with browser(app, LAPTOP) as sam, browser(app, LAPTOP) as again, browser(app, PHONE, KIM) as kim, \
            browser(app, "198.51.100.9", LIVE_ADMIN) as chief, browser(app, "198.51.100.9", LIVE_ADMIN) as deputy:
        sam.get("/api/me/device")
        kim.get("/api/me/device")
        mine, kims = stored(app)
        change(app, DevicePresence, kims.id, last_at=utcnow() - timedelta(days=31))  # lapsed, for the worker to close
        who = {"app": app, "sam": sam, "again": again, "chief": chief, "deputy": deputy, "tie": mine.id}
        start = utcnow()
        with stopped_before_it_writes(lambda: WRITERS[second](who), WAIT[engine]) as seen:
            WRITERS[first](who)
        assert seen["waiting"] == [True] and seen["raised"] == []
        both = {first, second}
        shown = [] if "assign" in both or ("forget" in both and (first, second) != ("forget", "sign_in")) else ["recent"]
        assert seen_by(sam) == shown
    mine, kims = stored(app)[:2]
    assert (kims.ended_by == "expired") == ("keep" in both)
    assert (mine.ended_at is not None) == ("forget" in both)
    if "forget" not in both:
        if "assign" in both:  # the assignment is the earliest moment the tie shows, whoever wrote last
            assert utc(mine.reach_from) >= start
        else:
            assert mine.reach_from == mine.first_at - timedelta(hours=1 if "switch" in both else 2)


@BOTH_ENGINES
@pytest.mark.parametrize("first", list(WRITERS))
def test_removing_the_source_waits_for_a_writer_of_a_tie(tmp_path, monkeypatch, request, engine, first):
    """Removal takes the devices' rows and then deletes the ties. A writer holds its device's row, so removal waits."""
    app, _gateway = home(tmp_path, monkeypatch, **on(engine, request))
    with browser(app, LAPTOP) as sam, browser(app, LAPTOP) as again, browser(app, PHONE, KIM) as kim, \
            browser(app, "198.51.100.9", LIVE_ADMIN) as chief, browser(app, "198.51.100.9", LIVE_ADMIN) as deputy:
        sam.get("/api/me/device")
        kim.get("/api/me/device")
        mine, kims = stored(app)
        change(app, DevicePresence, kims.id, last_at=utcnow() - timedelta(days=31))
        who = {"app": app, "sam": sam, "again": again, "chief": chief, "deputy": deputy, "tie": mine.id}

        def remove():
            with browser(app, "198.51.100.9", LIVE_ADMIN) as third:
                answer = third.request("DELETE", "/api/integrations/gw", json={"name": "Gateway"})
                assert answer.status_code == 200, answer.text

        with stopped_before_it_writes(remove, WAIT[engine]) as seen:
            done = WRITERS[first](who)
        assert seen["waiting"] == [True] and seen["raised"] == []
        assert done is None or done.status_code == 200  # the writer finished its own work first, undisturbed
    assert stored(app) == [] and stored(app, "conflict") == []


@BOTH_ENGINES
def test_a_collection_being_stored_and_a_change_of_the_setting_never_wait_for_each_other(tmp_path, monkeypatch,
                                                                                          request, engine):
    """A store holds the rows of what its read listed, then marks what it missed. The switch holds no device's row.

    Two devices are tied. The read listed the phone and missed the laptop. The store has written the phone's
    row and is about to mark the laptop when an administrator changes the setting. If the switch took the
    tied devices' rows it would hold the laptop's and wait for the phone's, the store the other way round.
    """
    app, _gateway = home(tmp_path, monkeypatch, **on(engine, request))
    with browser(app, LAPTOP) as sam, browser(app, PHONE, KIM) as kim, \
            browser(app, "198.51.100.9", LIVE_ADMIN) as chief:
        sam.get("/api/me/device")
        kim.get("/api/me/device")
        answers = []

        def change_the_setting():
            answers.append(chief.put("/api/presence", json={"enabled": True, "reach_back_hours": 1}).status_code)

        # The session closes inside the stop, so its locks are gone before the second writer is waited for.
        with stopped_before_it_writes(change_the_setting, WAIT[engine], at=2) as seen, \
                app.state.session_factory() as db:
            listed = [{key: getattr(row, key) for key in ("id", "name", "kind", "provider", "source_id", "site_id",
                                                          "evidence_kind", "attributes")}
                      for row in db.scalars(select(Resource).where(Resource.integration_id == "gw"))
                      if row.id != "gw:client:laptop"]
            collection.apply_snapshot(db, db.get(Integration, "gw"), core.Snapshot(resources=listed),
                                      app.state.settings)
            db.commit()
        assert seen["raised"] == [] and answers == [200]  # neither was ended for the other's sake
        if engine == "postgresql":
            assert seen["waiting"] == [False]  # the switch had no row of the store's to wait for
    with app.state.session_factory() as db:
        assert retention.is_missing(db.get(Resource, "gw:client:laptop"))
        assert not retention.is_missing(db.get(Resource, "gw:client:phone"))
    assert all(tie.reach_from == tie.first_at - timedelta(hours=1) for tie in stored(app))


@BOTH_ENGINES
def test_removing_many_devices_and_a_change_of_the_setting_never_wait_for_each_other(tmp_path, monkeypatch, request,
                                                                                      engine):
    """Removal deletes devices 500 at a time. It takes every tie on them first, in the order the switch takes ties.

    Two devices are tied and go in different lots of 500, the one with the later tie first. If each lot took
    its own ties, removal would hold the later tie and want the earlier, the switch the other way round.
    """
    app, _gateway = home(tmp_path, monkeypatch, **on(engine, request))
    with browser(app, LAPTOP) as sam, browser(app, PHONE, KIM) as kim, \
            browser(app, "198.51.100.9", LIVE_ADMIN) as chief:
        sam.get("/api/me/device")
        kim.get("/api/me/device")
        earlier_tie, later_tie = sorted(stored(app), key=lambda tie: tie.id)
        going = [later_tie.device_id, *(f"gw:client:spare-{n}" for n in range(499)), earlier_tie.device_id]
        answers = []

        def change_the_setting():
            answers.append(chief.put("/api/presence", json={"enabled": True, "reach_back_hours": 1}).status_code)

        # The session closes inside the stop, so its locks are gone before the second writer is waited for.
        with stopped_before_it_writes(change_the_setting, WAIT[engine]) as seen, app.state.session_factory() as db:
            # As the removal route does: the devices' rows first, in id order, then everything that hangs on them.
            db.scalars(select(Resource.id).where(Resource.id.in_(going)).order_by(Resource.id).with_for_update()).all()
            removal.forget(db, going)
            db.commit()
        assert seen["raised"] == [] and answers == [200]  # neither was ended for the other's sake
        if engine == "postgresql":
            assert seen["waiting"] == [True]  # the switch waited for the ties removal held, all of them
    assert stored(app) == []
    with app.state.session_factory() as db:
        assert sorted(row.details["user_id"] for row in db.scalars(select(Audit).where(
            Audit.action == "presence.ended"))) == ["kim", "sam"]


def waiting_for_a_lock(app):
    """How many of this database's connections are waiting for a lock right now, as PostgreSQL itself reports it."""
    with app.state.engine.connect() as connection:
        return connection.scalar(sql("select count(*) from pg_stat_activity "
                                      "where datname = current_database() and wait_event_type = 'Lock'"))


def until(reached):
    """Wait for something the database reports, FINISH seconds at most, and fail if it never comes."""
    end = time.monotonic() + FINISH
    while not reached():
        assert time.monotonic() < end, "what the test waited for never happened"
        time.sleep(0.05)


@pytest.mark.parametrize("records", ["two old records", "a lapsed tie and an old record"])
def test_the_workers_record_keeping_and_a_removal_never_wait_for_each_other(tmp_path, monkeypatch, request, records):
    """PostgreSQL only: it takes two rows held by two transactions, which SQLite's one write lock cannot show.

    A device that is going has two records the worker is about to deal with. Removal takes a device's
    records in id order. The worker must take them in that order too, one pass to a transaction, or each
    could hold a record the other wants. The earlier record is held here until both are waiting for it,
    removal first, so that when it is let go removal has it and wants the later one.
    """
    app, _gateway = home(tmp_path, monkeypatch, **on("postgresql", request))
    old, gone_quiet = utcnow() - timedelta(days=91), utcnow() - timedelta(days=31)
    later = {"two old records": {"kind": "conflict", "first_at": old, "last_at": old},
             "a lapsed tie and an old record": {"kind": "tie", "first_at": gone_quiet, "last_at": gone_quiet,
                                                "reach_from": gone_quiet}}[records]
    with app.state.session_factory() as db:
        # The later id is stored first, so a delete that takes rows as it finds them meets that one first.
        for id_, user, values in (("b-later", "kim", later),
                                  ("a-earlier", "sam", {"kind": "conflict", "first_at": old, "last_at": old})):
            db.add(DevicePresence(id=id_, user_id=user, device_id="gw:client:laptop", basis="live", session="s",
                                  address=LAPTOP, **values))
            db.commit()
    raised = []

    def run(work):
        try:
            work()
        except Exception as error:  # noqa: BLE001 - reported to the test, which fails on it
            raised.append(error)

    def remove():
        with app.state.session_factory() as db:
            db.scalars(select(Resource.id).where(Resource.id == "gw:client:laptop").with_for_update()).all()
            removal.forget(db, ["gw:client:laptop"])
            db.commit()

    def keep():
        presence.keep(app.state.session_factory, utcnow())

    with others_finish() as started, app.state.session_factory() as holder:
        holder.scalars(select(DevicePresence.id).where(DevicePresence.id == "a-earlier").with_for_update()).all()
        for work in (remove, keep):
            started.append(threading.Thread(target=run, args=(work,), daemon=True))
            started[-1].start()
            until(lambda: waiting_for_a_lock(app) >= len(started))
        holder.rollback()  # removal, which asked first, now has the earlier record
    assert raised == []
    with app.state.session_factory() as db:
        assert db.scalars(select(DevicePresence)).all() == [] and db.get(Resource, "gw:client:laptop") is None


def test_a_source_that_declares_no_lookup_takes_no_part_in_finding_a_device(tmp_path, monkeypatch):
    """Its networks and its stored devices tie nobody, and its range does not put another source's in doubt."""
    app, gateway = home(tmp_path, monkeypatch)
    other = next(row.id for row in registry.providers().values() if "devices.lookup" not in row.provides)
    with app.state.session_factory() as db:
        made = {"integration_id": "plain", "provider": other, "observed_at": utcnow(), "evidence_kind": "observed"}
        db.add(Integration(id="plain", provider=other, name="Plain", status="connected", last_sync=utcnow(),
                           config={}))
        db.flush()
        db.add(Resource(id="plain:network:lan", name="LAN", kind="network", source_id="lan",
                        attributes={"subnets": ["192.0.2.0/24", "198.51.100.0/24"]}, **made))
        db.add(Resource(id="plain:client:desk", name="Desk", kind="client", source_id="desk",
                        attributes={"ip": "198.51.100.7"}, **made))
        db.commit()
    refused(app, "198.51.100.7", "outside", "did not come from your network")
    with browser(app, LAPTOP) as sam:  # the range both sources hold is asked of the one that can answer
        assert sam.get("/api/me/device").json()["device_id"] == "gw:client:laptop"
    assert gateway["reads"] == 1


def test_a_listed_proxys_address_is_tied_to_nothing_and_administrators_are_told(tmp_path, monkeypatch):
    """Everyone behind a proxy that hides them arrives from its address, which may itself be in the inventory."""
    app, gateway = home(tmp_path, monkeypatch, trusted_proxies=LAPTOP)
    refused(app, LAPTOP, "proxy", "shares with other people", headers={"X-Forwarded-For": LAPTOP})
    assert gateway["reads"] == 0
    with browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
        lines = [item for item in admin.get("/api/attention").json() if item["kind"] == "presence"]
    assert [line["title"] for line in lines] == ["Members are arriving from a proxy's address"]
    assert "cannot tell their devices apart" in lines[0]["detail"]


def test_a_gateway_that_does_not_answer_and_an_old_inventory_tie_nothing(tmp_path, monkeypatch):
    """A failed read is a reason, never an error. The stored inventory stands in only while it is under 15 minutes old."""
    app, gateway = home(tmp_path, monkeypatch)
    gateway["down"] = True
    change(app, Integration, "gw", last_sync=utcnow() - timedelta(minutes=16))
    refused(app, LAPTOP, "not_answering", "could not ask your network")
    monkeypatch.setattr(presence, "_answers", {})
    change(app, Integration, "gw", last_sync=utcnow())
    blocked(app, recent=("laptop", 10), early=("laptop", 60))
    with browser(app, LAPTOP) as client:
        assert client.get("/api/me/device").json()["device_id"] == "gw:client:laptop"
        # The inventory may be a quarter of an hour behind, so such a tie shows nothing from before it was made.
        assert seen_by(client) == []
        blocked(app, phones=("laptop", 0))
        assert seen_by(client) == ["phones"]
    tie, = stored(app)
    assert (tie.device_id, tie.basis) == ("gw:client:laptop", "stored") and tie.reach_from == tie.first_at


def test_an_address_that_changed_hands_since_the_last_collection_goes_to_who_holds_it_now(tmp_path, monkeypatch):
    """The inventory still says the laptop; the gateway says the phone. The live read wins."""
    app, gateway = home(tmp_path, monkeypatch)
    gateway["holds"].update(laptop=None, phone=LAPTOP)
    with browser(app, LAPTOP) as client:
        assert client.get("/api/me/device").json()["device_id"] == "gw:client:phone"
    assert [(tie.device_id, tie.basis) for tie in stored(app)] == [("gw:client:phone", "live")]


def test_another_persons_device_is_a_conflict_the_member_learns_nothing_from(tmp_path, monkeypatch):
    """Kim's own tablet is never tied to Sam. The attempt is on record; Sam is not told whose it is."""
    app, _gateway = home(tmp_path, monkeypatch)
    told = refused(app, TABLET, "other_person", "another person's account")
    assert "Kim" not in str(told) and "tablet" not in str(told).lower()
    assert [(row.user_id, row.device_id) for row in stored(app, "conflict")] == [("sam", "gw:client:tablet")]
    with app.state.session_factory() as db:
        assert db.scalars(select(Audit).where(Audit.action == "presence.conflict")).one().details == {
            "device_name": "Tablet"}
    refused(app, TABLET, "other_person", "another person's account")
    assert len(stored(app, "conflict")) == 1  # asking again moves its time, it does not add a row


def test_a_second_person_on_a_device_that_is_not_shared_is_a_conflict_not_a_second_tie(tmp_path, monkeypatch):
    """Sam is tied to the laptop first. Kim signing in on it gets nothing and is told the same sentence."""
    app, _gateway = home(tmp_path, monkeypatch)
    with browser(app, LAPTOP) as sam:
        assert sam.get("/api/me/device").json()["device_id"] == "gw:client:laptop"
    with browser(app, LAPTOP, KIM) as kim:
        told = kim.get("/api/me/device").json()
        assert {key: told[key] for key in NOTHING} == NOTHING and told["reason"] == "other_person"
        assert "Sam" not in str(told) and kim.get("/api/devices").json() == []
    assert [tie.user_id for tie in stored(app)] == ["sam"]
    assert [(row.user_id, row.device_id) for row in stored(app, "conflict")] == [("kim", "gw:client:laptop")]


def test_a_member_on_the_console_address_is_tied_to_nothing(tmp_path, monkeypatch):
    """With a members' address set, a session replayed on the console address ties no device."""
    app, gateway = home(tmp_path, monkeypatch, public_url="http://console.example.test",
                        portal_url="http://portal.example.test")
    with browser(app, LAPTOP, base_url="http://portal.example.test") as client:
        told = client.get("/api/me/device", headers={"host": "console.example.test"}).json()
        assert {key: told[key] for key in NOTHING} == NOTHING and told["reason"] == "console"
        assert gateway["reads"] == 0 and stored(app) == []
        assert client.get("/api/me/device").json()["device_id"] == "gw:client:laptop"


# --- The tie and its life ----------------------------------------------------------------------------------------


def test_the_first_portal_request_ties_the_person_and_a_later_sign_in_moves_its_time(tmp_path, monkeypatch):
    """One tie, one gateway read a sign-in, an answer remembered a minute; the device's owner and class never change."""
    app, gateway = home(tmp_path, monkeypatch)
    clock = [1000.0]
    monkeypatch.setattr(presence, "monotonic", lambda: clock[0])
    with browser(app, LAPTOP) as sam:
        # A forwarding header from a peer that is no listed proxy is ignored: the phone's address names nothing.
        told = sam.get("/api/me/device", headers={"X-Forwarded-For": PHONE}).json()
        assert told == {"device_id": "gw:client:laptop", "name": "Laptop", "simulated": False, "how": "signed_in",
                        "reason": None, "message": None}
        written = []
        event.listen(app.state.engine, "before_cursor_execute", lambda _c, _cursor, statement, *_rest: written.append(
            statement) if statement.split()[0].upper() in {"INSERT", "UPDATE", "DELETE"} else None)
        assert sam.get("/api/me/device").json() == told and gateway["reads"] == 1
        assert [row["id"] for row in sam.get("/api/devices").json()] == ["gw:client:laptop"]
        mine = sam.get("/api/presence").json()
        assert written == []  # once tied, a member's page reads only: record keeping is the worker's
        assert [(row["kind"], row["device_name"]) for row in mine["items"]] == [("tie", "Laptop")] and "enabled" not in mine
        assert "address" not in mine["items"][0] and "mac" not in mine["items"][0]  # for administrators only
    first, = stored(app)
    assert (first.user_id, first.basis, first.address, first.mac) == ("sam", "live", LAPTOP, "00:00:5e:00:53:01")
    assert first.reach_from == first.first_at - timedelta(hours=2)
    change(app, DevicePresence, first.id, last_at=first.last_at - timedelta(days=3))
    for moment, reads in ((1059.0, 1), (1061.0, 2)):  # the gateway's answer is remembered for 60 seconds
        clock[0] = moment
        with browser(app, LAPTOP) as again:
            assert again.get("/api/me/device").json() == told
        assert gateway["reads"] == reads
    later, = stored(app)
    assert later.id == first.id and later.first_at == first.first_at and later.reach_from == first.reach_from
    assert later.last_at > first.last_at - timedelta(minutes=1)
    with app.state.session_factory() as db:
        assert [(db.get(Resource, f"gw:client:{name}").classification, db.get(Resource, f"gw:client:{name}").owner_id)
                for name in DEVICES] == [(row[1], row[2]) for row in DEVICES.values()]
        assert [(row.action, row.target_id, row.details) for row in db.scalars(
            select(Audit).where(Audit.action.like("presence.%")))] == [
                ("presence.tied", "gw:client:laptop", {"device_name": "Laptop"})]


def test_a_tie_ends_30_days_after_the_last_sign_in_and_stays_on_record_90_days(tmp_path, monkeypatch):
    """Past 30 days it shows nothing at once. The worker records the ending, once, and drops the record 90 days on."""
    app, _gateway = home(tmp_path, monkeypatch)
    with browser(app, LAPTOP) as sam, browser(app, TABLET) as elsewhere:
        sam.get("/api/me/device")
        elsewhere.get("/api/me/device")
    tie, = stored(app)
    change(app, DevicePresence, tie.id, last_at=utcnow() - timedelta(days=30, minutes=1))
    with browser(app, "testclient") as sam:  # signed in from nowhere, so nothing is tied again
        assert sam.get("/api/devices").json() == [] and sam.get("/api/presence").json()["items"] == []
    with browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
        shown = {row["kind"]: row["ended_at"] for row in admin.get("/api/presence").json()["items"]}
        assert shown["tie"] is not None and shown["conflict"] is None  # listed as ended before anything recorded it
    assert stored(app)[0].ended_at is None  # no page wrote that down
    upkeep = Upkeep(app.state.session_factory, app.state.settings)
    for _ in range(2):  # the worker's clearing out, twice: one ending, recorded once
        asyncio.run(upkeep._clear(utcnow()))
    ended, = stored(app)
    assert ended.ended_by == "expired" and ended.ended_at == ended.last_at + timedelta(days=30)
    with app.state.session_factory() as db:
        assert [(row.actor_id, row.target_id, row.details) for row in db.scalars(
            select(Audit).where(Audit.action == "presence.ended"))] == [
                (None, "gw:client:laptop", {"user_id": "sam", "device_name": "Laptop", "because": "lapsed"})]
    change(app, DevicePresence, tie.id, ended_at=utcnow() - timedelta(days=90, minutes=1))
    change(app, DevicePresence, stored(app, "conflict")[0].id, last_at=utcnow() - timedelta(days=89))
    asyncio.run(upkeep._clear(utcnow()))
    assert stored(app) == [] and len(stored(app, "conflict")) == 1
    change(app, DevicePresence, stored(app, "conflict")[0].id, last_at=utcnow() - timedelta(days=90, minutes=1))
    presence.keep(app.state.session_factory, utcnow())
    assert stored(app, "conflict") == []


def test_a_member_ends_only_their_own_tie_and_an_administrator_any_at_once(tmp_path, monkeypatch):
    """Ended is ended at once, the same sign-in does not tie the device again, and a new sign-in does."""
    app, _gateway = home(tmp_path, monkeypatch)
    with browser(app, LAPTOP) as sam, browser(app, PHONE, KIM) as kim:
        sam.get("/api/me/device")
        kim.get("/api/me/device")
        ours, theirs = stored(app)
        assert kim.delete(f"/api/presence/{ours.id}").status_code == 404 and stored(app)[0].ended_at is None
        assert sam.delete(f"/api/presence/{ours.id}", headers={"X-CSRF-Token": ""}).status_code == 403
        assert sam.delete("/api/presence/never-made").status_code == 404
        assert sam.delete(f"/api/presence/{ours.id}").json() == {"ok": True}
        assert sam.delete(f"/api/presence/{ours.id}").json() == {"ok": True}  # asked twice, it stays ended
        assert sam.get("/api/devices").json() == [] and stored(app)[0].ended_by == "sam"
        assert sam.get("/api/me/device").json()["reason"] == "forgotten"
        with browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
            assert admin.delete(f"/api/presence/{theirs.id}").json() == {"ok": True}
        assert kim.get("/api/devices").json() == [] and kim.get("/api/me/device").json()["reason"] == "forgotten"
    with browser(app, LAPTOP) as sam:
        assert sam.get("/api/me/device").json()["how"] == "signed_in"
    assert [(row.user_id, row.ended_at is None) for row in stored(app)] == [
        ("sam", False), ("kim", False), ("sam", True)]


# --- Who sees what, decided in one place -------------------------------------------------------------------------


def blocked(app, **ages):
    """Store one blocked lookup for each `name=(device, minutes ago)`, attributed to that device."""
    with app.state.session_factory() as db:
        for id_, (device, minutes) in ages.items():
            when = utcnow() - timedelta(minutes=minutes)
            db.add(Observation(id=id_, integration_id="gw", device_id=device and f"gw:client:{device}",
                               device_name=device or "", domain=f"{id_}.example", source="resolver", reason="list",
                               observed_at=when, expires_at=when + timedelta(hours=24), evidence_kind="observed",
                               attribution="assigned" if device else "unattributed", risk_score=None,
                               risk_explanation=""))
        db.commit()


def seen_by(client):
    """What one member's list, single read and search each show, which must agree."""
    listing = client.get("/api/blocks").json()
    ids = sorted(row["id"] for row in listing["rows"])
    assert listing["total"] == len(ids)
    for id_ in ("recent", "early", "phones", "unnamed"):
        assert (client.get("/api/blocks/one", params={"id": id_}).status_code == 200) == (id_ in ids)
        found = client.post("/api/blocks/find", json={"domain": f"{id_}.example"}).json()
        assert [row["id"] for row in found] == ([id_] if id_ in ids else [])
    return ids


def test_a_tie_shows_its_devices_blocks_from_the_reach_back_on_and_nothing_once_ended(tmp_path, monkeypatch):
    """Inside the reach-back and the tie's life: visible. Before it, on another device, or after ending: not."""
    app, _gateway = home(tmp_path, monkeypatch)
    blocked(app, recent=("laptop", 60), early=("laptop", 180), phones=("phone", 60), unnamed=(None, 60))
    with browser(app, LAPTOP) as sam, browser(app, PHONE, KIM) as kim:
        assert seen_by(sam) == [] and seen_by(kim) == []  # signed in, and nothing tied yet
        sam.get("/api/me/device")
        kim.get("/api/me/device")
        assert seen_by(sam) == ["recent"] and seen_by(kim) == ["phones"]
        with app.state.session_factory() as db:  # the list's conditions admit exactly what the one rule admits
            for id_ in ("sam", "kim"):
                user = db.get(User, id_)
                rows = list(db.scalars(select(Observation)))
                assert {row.id for row in db.scalars(select(Observation).where(*observations_permitted(db, user)))} \
                    == {row.id for row in rows if observation_permitted(db, row, user)}
        with browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
            # A shorter reach applies to ties already made; a longer one never widens them again.
            for hours in (0, 24):
                assert admin.put("/api/presence", json={"enabled": True, "reach_back_hours": hours}).status_code == 200
                assert seen_by(sam) == []
        for tie in stored(app):
            change(app, DevicePresence, tie.id, reach_from=utcnow() - timedelta(hours=2))
        assert seen_by(sam) == ["recent"]
        change(app, Resource, "gw:client:laptop", classification="personal", owner_id="kim")
        assert seen_by(sam) == [] and sam.get("/api/me/device").json()["reason"] == "other_person"
        change(app, Resource, "gw:client:laptop", classification="unassigned", owner_id=None)
        assert sam.delete(f"/api/presence/{stored(app)[0].id}").status_code == 200
        assert seen_by(sam) == [] and seen_by(kim) == ["phones"]


@pytest.mark.parametrize("values", [{"classification": "infrastructure"}, {"kind": "gateway"}])
def test_a_tie_shows_nothing_of_a_device_that_became_infrastructure_or_is_no_device(tmp_path, monkeypatch, values):
    """However the record came to say so, a tie in force shows neither such a device nor a lookup on it."""
    app, _gateway = home(tmp_path, monkeypatch)
    blocked(app, recent=("laptop", 10))
    with browser(app, LAPTOP) as sam:
        sam.get("/api/me/device")
        assert seen_by(sam) == ["recent"] and len(sam.get("/api/devices").json()) == 1
        change(app, Resource, "gw:client:laptop", **values)
        assert seen_by(sam) == [] and sam.get("/api/devices").json() == []


def earlier(app, action, *minutes):
    """Move the records of an action into the past, oldest first, and say when the newest now says it happened."""
    with app.state.session_factory() as db:
        rows = db.scalars(select(Audit).where(Audit.action == action).order_by(Audit.created_at)).all()
        assert len(rows) == len(minutes)
        for row, ago in zip(rows, minutes, strict=True):
            row.created_at = utcnow() - timedelta(minutes=ago)
        db.commit()
        return utc(rows[-1].created_at)


@pytest.mark.parametrize("device, steps, who", [
    ("laptop", [("personal", ["kim"])], KIM),                                # given to the person who then signs in
    ("tablet", [("unassigned", [])], LIVE_MEMBER),                           # taken from its owner
    ("laptop", [("infrastructure", []), ("unassigned", [])], LIVE_MEMBER),   # its classification changed, twice
    ("tablet", [("shared", ["sam", "kim"])], LIVE_MEMBER),                   # one person's device made shared
])
def test_a_new_tie_reaches_back_no_further_than_the_last_change_of_whose_the_device_is(tmp_path, monkeypatch, device,
                                                                                         steps, who):
    """What was looked up on a device before an administrator last said whose it is belongs to that earlier time."""
    app, _gateway = home(tmp_path, monkeypatch)
    blocked(app, recent=(device, 10), early=(device, 60))
    with browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
        for classification, owners in steps:
            assigned(admin, device, classification, *owners)
    changed = earlier(app, "device.assignment_changed", *(50, 30)[-len(steps):])
    with browser(app, DEVICES[device][0], who) as person:
        assert person.get("/api/me/device").json()["device_id"] == f"gw:client:{device}"
        assert seen_by(person) == ["recent"]
    tie, = stored(app)
    assert utc(tie.reach_from) == changed and tie.first_at - timedelta(hours=2) < tie.reach_from


@pytest.mark.parametrize("ending", ["forgotten", "ended by an administrator", "lapsed", "lapsed and recorded"])
def test_a_new_tie_reaches_back_no_further_than_the_end_of_another_persons_tie(tmp_path, monkeypatch, ending):
    """While Sam was the one tied to the laptop, its lookups were Sam's. Kim, tied afterwards, starts where Sam ended."""
    app, _gateway = home(tmp_path, monkeypatch)
    blocked(app, recent=("laptop", 10), early=("laptop", 60))
    with browser(app, LAPTOP) as sam:
        sam.get("/api/me/device")
        theirs, = stored(app)
        if ending == "forgotten":
            assert sam.delete(f"/api/presence/{theirs.id}").status_code == 200
    if ending == "ended by an administrator":
        with browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
            assert admin.delete(f"/api/presence/{theirs.id}").status_code == 200
    half = utcnow() - timedelta(minutes=30)
    if ending.startswith("lapsed"):
        change(app, DevicePresence, theirs.id, last_at=half - timedelta(days=30))
        if ending == "lapsed and recorded":
            presence.keep(app.state.session_factory, utcnow())
    else:
        change(app, DevicePresence, theirs.id, ended_at=half)
    with browser(app, LAPTOP, KIM) as kim:
        assert kim.get("/api/me/device").json()["how"] == "signed_in"
        assert seen_by(kim) == ["recent"]
    mine = stored(app)[-1]
    assert mine.user_id == "kim" and utc(mine.reach_from) == half


def test_on_a_shared_device_and_after_a_persons_own_tie_the_reach_is_the_setting(tmp_path, monkeypatch):
    """Several people hold a shared device at once, and a person's own earlier tie takes nothing from their next."""
    app, _gateway = home(tmp_path, monkeypatch)
    for address in (SHARED, LAPTOP):
        with browser(app, address) as sam:
            sam.get("/api/me/device")
            assert sam.delete(f"/api/presence/{stored(app)[-1].id}").status_code == 200
    with browser(app, SHARED, KIM) as kim, browser(app, LAPTOP) as sam:
        assert [client.get("/api/me/device").json()["how"] for client in (kim, sam)] == ["signed_in", "signed_in"]
    live = [tie for tie in stored(app) if tie.ended_at is None]
    assert sorted((tie.user_id, tie.device_id) for tie in live) == [("kim", "gw:client:shared"), ("sam", "gw:client:laptop")]
    assert all(tie.reach_from == tie.first_at - timedelta(hours=2) for tie in live)


def test_only_deps_decides_which_device_a_member_may_see():
    """Structural. A module that reads a grant's or a tie's window, or queries either, has grown a rule of its own.

    `retention` reads grants to keep an assigned device from being dropped, which shows nobody anything.
    """
    allowed = {"DeviceGrant": {"deps", "models", "main", "removal", "retention", "seed"},
               "DevicePresence": {"deps", "models", "presence", "seed"},
               "valid_from": {"deps", "models", "main", "seed"},
               "valid_until": {"deps", "models", "main", "removal", "retention", "seed"},
               "reach_from": {"deps", "models", "presence", "seed"},
               "grant_at": {"deps", "main"}, "live_ties": {"deps", "presence"},
               "_assigned": {"deps"}, "_tied": {"deps"}, "_tie_allowed": {"deps"}}
    used: dict[str, set[str]] = {}
    for path in sorted(Path(presence.__file__).parent.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            names = [getattr(node, "id", None), getattr(node, "attr", None), getattr(node, "arg", None),
                     *(alias.name for alias in getattr(node, "names", []) if isinstance(node, ast.ImportFrom))]
            for name in names:
                if name in allowed:
                    used.setdefault(name, set()).add(path.stem)
    assert {name: sorted(where - allowed[name]) for name, where in used.items() if where - allowed[name]} == {}
    assert set(used) == set(allowed)  # every name is still there to be watched


# --- Several people, and what an administrator sees --------------------------------------------------------------


def test_a_shared_device_holds_several_ties_and_an_administrator_sees_and_ends_them(tmp_path, monkeypatch):
    """Two people on the shared device are two ties. Ties and conflicts are listed with who and when."""
    app, _gateway = home(tmp_path, monkeypatch)
    with browser(app, SHARED) as sam, browser(app, SHARED, KIM) as kim:
        assert [client.get("/api/me/device").json()["how"] for client in (sam, kim)] == ["signed_in", "signed_in"]
        with browser(app, TABLET) as elsewhere:
            assert elsewhere.get("/api/me/device").json()["reason"] == "other_person"
        assert sam.put("/api/presence", json={"enabled": False, "reach_back_hours": 2}).status_code == 403
        with browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
            told = admin.get("/api/presence").json()
            assert (told["enabled"], told["reach_back_hours"]) == (True, 2)
            assert sorted((row["kind"], row["user_name"], row["device_name"]) for row in told["items"]) == [
                ("conflict", "Sam", "Tablet"), ("tie", "Kim", "Shared"), ("tie", "Sam", "Shared")]
            assert all(row["first_at"] and row["last_at"] and row["ended_at"] is None for row in told["items"])
            assert {(row["address"], row["mac"]) for row in told["items"] if row["kind"] == "tie"} == {
                (SHARED, "00:00:5e:00:53:01")}  # where each signed in from, shown to administrators only
            assert admin.put("/api/presence", json={"enabled": True, "reach_back_hours": 25}).status_code == 422
            kims = next(row for row in told["items"] if row["kind"] == "tie" and row["user_name"] == "Kim")
            assert admin.delete(f"/api/presence/{kims['id']}").json() == {"ok": True}
            assert kim.get("/api/devices").json() == [] and len(sam.get("/api/devices").json()) == 1
            # Switching recognition off ends every tie at once, with a record for each that says whose.
            with browser(app, PHONE, KIM) as again:
                assert again.get("/api/me/device").json()["device_id"] == "gw:client:phone"
            assert admin.put("/api/presence", json={"enabled": False, "reach_back_hours": 2}).json()["enabled"] is False
            assert sam.get("/api/devices").json() == [] and all(tie.ended_at for tie in stored(app))
    with app.state.session_factory() as db:
        changed = db.scalars(select(Audit).where(Audit.action == "presence.setting_changed")).all()[-1]
        assert changed.details == {"enabled": False, "reach_back_hours": 2, "ties_ended": 2}
        ended = db.scalars(select(Audit).where(Audit.action == "presence.ended")).all()
        assert sorted((row.details["device_name"], row.details["user_id"], row.details.get("because"))
                      for row in ended) == [
            ("Phone", "kim", "switched_off"), ("Shared", "kim", None), ("Shared", "sam", "switched_off")]
        assert all(row.target_id == "gw:client:" + row.details["device_name"].lower() for row in ended)
        assert {row.actor_id for row in ended} == {changed.actor_id}


def assigned(admin, device, classification, *owners):
    """Have an administrator say whose a device is, as the console does."""
    answer = admin.put(f"/api/devices/gw:client:{device}/assignment",
                       json={"classification": classification, "user_ids": list(owners)})
    assert answer.status_code == 200, answer.text


@pytest.mark.parametrize("was, becomes, owners, keeps", [
    ("shared", "personal", ["kim"], ["kim"]),      # stops being shared: only the new owner's tie stays
    ("shared", "unassigned", [], []),              # set to nobody yet
    ("shared", "infrastructure", [], []),          # set to not a personal device
    ("personal", "personal", ["sam"], []),         # its owner changes: the old owner's tie ends
    ("personal", "unassigned", [], []),            # its owner goes
    ("unassigned", "personal", ["kim"], []),       # nobody's, then someone else's than the one tied
    ("unassigned", "shared", ["sam", "kim"], ["sam"]),  # made shared with the one tied among those named
    ("unassigned", "shared", ["kim"], []),              # made shared between other people than the one tied
    ("personal", "shared", ["sam"], []),                # one person's device made shared between others
    ("shared", "shared", ["sam"], ["sam"]),             # still shared, between other people than before
    ("unassigned", "unassigned", [], ["sam"]),          # saved again with nothing changed: nothing ends
])
def test_a_device_that_changes_hands_keeps_no_tie_but_its_new_owners(tmp_path, monkeypatch, was, becomes, owners,
                                                                       keeps):
    """An administrator's word replaces what sign-ins suggested: the ties of people it does not name end, audited."""
    app, _gateway = home(tmp_path, monkeypatch)
    device = {"shared": "shared", "personal": "tablet", "unassigned": "laptop"}[was]
    people = {"shared": [LIVE_MEMBER, KIM], "personal": [KIM], "unassigned": [LIVE_MEMBER]}[was]
    for who in people:
        with browser(app, DEVICES[device][0], who) as person:
            assert person.get("/api/me/device").json()["device_id"] == f"gw:client:{device}"
    with browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
        assigned(admin, device, becomes, *owners)
        listed = admin.get("/api/presence").json()["items"]
    assert sorted(row["user_id"] for row in listed if row["kind"] == "tie" and not row["ended_at"]) == keeps
    ended = [tie for tie in stored(app) if tie.ended_at is not None]
    with app.state.session_factory() as db:
        admin_id = db.scalar(select(User.id).where(User.email == LIVE_ADMIN[0]))
        audits = db.scalars(select(Audit).where(Audit.action == "presence.ended")).all()
    assert {tie.ended_by for tie in ended} <= {admin_id} and len(ended) == len(people) - len(keeps)
    assert sorted((row.actor_id, row.target_id, row.details["user_id"], row.details["because"]) for row in audits) == \
        sorted((admin_id, f"gw:client:{device}", tie.user_id, "assignment") for tie in ended)
    for who in people:  # and what a person may see follows at once
        with browser(app, "testclient", who) as person:
            mine = [row["id"] for row in person.get("/api/devices").json()]
        name = "sam" if who is LIVE_MEMBER else "kim"
        may = name in keeps or (becomes in {"personal", "shared"} and name in owners)
        assert (f"gw:client:{device}" in mine) == may, (name, mine)


@pytest.mark.parametrize("device, becomes, owners", [
    ("laptop", "shared", ["sam", "kim"]),   # nobody's, then shared with the person tied among those named
    ("laptop", "personal", ["sam"]),        # nobody's, then given to the person tied
    ("laptop", "unassigned", []),           # saved again with nothing changed
])
def test_a_tie_an_assignment_keeps_starts_again_at_the_assignment(tmp_path, monkeypatch, device, becomes, owners):
    """What an administrator's word does not cover from before it, a tie made earlier must not show either."""
    app, _gateway = home(tmp_path, monkeypatch)
    blocked(app, recent=(device, 10), early=(device, 60))
    with browser(app, DEVICES[device][0]) as sam:
        sam.get("/api/me/device")
        assert seen_by(sam) == ["early", "recent"]
        before = utcnow()
        with browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
            assigned(admin, device, becomes, *owners)
        tie, = stored(app)
        assert tie.ended_at is None and utc(tie.reach_from) >= before
        assert seen_by(sam) == []
        blocked(app, phones=(device, 0))
        assert seen_by(sam) == ["phones"]


def test_saving_a_shared_device_again_with_the_same_people_ends_nobodys_tie(tmp_path, monkeypatch):
    """Someone not named who signed in on it afterwards stays tied until the administrator changes who it is for."""
    app, _gateway = home(tmp_path, monkeypatch)
    with browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
        assigned(admin, "shared", "shared", "sam")
        with browser(app, SHARED) as sam, browser(app, SHARED, KIM) as kim:
            assert [client.get("/api/me/device").json()["device_id"] for client in (sam, kim)] == ["gw:client:shared"] * 2
        assigned(admin, "shared", "shared", "sam")
        assert [tie.ended_at for tie in stored(app)] == [None, None]
        assigned(admin, "shared", "shared", "kim")
    assert [(tie.user_id, tie.ended_at is None) for tie in stored(app)] == [("sam", False), ("kim", True)]


def test_a_device_that_is_dropped_or_whose_source_is_removed_takes_its_ties_with_it_on_record(tmp_path, monkeypatch):
    """A tie and a conflict name a device. When the device goes, each tie in force ends on record and both rows go."""
    app, _gateway = home(tmp_path, monkeypatch)
    with browser(app, LAPTOP) as sam, browser(app, PHONE, KIM) as kim, browser(app, LAPTOP, KIM) as second:
        assert [client.get("/api/me/device").json()["reason"] for client in (sam, kim, second)] == [
            None, None, "other_person"]
    # The laptop left the gateway eight days ago and whole reads on seven days since have not listed it.
    days = [(utcnow() - timedelta(days=ago)).date().isoformat() for ago in range(8, 1, -1)]
    change(app, Resource, "gw:client:laptop", attributes={
        "ip": LAPTOP, retention.MISSING: True, retention.SINCE: (utcnow() - timedelta(days=8)).isoformat(),
        retention.DAYS: days})
    with app.state.session_factory() as db:
        db.add(Audit(actor_id=None, action="integration.collected", target_id="gw", details={"unread": []}))
        db.commit()
    assert retention.drop(app.state.session_factory, utcnow()) == 1
    assert [(tie.user_id, tie.device_id) for tie in stored(app)] == [("kim", "gw:client:phone")]
    assert stored(app, "conflict") == []
    with browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
        assert admin.request("DELETE", "/api/integrations/gw", json={"name": "Gateway"}).status_code == 200
    assert stored(app) == []
    with app.state.session_factory() as db:
        admin_id = db.scalar(select(User.id).where(User.email == LIVE_ADMIN[0]))
        assert [(row.actor_id, row.target_id, row.details) for row in db.scalars(
            select(Audit).where(Audit.action == "presence.ended").order_by(Audit.created_at))] == [
                (None, "gw:client:laptop", {"user_id": "sam", "device_name": "Laptop", "because": "device_removed"}),
                (admin_id, "gw:client:phone", {"user_id": "kim", "device_name": "Phone", "because": "device_removed"})]
    for who in (LIVE_MEMBER, KIM):
        with browser(app, "testclient", who) as person:
            assert person.get("/api/devices").json() == [] and person.get("/api/presence").json() == {"items": []}


# --- The gateway lookup ------------------------------------------------------------------------------------------


def test_the_gateway_lookup_only_reads_is_paced_and_compares_addresses_as_addresses(monkeypatch):
    """GET requests only, through the declared capability, under the address's request limit."""
    sent = []
    clients = [{"id": "c1", "ipAddress": "192.0.2.10", "macAddress": "00:00:5e:00:53:10"},
               {"id": "c2", "ipAddress": "2001:DB8::0010"}, {"id": "c3", "ipAddress": "192.0.2.010"}, {"id": "c4"}]

    def gateway(request):
        sent.append((request.method, request.url.path.rpartition("/integration")[2]))
        rows = [{"id": "site-one"}] if request.url.path.endswith("/v1/sites") else clients
        return httpx.Response(200, json={"data": rows, "count": len(rows), "offset": 0, "totalCount": len(rows)})

    monkeypatch.setattr(core, "make_http_client", lambda key: httpx.AsyncClient(
        transport=httpx.MockTransport(gateway), headers={"X-Api-Key": key}))
    monkeypatch.setattr(core, "_turns", {})
    provider = registry.get("unifi_network")
    assert "devices.lookup" in provider.provides and "devices.lookup" not in registry.WRITES
    cloud = {"base_url": "https://api.ui.com/v1/connector/consoles/abc/proxy/network/integration"}

    def ask(address, site="site-one", config=cloud):
        return asyncio.run(provider.client_at("gw", config, "fabricated-key", address, site))

    assert ask("::ffff:192.0.2.10") == [{"id": "gw:client:c1", "mac": "00:00:5e:00:53:10"}]
    assert ask("2001:db8:0:0:0:0:0:10") == [{"id": "gw:client:c2", "mac": None}]
    assert ask("192.0.2.010") == [] and ask("not an address") == []  # leading zeros are no address, as for `peer`
    assert ask("192.0.2.10", "site-two")[0]["id"] == "gw:client:c1"
    # Only the site named is read, and only if it is the one the source is set to read: never every site's list.
    assert ask("192.0.2.10", None) == [] and ask("192.0.2.10", "site-two", {**cloud, "site_id": "site-one"}) == []
    with pytest.raises(IntegrationError):
        ask("192.0.2.10", "site-one/../site-two")
    assert sent == [("GET", "/v1/sites/site-one/clients")] * 2 + [("GET", "/v1/sites/site-two/clients")]
    assert len(core._turns["unifi_network:abc"]) == 3
    for text in ("192.0.2.10", "::ffff:192.0.2.10", "2001:DB8::10", "192.0.2.010", "fe80::1%eth0", "a name", ""):
        assert core.plain_address(text) == peer._ip(text)


def test_a_gateway_that_never_answers_is_given_up_on_and_said_in_plain_words(tmp_path, monkeypatch):
    """The read has a time limit of its own, and its failure is remembered like an answer: no error, no second wait."""
    app, gateway = home(tmp_path, monkeypatch)
    change(app, Integration, "gw", last_sync=None)

    async def never(*_args):
        gateway["reads"] += 1
        await asyncio.Event().wait()

    provider = registry.get("unifi_network")
    monkeypatch.setitem(registry.providers(), provider.id, dataclasses.replace(provider, client_at=never))
    monkeypatch.setattr(presence, "READ_SECONDS", 0.01)
    with browser(app, LAPTOP) as sam:
        for _ in range(2):
            answer = sam.get("/api/me/device")
            assert answer.status_code == 200 and answer.json()["reason"] == "not_answering"
    assert gateway["reads"] == 1 and stored(app) == []


# --- The demonstration -------------------------------------------------------------------------------------------


def test_the_demo_shows_one_tie_and_one_conflict_and_its_simulated_device_is_as_before(client, admin_headers):
    """Fabricated names only; signing in to the demo ties nothing and reads no gateway."""
    told = client.get("/api/presence").json()
    assert sorted((row["kind"], row["user_name"], row["device_name"]) for row in told["items"]) == [
        ("conflict", "Jamie Rivera", "Alex's workstation"), ("tie", "Alex Morgan", "Front desk tablet")]
    assert told["enabled"] is True
    live_signin(client, ("jamie@nyctr.demo", "nyctr-demo"))
    assert client.get("/api/me/device").json() == {
        "device_id": "laptop-jamie", "name": "Jamie's MacBook", "simulated": True, "how": "assigned",
        "reason": None, "message": None}
    assert client.get("/api/presence").json() == {"items": []}  # a conflict is never listed to the member


def test_the_demonstration_ties_nobody_whatever_address_a_request_comes_from(app):
    """Its network is fabricated. A request from a fabricated device's own address is not looked up and not recorded."""
    with TestClient(app, client=("192.0.2.62", 50000)) as client:
        with app.state.session_factory() as db:
            db.add(Resource(id="demo-lan", integration_id="demo-unifi", name="LAN", kind="network",
                            provider="unifi_network", source_id="demo-lan", observed_at=utcnow(),
                            evidence_kind="configured", attributes={"subnets": ["192.0.2.0/24"]}))
            db.commit()
            before = len(db.scalars(select(DevicePresence)).all())
        live_signin(client, ("jamie@nyctr.demo", "nyctr-demo"))
        told = client.get("/api/me/device").json()
        assert (told["device_id"], told["simulated"], told["how"]) == ("laptop-jamie", True, "assigned")
        with app.state.session_factory() as db:
            assert len(db.scalars(select(DevicePresence)).all()) == before == 2


@pytest.mark.parametrize("values", [{"client_at": None}, {"provides": unifi.PROVIDER.provides - {"devices.lookup"}}])
def test_an_integration_declares_the_lookup_and_its_read_together_or_not_at_all(monkeypatch, values):
    """Start-up refuses an integration that offers the capability with no read behind it, or a read nobody declared."""
    monkeypatch.setattr(registry, "_cache", None)
    monkeypatch.setattr(unifi, "PROVIDER", dataclasses.replace(unifi.PROVIDER, **values))
    with pytest.raises(RuntimeError, match="declares devices.lookup without its actions"):
        registry.providers()


def test_a_request_that_matches_no_device_asks_about_nobodys_access(tmp_path, monkeypatch):
    """The address is compared first. Only a device that holds it is checked for whether the person may see it."""
    app, _gateway = home(tmp_path, monkeypatch, switched_on=False)
    with browser(app, "198.51.100.7") as sam, browser(app, "198.51.100.9", LIVE_ADMIN) as admin:
        assigned(admin, "phone", "personal", "sam")
        asked = []
        event.listen(app.state.engine, "before_cursor_execute", lambda _c, _cursor, statement, *_rest: asked.append(
            statement) if "FROM device_grants" in statement or "FROM device_presence" in statement else None)
        assert sam.get("/api/me/device").json()["device_id"] is None and asked == []
    with browser(app, PHONE) as sam:  # the one device at this address is checked, and it is Sam's
        told = sam.get("/api/me/device").json()
        assert (told["device_id"], told["how"]) == ("gw:client:phone", "assigned") and len(asked) >= 1
