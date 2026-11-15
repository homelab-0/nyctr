"""Signing in on a device ties the person to it. Denial paths first, then the tie, then who sees what."""

import ast
import asyncio
import dataclasses
import inspect
import threading
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from conftest import LIVE_ADMIN, LIVE_MEMBER, live_app, live_signin
from fastapi.testclient import TestClient
from sqlalchemy import event, select
from sqlalchemy.exc import OperationalError

from nyctr import access, peer, presence, retention
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


def switch_off(app):
    """Have an administrator switch recognition off, through the route's own function, and say what it answered."""
    with app.state.session_factory() as db:
        admin = db.scalars(select(User).where(User.role == "admin")).first()
        return presence.switch(presence.Recognition(enabled=False, reach_back_hours=2), admin, db)


def test_recognition_switched_off_while_the_network_is_being_asked_ties_nobody(tmp_path, monkeypatch):
    """The sign-in passed the check while recognition was on. Switched off before the tie is written, none is made."""
    app, gateway = home(tmp_path, monkeypatch)
    provider, asked = registry.get("unifi_network"), []

    async def client_at(integration_id, *_rest):
        asked.append(switch_off(app))  # the administrator's change lands while the lookup is out
        return [{"id": f"{integration_id}:client:laptop", "mac": None}]

    monkeypatch.setitem(registry.providers(), provider.id, dataclasses.replace(provider, client_at=client_at))
    refused(app, LAPTOP, "off", "not set to recognise")
    assert asked == [{"enabled": False, "reach_back_hours": 2}] and gateway["reads"] == 0


def test_switching_recognition_off_waits_for_a_tie_being_written_and_then_ends_it(tmp_path, monkeypatch):
    """Whichever comes first, no tie is in force once recognition is off: the switch and the write take one lock."""
    app, _gateway = home(tmp_path, monkeypatch)
    write, others, answers, waiting = presence._record, [], [], []

    def record(*args):
        # The tie is about to be written. An administrator switches off now, on another connection.
        other = threading.Thread(target=lambda: answers.append(switch_off(app)))
        other.start()
        other.join(1.0)  # with the lock it is still waiting when this gives up, however long that takes
        waiting.append(other.is_alive())
        others.append(other)
        return write(*args)

    monkeypatch.setattr(presence, "_record", record)
    with browser(app, LAPTOP) as sam:
        sam.get("/api/me/device")
        others[0].join()
        assert waiting == [True] and answers == [{"enabled": False, "reach_back_hours": 2}]
        assert sam.get("/api/devices").json() == []
    tie, = stored(app)
    assert tie.ended_at is not None
    with app.state.session_factory() as db:
        assert db.scalars(select(Audit).where(Audit.action == "presence.setting_changed")).all()[-1].details[
            "ties_ended"] == 1


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
