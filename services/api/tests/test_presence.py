"""Signing in on a device ties the person to it. Denial paths first, then the tie, then who sees what."""

import ast
import asyncio
import dataclasses
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from conftest import LIVE_ADMIN, LIVE_MEMBER, live_app, live_signin
from fastapi.testclient import TestClient
from sqlalchemy import select

from nyctr import peer, presence
from nyctr.deps import observation_permitted, observations_permitted
from nyctr.integrations import IntegrationError, core, registry
from nyctr.models import Audit, DevicePresence, Integration, Observation, Resource, Setting, User, utcnow
from nyctr.security import hash_password

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
    holds which address now, how often it was read, and whether it answers at all.
    """
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_GW", "fabricated-key")
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "gateway.example")
    gateway = {"holds": {name: row[0] for name, row in DEVICES.items()}, "reads": 0, "down": False}

    async def client_at(integration_id, config, key, address):
        gateway["reads"] += 1
        if gateway["down"]:
            raise IntegrationError("The source did not answer in time.", category="timeout")
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


# --- AC-1: every way a tie is not made ---------------------------------------------------------------------------


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
    ("192.0.2.99", {}, "nobody", "lists no device"),
    (LAPTOP, {"phone": LAPTOP}, "several", "more than one device"),
    (LAPTOP, {"laptop": None, "newcomer": LAPTOP}, "not_collected", "has not read this device"),
    (PRINTER, {}, "infrastructure", "not a personal device"),
])
def test_an_address_that_names_no_one_device_of_a_person_is_tied_to_nothing(tmp_path, monkeypatch, address, holds,
                                                                             code, says):
    """Outside every collected network, held by nobody, claimed by two, not yet collected, or infrastructure."""
    app, gateway = home(tmp_path, monkeypatch)
    gateway["holds"].update(holds)
    refused(app, address, code, says)
    assert gateway["reads"] == (0 if code == "outside" else 1)


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
    change(app, Integration, "gw", last_sync=utcnow() - timedelta(minutes=14))
    with browser(app, LAPTOP) as client:
        assert client.get("/api/me/device").json()["device_id"] == "gw:client:laptop"
    assert [(tie.device_id, tie.basis) for tie in stored(app)] == [("gw:client:laptop", "stored")]


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


# --- AC-2: the tie and its life ----------------------------------------------------------------------------------


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
        assert sam.get("/api/me/device").json() == told and gateway["reads"] == 1
        assert [row["id"] for row in sam.get("/api/devices").json()] == ["gw:client:laptop"]
        mine = sam.get("/api/presence").json()
        assert [(row["kind"], row["device_name"]) for row in mine["items"]] == [("tie", "Laptop")] and "enabled" not in mine
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
        assert [row.action for row in db.scalars(select(Audit).where(Audit.action.like("presence.%")))] == [
            "presence.tied"]


def test_a_tie_ends_30_days_after_the_last_sign_in_and_stays_on_record_90_days(tmp_path, monkeypatch):
    """Past 30 days it shows nothing, whether or not anything has swept it yet; 90 days after ending it is dropped."""
    app, _gateway = home(tmp_path, monkeypatch)
    with browser(app, LAPTOP) as sam:
        sam.get("/api/me/device")
    tie, = stored(app)
    change(app, DevicePresence, tie.id, last_at=utcnow() - timedelta(days=30, minutes=1))
    with browser(app, "testclient") as sam:  # signed in from nowhere, so nothing is tied again
        assert sam.get("/api/devices").json() == []
        assert stored(app)[0].ended_at is None  # nothing swept it yet, and it already shows nothing
        assert sam.get("/api/presence").json()["items"] == []
        ended, = stored(app)
        assert ended.ended_by == "expired" and ended.ended_at == ended.last_at + timedelta(days=30)
        change(app, DevicePresence, tie.id, ended_at=utcnow() - timedelta(days=90, minutes=1))
        sam.get("/api/presence")
    assert stored(app) == []


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


# --- AC-3: who sees what, decided in one place -------------------------------------------------------------------


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


def test_only_deps_decides_which_device_a_member_may_see():
    """Structural. A module that reads a grant's or a tie's window, or queries either, has grown a rule of its own."""
    allowed = {"DeviceGrant": {"deps", "models", "main", "removal", "seed"},
               "DevicePresence": {"deps", "models", "presence", "removal", "seed"},
               "valid_from": {"deps", "models", "main", "seed"},
               "valid_until": {"deps", "models", "main", "removal", "seed"},
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


# --- AC-4: several people, and what an administrator sees --------------------------------------------------------


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
            assert admin.put("/api/presence", json={"enabled": True, "reach_back_hours": 25}).status_code == 422
            kims = next(row for row in told["items"] if row["kind"] == "tie" and row["user_name"] == "Kim")
            assert admin.delete(f"/api/presence/{kims['id']}").json() == {"ok": True}
            assert kim.get("/api/devices").json() == [] and len(sam.get("/api/devices").json()) == 1
            # Switching recognition off ends every tie at once.
            assert admin.put("/api/presence", json={"enabled": False, "reach_back_hours": 2}).json()["enabled"] is False
            assert sam.get("/api/devices").json() == [] and all(tie.ended_at for tie in stored(app))
    with app.state.session_factory() as db:
        changed = db.scalars(select(Audit).where(Audit.action == "presence.setting_changed")).all()[-1]
        assert changed.details == {"enabled": False, "reach_back_hours": 2, "ties_ended": 1}


# --- AC-5: the gateway lookup ------------------------------------------------------------------------------------


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

    def ask(address, config=cloud):
        return asyncio.run(provider.client_at("gw", config, "fabricated-key", address))

    assert ask("::ffff:192.0.2.10") == [{"id": "gw:client:c1", "mac": "00:00:5e:00:53:10"}]
    assert ask("2001:db8:0:0:0:0:0:10") == [{"id": "gw:client:c2", "mac": None}]
    assert ask("192.0.2.010") == [] and ask("not an address") == []  # leading zeros are no address, as for `peer`
    assert ask("192.0.2.10", {**cloud, "site_id": "site-two"})[0]["id"] == "gw:client:c1"
    assert {method for method, _path in sent} == {"GET"} and len(sent) == 5
    assert sent[-1] == ("GET", "/v1/sites/site-two/clients") and len(core._turns["unifi_network:abc"]) == 5
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


# --- AC-8: the demonstration -------------------------------------------------------------------------------------


def test_the_demo_shows_one_tie_and_one_conflict_and_its_simulated_device_is_as_before(client, admin_headers):
    """Fabricated names only; signing in to the demo ties nothing and reads no gateway."""
    told = client.get("/api/presence").json()
    assert sorted((row["kind"], row["user_name"], row["device_name"]) for row in told["items"]) == [
        ("conflict", "Jamie Rivera", "Alex's workstation"), ("tie", "Jamie Rivera", "Front desk tablet")]
    assert told["enabled"] is True
    live_signin(client, ("jamie@nyctr.demo", "nyctr-demo"))
    assert client.get("/api/me/device").json() == {
        "device_id": "laptop-jamie", "name": "Jamie's MacBook", "simulated": True, "how": "assigned",
        "reason": None, "message": None}
    assert len(client.get("/api/presence").json()["items"]) == 1
