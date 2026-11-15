"""Signing in on a device ties the person to it. Denial paths first, then the tie, then who sees what."""

import dataclasses
from contextlib import contextmanager
from datetime import timedelta

import pytest
from conftest import LIVE_ADMIN, LIVE_MEMBER, live_app, live_signin
from fastapi.testclient import TestClient
from sqlalchemy import select

from nyctr import presence
from nyctr.integrations import IntegrationError, registry
from nyctr.models import DevicePresence, Integration, Resource, Setting, User, utcnow
from nyctr.security import hash_password

KIM = ("kim@example.net", "a third secure password")
LAPTOP, PHONE, TABLET, PRINTER, SHARED = (f"192.0.2.{n}" for n in (10, 11, 12, 20, 30))
# name: (address, classification, owner)
DEVICES = {"laptop": (LAPTOP, "unassigned", None), "phone": (PHONE, "unassigned", None),
           "tablet": (TABLET, "personal", "kim"), "printer": (PRINTER, "infrastructure", None),
           "shared": (SHARED, "shared", None)}
NOTHING = {"device_id": None, "name": None, "simulated": False, "how": None, "tie_id": None}


def home(tmp_path, monkeypatch, switched_on=True, **settings):
    """A live installation whose gateway source collected one network and five devices.

    Returns the app and the fabricated client list its gateway answers from: which device
    holds which address now, how often it was read, and whether it answers at all.
    """
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_GW", "fabricated-key")
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
        assert "Sam" not in str(told) and kim.get("/api/devices").json() == [
            row for row in kim.get("/api/devices").json() if row["id"] == "gw:client:tablet"]
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
