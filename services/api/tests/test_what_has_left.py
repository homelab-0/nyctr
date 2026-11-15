"""What a source no longer reports is marked, not counted, and dropped after a stated time, never on doubt.

Fabricated sources on a clock the test moves. Every case asserts what was stored, marked or deleted.
"""

import asyncio
from datetime import timedelta

import pytest
from conftest import live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import select

from nyctr import retention, worker
from nyctr.collection import collect_integration
from nyctr.integrations import IntegrationError, Snapshot, core, registry
from nyctr.models import (
    AccessRequest,
    Audit,
    DeviceGrant,
    DeviceLink,
    GuestAction,
    Integration,
    Lease,
    Observation,
    Resource,
    utcnow,
)

LAPTOP, TABLET, PHONE = "unifi:client:laptop", "unifi:client:tablet", "unifi:client:phone"


def thing(source, kind, key, **attributes):
    return {"id": f"{source}:{kind}:{key}", "name": key, "kind": kind, "provider": "fabricated", "source_id": key,
            "site_id": None, "evidence_kind": "observed", "attributes": attributes}


class World:
    """Two saved sources whose next read lists what the test says, on the test's clock."""

    def __init__(self, app, client, monkeypatch):
        self.app, self.client, self.now = app, client, utcnow()
        self.gaps, self.fail, self.partial, self.unread, self.lookups = [], False, None, [], []
        monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "dns-secret")
        monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "fabricated-key")
        monkeypatch.setattr("nyctr.integrations.collect", self.collect)
        monkeypatch.setattr("nyctr.collection.utcnow", lambda: self.now)

    async def collect(self, provider, integration_id, config, api_key):
        if self.fail:
            raise IntegrationError("Could not connect.", category="transport")
        for gap in self.gaps:
            core.record_gap(gap)
        blocks = [{"id": f"dns:block:{name}:{self.now.isoformat()}", "device_id": None, "device_name": "Unattributed",
                   "domain": name, "source": provider, "reason": "Fabricated list", "evidence_kind": "observed",
                   "observed_at": self.now.isoformat(), "attribution": "unattributed", "risk_score": None,
                   "risk_explanation": ""} for name in self.lookups]
        return Snapshot(resources=self.listed, blocks=blocks, partial_rows=self.partial, unread=self.unread)

    def read(self, *listed, source="unifi", days=0, **doubt):
        """Collect `source` after `days` more days. `doubt` sets gaps, fail, partial, unread or lookups for this read."""
        self.now += timedelta(days=days)
        self.listed = [thing(source, *key.split(":")[1:]) if isinstance(key, str) else key for key in listed]
        self.gaps, self.fail, self.partial, self.unread, self.lookups = (
            doubt.get("gaps", []), doubt.get("fail", False), doubt.get("partial"), doubt.get("unread", []),
            doubt.get("lookups", []))
        return asyncio.run(collect_integration(self.app.state.session_factory, self.app.state.settings, source, None))

    def drop(self):
        retention.expire_lookups(self.app.state.session_factory, self.now)
        return retention.drop(self.app.state.session_factory, self.now)

    def stored(self):
        """Every stored item's id, with the time it was first missed, or None while it is present."""
        with self.app.state.session_factory() as db:
            return {row.id: row.attributes.get("missing_since") for row in db.scalars(select(Resource))}

    def missing(self):
        return {id_ for id_, since in self.stored().items() if since}

    def change(self, *rows, **source):
        """Store rows Nyctr itself would hold, or set fields on the network source."""
        with self.app.state.session_factory() as db:
            db.add_all(rows)
            for key, value in source.items():
                setattr(db.get(Integration, "unifi"), key, value)
            db.commit()

    def dropped(self):
        with self.app.state.session_factory() as db:
            return [record.details for record in db.scalars(
                select(Audit).where(Audit.action == "inventory.dropped").order_by(Audit.created_at))]


@pytest.fixture
def world(tmp_path, monkeypatch):
    """Sam's assigned laptop at the network source, and one stored lookup tied to it at the DNS source."""
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        yield World(app, client, monkeypatch)


def test_what_a_whole_read_left_out_is_marked_once_kept_and_not_counted_as_present(world):
    world.read(LAPTOP, TABLET, PHONE)
    assert world.missing() == set()
    world.read(LAPTOP, days=1)
    first = world.stored()
    assert world.missing() == {TABLET, PHONE} and first[LAPTOP] is None
    world.read(LAPTOP, days=1)
    assert world.stored() == first  # The time it was first missed is not moved by later reads.
    headers = live_signin(world.client)
    overview = world.client.get("/api/overview").json()
    assert overview["kind_counts"] == {"client": 1} and overview["missing_counts"] == {"client": 2}
    assert overview["resource_count"] == 1
    # Still findable, and marked as before.
    listed = {row["id"]: row["attributes"] for row in world.client.get("/api/resources").json()}
    assert set(listed) == {LAPTOP, TABLET, PHONE} and listed[TABLET]["missing_from_latest_snapshot"] is True
    plan = world.client.get("/api/integrations/unifi/removal", headers=headers).json()
    assert plan["remove"]["devices"] == 1 and plan["missing"] == 2
    # The Map's answer leaves them out, unless one is the item asked for.
    assert {node["id"] for node in world.client.get("/api/graph").json()["nodes"]} == {LAPTOP}
    assert TABLET in {node["id"] for node in world.client.get("/api/graph", params={"focus": TABLET}).json()["nodes"]}


DOUBT = {
    "a read that kept only its most recent rows": {"partial": 1},
    "a gap that may have hidden items": {"gaps": ["unifi_no_visible_sites"]},
    "a gap this release cannot describe": {"gaps": ["a_code_nobody_declared"]},
    "a kind the adapter did not list in full": {"unread": ["client"]},
    "a failed collection": {"fail": True},
}


@pytest.mark.parametrize("doubt", DOUBT.values(), ids=DOUBT.keys())
def test_a_read_in_doubt_marks_nothing_new_and_drops_nothing(world, doubt):
    world.read(LAPTOP, TABLET, PHONE)
    world.read(LAPTOP, PHONE, days=1)
    assert world.missing() == {TABLET}
    world.read(LAPTOP, days=8, **doubt)  # The phone is not listed, and the tablet has been missing 8 days.
    assert world.missing() == {TABLET}
    assert world.drop() == 0 and TABLET in world.stored() and world.dropped() == []
    # The same read without the doubt marks the phone and lets the tablet go, so the doubt is what held both.
    world.read(LAPTOP)
    assert world.missing() == {TABLET, PHONE}
    assert world.drop() == 1 and set(world.stored()) == {LAPTOP, PHONE}


def test_a_gap_that_leaves_every_list_whole_and_a_kind_read_in_full_are_not_doubt(world):
    world.read(LAPTOP, TABLET, "unifi:policy:cameras", "unifi:network:lan")
    world.read(LAPTOP, "unifi:policy:cameras", "unifi:network:lan", gaps=["unifi_wifi_unavailable"])
    assert world.missing() == {TABLET}
    world.read("unifi:network:lan", unread=["client"])
    assert world.missing() == {TABLET, "unifi:policy:cameras"}  # The laptop's kind was not read in full.
    for provider in registry.providers().values():
        assert provider.detail_gaps <= set(provider.gap_notes), provider.id


HELD_BACK = {
    "a collection is going": {"status": "syncing"},
    "the source was edited and has not collected since": {"status": "configured"},
    "its latest collection failed and a retry is waiting": {"last_error": "Could not connect."},
    "it has never completed a collection": {"last_sync": None},
}


@pytest.mark.parametrize("state", HELD_BACK.values(), ids=HELD_BACK.keys())
def test_nothing_is_dropped_while_the_source_is_collecting_edited_failing_or_never_collected(world, state):
    world.read(LAPTOP, TABLET)
    world.read(LAPTOP, days=1)
    world.read(LAPTOP, days=8)
    with world.app.state.session_factory() as db:
        before = {key: getattr(db.get(Integration, "unifi"), key) for key in state}
    world.change(**state)
    assert world.drop() == 0 and TABLET in world.stored()
    world.change(**before)
    assert world.drop() == 1 and TABLET not in world.stored()


def test_a_source_removed_meanwhile_and_one_collected_by_an_earlier_release_lose_nothing(world):
    world.change(Resource(id="unifi:client:old", integration_id="unifi", name="old", kind="client", provider="x",
                          source_id="old", observed_at=utcnow(), evidence_kind="observed",
                          attributes={"missing_from_latest_snapshot": True,
                                      "missing_since": (world.now - timedelta(days=30)).isoformat()}))
    # No collection of this source ever recorded what it read in full: not known, so nothing goes.
    assert world.drop() == 0 and "unifi:client:old" in world.stored()
    with world.app.state.session_factory() as db:
        assert retention.drop_from(db, "a source that is gone", world.now) == 0


def test_an_item_missing_for_seven_days_goes_with_one_record_and_not_a_day_sooner(world):
    world.read(LAPTOP, TABLET, PHONE, "unifi:network:guest")
    world.read(LAPTOP, days=1)
    world.read(LAPTOP, days=6)
    assert world.drop() == 0 and len(world.stored()) == 4  # Six days missing at the latest whole read.
    world.read(LAPTOP, days=1)
    assert world.drop() == 3 and set(world.stored()) == {LAPTOP}
    assert world.dropped() == [{"name": "UniFi", "resources": 3, "kinds": {"client": 2, "network": 1},
                                "assignments": 0, "links": 0}]
    assert world.drop() == 0 and len(world.dropped()) == 1  # A run that drops nothing records nothing.


def test_a_blocked_address_goes_when_no_stored_lookup_names_it_also_after_a_read_cut_short(world):
    one, two = thing("dns", "domain", "one.example"), thing("dns", "domain", "two.example")
    world.read(one, two, source="dns", lookups=["one.example", "two.example"], partial=2, unread=["domain", "client"])
    world.read(two, source="dns", lookups=["two.example"], partial=1, unread=["domain", "client"], days=0.9)
    assert world.missing() == set()  # A read cut short marks no address.
    assert world.drop() == 0 and {one["id"], two["id"]} <= set(world.stored())
    world.now += timedelta(days=0.2)  # The first read's lookups are now past their time; the second's are not.
    assert world.drop() == 1 and one["id"] not in world.stored() and two["id"] in world.stored()
    assert world.dropped() == [{"name": "Office DNS", "resources": 1, "kinds": {"domain": 1},
                                "assignments": 0, "links": 0}]


def test_the_tick_removes_expired_lookups_every_time_and_looks_for_what_left_once_an_hour(world):
    world.read(LAPTOP, TABLET)
    world.read(LAPTOP, days=1)
    world.read(LAPTOP, days=8)
    upkeep = worker.Upkeep(world.app.state.session_factory, world.app.state.settings, clock=lambda: world.now)

    async def tick():
        upkeep.tick()
        await upkeep.stop()  # The collection pass the tick started is not part of this case.

    with world.app.state.session_factory() as db:
        assert db.get(Observation, "dns:block:one") is not None  # Seeded, and nine days past its time.
    asyncio.run(tick())
    with world.app.state.session_factory() as db:
        assert db.get(Observation, "dns:block:one") is None  # Nobody opened Blocks or the Portal.
    assert TABLET not in world.stored() and len(world.dropped()) == 1
    # Something becomes droppable right after: the next tick leaves it, the first tick an hour on takes it.
    world.change(Resource(id="unifi:client:late", integration_id="unifi", name="late", kind="client", provider="x",
                          source_id="late", observed_at=utcnow(), evidence_kind="observed",
                          attributes={"missing_from_latest_snapshot": True,
                                      "missing_since": (world.now - timedelta(days=8)).isoformat()}))
    world.now += timedelta(seconds=30)
    asyncio.run(tick())
    assert "unifi:client:late" in world.stored()
    world.now += retention.DROP_EVERY
    asyncio.run(tick())
    assert "unifi:client:late" not in world.stored() and len(world.dropped()) == 2


def guest(**grant):
    return thing("unifi", "client", "visitor", guest={"authorized": True, **grant})


def lookup(**fields):
    now = utcnow()
    return Observation(id="dns:block:held", integration_id="dns", device_name="x", domain="held.example",
                       source="nextdns", reason="x", observed_at=now, expires_at=now + timedelta(days=30),
                       evidence_kind="observed", attribution="assigned", risk_explanation="", **fields)


HOLDS = {
    "an open exception for the address": (
        thing("dns", "domain", "held.example"),
        lambda: Lease(id="held", integration_id="dns", domain="held.example", status="active"), Lease),
    "an opening not confirmed yet": (
        thing("dns", "domain", "held.example"),
        lambda: Lease(id="held", integration_id="dns", domain="held.example", status="unconfirmed"), Lease),
    "a request waiting for a decision": (
        thing("dns", "domain", "held.example"),
        lambda: AccessRequest(id="held", block_id="gone", domain="held.example", device_name="x", requester_id="sam",
                              reason="x", duration_minutes=30, integration_id="dns"), AccessRequest),
    "a stored lookup tied to the device": (
        thing("unifi", "client", "visitor"), lambda: lookup(device_id="unifi:client:visitor"), Observation),
    "a stored lookup from the label": (
        thing("dns", "client", "visitor"), lambda: lookup(source_device_id="dns:client:visitor"), Observation),
    "a guest Nyctr cut off": (
        guest(), lambda: GuestAction(id="held", device_id="unifi:client:visitor", action="cut", actor="owner",
                                     execution="applied"), GuestAction),
    "a guest Nyctr locked out": (
        guest(), lambda: GuestAction(id="held", device_id="unifi:client:visitor", action="lock", actor="rule",
                                     execution="applied"), GuestAction),
}


@pytest.mark.parametrize("item,hold,model", HOLDS.values(), ids=HOLDS.keys())
def test_an_item_nyctr_holds_something_on_is_kept_until_that_ends_then_goes(world, item, hold, model):
    source = item["id"].split(":")[0]
    rest = [LAPTOP] if source == "unifi" else []  # The seeded laptop stays listed, so only the item is in question.
    world.read(item, *rest, source=source)
    world.read(*rest, source=source, days=1)
    world.change(hold())
    world.read(*rest, source=source, days=8)
    assert world.drop() == 0 and item["id"] in world.missing()  # Kept, and still marked missing.
    with world.app.state.session_factory() as db:
        held = db.get(model, "dns:block:held" if model is Observation else "held")
        if model in (Lease, AccessRequest):
            held.status = "ended" if model is Lease else "denied"
        else:
            db.delete(held)
        db.commit()
    assert world.drop() == 1 and item["id"] not in world.stored()


def test_a_guest_whose_access_at_the_source_has_not_run_out_is_kept_until_it_has(world):
    world.read(LAPTOP, guest(expires_at=(world.now + timedelta(days=20)).isoformat()))
    world.read(LAPTOP, days=1)
    world.read(LAPTOP, days=8)
    assert world.drop() == 0 and "unifi:client:visitor" in world.stored()
    world.read(LAPTOP, days=12)
    assert world.drop() == 1 and "unifi:client:visitor" not in world.stored()


def owned(world):
    """What a person attached to the laptop: its owner, its assignment and a DNS label linked to it."""
    with world.app.state.session_factory() as db:
        row = db.get(Resource, LAPTOP)
        return (row and (row.classification, row.owner_id),
                [grant.user_id for grant in db.scalars(select(DeviceGrant).where(DeviceGrant.device_id == LAPTOP))],
                [link.source_id for link in db.scalars(select(DeviceLink).where(DeviceLink.device_id == LAPTOP))])


def test_a_device_back_within_seven_days_is_the_same_device_and_one_back_later_is_a_new_item(world):
    label = thing("dns", "client", "sams-laptop")
    world.read(label, source="dns")
    world.read(LAPTOP)
    world.change(DeviceLink(source_id=label["id"], device_id=LAPTOP, created_by="owner"))
    mine = (("personal", "sam"), ["sam"], [label["id"]])
    assert owned(world) == mine
    world.read(days=1)
    world.read(days=5)
    assert world.missing() == {LAPTOP} and world.drop() == 0
    world.read(LAPTOP, days=0.5)
    assert world.missing() == set() and owned(world) == mine  # Same identifier, nothing a person did lost.
    world.read(days=1)
    world.read(days=7)
    assert world.drop() == 1 and owned(world) == (None, [], [])
    assert world.dropped()[-1] == {"name": "UniFi", "resources": 1, "kinds": {"client": 1},
                                   "assignments": 1, "links": 1}
    world.read(LAPTOP, days=1)
    assert owned(world) == (("unassigned", None), [], [])
