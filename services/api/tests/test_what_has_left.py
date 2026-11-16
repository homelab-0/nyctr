"""What a source no longer reports is marked, not counted, and dropped after a stated time, never on doubt.

Fabricated sources on a clock the test moves. Every case asserts what was stored, marked or deleted.
"""

import asyncio
import threading
from datetime import timedelta

import pytest
from conftest import LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import event, insert, select
from test_collection_store import POSTGRES, postgres_database

from nyctr import collection, retention, schedule, worker
from nyctr.collection import collect_integration
from nyctr.integrations import IntegrationError, Snapshot, core
from nyctr.models import (
    AccessRequest,
    Audit,
    DeviceGrant,
    DeviceLink,
    GuestAction,
    Integration,
    Lease,
    Observation,
    Relationship,
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

    async def collect(self, provider, integration_id, config, api_key, since=None):
        if self.fail:
            raise IntegrationError("Could not connect.", category="transport")
        for gap in self.gaps:
            core.record_gap(gap)
        blocks = [{"id": f"dns:block:{name}:{self.now.isoformat()}", "device_id": None, "device_name": "Unattributed",
                   "domain": name, "source": provider, "reason": "Fabricated list", "evidence_kind": "observed",
                   "observed_at": self.now.isoformat(), "attribution": "unattributed", "risk_score": None,
                   "risk_explanation": ""} for name in self.lookups]
        return Snapshot(resources=self.listed, relationships=self.joins, blocks=blocks, partial_rows=self.partial,
                        unread=self.unread, log=self.log)

    def read(self, *listed, source="unifi", days=0, joins=(), **doubt):
        """Collect `source` after `days` more days. `doubt` sets gaps, fail, partial, unread or lookups for this read."""
        self.now += timedelta(days=days)
        self.listed = [thing(source, *key.split(":")[1:]) if isinstance(key, str) else key for key in listed]
        for item in self.listed:
            item["observed_at"] = self.now.isoformat()
        self.joins = list(joins)
        self.gaps, self.fail, self.partial, self.unread, self.lookups = (
            doubt.get("gaps", []), doubt.get("fail", False), doubt.get("partial"), doubt.get("unread", []),
            doubt.get("lookups", []))
        # The DNS source says what stretch of its one-day window it read: all of it, or, for a read
        # that picked up, the last ten minutes.
        start = self.now - timedelta(days=1)
        self.log = {"window_from": start.isoformat(), "read_to": self.now.isoformat(),
                    "read_from": (self.now - timedelta(minutes=10) if doubt.get("resumed") else start).isoformat(),
                    } if source == "dns" else None
        return asyncio.run(collect_integration(self.app.state.session_factory, self.app.state.settings, source, None))

    def daily(self, *listed, days, **read):
        """Collect once a day for `days` days, each read listing the same."""
        for _ in range(days):
            self.read(*listed, days=1, **read)

    def drop(self):
        retention.expire_lookups(self.app.state.session_factory, self.now)
        return retention.drop(self.app.state.session_factory, self.now)

    def stored(self):
        """Every stored item's id, with the time it was first missed, or None while it is present."""
        with self.app.state.session_factory() as db:
            return {row.id: row.attributes.get("missing_since") for row in db.scalars(select(Resource))}

    def missing(self):
        return {id_ for id_, since in self.stored().items() if since}

    def gone(self, key, days=8):
        """An unclaimed device that whole reads on seven days left out, the first of them `days` days ago."""
        return Resource(id=f"unifi:client:{key}", integration_id="unifi", name=key, kind="client", provider="x",
                        source_id=key, observed_at=utcnow(), evidence_kind="observed",
                        attributes={"missing_from_latest_snapshot": True, "missing_days": ["a day"] * 7,
                                    "missing_since": (self.now - timedelta(days=days)).isoformat()})

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


@pytest.fixture
def world_on_postgresql(tmp_path, monkeypatch, request):
    """The same world on the PostgreSQL server named in the environment; the test skips when none is named."""
    place = postgres_database(request)
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    app = live_app(tmp_path, **place)
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
def test_a_read_in_doubt_marks_nothing_counts_no_day_and_drops_nothing(world, doubt):
    world.read(LAPTOP, TABLET, PHONE)
    world.read(LAPTOP, PHONE, days=1)
    world.daily(LAPTOP, PHONE, days=6)  # Whole reads on seven days have now left the tablet out.
    assert world.missing() == {TABLET}
    world.read(LAPTOP, days=1, **doubt)  # The phone is not listed, and the tablet has been missing 7 days.
    assert world.missing() == {TABLET}
    assert world.drop() == 0 and TABLET in world.stored() and world.dropped() == []
    # The same read without the doubt marks the phone and lets the tablet go, so the doubt is what held both.
    world.read(LAPTOP)
    assert world.missing() == {TABLET, PHONE}
    assert world.drop() == 1 and set(world.stored()) == {LAPTOP, PHONE}
    # And the days in doubt were not counted towards the phone's seven.
    world.daily(LAPTOP, days=5, **doubt)
    world.read(LAPTOP, days=3)
    assert world.drop() == 0 and PHONE in world.stored()


def test_a_gap_that_leaves_every_list_whole_and_a_kind_read_in_full_are_not_doubt(world):
    world.read(LAPTOP, TABLET, "unifi:policy:cameras", "unifi:network:lan")
    world.read(LAPTOP, "unifi:policy:cameras", "unifi:network:lan", gaps=["unifi_wifi_unavailable"])
    assert world.missing() == {TABLET}
    world.read("unifi:network:lan", unread=["client"])
    assert world.missing() == {TABLET, "unifi:policy:cameras"}  # The laptop's kind was not read in full.


SEEN_TOO_LITTLE = {
    "the source could not be reached for eight days": {"fail": True},
    "nobody collected for eight days": None,
    "eight days of reads that were in doubt for devices": {"unread": ["client"]},
}


@pytest.mark.parametrize("between", SEEN_TOO_LITTLE.values(), ids=SEEN_TOO_LITTLE.keys())
def test_two_reads_a_week_apart_drop_nothing_only_whole_reads_on_seven_days_do(world, between):
    """The tablet was asleep at one read. Until it has been left out on seven days, it was not looked for enough."""
    world.now = world.now.replace(hour=12)
    world.read(LAPTOP, TABLET)
    world.read(LAPTOP, days=1)
    for _ in range(7):
        world.read(LAPTOP, days=0.001)  # However often it is read in a day, that is one day.
    if between:
        world.daily(LAPTOP, days=8, **between)
    else:
        world.now += timedelta(days=8)
    world.read(LAPTOP)  # The first whole read after the stretch: asleep again, nine days after it was first missed.
    assert world.missing() == {TABLET} and world.drop() == 0
    world.daily(LAPTOP, days=4)
    assert world.drop() == 0 and TABLET in world.stored()  # Left out on six days.
    world.read(LAPTOP, days=1)
    assert world.drop() == 1 and TABLET not in world.stored()


def test_days_with_no_stored_read_and_a_clock_that_was_wrong_do_not_count(world):
    world.read(LAPTOP, TABLET, PHONE)
    world.now -= timedelta(days=10)  # The server's clock was ten days behind when the tablet was first missed.
    world.read(LAPTOP, PHONE)
    world.now += timedelta(days=10)
    world.read(LAPTOP, PHONE)
    assert world.drop() == 0 and TABLET in world.stored()  # "Ten days" missing, left out on two.
    world.read(LAPTOP, days=1)
    world.daily(LAPTOP, days=6)  # The phone: left out on seven days, the last six days after the first.
    world.now += timedelta(days=3)  # Then collection stops. The clock goes on; nobody is looking.
    assert world.drop() == 1 and PHONE in world.stored() and TABLET not in world.stored()
    world.read(LAPTOP)
    assert world.drop() == 1 and PHONE not in world.stored()


HELD_BACK = {
    "a collection is going": {"status": "syncing"},
    "the source was edited and has not collected since": {"status": "configured"},
    "its latest collection failed and a retry is waiting": {"last_error": "Could not connect."},
    "it has never completed a collection": {"last_sync": None},
}


@pytest.mark.parametrize("state", HELD_BACK.values(), ids=HELD_BACK.keys())
def test_nothing_is_dropped_while_the_source_is_collecting_edited_failing_or_never_collected(world, state, caplog):
    world.read(LAPTOP)
    world.change(world.gone("old"))
    with world.app.state.session_factory() as db:
        before = {key: getattr(db.get(Integration, "unifi"), key) for key in state}
    world.change(**state)
    assert world.drop() == 0 and "unifi:client:old" in world.stored()
    # Left alone because of its state, not because going through it failed on the way.
    assert [record for record in caplog.records if record.name == "nyctr.retention"] == []
    world.change(**before)
    assert world.drop() == 1 and "unifi:client:old" not in world.stored()


def test_a_source_removed_meanwhile_and_one_collected_by_an_earlier_release_lose_nothing(world):
    world.change(world.gone("old", days=30))
    # No collection of this source ever recorded what it read in full: not known, so nothing goes.
    assert world.drop() == 0 and "unifi:client:old" in world.stored()
    assert retention.drop_from(world.app.state.session_factory, "a source that is gone", world.now) == (0, False)
    # A record an earlier release wrote says nothing of what was read in full: that is not "all of it".
    world.read(LAPTOP)
    with world.app.state.session_factory() as db:
        last = db.scalars(select(Audit).where(Audit.action == "integration.collected", Audit.target_id == "unifi")
                          .order_by(Audit.created_at.desc())).first()
        said, last.details = last.details, {key: value for key, value in last.details.items() if key != "unread"}
        db.commit()
    assert world.drop() == 0 and "unifi:client:old" in world.stored()
    with world.app.state.session_factory() as db:
        db.get(Audit, last.id).details = said
        db.commit()
    assert world.drop() == 1 and "unifi:client:old" not in world.stored()


def test_an_item_missing_for_seven_days_goes_with_one_record_and_not_a_day_sooner(world):
    world.read(LAPTOP, TABLET, PHONE, "unifi:network:guest")
    world.read(LAPTOP, days=1)
    world.daily(LAPTOP, days=6)
    assert world.drop() == 0 and len(world.stored()) == 4  # Left out on seven days, six days after the first.
    world.read(LAPTOP, days=1)
    assert world.drop() == 3 and set(world.stored()) == {LAPTOP}
    assert world.dropped() == [{"name": "UniFi", "resources": 3, "kinds": {"client": 2, "network": 1}}]
    assert world.drop() == 0 and len(world.dropped()) == 1  # A run that drops nothing records nothing.


def test_a_blocked_address_goes_when_no_stored_lookup_names_it_also_after_a_read_cut_short(world):
    one, two = thing("dns", "domain", "one.example"), thing("dns", "domain", "two.example")
    world.read(one, two, source="dns", lookups=["one.example", "two.example"], partial=2, unread=["domain", "client"])
    world.read(two, source="dns", lookups=["two.example"], partial=1, unread=["domain", "client"], days=0.9)
    assert world.missing() == set()  # A read cut short marks no address.
    assert world.drop() == 0 and {one["id"], two["id"]} <= set(world.stored())
    world.now += timedelta(days=0.2)  # The first read's lookups are now past their time; the second's are not.
    assert world.drop() == 1 and one["id"] not in world.stored() and two["id"] in world.stored()
    assert world.dropped() == [{"name": "Office DNS", "resources": 1, "kinds": {"domain": 1}}]


def test_a_read_that_picks_up_where_the_last_ended_marks_only_what_has_fallen_out_of_the_window(world):
    one = thing("dns", "domain", "one.example")
    world.read(one, source="dns", lookups=["one.example"])
    world.read(source="dns", days=0.5, resumed=True)  # Not read again, and still inside the window.
    assert world.missing() == set() and world.drop() == 0
    world.read(source="dns", days=1, resumed=True)  # Now older than the window, and its lookup has expired.
    assert world.missing() == {one["id"]}
    assert world.drop() == 1 and one["id"] not in world.stored()


def collected(world, source="dns"):
    with world.app.state.session_factory() as db:
        return [record.details for record in db.scalars(select(Audit).where(
            Audit.action == "integration.collected", Audit.target_id == source).order_by(Audit.created_at))]


def test_a_gap_moves_the_time_doubt_ends_and_not_the_time_the_stored_log_is_whole_from(world):
    """Two times in one record, each with its own reader: `whole_from` says the stored log has no hole and
    is what the next read that picks up stands on for "partial"; `unread_from` says nothing is in doubt."""
    world.read(source="dns", lookups=["a.example"])
    first = collected(world)[-1]
    assert first["partial"] is False and first["unread"] == []
    assert first["whole_from"] == first["unread_from"] == (world.now - timedelta(days=1)).isoformat()
    world.read(source="dns", days=0.25, resumed=True, gaps=["a_code_nobody_declared"])
    gap = collected(world)[-1]
    # No row was left unread, so the log has no hole; what the gap hid is in doubt from this read's end.
    assert gap["whole_from"] == first["whole_from"] and gap["partial"] is False
    assert gap["unread"] == ["*"] and gap["unread_from"] == world.now.isoformat()
    world.read(source="dns", days=0.25, resumed=True)
    after = collected(world)[-1]
    # The read after it stands on both: still whole from the first read's start and so not partial,
    # still in doubt from the gap. Were one key read for the other, this read would be called partial.
    assert after["whole_from"] == first["whole_from"] and after["partial"] is False
    assert after["unread"] == ["*"] and after["unread_from"] == gap["unread_from"]
    with world.app.state.session_factory() as db:
        assert db.get(Integration, "dns").status == "connected"


def test_a_read_that_picks_up_after_one_that_kept_only_part_is_in_doubt_until_the_hole_has_left_the_window(world):
    """One failed run makes the next read the whole window; on a busy source that read keeps only part.

    The reads after it pick up and are complete, but none goes back for the hole. A label whose
    newest lookup lies in the hole is still listed by the source, so nothing may count it as left out.
    """
    label, tv = thing("dns", "client", "sams-laptop"), thing("dns", "client", "kitchen-tv")
    world.read(label, tv, source="dns")
    world.read(source="dns", days=0.5, fail=True)
    # The whole window is read again and cut short: its oldest row kept is from now.
    world.read(tv, source="dns", days=0.6, lookups=["kept.example"], partial=1, unread=["client", "domain"])
    assert world.missing() == set() and collected(world)[-1]["unread_from"] == world.now.isoformat()
    hole_until = world.now
    world.read(source="dns", days=0.5, resumed=True)
    # The first label is outside the window by what Nyctr stored. The source may hold a newer lookup in the hole.
    assert world.missing() == set() and collected(world)[-1]["unread"] == ["client", "domain"]
    assert collected(world)[-1]["unread_from"] == hole_until.isoformat()
    world.read(source="dns", days=0.6, resumed=True)  # The hole is older than the window now.
    assert collected(world)[-1]["unread"] == [] and world.missing() == {label["id"], tv["id"]}
    # A collection stored before this was recorded says nothing of how far back it is whole: not known.
    with world.app.state.session_factory() as db:
        last = db.scalars(select(Audit).where(Audit.action == "integration.collected", Audit.target_id == "dns")
                          .order_by(Audit.created_at.desc())).first()
        last.details = {key: value for key, value in last.details.items() if key != "unread_from"}
        db.commit()
    world.read(source="dns", days=0.1, resumed=True)
    assert collected(world)[-1]["unread"] == ["*"]


def test_an_item_a_read_counts_as_listed_without_listing_it_again_loses_its_mark_and_its_days(world):
    label = thing("dns", "client", "sams-laptop")
    world.read(label, source="dns")
    with world.app.state.session_factory() as db:
        row = db.get(Resource, label["id"])  # Marked earlier, for whatever reason, though inside the window.
        row.attributes = {**row.attributes, "missing_from_latest_snapshot": True, "missing_days": ["a day"] * 7,
                          "missing_since": (world.now - timedelta(days=9)).isoformat(), "model": "kept"}
        db.commit()
    world.read(source="dns", days=0.5, resumed=True)
    with world.app.state.session_factory() as db:
        assert db.get(Resource, label["id"]).attributes == {"model": "kept"}
    assert world.drop() == 0 and label["id"] in world.stored()


def test_an_item_inside_the_window_whose_link_a_whole_read_deleted_is_still_present(world):
    label, profile = thing("dns", "client", "sams-laptop"), thing("dns", "dns_profile", "abc123")
    profile["evidence_kind"] = "configured"
    join = {"id": "dns:uses", "source": label["id"], "target": profile["id"], "kind": "uses_dns_profile",
            "provider": "fabricated", "evidence_kind": "observed", "observed_at": world.now.isoformat()}
    world.read(label, profile, source="dns", joins=[join])
    # A whole-window read that kept only part does not name the label, and replaces every link.
    world.read(profile, source="dns", days=0.5, partial=1, unread=["client", "domain"])
    with world.app.state.session_factory() as db:
        assert db.scalars(select(Relationship).where(Relationship.integration_id == "dns")).all() == []
    world.read(profile, source="dns", days=0.2, resumed=True)
    assert world.missing() == set() and world.drop() == 0 and label["id"] in world.stored()


def test_dropping_an_item_takes_no_lookup_request_or_record_with_it(world):
    address = thing("dns", "domain", "old.example")
    world.read(address, LAPTOP, source="dns", lookups=["old.example"])
    world.read(LAPTOP)
    world.change(world.gone("old"),
                 AccessRequest(id="asked", block_id="gone", domain="old.example", device_name="old",
                               requester_id="sam", reason="x", duration_minutes=30, integration_id="dns",
                               status="denied"),
                 Lease(id="ended", integration_id="dns", domain="old.example", status="ended"))
    world.now += timedelta(hours=1)

    def kept():
        with world.app.state.session_factory() as db:
            return (sorted(db.scalars(select(Observation.id))), sorted(db.scalars(select(AccessRequest.id))),
                    sorted(db.scalars(select(Lease.id))), sorted(db.scalars(select(Audit.id))))
    before = kept()
    assert retention.drop(world.app.state.session_factory, world.now) == 1  # The device; the address has a lookup.
    after = kept()
    assert after[:3] == before[:3] and set(before[3]) < set(after[3]) and len(after[3]) == len(before[3]) + 1
    world.now += timedelta(days=2)
    assert world.drop() == 1 and address["id"] not in world.stored()  # Its lookup's time was up, and went first.
    assert kept()[1:3] == before[1:3] and set(after[3]) < set(kept()[3])


def test_the_tick_removes_expired_lookups_every_time_and_looks_for_what_left_once_an_hour(world, monkeypatch):
    world.read(LAPTOP)
    world.change(world.gone("old"))
    world.now += timedelta(days=1)
    upkeep = worker.Upkeep(world.app.state.session_factory, world.app.state.settings, clock=lambda: world.now)

    async def nothing(*args, **kwargs):
        return False
    monkeypatch.setattr(worker, "collection_pass", nothing)  # Collecting is not part of this case.

    async def tick():
        upkeep.tick()
        await upkeep.clearing
        await upkeep.stop()

    with world.app.state.session_factory() as db:
        assert db.get(Observation, "dns:block:one") is not None  # Seeded, and past its time.
    asyncio.run(tick())
    with world.app.state.session_factory() as db:
        assert db.get(Observation, "dns:block:one") is None  # Nobody opened Blocks or the Portal.
    assert "unifi:client:old" not in world.stored() and len(world.dropped()) == 1
    # Something becomes droppable right after: the next tick leaves it, the first tick an hour on takes it.
    world.change(world.gone("late"))
    world.now += timedelta(seconds=30)
    asyncio.run(tick())
    assert "unifi:client:late" in world.stored()
    world.now += retention.DROP_EVERY
    asyncio.run(tick())
    assert "unifi:client:late" not in world.stored() and len(world.dropped()) == 2


def test_a_source_collected_at_every_hourly_tick_still_has_what_left_it_dropped_within_the_hour(world, monkeypatch):
    """The real tick every 30 seconds for two hours, the default schedule, a collection due at the first tick.

    The pass takes the DNS source first, so a look that starts at the same tick finds it being
    collected, and with one hour counted for all sources it would find that at every hour. Each
    source answers only after the clearing out of that tick has ended, as a real source is
    slower than a look at the database.
    """
    address = thing("dns", "domain", "old.example")
    world.read(address, source="dns")  # A blocked address no stored lookup names.
    world.read(LAPTOP)
    factory = world.app.state.session_factory
    upkeep = worker.Upkeep(factory, world.app.state.settings, clock=lambda: world.now)
    found, real = [], retention.drop_from

    def looked(*args):
        result = real(*args)
        found.append((args[1], result[1]))
        return result
    monkeypatch.setattr(retention, "drop_from", looked)

    async def answer(provider, integration_id, config, api_key, since=None):
        while not upkeep.clearing.done():
            await asyncio.sleep(0.005)
        if integration_id != "dns":
            return Snapshot(resources=[{**thing("unifi", "client", "laptop"), "observed_at": world.now.isoformat()}])
        start = world.now - timedelta(days=1)
        return Snapshot(resources=[{**item, "observed_at": world.now.isoformat()} for item in listed],
                        log={"window_from": start.isoformat(), "read_from": start.isoformat(),
                             "read_to": world.now.isoformat()})
    monkeypatch.setattr("nyctr.integrations.collect", answer)

    async def nothing(*args, **kwargs):
        return None
    monkeypatch.setattr(worker, "_analyse", nothing)
    with factory() as db:
        plan = schedule.in_force(db, world.app.state.settings)
        assert plan["enabled"] and plan["interval_seconds"] == 900  # So a run falls on every hourly tick.
    listed, went, late = [], {}, thing("dns", "domain", "late.example")

    async def ticks():
        for tick in range(245):
            if tick == 60:
                listed.append(late)  # The source lists an address no lookup names, once, half an hour in.
            upkeep.tick()
            await asyncio.gather(*(task for task in (upkeep.collecting, upkeep.clearing) if task))
            listed.clear()
            for id_ in (address["id"], late["id"]):
                if (tick >= 60 or id_ != late["id"]) and id_ not in world.stored():
                    went.setdefault(id_, tick)
            world.now += timedelta(seconds=30)
        await upkeep.stop()
    asyncio.run(ticks())
    # The DNS source was being collected at the first tick. It was tried again at the next and cleared
    # then, not an hour later and not never; from there its hour no longer falls on the collection's.
    looks = [(source, busy) for source, busy in found]
    assert looks[:3] == [("dns", True), ("unifi", False), ("dns", False)] and went[address["id"]] == 1
    # Each source is gone through again an hour after it last was: the network source at the ticks on
    # the hour, the DNS source one tick later, so what came half an hour in went within the hour.
    assert looks[3:] == [("unifi", False), ("dns", False)] * 2 and went[late["id"]] == 121


def address(key):
    """A blocked address at the DNS source that no stored lookup names."""
    return Resource(id=f"dns:domain:{key}", integration_id="dns", name=key, kind="domain", provider="x",
                    source_id=key, observed_at=utcnow(), evidence_kind="observed", attributes={})


def test_a_source_that_is_being_collected_whenever_its_hour_comes_is_tried_at_every_run_until_it_is_free(world):
    world.read(source="dns")
    factory, ran = world.app.state.session_factory, {}

    def dns(status):
        with factory() as db:
            db.get(Integration, "dns").status = status
            db.commit()
    for hour in range(3):
        world.change(address(f"hour{hour}.example"))
        dns("syncing")
        before = ran.get("dns")
        for _ in range(4):  # Still being collected two minutes on: looked at every time, never stamped.
            assert retention.drop(factory, world.now, ran) == 0 and ran.get("dns") == before
            world.now += timedelta(seconds=30)
        dns("connected")
        # Free at last: what turned up since its last time goes with it, and its hour runs from here.
        assert retention.drop(factory, world.now, ran) == (2 if hour else 1) and ran["dns"] == world.now
        world.change(address(f"soon{hour}.example"))
        world.now += retention.DROP_EVERY - timedelta(seconds=30)
        assert retention.drop(factory, world.now, ran) == 0
        world.now += timedelta(seconds=30)
        dns("syncing")
    assert [details["resources"] for details in world.dropped()] == [1, 2, 2]
    # A source removed meanwhile is forgotten.
    ran["a source that is gone"] = world.now
    retention.drop(factory, world.now, ran)
    assert set(ran) == {"dns", "unifi"}


def test_the_clearing_out_runs_off_the_servers_loop_a_batch_to_a_transaction_with_one_record(world, monkeypatch):
    """What runs where: every batch on a worker thread, while the loop goes on turning with a batch held open."""
    world.read(LAPTOP)
    world.change(*[world.gone(f"old{n}") for n in range(5)])
    monkeypatch.setattr(retention, "BATCH", 2)
    entered, release, ran, records = threading.Event(), threading.Event(), [], []
    batch, expire = retention._batch, retention.expire_lookups

    def held(db, integration_id, *args):
        result = batch(db, integration_id, *args)
        if integration_id == "unifi":
            ran.append((threading.get_ident(), len(result[0])))
            records.append(len(world.dropped()))  # What other sessions see before this batch is committed.
            entered.set()
            assert release.wait(30)  # Open: the source's row locked, deletions staged, nothing committed.
        return result

    def expired(*args):
        ran.append((threading.get_ident(), "lookups"))
        return expire(*args)
    monkeypatch.setattr(retention, "_batch", held)
    monkeypatch.setattr(retention, "expire_lookups", expired)
    # Between two batches of a source whatever else waits to write is let in: SQLite has one write lock.
    monkeypatch.setattr(retention.time, "sleep", lambda seconds: ran.append((threading.get_ident(), seconds)))

    async def nothing(*args, **kwargs):
        return False
    monkeypatch.setattr(worker, "collection_pass", nothing)
    upkeep = worker.Upkeep(world.app.state.session_factory, world.app.state.settings, clock=lambda: world.now)

    async def scenario():
        upkeep.tick()
        assert await asyncio.to_thread(entered.wait, 30)
        for _ in range(50):
            await asyncio.sleep(0)  # The server's loop turns freely while the batch is open.
        assert not upkeep.clearing.done()
        release.set()
        await upkeep.clearing
        await upkeep.stop()
        return threading.get_ident()
    loop = asyncio.run(scenario())
    assert [what for _thread, what in ran] == ["lookups", 2, retention.PAUSE, 2, retention.PAUSE, 1]
    assert loop not in {thread for thread, _what in ran}
    # Each batch was committed before the next began, into the one record of the run.
    assert records == [0, 1, 1]
    assert world.dropped() == [{"name": "UniFi", "resources": 5, "kinds": {"client": 5}}]
    assert set(world.stored()) == {LAPTOP}


def test_the_work_under_the_write_lock_does_not_grow_with_addresses_times_lookups(world):
    """SQLite counts the steps it takes. Ten times the addresses and lookups may cost ten times, not a hundred."""
    engine = world.app.state.session_factory.kw["bind"]
    if engine.dialect.name != "sqlite":
        pytest.skip("counts SQLite's own steps; PostgreSQL plans the same statements with its own indexes")
    steps = [0]

    def count():
        steps[0] += 1

    @event.listens_for(engine, "checkout")
    def counted(connection, _record, _proxy):
        connection.set_progress_handler(count, 100)
    world.read(source="dns")
    now, work = utcnow(), []
    for more in (300, 3000):
        with world.app.state.session_factory() as db:
            # Addresses that still have a lookup, and their lookups: none of them is to go.
            names = [f"kept{more}-{n}.example" for n in range(more)]
            db.execute(insert(Resource), [{"id": f"dns:domain:{name}", "integration_id": "dns", "name": name,
                                           "kind": "domain", "provider": "x", "source_id": name, "observed_at": now,
                                           "evidence_kind": "observed", "attributes": {}} for name in names])
            db.execute(insert(Observation), [{
                "id": f"dns:block:{name}", "integration_id": "dns", "device_name": "x", "domain": name,
                "source": "x", "reason": "x", "observed_at": now, "expires_at": now + timedelta(days=30),
                "evidence_kind": "observed", "attribution": "unattributed", "risk_explanation": ""} for name in names])
            db.add_all([address(f"left{more}-{n}.example") for n in range(20)])
            db.commit()
        steps[0] = 0
        assert world.drop() == 20
        work.append(steps[0])
    event.remove(engine, "checkout", counted)
    # 300 and then 3,300 kept addresses, each with a lookup; the same twenty to drop both times.
    assert work[1] < 20 * work[0], work


def test_an_address_looked_up_after_the_run_read_what_may_go_is_kept(world, monkeypatch):
    """What may go is read once, with no lock held. A batch that finds a collection stored since reads again."""
    world.read(source="dns")
    world.change(address("again.example"), address("quiet.example"))
    batch, calls = retention._batch, []

    def meanwhile(db, integration_id, *args):
        calls.append(integration_id)
        if calls == ["dns"]:
            world.read(source="dns", lookups=["again.example"])  # A whole collection, before the first batch.
        return batch(db, integration_id, *args)
    monkeypatch.setattr(retention, "_batch", meanwhile)
    factory, ran = world.app.state.session_factory, {}
    assert retention.drop(factory, world.now, ran) == 0 and "dns" not in ran  # Not done: tried again next time.
    assert {"dns:domain:again.example", "dns:domain:quiet.example"} <= set(world.stored())
    assert retention.drop(factory, world.now, ran) == 1 and "dns" in ran
    assert "dns:domain:again.example" in world.stored() and "dns:domain:quiet.example" not in world.stored()


def test_a_lookup_at_another_source_does_not_keep_an_address(world):
    world.read(source="dns")
    elsewhere = lookup()
    elsewhere.id, elsewhere.integration_id, elsewhere.domain = "unifi:block:same", "unifi", "same.example"
    world.change(address("same.example"), elsewhere)
    assert world.drop() == 1 and "dns:domain:same.example" not in world.stored()


def test_an_item_whose_mark_was_taken_off_after_the_run_read_what_may_go_is_kept(world, monkeypatch):
    """A batch looks again at each item's mark, not only at the days noted while it was missing."""
    world.read(LAPTOP)
    world.change(world.gone("back"))
    batch = retention._batch

    def meanwhile(db, integration_id, *args):
        if integration_id == "unifi":
            with world.app.state.session_factory() as other:
                row = other.get(Resource, "unifi:client:back")
                row.attributes = {**row.attributes, "missing_from_latest_snapshot": False}
                other.commit()
        return batch(db, integration_id, *args)
    monkeypatch.setattr(retention, "_batch", meanwhile)
    assert world.drop() == 0 and "unifi:client:back" in world.stored()


def test_a_device_being_filed_while_a_batch_reads_it_is_kept_on_postgresql(world_on_postgresql, monkeypatch):
    """The batch locks its items before it decides. Without that, a device an administrator is filing
    at that moment is judged by what it was, and deleted once the filing is saved."""
    world = world_on_postgresql
    engine = world.app.state.session_factory.kw["bind"]
    world.read(LAPTOP)
    world.change(world.gone("old"))
    with world.app.state.session_factory() as filing:
        filing.get(Resource, "unifi:client:old").classification = "personal"
        filing.flush()  # Written and not saved yet: the row is the administrator's until it is.
        dropping = threading.Thread(target=world.drop)
        dropping.start()
        with engine.connect() as watch:
            for _ in range(3000):  # Until the drop is waiting for that row, however long that takes.
                watch.rollback()  # A transaction sees the activity as it was at its first look.
                if watch.exec_driver_sql("select count(*) from pg_stat_activity where wait_event_type = 'Lock'"
                                         " and datname = current_database()").scalar():
                    break
                threading.Event().wait(0.01)
            else:
                pytest.fail("the drop never waited for the device")
        filing.commit()
    dropping.join(30)
    assert "unifi:client:old" in world.stored() and world.dropped() == []


def test_a_collection_that_starts_between_two_batches_stops_the_run_at_what_it_recorded(world, monkeypatch):
    world.read(LAPTOP)
    world.change(*[world.gone(f"old{n}") for n in range(4)])
    monkeypatch.setattr(retention, "BATCH", 2)
    batch, calls = retention._batch, []

    def between(db, integration_id, *args):
        calls.append(integration_id)
        if calls == ["unifi", "unifi"]:
            world.change(status="syncing")  # A collection took the source after the first batch was committed.
        return batch(db, integration_id, *args)
    monkeypatch.setattr(retention, "_batch", between)
    assert world.drop() == 2 and len(world.stored()) == 3
    assert world.dropped() == [{"name": "UniFi", "resources": 2, "kinds": {"client": 2}}]
    world.change(status="connected")
    assert world.drop() == 2 and set(world.stored()) == {LAPTOP} and len(world.dropped()) == 2


def test_a_collection_waits_for_the_batch_that_holds_its_source_and_stores_after_it(world, monkeypatch):
    """A drop and a store of one source never work at once: the batch locks the source's row first."""
    world.read(LAPTOP)
    world.change(world.gone("old"))
    entered, release, order = threading.Event(), threading.Event(), []
    batch, stage = retention._batch, collection.apply_snapshot

    def held(db, integration_id, *args):
        result = batch(db, integration_id, *args)
        if integration_id == "unifi":
            order.append("batch open")
            entered.set()
            assert release.wait(30)
            order.append("batch closing")
        return result

    def staged(*args):
        order.append("store")
        return stage(*args)
    monkeypatch.setattr(retention, "_batch", held)
    monkeypatch.setattr(collection, "apply_snapshot", staged)
    dropping = threading.Thread(target=world.drop)
    dropping.start()
    assert entered.wait(30)
    collecting = threading.Thread(target=world.read, args=(LAPTOP,))
    collecting.start()
    collecting.join(1)  # It cannot get the source while the batch is open, however long it is given.
    assert collecting.is_alive() and order == ["batch open"]
    release.set()
    dropping.join(30)
    collecting.join(30)
    assert order == ["batch open", "batch closing", "store"] and set(world.stored()) == {LAPTOP}
    assert len(world.dropped()) == 1 and len(collected(world, "unifi")) == 2


def test_one_source_that_fails_does_not_keep_the_others_from_being_cleared(world, monkeypatch):
    world.read(LAPTOP)
    world.change(world.gone("old"), address("left.example"))  # Something to go at each source.
    batch, calls = retention._batch, []

    def broken(db, integration_id, *args):
        calls.append(integration_id)
        if integration_id == "dns":
            raise RuntimeError("the first source cannot be cleared")
        return batch(db, integration_id, *args)
    monkeypatch.setattr(retention, "_batch", broken)
    assert world.drop() == 1 and calls == ["dns", "unifi"] and "unifi:client:old" not in world.stored()
    # A time first missed that cannot be read is not a time that has passed: the item is kept, the run goes on.
    odd = world.gone("odd")
    odd.attributes = {**odd.attributes, "missing_since": "not a time"}
    world.change(odd, world.gone("other"))
    assert world.drop() == 1 and {"unifi:client:odd", LAPTOP, "dns:domain:left.example"} == set(world.stored())


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
    "a label an administrator linked to a device": (
        thing("dns", "client", "visitor"),
        lambda: DeviceLink(source_id="dns:client:visitor", device_id=LAPTOP, created_by="owner"), DeviceLink),
    "a device an administrator linked a label to": (
        thing("unifi", "client", "visitor"),
        lambda: DeviceLink(source_id="dns:client:label", device_id="unifi:client:visitor", created_by="owner"),
        DeviceLink),
    "a device assigned to a person": (
        thing("unifi", "client", "visitor"),
        lambda: DeviceGrant(id="held", device_id="unifi:client:visitor", user_id="sam", valid_from=utcnow()),
        DeviceGrant),
}


@pytest.mark.parametrize("item,hold,model", HOLDS.values(), ids=HOLDS.keys())
def test_an_item_something_still_rests_on_is_kept_until_that_ends_then_goes(world, item, hold, model):
    source = item["id"].split(":")[0]
    rest = [LAPTOP] if source == "unifi" else []  # The seeded laptop stays listed, so only the item is in question.
    world.read(item, *rest, source=source)
    world.read(*rest, source=source, days=1)
    world.change(hold())
    world.daily(*rest, source=source, days=7)
    assert world.drop() == 0 and item["id"] in world.missing()  # Kept, and still marked missing.
    with world.app.state.session_factory() as db:
        held = db.get(model, "dns:block:held" if model is Observation
                      else hold().source_id if model is DeviceLink else "held")
        if model in (Lease, AccessRequest):
            held.status = "ended" if model is Lease else "denied"
        elif model is DeviceGrant:
            held.valid_until = utcnow()  # Unassigned: the past assignment stays on record until the item goes.
        else:
            db.delete(held)
        db.commit()
    assert world.drop() == 1 and item["id"] not in world.stored()


def test_what_was_done_to_the_guests_in_a_batch_is_read_once_not_once_a_guest(world):
    world.read(LAPTOP)
    visitors = []
    for n in range(6):
        row = world.gone(f"visitor{n}")
        row.attributes = {**row.attributes, "guest": {"authorized": False}}
        visitors.append(row)
    world.change(*visitors, GuestAction(id="cut", device_id="unifi:client:visitor0", action="cut",
                                        actor="owner", execution="applied"))
    reads = []

    @event.listens_for(world.app.state.session_factory.kw["bind"], "before_cursor_execute")
    def seen(_conn, _cursor, statement, *_rest):
        if statement.lstrip().upper().startswith("SELECT") and "FROM guest_actions" in statement:
            reads.append(statement)
    assert world.drop() == 5 and len(reads) == 1
    event.remove(world.app.state.session_factory.kw["bind"], "before_cursor_execute", seen)
    assert set(world.stored()) == {LAPTOP, "unifi:client:visitor0"}  # The one Nyctr cut off is kept.


def test_a_guest_whose_access_at_the_source_has_not_run_out_is_kept_until_it_has(world):
    world.read(LAPTOP, guest(expires_at=(world.now + timedelta(days=20)).isoformat()))
    world.read(LAPTOP, days=1)
    world.daily(LAPTOP, days=7)
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


def test_a_linked_label_with_no_blocked_lookup_for_a_week_keeps_its_link_while_the_device_never_left(world):
    """A label exists only through blocked lookups. A quiet week says nothing about the device or the link."""
    label = thing("dns", "client", "sams-laptop")
    world.read(label, source="dns", lookups=["ads.example"])
    world.read(LAPTOP)
    world.change(DeviceLink(source_id=label["id"], device_id=LAPTOP, created_by="owner"))
    mine = (("personal", "sam"), ["sam"], [label["id"]])
    for _ in range(9):  # Nothing of the laptop's is blocked. Every read is whole; the laptop is always listed.
        world.read(source="dns", days=1)
        world.read(LAPTOP)
        assert world.drop() == 0
    assert world.missing() == {label["id"]} and owned(world) == mine and world.dropped() == []
    world.read(label, source="dns", lookups=["ads.example"], days=1)  # The next blocked lookup: the same label.
    assert world.missing() == set() and owned(world) == mine


def test_a_device_someone_is_assigned_to_is_never_dropped_and_an_unclaimed_one_back_in_time_is_the_same(world):
    world.read(LAPTOP, TABLET)
    world.read(days=1)
    world.daily(days=5)
    assert world.missing() == {LAPTOP, TABLET} and world.drop() == 0
    world.read(TABLET, days=0.5)
    assert world.missing() == {LAPTOP}  # Same identifier, mark and days gone.
    world.read(days=1)
    world.daily(days=30)  # The family was away for a month.
    mine = (("personal", "sam"), ["sam"], [])
    assert world.drop() == 1 and TABLET not in world.stored() and owned(world) == mine
    headers = live_signin(world.client, LIVE_MEMBER)
    assert [row["id"] for row in world.client.get("/api/devices").json()] == [LAPTOP]  # Sam's own list is not empty.
    world.client.post("/api/auth/logout", headers=headers)
    # The administrator files it as equipment instead: still something a person said about it.
    headers = live_signin(world.client)

    def filed(classification):
        return world.client.put(f"/api/devices/{LAPTOP}/assignment", headers=headers,
                                json={"classification": classification, "user_ids": []}).status_code
    assert filed("infrastructure") == 200 and world.drop() == 0 and LAPTOP in world.missing()
    # Then takes that away too; nothing rests on the laptop any more.
    assert filed("unassigned") == 200 and world.drop() == 1 and owned(world) == (None, [], [])
    world.read(LAPTOP, days=1)
    assert owned(world) == (("unassigned", None), [], [])  # Back later: a new item nobody is assigned to.
