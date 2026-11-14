"""The list of blocked lookups is one bounded page, counted on the server for the caller alone."""

import random
import time
from collections import Counter
from datetime import timedelta

from conftest import signin
from sqlalchemy import event, insert, select, update

from nyctr import blocks as block_list
from nyctr.deps import observation_permitted
from nyctr.models import DeviceGrant, Observation, User, utcnow

REASONS = [("HaGeZi Multi PRO++", ["blocklist:hagezi-multi-pro-plusplus"]), ("Denylist", ["denylist"]),
           ("Threat Intelligence Feeds", ["threat-intelligence-feeds"]), ("Not a reason Nyctr knows", [])]


def store(app, count, device=None, name="Unknown device", start=0, step=2, tag="bulk", attribution=None):
    """Store fabricated lookups, one every `step` seconds going back from `start` seconds ago."""
    now = utcnow()
    rows = []
    for index in range(count):
        when = now - timedelta(seconds=start + index * step)
        reason, codes = REASONS[index % len(REASONS)]
        rows.append({"id": f"{tag}-{index:05d}", "integration_id": "demo-nextdns", "device_id": device,
                     "device_name": name, "domain": f"host-{index:05d}.{tag}.example", "source": "nextdns",
                     "reason": reason, "reason_codes": codes, "observed_at": when,
                     "expires_at": when + timedelta(hours=24), "evidence_kind": "observed",
                     "attribution": attribution or ("assigned" if device else "unattributed"),
                     "risk_score": None, "risk_explanation": "Fabricated."})
    # Stored out of order, so nothing a test sees can rest on the order rows were written in.
    random.Random(count).shuffle(rows)
    with app.state.session_factory() as db:
        db.execute(insert(Observation), rows)
        db.commit()


def every_page(client, query=""):
    """Follow `next` to the end and return every row, asserting each page keeps to the bound."""
    asked = dict(part.split("=") for part in query.split("&") if part)
    rows, body = [], client.get("/api/blocks", params=asked).json()
    while True:
        assert len(body["rows"]) <= body["page_size"] == block_list.PAGE
        rows += body["rows"]
        if not body["next"]:
            return rows
        body = client.get("/api/blocks", params={**asked, "before": body["next"]}).json()


def test_page_is_bounded_newest_first_and_older_pages_hold_while_lookups_arrive(client, app, admin_headers):
    """An older page continues from the last row shown: nothing is skipped or repeated when lookups arrive."""
    store(app, 450, step=0)  # One shared time, so the order rests on the identifier as well.
    first = client.get("/api/blocks").json()
    assert len(first["rows"]) == block_list.PAGE and first["total"] == first["matching"] == 450 + 15
    keys = [(row["observed_at"], row["id"]) for row in first["rows"]]
    assert keys == sorted(keys, reverse=True)
    with app.state.session_factory() as db:
        before = set(db.scalars(select(Observation.id)))
    store(app, 30, start=-2, step=0, tag="newer")  # Arrives after the first page was read, and is newer than all of it.
    store(app, 30, start=3600, tag="late")  # Arrives late but happened long ago.
    rest, body = [], first
    while body["next"]:
        body = client.get("/api/blocks", params={"before": body["next"]}).json()
        rest += body["rows"]
    seen = [row["id"] for row in first["rows"] + rest]
    assert len(seen) == len(set(seen))
    assert before <= set(seen) and {f"late-{i:05d}" for i in range(30)} <= set(seen)
    assert not any(id_.startswith("newer-") for id_ in seen)
    assert client.get("/api/blocks").json()["rows"][0]["id"].startswith("newer-")
    assert client.get("/api/blocks", params={"before": "not a place"}).status_code == 422
    # Times at the ends of the calendar cannot be moved to UTC; they are refused, not an error.
    for crafted in ("9999-12-31T23:59:59-23:59~x", "0001-01-01T00:00:00+23:59~x", "2026-01-01T00:00:00+00:00~a\x00b"):
        refused = client.get("/api/blocks", params={"before": crafted})
        assert (refused.status_code, refused.json()["detail"]) == (
            422, "That place in the list is not valid. Load the list again."), crafted
    assert client.get("/api/blocks", params={"band": "severe"}).status_code == 422


def test_counts_cover_everything_stored_and_filters_are_applied_by_the_server(client, app, admin_headers):
    """Totals and filter counts describe every stored lookup, whatever page or filter is asked for."""
    store(app, 500)
    store(app, 120, device="workstation", name="Alex's workstation", tag="named")
    everything = every_page(client)
    body = client.get("/api/blocks").json()
    assert body["total"] == len(everything) == 635
    assert body["counts"]["band"] == {band: Counter(row["risk_band"] for row in everything)[band]
                                      for band in block_list.BANDS}
    unnamed = [row for row in everything if row["attribution"] == "unattributed"]
    assert (body["counts"]["named"], body["counts"]["unnamed"]) == (635 - len(unnamed), len(unnamed))
    assert body["counts"]["source"] == {"nextdns": {"total": 634, "unnamed": 501}, "pihole": {"total": 1, "unnamed": 0}}
    assert body["oldest_at"] == min(row["observed_at"] for row in everything)
    assert body["newest_at"] == max(row["observed_at"] for row in everything)
    high = client.get("/api/blocks", params={"band": "high"}).json()
    assert high["matching"] == body["counts"]["band"]["high"] > block_list.PAGE
    assert {row["risk_band"] for row in every_page(client, "band=high")} == {"high"}
    assert len(every_page(client, "band=high")) == high["matching"]
    # The counts and the total are still about everything, not about the filter or the page.
    assert (high["total"], high["counts"]) == (body["total"], body["counts"])
    found = client.get("/api/blocks", params={"q": " Alex's WORK ", "band": "unknown"}).json()
    assert found["matching"] == 30 and found["next"] is None and found["counts"] == body["counts"]
    assert {row["device_name"] for row in found["rows"]} == {"Alex's workstation"}
    assert client.get("/api/blocks", params={"q": "host-00007.bulk"}).json()["matching"] == 1
    assert client.get("/api/blocks", params={"q": "nothing like this"}).json()["rows"] == []


def test_member_page_counts_and_boundaries_come_only_from_lookups_they_may_see(client, app):
    """A member's bound, totals and counts are worked out after their rights, so they reveal nothing else."""
    signin(client, member=True)
    mine = client.get("/api/blocks").json()
    assert mine["total"] == 6 and mine["counts"]["unnamed"] == 0
    store(app, 300, tag="unnamed")
    store(app, 300, device="workstation", name="Alex's workstation", tag="other")
    store(app, 40, device="guest-pixel", name="Pixel 8", tag="guest", attribution="inferred")
    store(app, 40, device="laptop-jamie", name="Jamie's MacBook", tag="unsure", attribution="unverified")
    # On the member's own device, but from before any grant of theirs covered it.
    store(app, 40, device="laptop-jamie", name="Jamie's MacBook", start=40 * 86400, tag="early")
    with app.state.session_factory() as db:
        db.execute(update(Observation).where(Observation.id.like("early-%"))
                   .values(expires_at=utcnow() + timedelta(hours=1)))
        db.commit()
    assert client.get("/api/blocks").json() == mine
    for query in ("band=high", "q=workstation", "q=host-0", "band=unknown&q=example"):
        assert {row["id"] for row in every_page(client, query)} <= {row["id"] for row in mine["rows"]}
    assert client.get("/api/blocks", params={"q": "workstation"}).json()["matching"] == 0
    store(app, 250, device="laptop-jamie", name="Jamie's MacBook", tag="mine")
    body = client.get("/api/blocks").json()
    assert body["total"] == body["matching"] == 256 and len(body["rows"]) == block_list.PAGE
    assert sum(body["counts"]["band"].values()) == 256 == body["counts"]["named"]
    assert body["counts"]["source"] == {"nextdns": {"total": 255, "unnamed": 0}, "pihole": {"total": 1, "unnamed": 0}}
    older = client.get("/api/blocks", params={"before": body["next"]}).json()
    assert len(older["rows"]) == 56 and older["next"] is None
    assert {row["device_id"] for row in body["rows"] + older["rows"]} == {"laptop-jamie", "tablet-family"}
    # A place in the list taken from an administrator's page gives a member nothing more.
    signin(client)
    place = client.get("/api/blocks").json()["next"]
    signin(client, member=True)
    assert {row["device_id"] for row in client.get("/api/blocks", params={"before": place}).json()["rows"]} <= {
        "laptop-jamie", "tablet-family"}


def test_member_with_no_device_and_nobody_signed_in_learn_nothing(client, app):
    """Without a device there is no row, total or count; without a session there is no answer."""
    store(app, 300)
    for query in ("", "?band=high", "?q=example", "?before=2030-01-01T00:00:00%2B00:00~x"):
        assert client.get("/api/blocks" + query).status_code == 401
    with app.state.session_factory() as db:
        db.execute(update(DeviceGrant).where(DeviceGrant.user_id == "user-jamie").values(valid_until=utcnow()))
        db.commit()
    signin(client, member=True)
    assert client.get("/api/devices").json() == []
    for query in ("", "?band=high", "?q=example"):
        body = client.get("/api/blocks" + query).json()
        assert (body["rows"], body["total"], body["matching"], body["next"]) == ([], 0, 0, None)
        assert (body["oldest_at"], body["newest_at"]) == (None, None)
        assert body["counts"] == {"band": dict.fromkeys(block_list.BANDS, 0), "source": {}, "named": 0, "unnamed": 0}


def test_rights_applied_before_paging_match_the_check_made_on_one_lookup(client, app):
    """The conditions that bound the list admit exactly the lookups `observation_permitted` admits."""
    store(app, 20, device="laptop-jamie", name="Jamie's MacBook", start=40 * 86400, tag="early")
    store(app, 20, device="old-laptop", name="Reassigned laptop", tag="reassigned")
    store(app, 20, device="tablet-family", name="Family tablet", tag="shared")
    store(app, 20, device="washer", name="Laundry appliance", tag="thing")
    store(app, 20)
    with app.state.session_factory() as db:
        db.execute(update(Observation).values(expires_at=utcnow() + timedelta(hours=1)))
        for user in db.scalars(select(User)):
            listed = set(db.scalars(select(Observation.id).where(*block_list.visible(db, user))))
            allowed = {row.id for row in db.scalars(select(Observation)) if observation_permitted(db, row, user)}
            assert listed == allowed and listed, user.email
        member = db.get(User, "user-jamie")
        assert 0 < len(set(db.scalars(select(Observation.id).where(*block_list.visible(db, member))))) < 117


def test_member_opens_a_lookup_from_an_older_page_by_its_address_and_nothing_they_may_not_see(client, app):
    """A lookup beyond the first page is found by address and opened; hidden, expired and missing are one refusal."""
    headers = signin(client, member=True)
    store(app, 250, device="laptop-jamie", name="Jamie's MacBook", tag="mine")
    store(app, 5, device="workstation", name="Alex's workstation", tag="other")
    listed = {row["id"] for row in client.get("/api/blocks").json()["rows"]}
    assert len(listed) == block_list.PAGE and "mine-00240" not in listed
    found = client.post("/api/blocks/find", headers=headers, json={"domain": "host-00240.mine.example"}).json()
    assert [row["id"] for row in found] == ["mine-00240"]
    opened = client.get("/api/blocks/one", params={"id": "mine-00240"})
    assert opened.status_code == 200 and opened.json() == found[0]
    asked = client.post("/api/requests", headers=headers,
                        json={"block_id": "mine-00240", "reason": "Needed for work", "duration_minutes": 30})
    assert asked.status_code == 201 and asked.json()["domain"] == "host-00240.mine.example"
    # Another person's, one with no device, one of their own that has just expired, and one that never existed.
    with app.state.session_factory() as db:
        db.execute(update(Observation).where(Observation.id == "mine-00241").values(expires_at=utcnow()))
        db.commit()
    refusals = [client.get("/api/blocks/one", params={"id": id_})
                for id_ in ("other-00001", "block-admin", "block-unattributed", "mine-00241", "never-stored", "a\x00b")]
    assert {(r.status_code, r.text) for r in refusals} == {(404, '{"detail":"Block event not found"}')}
    assert client.post("/api/blocks/find", headers=headers, json={"domain": "host-00001.other.example"}).json() == []
    signin(client)
    assert client.get("/api/blocks/one", params={"id": "other-00001"}).json()["device_name"] == "Alex's workstation"
    assert client.get("/api/blocks/one", params={"id": "mine-00241"}).status_code == 404
    client.cookies.clear()
    assert client.get("/api/blocks/one", params={"id": "mine-00240"}).status_code == 401


def test_an_expired_lookup_is_neither_listed_nor_counted_before_it_is_removed(client, app):
    """The list itself leaves out what has expired; it does not rest on the route removing it first."""
    with app.state.session_factory() as db:
        assert db.get(Observation, "block-expired") is not None
        for user_id, expected in (("user-admin", 15), ("user-jamie", 6)):
            body = block_list.page(db, db.get(User, user_id))
            assert body["total"] == body["matching"] == sum(body["counts"]["band"].values()) == expected
            assert "block-expired" not in {row["id"] for row in body["rows"]}
            assert body["oldest_at"] > utcnow() - timedelta(hours=24)


def test_first_page_of_twenty_thousand_does_one_page_of_work_and_other_readers_see_them_all(client, app, admin_headers):
    """With 20,000 lookups stored, only one page of them is read in full and sent; the Briefing still counts all.

    What is held here does not depend on how busy the machine is: how many stored lookups are
    loaded whole, how many statements run, and the size of the answer. The measured times are
    stated in the pull request; the one time held here is a wide guard, explained where it is.
    """
    store(app, 20_000, step=4)
    whole, statements = [], []
    engine = app.state.session_factory.kw["bind"]

    def loaded(row, _context):
        whole.append(row.id)

    def ran(_connection, _cursor, statement, *_rest):
        statements.append(statement)

    event.listen(Observation, "load", loaded)
    event.listen(engine, "before_cursor_execute", ran)
    try:
        started = time.perf_counter()
        response = client.get("/api/blocks")
        took = time.perf_counter() - started
    finally:
        event.remove(Observation, "load", loaded)
        event.remove(engine, "before_cursor_execute", ran)
    body = response.json()
    print(f"\n20,000 stored: first page in {took * 1000:.0f} ms, {len(response.content) / 1024:.1f} KB, "
          f"{len(whole)} lookups loaded whole, {len(statements)} statements, {len(body['rows'])} rows of {body['total']}")
    # One page of lookups is loaded whole, however many are stored, and nothing is asked per lookup.
    assert len(whole) == len(body["rows"]) == block_list.PAGE and len(statements) < 20
    assert len(response.content) < 300_000
    assert body["total"] == 20_015 and sum(body["counts"]["band"].values()) == 20_015
    # A guard, not the measurement: several times the slowest reading seen on an overloaded machine
    # (1.1 s), so it fails only if a query or a full load per stored lookup comes back.
    assert took < 8.0
    assert client.get("/api/overview").json()["recent_block_count"] == 20_015
