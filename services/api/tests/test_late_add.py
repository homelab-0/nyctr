"""An add the source applies after Nyctr stopped waiting for it is still Nyctr's to remove.

The stand-in source takes the add, does not answer in time, and applies it only when the test says so.
"""

import asyncio
import json
from datetime import datetime, timedelta

import httpx
import pytest
from sqlalchemy import select, update
from test_approval import review, words
from test_crossing import DOMAIN, Source, ask, claims, console, started
from test_unconfirmed import rows
from test_upkeep import Sources, upkeep

from nyctr import access
from nyctr.models import Audit, Lease, utcnow


class Late(Source):
    """The first add is taken and not answered; `land` applies it, as a source does that was only slow."""

    def __init__(self, monkeypatch, **more):
        super().__init__(monkeypatch, **more)
        self.late, self.taken, self.land_at = 1, [], None

    async def answer(self, request):
        if len(self.calls) == self.land_at:
            self.land()
        if request.method == "POST" and self.late:
            self.late -= 1
            self.calls.append("POST")
            self.seen.append(self.watch())
            self.taken.append(json.loads(request.content)["id"])
            raise httpx.ReadTimeout("fabricated: no answer in time", request=request)
        return await super().answer(request)

    def land(self):
        self.listed.extend(name for name in self.taken if name not in self.listed)
        self.taken.clear()


async def open_by(path, app, sam, owner):
    """One opening by each way an exception is opened; returns the request, if there is one, and the answer."""
    if path == "suggestion":
        with app.state.session_factory() as db:  # The rule opened it before, so it is suggested.
            db.add(Lease(integration_id="dns", domain=DOMAIN, decided_by="rule", status="ended"))
            db.commit()
        return None, await owner.post("/api/suggestions", json={"domain": DOMAIN, "action": "make_permanent"})
    made = await sam.post("/api/requests", json=ask("one"))
    return made.json(), made if path == "access rule" else await review(owner, made.json()["id"])


async def ticked(app, now=None):
    """One tick of a copy just started, and its endings."""
    up = upkeep(app, [now or utcnow() + timedelta(seconds=1)])
    up.tick()
    await asyncio.gather(*up.ending.values())
    await up.stop()


def older(app, by):
    """The attempts on record were made that long ago."""
    with app.state.session_factory() as db:
        db.execute(update(Lease).where(Lease.status == "unconfirmed").values(created_at=utcnow() - by))
        db.commit()


@pytest.mark.parametrize("path", ["approval", "access rule", "suggestion"])
def test_an_add_applied_after_nyctr_gave_up_is_found_on_a_later_tick_and_removed(tmp_path, monkeypatch, path):
    """The opening fails and nothing is at the source: the record is not settled on that one read. It is listed
    with until when Nyctr goes on checking, the person who asked is told nothing was opened and sees no row. The
    source then applies the add; a copy started in between finds it on its tick, removes it and says so."""
    with started(tmp_path, rule=path == "access rule") as (app, _client, member, admin):
        source = Late(monkeypatch)

        async def scenario():
            Sources(monkeypatch)
            async with console(app, member) as sam, console(app, admin) as owner:
                made, answer = await open_by(path, app, sam, owner)
                assert answer.status_code == (201 if path == "access rule" else 502)
                assert source.calls == ["GET", "GET", "POST", "GET"] and rows(app)[-1] == ("unconfirmed", None, True)
                if made:
                    mine = (await sam.get("/api/requests")).json()[0]
                    assert mine["status"] == "pending" and mine["decision_note"] in (
                        access.NOT_OPENED, "Nyctr could not change Office DNS just now, so a person decides.")
                assert (await sam.get("/api/leases")).json() == []
                row = next(row for row in (await owner.get("/api/leases")).json() if row["status"] == "unconfirmed")
                until = utcnow() + access.STILL_CHECKING
                assert abs((datetime.fromisoformat(row["checking_until"]) - until).total_seconds()) < 30
                assert all(part in row["last_error"] for part in (
                    "may be open there", "Nyctr removes it", "five minutes", "do not add it there by hand"))
                refused = await owner.post(f"/api/leases/{row['id']}/end")
                assert refused.status_code == 409 and "still checking" in refused.json()["detail"]
                looks = len(source.calls)
                await ticked(app)  # Each look since (the lists, the refused ending, this tick) only read.
                assert len(source.calls) == looks + 1 and set(source.calls[4:]) == {"GET"}
                assert rows(app)[-1] == ("unconfirmed", None, True)
                source.land()  # Five seconds after Nyctr gave up, say.
                await ticked(app)
                assert source.calls[looks + 1:] == ["GET", "DELETE", "GET"] and source.listed == []
                return row["id"]

        record = asyncio.run(scenario())
        with app.state.session_factory() as db:
            closed = db.scalars(select(Audit).where(Audit.action == "access.closed", Audit.target_id == record)).one()
            assert closed.details["removal"] == "removed" and closed.details["looked"] >= 0
            assert db.get(Lease, record).status == "ended" and claims(app) == []


@pytest.mark.parametrize("second", ["before the add lands", "after the add lands", "and is ended before the add lands",
                                    "as the add lands, between its two reads"])
def test_a_second_opening_while_the_first_is_still_checked_takes_the_entry_as_nyctrs_own(tmp_path, monkeypatch,
                                                                                         second):
    """Approve, fail at the limit, approve again, end: nothing is left at the source, whether the first add lands
    before the second approval, after it, or after the second exception has already been ended. The second
    exception is never recorded as resting on an entry that was there before."""
    with started(tmp_path) as (app, _client, member, admin):
        source = Late(monkeypatch)

        async def scenario():
            Sources(monkeypatch)
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                assert (await review(owner, made)).status_code == 502
                if second == "after the add lands":
                    source.land()
                elif second == "as the add lands, between its two reads":
                    # Its look for the earlier attempt finds nothing; its own question finds the entry there.
                    source.land_at = len(source.calls) + 1
                assert (await review(owner, made)).status_code == 200
                with app.state.session_factory() as db:  # As stored, before any later look could correct it.
                    stored = db.scalars(select(Lease).where(Lease.status == "active")).one()
                    assert stored.owned is True and stored.execution == "applied"
                lease = next(row for row in (await owner.get("/api/leases")).json() if row["status"] == "active")
                if second == "before the add lands":
                    source.land()  # The source already holds the entry the second opening added: nothing changes.
                    await ticked(app)
                assert source.listed == [DOMAIN]
                assert (await owner.post(f"/api/leases/{lease['id']}/end")).status_code == 200
                assert source.listed == []
                if second == "and is ended before the add lands":
                    source.land()
                    assert source.listed == [DOMAIN]
                await ticked(app)  # Still within the time: the first attempt's record is read again.
                assert source.listed == []
                older(app, access.STILL_CHECKING)
                await ticked(app)

        asyncio.run(scenario())
        assert source.listed == [] and claims(app) == []
        assert sorted(row[0] for row in rows(app)) == ["ended", "ended"] and "not_owned" not in words(app)


def test_when_the_time_is_up_the_record_is_settled_and_says_how_long_nyctr_looked(tmp_path, monkeypatch):
    """Nothing appears for five minutes: one last read, the record ends with "nothing removed" and the time. An
    add the source applies later than that is the stated limit: nothing on record removes it."""
    with started(tmp_path) as (app, _client, member, admin):
        source = Late(monkeypatch)

        async def scenario():
            Sources(monkeypatch)
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                assert (await review(owner, made)).status_code == 502
                older(app, access.STILL_CHECKING - timedelta(seconds=20))
                await ticked(app)
                assert rows(app) == [("unconfirmed", None, True)]  # Twenty seconds to go.
                older(app, access.STILL_CHECKING)
                await ticked(app)
                listed = (await owner.get("/api/leases")).json()
                assert [(row["status"], row["removal"], row["checking_until"]) for row in listed] == [
                    ("ended", "nothing_removed", None)]

        asyncio.run(scenario())
        with app.state.session_factory() as db:
            closed = db.scalars(select(Audit).where(Audit.action == "access.closed")).one()
            assert closed.details["removal"] == "nothing_removed" and closed.details["looked"] >= 300
        assert source.calls.count("DELETE") == 0 and claims(app) == []
        source.land()
        asyncio.run(ticked(app))
        assert source.listed == [DOMAIN]  # The known limit: applied more than five minutes late.


def test_an_openings_own_record_never_makes_a_persons_entry_nyctrs_own(tmp_path, monkeypatch):
    """No earlier attempt. A person adds the address by hand between Nyctr's first read and its add's own read, so
    the add finds it there and sends nothing. The opening's own record is on record for the address at that
    moment; it must not count as an earlier attempt of Nyctr's. The exception is stored as not Nyctr's, and when it
    ends nothing is sent and the person's entry is still there."""
    with started(tmp_path) as (app, _client, member, admin):
        source = Source(monkeypatch)
        real = source.answer

        async def answer(request):
            if len(source.calls) == 1:
                source.listed.append(DOMAIN)  # By hand, between the two reads.
            return await real(request)
        source.answer = answer

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                assert (await review(owner, made)).status_code == 200 and source.calls == ["GET", "GET"]
                with app.state.session_factory() as db:  # As stored, before any later look.
                    stored = db.scalars(select(Lease)).one()
                    assert (stored.status, stored.execution, stored.owned) == ("active", "applied", False)
                assert (await owner.post(f"/api/leases/{stored.id}/end")).status_code == 200

        asyncio.run(scenario())
        assert source.calls == ["GET", "GET"] and source.listed == [DOMAIN] and words(app) == ["not_owned"]
        assert claims(app) == []
