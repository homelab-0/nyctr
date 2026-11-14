"""An opening that fails after its add may have reached the source leaves a record, and Nyctr removes the entry.

The stand-in source accepts an add and then fails chosen calls, so the opening cannot confirm what it did.
"""

import asyncio
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select, update
from test_crossing import DOMAIN, Source, ask, claims, console, started
from test_upkeep import Sources, upkeep

from nyctr import access
from nyctr.integrations import IntegrationError
from nyctr.models import AccessRequest, Audit, Integration, Lease, Setting, utcnow

REVIEW = {"decision": "approved", "note": "Looked at it"}


class Failing(Source):
    """The fabricated allowlist, answering 500 to the calls whose order is in `fail` after acting on them."""

    def __init__(self, monkeypatch, fail=(), **more):
        super().__init__(monkeypatch, **more)
        self.fail = set(fail)

    async def answer(self, request):
        call = len(self.calls)
        answer = await super().answer(request)
        return httpx.Response(500) if call in self.fail else answer


def rows(app):
    """Every lease as (status, how it ended, owned), oldest first."""
    with app.state.session_factory() as db:
        return [(row.status, row.ended_reason, row.owned) for row in db.scalars(select(Lease).order_by(Lease.created_at))]


def trail(app):
    """What the audit record says happened to exceptions, as (action, provider outcome)."""
    with app.state.session_factory() as db:
        return [(row.action, row.details.get("execution")) for row in db.scalars(
            select(Audit).where(Audit.action.like("access.%"), Audit.action != "access.requested").order_by(Audit.created_at))]


def test_an_opening_whose_read_back_fails_is_refused_and_its_entry_is_removed_before_it_answers(tmp_path, monkeypatch):
    """Calls: asked whether it is there, the add's own read, the add (accepted), the read-back (fails), then the
    removal. The record is there before the add is sent and not before."""
    with started(tmp_path, rule=True) as (app, client, member, admin):
        source = Failing(monkeypatch, fail={3}, watch=lambda: [row[0] for row in rows(app)])

        async def scenario():
            async with console(app, member) as sam:
                return (await sam.post("/api/requests", json=ask("one"))).json()

        answer = asyncio.run(scenario())
        assert answer["status"] == "pending" and "a person decides" in answer["decision_note"]
        assert source.calls == ["GET", "GET", "POST", "GET", "GET", "DELETE", "GET"] and source.listed == []
        assert source.seen[0] == [] and source.seen[2] == ["unconfirmed"]
        assert rows(app) == [("ended", "not_confirmed", True)] and claims(app) == []
        assert trail(app) == [("access.open_unconfirmed", "failed"), ("access.closed", "applied")]


def test_what_the_first_try_could_not_remove_is_listed_never_as_access_and_settled_before_a_new_opening(
        tmp_path, monkeypatch):
    """The read-back and the removal both fail. An administrator sees it in plain words; the member sees nothing;
    the source cannot be removed; a new opening is refused until the entry is gone, and then opens its own."""
    with started(tmp_path, rule=True) as (app, client, member, admin):
        source = Failing(monkeypatch, fail=set(range(3, 99)))

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()
                listed = (await owner.get("/api/leases")).json()
                assert [(row["status"], row["execution"], row["requester_id"]) for row in listed] == [
                    ("unconfirmed", "not_applied", None)]
                assert all(part in listed[0]["last_error"] for part in (
                    f"tried to open {DOMAIN} at Home DNS", "not confirmed", "may be open there", "Nyctr removes it"))
                assert made["status"] == "pending" and (await sam.get("/api/leases")).json() == []
                assert (await owner.get("/api/suggestions")).json() == []
                refused = await owner.request("DELETE", "/api/integrations/dns", json={"name": "Home DNS"})
                assert refused.status_code == 409 and "1 open exception" in refused.json()["detail"]
                again = await owner.post(f"/api/requests/{made['id']}/review", json=REVIEW)
                assert again.status_code == 409 and "still removing an earlier attempt" in again.json()["detail"]
                assert source.listed == [DOMAIN] and "POST" not in source.calls[3:]  # Nothing new was sent.
                tries = trail(app)  # The try before the answer, then one each time the list or an opening looked.
                assert tries[0] == ("access.open_unconfirmed", "failed") and len(tries) > 2
                assert set(tries[1:]) == {("access.close_failed", None)}
                source.fail.clear()
                sent = len(source.calls)
                assert (await owner.post(f"/api/requests/{made['id']}/review", json=REVIEW)).status_code == 200
                assert source.calls[sent:] == ["GET", "DELETE", "GET", "GET", "GET", "POST", "GET"]
                return (await sam.get("/api/leases")).json()

        mine = asyncio.run(scenario())
        assert [(row["status"], row["execution"]) for row in mine] == [("active", "applied")]
        assert rows(app) == [("ended", "not_confirmed", True), ("active", None, True)]
        assert source.listed == [DOMAIN] and claims(app) == []


@pytest.mark.parametrize("landed", [True, False])
def test_a_record_left_by_a_killed_copy_is_settled_on_the_tick_once_its_claim_can_be_taken_over(tmp_path, monkeypatch,
                                                                                               landed):
    """Killed between the add and the stored exception, or before the add was sent: found and settled by the tick."""
    with started(tmp_path) as (app, *_):
        source, now = Source(monkeypatch), [utcnow()]

        async def scenario():
            Sources(monkeypatch)
            with app.state.session_factory() as db:  # As far as a copy gets before its add, then it is killed.
                await access.hold_entry(db, app.state.settings, db.get(Integration, "dns"), DOMAIN)
            source.listed.extend([DOMAIN] * landed)
            up = upkeep(app, now)
            up.tick()
            await asyncio.gather(*up.ending.values())
            assert source.calls == ["GET"] and rows(app) == [("unconfirmed", None, True)]  # Not due, claim held.
            now[0] += access.ENDING_HOLD + timedelta(seconds=5)
            with app.state.session_factory() as db:
                db.execute(update(Setting).where(Setting.key.startswith("ending:")).values(
                    updated_at=utcnow() - access.ENDING_HOLD))
                db.commit()
            up.tick()
            await up.ending["dns"]
            await up.stop()

        asyncio.run(scenario())
        assert source.calls[1:] == (["GET", "DELETE", "GET"] if landed else ["GET"]) and source.listed == []
        assert rows(app) == [("ended", "not_confirmed", True)] and claims(app) == []
        assert trail(app) == [("access.closed", "applied" if landed else "not_applied")]


def test_nyctr_never_removes_an_entry_that_was_there_before_or_that_another_exception_uses(tmp_path, monkeypatch):
    """Denial paths: the address was already allowed; the add itself says so; a real exception uses the entry."""
    with started(tmp_path, rule=True) as (app, client, member, admin):
        source = Failing(monkeypatch, fail={1})
        source.listed.append(DOMAIN)

        async def scenario():
            async with console(app, member) as sam:  # Asked first: it is there. The opening then fails.
                assert (await sam.post("/api/requests", json=ask("one"))).json()["status"] == "pending"
            assert rows(app) == [] and source.calls == ["GET", "GET"] and source.listed == [DOMAIN]
            source.listed.clear()
            with app.state.session_factory() as db:
                settings, dns = app.state.settings, db.get(Integration, "dns")
                claim = await access.hold_entry(db, settings, dns, DOMAIN)  # Not there when asked ...
                source.listed.append(DOMAIN)  # ... but the add's own read found it and added nothing.
                await access._not_confirmed(db, settings, claim, IntegrationError("later"), True, False)
                assert rows(app) == [] and claims(app) == []
                source.listed.clear()
                await access.hold_entry(db, settings, dns, DOMAIN)
                source.listed.append(DOMAIN)  # The add landed, and a real exception uses the address.
                db.execute(update(Lease).values(expires_at=utcnow()))
                db.execute(update(Setting).values(updated_at=utcnow() - access.ENDING_HOLD))
                db.add(Lease(integration_id="dns", domain=DOMAIN, execution="applied", owned=False,
                             created_at=utcnow() + timedelta(seconds=1)))
                db.commit()
                assert await access.reconcile(db, settings) == 1
            assert "DELETE" not in source.calls and source.listed == [DOMAIN]
            assert rows(app) == [("ended", "not_confirmed", True), ("active", None, True)]  # It carries the entry now.

        asyncio.run(scenario())
        assert trail(app)[-1] == ("access.closed", "not_applied")


def test_a_source_that_cannot_say_whether_the_address_was_there_gets_a_record_nyctr_never_acts_on(tmp_path,
                                                                                                 monkeypatch):
    """No read is declared: after a failed opening Nyctr removes nothing, says so, and a person ends the record."""
    class NoRead:
        removals = 0

        async def allow_domain(self, config, key, domain, *, allowed):
            raise IntegrationError("The source did not answer.")

        async def disallow_domain(self, config, key, domain, *, allowed):
            NoRead.removals += 1

    with started(tmp_path, rule=True) as (app, client, member, admin):
        Source(monkeypatch)
        monkeypatch.setattr(access, "_opener", lambda integration: NoRead())

        async def scenario():
            Sources(monkeypatch)
            async with console(app, member) as sam, console(app, admin) as owner:
                assert (await sam.post("/api/requests", json=ask("one"))).json()["status"] == "pending"
                up = upkeep(app, [utcnow() + timedelta(days=1)])
                up.tick()
                await up.stop()
                listed = (await owner.get("/api/leases")).json()
                assert [(row["status"], row["owned"], row["expires_at"]) for row in listed] == [
                    ("unconfirmed", False, None)]
                assert "cannot tell whether it put it there" in listed[0]["last_error"]
                assert (await sam.get("/api/leases")).json() == []
                assert (await owner.post(f"/api/leases/{listed[0]['id']}/end")).status_code == 200

        asyncio.run(scenario())
        assert NoRead.removals == 0 and rows(app) == [("ended", "not_confirmed", False)]
        assert trail(app) == [("access.open_unconfirmed", "failed"), ("access.closed", "not_applied")]


def test_a_refusal_before_anything_is_sent_leaves_no_record(tmp_path, monkeypatch):
    """Never collected answers 409 and a missing secret 502, as before, and neither asks the source anything."""
    with started(tmp_path) as (app, client, member, admin):
        source = Source(monkeypatch)

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()
                with app.state.session_factory() as db:
                    db.execute(update(Integration).values(last_sync=None))
                    db.commit()
                    first = await owner.post(f"/api/requests/{made['id']}/review", json=REVIEW)
                    db.execute(update(Integration).values(last_sync=utcnow()))
                    db.commit()
                monkeypatch.delenv("NYCTR_CONNECTOR_SECRET_DNS")
                second = await owner.post(f"/api/requests/{made['id']}/review", json=REVIEW)
                with app.state.session_factory() as db:
                    assert db.get(AccessRequest, made["id"]).status == "pending"
                return first.status_code, second.status_code

        assert asyncio.run(scenario()) == (409, 502)
        assert source.calls == [] and rows(app) == [] and claims(app) == []
