"""Opening and ending one address at one source go one at a time, and no change at a source can hang.

The stand-in source holds one chosen call until the test lets it go, or answers a byte at a time for ever.
"""

import asyncio
import contextlib
import json
from datetime import timedelta

import httpx
import pytest
from conftest import LIVE_ADMIN, LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from test_access import put_rule
from test_upkeep import Sources, closings, opened, stored, upkeep

from nyctr import access
from nyctr.integrations import IntegrationError, actions, core
from nyctr.models import AccessRequest, Audit, Integration, Lease, Observation, Setting, utcnow

DOMAIN = "click.proofing-studio.example"
GATEWAY = {"base_url": "https://unifi.example/proxy/network/integration"}


class Trickle(httpx.AsyncByteStream):
    """An answer that starts and never ends."""

    async def __aiter__(self):
        yield b"{"
        await asyncio.sleep(3600)


class Source:
    """A fabricated DNS allowlist. `hold` names one call by its order and whether it waits before it acts or
    after (its answer not yet given). A call whose path ends in a name in `stuck` trickles for ever."""

    def __init__(self, monkeypatch, hold=None, stuck=(), watch=lambda: None):
        self.listed, self.calls, self.seen, self.hold, self.stuck, self.watch = [], [], [], hold, set(stuck), watch
        self.reached, self.go = asyncio.Event(), asyncio.Event()
        monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "dns-secret")
        monkeypatch.setattr(core, "make_http_client", lambda key, **_: httpx.AsyncClient(
            transport=httpx.MockTransport(self.answer), headers={"X-Api-Key": key}, trust_env=False))

    async def wait(self, moment):
        if self.hold == moment:
            self.reached.set()
            await self.go.wait()

    async def answer(self, request):
        call, name = len(self.calls), request.url.path.rsplit("/", 1)[1]
        self.calls.append(request.method)
        self.seen.append(self.watch())
        if name in self.stuck:
            return httpx.Response(200, stream=Trickle())
        await self.wait((call, "before"))
        if request.method == "POST":
            self.listed.append(json.loads(request.content)["id"])
        elif request.method == "DELETE" and name in self.listed:
            self.listed.remove(name)
        answer = httpx.Response(200, json={"data": [{"id": name, "active": True} for name in self.listed]})
        await self.wait((call, "after"))
        return answer


def claims(app):
    """The mark of every claim on a source entry that is held right now."""
    with app.state.session_factory() as db:
        return list(db.scalars(select(Setting.updated_by).where(Setting.key.startswith("ending:"))))


@contextlib.contextmanager
def started(tmp_path, rule=False):
    """A live copy with two fresh blocks of one address; yields it with the member's and the administrator's
    cookies and header. The plain client is left signed in as the administrator."""
    app = live_app(tmp_path, provider_writes="nextdns")
    with TestClient(app) as client:
        seed_live_member(app)
        with app.state.session_factory() as db:
            one = db.get(Observation, "dns:block:one")
            db.add(Observation(id="dns:block:two", **{name: getattr(one, name) for name in (
                "integration_id", "device_id", "device_name", "domain", "source", "reason", "reason_codes",
                "observed_at", "expires_at", "evidence_kind", "attribution", "risk_explanation")}))
            db.commit()
        people = []
        for who in (LIVE_MEMBER, LIVE_ADMIN):
            client.cookies.clear()  # Signing in over a session ends it; each person keeps their own.
            people.append({"headers": live_signin(client, who), "cookies": dict(client.cookies)})
        if rule:
            put_rule(client, people[1]["headers"])
        yield app, client, *people


def console(app, person):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver", **person)


def ask(block):
    return {"block_id": f"dns:block:{block}", "reason": "Need the gallery", "duration_minutes": 60}


def test_two_openings_of_one_address_at_once_share_one_entry_that_goes_with_the_last(tmp_path, monkeypatch):
    """The first has added the entry and not read it back when the second arrives: the second waits, then shares."""
    source = Source(monkeypatch, hold=(2, "after"))

    async def scenario(app, member, admin):
        async with console(app, member) as sam, console(app, admin) as owner:
            first = asyncio.create_task(sam.post("/api/requests", json=ask("one")))
            await asyncio.wait_for(source.reached.wait(), 5)
            second = asyncio.create_task(sam.post("/api/requests", json=ask("two")))
            await asyncio.sleep(0.6)
            assert source.calls == ["GET", "GET", "POST"]  # The second is waiting and has sent nothing.
            source.go.set()
            assert [(await task).json()["status"] for task in (first, second)] == ["auto_approved"] * 2
            assert source.listed == [DOMAIN] and source.calls == ["GET", "GET", "POST", "GET", "GET", "GET"]
            leases = (await owner.get("/api/leases")).json()
            assert [(row["execution"], row["owned"]) for row in leases] == [("applied", True)] * 2
            for lease, left in zip(leases, ([DOMAIN], []), strict=True):
                assert (await owner.post(f"/api/leases/{lease['id']}/end")).status_code == 200
                assert source.listed == left  # The entry stays for the other exception and goes with the last.
        assert claims(app) == []

    with started(tmp_path, rule=True) as (app, _client, member, admin):
        asyncio.run(scenario(app, member, admin))


@pytest.mark.parametrize("first", ["removal", "opening"])
def test_an_opening_and_a_removal_of_one_address_cannot_cross(tmp_path, monkeypatch, first):
    """Whichever is in flight first, the other sends nothing until it is done, and the open exception has its entry."""
    source = Source(monkeypatch, hold=(1, "before") if first == "removal" else (0, "after"))
    now = [utcnow()]

    async def scenario(app, member):
        Sources(monkeypatch)
        old, up = opened(app, source.listed, DOMAIN, now[0] - timedelta(seconds=1)), upkeep(app, now)
        async with console(app, member) as sam:
            if first == "removal":  # The removal has read the list and is about to delete.
                up.tick()
                await asyncio.wait_for(source.reached.wait(), 5)
                asking = asyncio.create_task(sam.post("/api/requests", json=ask("one")))
                await asyncio.sleep(0.6)
                assert source.calls == ["GET", "DELETE"]  # The opening waits, having sent nothing.
                source.go.set()
                await up.ending["dns"]
                assert (await asking).json()["status"] == "auto_approved"
                assert source.calls == ["GET", "DELETE", "GET", "GET", "GET", "POST", "GET"]  # Added its own.
            else:  # The opening has read the list and has not stored its exception yet.
                asking = asyncio.create_task(sam.post("/api/requests", json=ask("one")))
                await asyncio.wait_for(source.reached.wait(), 5)
                up.tick()
                await up.ending["dns"]
                assert source.calls == ["GET"] and stored(app, Lease, old) == "active"  # Refused; tried next tick.
                source.go.set()
                assert (await asking).json()["status"] == "auto_approved"
                up.tick()
                await up.ending["dns"]
                assert source.calls == ["GET", "GET"]  # The entry is now the new exception's too, so it stays.
        await up.stop()
        with app.state.session_factory() as db:
            assert [(row.id == old, row.execution, row.owned) for row in db.scalars(select(Lease).where(
                Lease.status == "active"))] == [(False, "applied", True)]
        assert stored(app, Lease, old) == "ended" and source.listed == [DOMAIN] and claims(app) == []

    with started(tmp_path, rule=True) as (app, _client, member, _admin):
        asyncio.run(scenario(app, member))


def test_an_approval_takes_the_claim_first_and_gives_it_back_on_every_way_out(tmp_path, monkeypatch):
    """Already reviewed, refused while the address is being changed, never collected, a failed opening: each leaves
    the request waiting, nothing stored and no claim. A denial takes none. An approval holds it for its call."""
    monkeypatch.setattr(actions, "CHANGE_SECONDS", 0.3)

    async def scenario(app, member, admin):
        source, factory = Source(monkeypatch, watch=lambda: len(claims(app))), app.state.session_factory
        async with console(app, member) as sam, console(app, admin) as owner:
            one, two = [(await sam.post("/api/requests", json=ask(block))).json()["id"] for block in ("one", "two")]

            async def review(request, decision="approved"):
                answer = await asyncio.wait_for(owner.post(
                    f"/api/requests/{request}/review", json={"decision": decision, "note": "Looked at it"}), 20)
                with factory() as db:
                    return answer.status_code, db.get(AccessRequest, request).status, answer.json().get("detail", "")

            with factory() as db:
                held = access._claim_entry(db, Lease(integration_id="dns", domain=DOMAIN))  # Being changed.
                waiting = asyncio.create_task(review(two))
                await asyncio.sleep(0.4)
                assert (await review(two, "denied"))[:2] == (200, "denied")  # Opens nothing, so takes no claim.
                access.release_entry(db, held)
                code, _, detail = await waiting
                assert code == 409 and "already been reviewed" in detail and claims(app) == []
                held = access._claim_entry(db, Lease(integration_id="dns", domain=DOMAIN))
                monkeypatch.setattr(access, "OPENING_WAITS", 0.3)
                code, status, detail = await review(one)
                assert (code, status) == (409, "pending") and "already changing" in detail
                access.release_entry(db, held)
                db.execute(update(Integration).values(last_sync=None))
                db.commit()
                code, status, detail = await review(one)
                assert (code, status) == (409, "pending") and "has not collected" in detail and claims(app) == []
                db.execute(update(Integration).values(last_sync=utcnow()))
                db.commit()
                source.stuck.add("allowlist")  # The source trickles its answer: the opening fails at its limit.
                assert (await review(one))[:2] == (502, "pending") and claims(app) == []
                assert db.scalars(select(Lease)).all() == [] and source.listed == []
            source.stuck.clear()
            source.seen.clear()
            assert (await review(one))[:2] == (200, "approved") and source.listed == [DOMAIN]
            assert source.seen == [1, 1, 1, 1] and claims(app) == []  # Held for the whole call, then given back.
            assert (await review(one))[0] == 409 and claims(app) == []

    with started(tmp_path) as (app, _client, member, admin):
        asyncio.run(scenario(app, member, admin))


@pytest.mark.parametrize("change", [
    lambda: actions.nextdns_allow({"profile_id": "abc123"}, "key", "slow.example", allowed=True),
    lambda: actions.nextdns_disallow({"profile_id": "abc123"}, "key", "slow.example", allowed=True),
    lambda: actions.unifi_create_voucher(GATEWAY, "key", "site", name="Guest", minutes=60, guest_limit=None,
                                         data_limit_mb=None, allowed=True),
    lambda: actions.unifi_delete_voucher(GATEWAY, "key", "site", "voucher", allowed=True),
    lambda: actions.unifi_set_guest_access(GATEWAY, "key", "site", "client", True, allowed=True),
    lambda: actions.unifi_set_guest_access(GATEWAY, "key", "site", "client", False, allowed=True),
], ids=["open", "remove", "issue a pass", "end a pass", "let a guest on", "cut a guest off"])
def test_every_change_at_a_source_that_trickles_its_answer_for_ever_fails_at_its_limit(monkeypatch, change):
    """Each request's own limits never fire, because bytes keep arriving. The change as a whole still ends, failed."""
    monkeypatch.setattr(actions, "CHANGE_SECONDS", 0.2)
    Source(monkeypatch, stuck={"allowlist", "vouchers", "voucher", "actions"})

    async def run():
        with pytest.raises(IntegrationError) as failed:
            await asyncio.wait_for(change(), 5)
        assert failed.value.category == "timeout" and "too long" in str(failed.value)

    asyncio.run(run())


def test_a_stuck_removal_fails_at_its_limit_is_recorded_as_failed_and_the_next_exception_is_ended(tmp_path,
                                                                                                 monkeypatch):
    """Two exceptions have run out at one source and the first one's removal never finishes."""
    monkeypatch.setattr(actions, "CHANGE_SECONDS", 0.3)
    source, now = Source(monkeypatch, stuck={"stuck.example"}), [utcnow()]

    async def scenario(app):
        Sources(monkeypatch)
        stuck = opened(app, source.listed, "stuck.example", now[0] - timedelta(seconds=2))
        fine, up = opened(app, source.listed, "fine.example", now[0] - timedelta(seconds=1)), upkeep(app, now)
        up.tick()
        await asyncio.wait_for(up.ending["dns"], 5)
        await up.stop()
        with app.state.session_factory() as db:
            assert db.get(Lease, stuck).status == "active" and "too long" in db.get(Lease, stuck).last_error
            assert list(db.scalars(select(Audit.target_id).where(Audit.action == "access.close_failed"))) == [stuck]
        assert stored(app, Lease, fine) == "ended" and closings(app) == ["expired"]
        assert source.listed == ["stuck.example"] and claims(app) == []  # Given back, so the next tick tries again.

    with started(tmp_path) as (app, *_):
        asyncio.run(scenario(app))


def test_a_removal_that_returns_after_its_claim_was_taken_over_leaves_the_newer_claim_and_records_nothing(
        tmp_path, monkeypatch):
    """Only the attempt that holds a claim gives it back; and an attempt holding the claim reads the exception again."""
    source, now = Source(monkeypatch, hold=(1, "before")), [utcnow()]

    async def scenario(app):
        Sources(monkeypatch)
        lease, up, factory = opened(app, source.listed, "late.example", now[0] - timedelta(seconds=1)), \
            upkeep(app, now), app.state.session_factory
        up.tick()
        await asyncio.wait_for(source.reached.wait(), 5)
        with factory() as db, factory() as other:
            db.execute(update(Setting).where(Setting.key.startswith("ending:")).values(
                updated_at=utcnow() - access.ENDING_HOLD))
            db.commit()
            newer = access._claim_entry(db, db.get(Lease, lease))  # The hold ran out; another attempt took it over.
            source.go.set()
            await up.ending["dns"]
            await up.stop()
            assert claims(app) == [newer.mark] and closings(app) == [] and stored(app, Lease, lease) == "active"
            access.release_entry(db, newer)
            stale = other.get(Lease, lease)  # Read as open by an attempt that then waits its turn.
            assert await access.end_lease(db, app.state.settings, db.get(Lease, lease), "expired")
            db.commit()
            sent = len(source.calls)
            assert await access.end_lease(other, app.state.settings, stale, "expired") and len(source.calls) == sent
            other.commit()
        assert closings(app) == ["expired"] and claims(app) == []

    with started(tmp_path) as (app, *_):
        asyncio.run(scenario(app))


def test_the_approval_route_refuses_whom_it_refused_before_and_they_take_no_claim(tmp_path, monkeypatch):
    """A member, someone signed out, and a missing or wrong token are turned away before any claim or call."""
    with started(tmp_path) as (app, client, member, admin):
        source, wrong = Source(monkeypatch), {"X-CSRF-Token": "fabricated-wrong-token"}
        client.cookies.clear()
        client.cookies.update(member["cookies"])
        made = client.post("/api/requests", headers=member["headers"], json=ask("one")).json()
        for cookies, headers, refused in ((member["cookies"], member["headers"], 403), ({}, admin["headers"], 401),
                                          (admin["cookies"], {}, 403), (admin["cookies"], wrong, 403)):
            client.cookies.clear()
            client.cookies.update(cookies)
            answer = client.post(f"/api/requests/{made['id']}/review", headers=headers,
                                 json={"decision": "approved", "note": "Looked at it"})
            assert answer.status_code == refused and source.calls == [] and claims(app) == []
        with app.state.session_factory() as db:
            assert db.get(AccessRequest, made["id"]).status == "pending" and db.scalars(select(Lease)).all() == []
