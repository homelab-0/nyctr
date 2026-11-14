"""An approval holds nothing unsaved while it calls a source, and an entry Nyctr added always has someone to remove it.

The stand-in source holds one chosen call until the test lets it go, so a second decision, a takeover of the
claim or the removal of the source can arrive in the middle of an opening.
"""

import asyncio
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select, update
from test_crossing import DOMAIN, Source, ask, claims, console, started
from test_unconfirmed import Failing, rows, trail
from test_upkeep import Sources, opened, upkeep

from nyctr import access, removal
from nyctr.integrations import IntegrationError, actions, core
from nyctr.models import AccessRequest, Integration, Lease, Observation, Setting, utcnow

GONE = {"name": "Office DNS"}


def gates(app):
    """The claims on requests that are held right now."""
    with app.state.session_factory() as db:
        return list(db.scalars(select(Setting.key).where(Setting.key.startswith("review:"))))


def note(app, request_id):
    with app.state.session_factory() as db:
        row = db.get(AccessRequest, request_id)
        return row.status, row.decision_note or ""


def age(app, prefix):
    """Make the claims whose key starts so old enough to be taken over, as after a copy was killed or stood still."""
    with app.state.session_factory() as db:
        db.execute(update(Setting).where(Setting.key.startswith(prefix)).values(
            updated_at=utcnow() - access.ENDING_HOLD))
        db.commit()


def review(person, request_id, decision="approved"):
    return person.post(f"/api/requests/{request_id}/review", json={"decision": decision, "note": "Looked at it"})


def test_a_second_decision_while_an_approval_is_at_the_source_is_answered_at_once(tmp_path, monkeypatch):
    """The add is accepted and its answer not yet read. A denial, a "reviewed" and a second approval are each told
    at once that the request is being approved; the member sees it waiting; the approval then finishes."""
    with started(tmp_path) as (app, _client, member, admin):
        source = Source(monkeypatch, hold=(2, "after"))

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                approving = asyncio.create_task(review(owner, made))
                await asyncio.wait_for(source.reached.wait(), 5)
                for decision in ("denied", "reviewed", "approved"):
                    answer = await asyncio.wait_for(review(owner, made, decision), 2)
                    assert answer.status_code == 409 and answer.json()["detail"] == access.REVIEWING
                assert [row["status"] for row in (await sam.get("/api/requests")).json()] == ["pending"]
                assert len(gates(app)) == 1 and source.calls == ["GET", "GET", "POST"]
                source.go.set()
                assert (await approving).status_code == 200 and note(app, made)[0] == "approved"
                assert (await review(owner, made, "denied")).status_code == 409  # Already reviewed.

        asyncio.run(scenario())
        assert gates(app) == [] and claims(app) == [] and source.listed == [DOMAIN]
        assert rows(app) == [("active", None, True)]


def test_an_approval_that_cannot_be_stored_or_whose_copy_is_killed_leaves_the_request_waiting_with_a_note(
        tmp_path, monkeypatch):
    """The source accepts the add and storing then fails: both claims go back, the request waits with a note and
    the tick removes the entry. A claim left by a killed copy is refused in the same words until it is cleared."""
    with started(tmp_path) as (app, _client, member, admin):
        source, now = Source(monkeypatch), [utcnow()]

        def broken(*_args, **_more):
            raise RuntimeError("fabricated storage failure")

        async def scenario():
            Sources(monkeypatch)
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                with monkeypatch.context() as patch, pytest.raises(RuntimeError):
                    patch.setattr("nyctr.main.audit", broken)
                    await review(owner, made)
                assert note(app, made) == ("pending", access.NOT_OPENED)  # Nothing of the source or the reason.
                assert gates(app) == [] and claims(app) == [] and source.listed == [DOMAIN]
                assert rows(app) == [("unconfirmed", None, True)]
                up, now[0] = upkeep(app, now), utcnow() + timedelta(seconds=1)
                up.tick()
                await asyncio.gather(*up.ending.values())
                assert source.listed == [] and rows(app) == [("ended", "not_confirmed", True)]
                with app.state.session_factory() as db:  # As far as a copy gets before it is killed mid-approval.
                    assert access.hold_review(db, made)
                refused = await review(owner, made, "denied")
                assert refused.status_code == 409 and refused.json()["detail"] == access.REVIEWING
                up.tick()
                assert len(gates(app)) == 1  # Not old enough to be a killed copy's.
                age(app, "review:")
                up.tick()
                await up.stop()
                assert gates(app) == [] and "Nyctr was stopped while this was being decided" in note(app, made)[1]
                assert (await review(owner, made, "denied")).status_code == 200

        asyncio.run(scenario())


@pytest.mark.parametrize("by_rule", [False, True, "turn"])
def test_a_source_removed_while_an_opening_waits_is_refused_as_removed_and_leaves_no_claim(tmp_path, monkeypatch,
                                                                                         by_rule):
    """Another change holds the address (`turn`: the person's turn for automatic openings); the source is removed
    during the wait; the claim comes free."""
    with started(tmp_path, rule=by_rule) as (app, _client, member, admin):
        source, real = Source(monkeypatch), access._claim

        def busy_turn(db, name):  # The entry's claim is free; the first tries for the person's turn are refused.
            if by_rule != "turn" or not name.startswith("ending:auto:") or source.seen.append(0) or len(source.seen) > 4:
                return real(db, name)
            db.rollback()  # As a refused try does.
        monkeypatch.setattr(access, "_claim", busy_turn)

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                with app.state.session_factory() as db:
                    held = by_rule != "turn" and access._claim_entry(db, Lease(integration_id="dns", domain=DOMAIN))
                    if by_rule:
                        waiting = asyncio.create_task(sam.post("/api/requests", json=ask("one")))
                    else:
                        made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                        waiting = asyncio.create_task(review(owner, made))
                    await asyncio.sleep(0.4)
                    assert (await owner.request("DELETE", "/api/integrations/dns", json=GONE)).status_code == 200
                    access.release_entry(db, held)
                answer = await waiting
                made = answer.json()["id"] if by_rule else made
                assert answer.status_code == (201 if by_rule else 409)
                assert "was removed from Nyctr while" in (answer.json().get("detail") or answer.json()["decision_note"])
                status, why = note(app, made)
                assert status == "pending" and (
                    "was removed from Nyctr while" in why if by_rule else why == access.NOT_OPENED)

        asyncio.run(scenario())
        assert source.calls == [] and claims(app) == [] and gates(app) == [] and rows(app) == []


@pytest.mark.parametrize("taken_by", ["opening", "ending", "the tick, then a person"])
def test_an_opening_whose_claim_was_taken_over_stores_nothing_on_trust(tmp_path, monkeypatch, taken_by):
    """It stood still past the hold. Taken over by a second opening after its add: one exception and one entry.
    Taken over by the ending of an older exception whose entry it had read: no exception and no entry.
    Taken over by the tick, which removes its entry; a person then allows the address by hand and an approval
    finds it there: the opening that comes back cannot know whose the entry is, so its record says so, nothing
    is passed on, and the person's entry is never removed."""
    with started(tmp_path) as (app, _client, member, admin):
        source = Source(monkeypatch, hold=(1, "after") if taken_by == "ending" else (2, "after"))

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                one, two = [(await sam.post("/api/requests", json=ask(block))).json()["id"] for block in ("one", "two")]
                if taken_by == "ending":
                    opened(app, source.listed, DOMAIN, utcnow() - timedelta(seconds=1))
                stalled = asyncio.create_task(review(owner, one))
                await asyncio.wait_for(source.reached.wait(), 5)
                age(app, "ending:")
                if taken_by == "opening":
                    assert (await review(owner, two)).status_code == 200
                    assert source.calls[3:] == ["GET", "DELETE", "GET", "GET", "GET", "POST", "GET"]
                else:
                    with app.state.session_factory() as db:
                        if taken_by != "ending":  # The opening's own record is due once the hold has run out.
                            db.execute(update(Lease).values(expires_at=utcnow()))
                            db.commit()
                        assert await access.reconcile(db, app.state.settings) == 1
                    assert source.listed == []
                if taken_by == "the tick, then a person":
                    source.listed.append(DOMAIN)  # By hand, at the source.
                    assert (await review(owner, two)).status_code == 200 and rows(app)[-1] == ("active", None, False)
                source.go.set()
                late = await stalled
                assert late.status_code == 409 and "took too long" in late.json()["detail"]
                assert note(app, one) == ("pending", access.NOT_OPENED)
                listed = (await owner.get("/api/leases")).json()
                if taken_by != "ending":  # What the administrator is asked to check, and what Nyctr then leaves alone.
                    record = next(row for row in listed if row["status"] == "unconfirmed")
                    assert not record["owned"] and record["expires_at"] is None
                    assert "cannot tell whether it put it there" in record["last_error"]
                    for row in listed:
                        if row["status"] != "ended":
                            assert (await owner.post(f"/api/leases/{row['id']}/end")).status_code == 200

        asyncio.run(scenario())
        assert claims(app) == [] and gates(app) == []
        if taken_by == "opening":  # The second opening's own entry, removed when its exception was ended.
            assert source.listed == [] and source.calls.count("DELETE") == 2
        elif taken_by == "ending":
            assert source.listed == [] and [row[0] for row in rows(app)] == ["ended"]
        else:  # Only the tick's removal of Nyctr's entry; the person's is still there and was never Nyctr's.
            assert source.listed == [DOMAIN] and source.calls.count("DELETE") == 1
            assert [row[2] for row in rows(app)] == [True, False, False]


@pytest.mark.parametrize("way_out", ["the read-back fails", "cut off at the time limit", "an unexpected error",
                                     "stopped"])
def test_a_stalled_opening_never_calls_an_entry_its_own_whichever_way_it_comes_out(tmp_path, monkeypatch, way_out):
    """Its add was accepted and it stood still past the hold; the tick removed the entry; a person allowed the
    address by hand and a second approval found it there. However the first opening then ends, its claim is no
    longer its own: its record says not known, nothing is passed on, and the person's entry is never removed."""
    with started(tmp_path) as (app, _client, member, admin):
        source = Failing(monkeypatch, hold=(2, "after"))
        if way_out == "cut off at the time limit":
            monkeypatch.setattr(actions, "CHANGE_SECONDS", 2.0)

        def broken(*_args, **_more):
            raise RuntimeError("fabricated failure")

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                one, two = [(await sam.post("/api/requests", json=ask(block))).json()["id"] for block in ("one", "two")]
                stalled = asyncio.create_task(review(owner, one))
                await asyncio.wait_for(source.reached.wait(), 5)
                age(app, "ending:")
                with app.state.session_factory() as db:
                    db.execute(update(Lease).values(expires_at=utcnow()))  # The record is due after the hold.
                    db.commit()
                    assert await access.reconcile(db, app.state.settings) == 1 and source.listed == []
                source.listed.append(DOMAIN)  # By hand, at the source.
                assert (await review(owner, two)).status_code == 200 and rows(app)[-1] == ("active", None, False)
                if way_out == "the read-back fails":
                    source.fail = {len(source.calls)}
                elif way_out == "an unexpected error":  # After the add returned, before anything is stored.
                    monkeypatch.setattr(access, "source_unchanged", broken)
                if way_out == "stopped":
                    stalled.cancel()
                elif way_out != "cut off at the time limit":
                    source.go.set()
                if way_out in ("an unexpected error", "stopped"):
                    with pytest.raises(RuntimeError if way_out == "an unexpected error" else asyncio.CancelledError):
                        await stalled
                else:
                    assert (await stalled).status_code == 502
                monkeypatch.undo()
                Failing(monkeypatch).listed = source.listed
                listed = (await owner.get("/api/leases")).json()
                record = next(row for row in listed if row["status"] == "unconfirmed")
                assert not record["owned"] and record["expires_at"] is None
                assert "cannot tell whether it put it there" in record["last_error"]
                for row in listed:
                    if row["status"] != "ended":
                        assert (await owner.post(f"/api/leases/{row['id']}/end")).status_code == 200

        asyncio.run(scenario())
        assert source.listed == [DOMAIN] and source.calls.count("DELETE") == 1  # The tick's, of Nyctr's own entry.
        assert [row[2] for row in rows(app)] == [True, False, False] and claims(app) == [] and gates(app) == []


@pytest.mark.parametrize("first", ["own", "other", "theirs"])
def test_the_duty_to_remove_an_entry_nyctr_added_passes_on_and_a_persons_entry_is_never_removed(tmp_path, monkeypatch,
                                                                                               first):
    """A person's entry backs one exception; they remove it; a second approval adds Nyctr's. Ended in either order,
    nothing of Nyctr's is left. `theirs`: the person's entry is still there, and ending removes nothing."""
    with started(tmp_path) as (app, _client, member, admin):
        source = Source(monkeypatch)
        source.listed.append(DOMAIN)

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                for block in ("one", "two"):
                    made = (await sam.post("/api/requests", json=ask(block))).json()["id"]
                    assert (await review(owner, made)).status_code == 200
                    if first != "theirs" and block == "one":
                        source.listed.clear()  # The person takes their entry out before the second approval.
                leases = {row["owned"]: row["id"] for row in (await owner.get("/api/leases")).json()}
                assert set(leases) == ({False} if first == "theirs" else {True, False})
                ids = [row["id"] for row in (await owner.get("/api/leases")).json()]
                for lease in sorted(ids, key=lambda x: (x == leases.get(True)) != (first == "own")):
                    assert (await owner.post(f"/api/leases/{lease}/end")).status_code == 200

        asyncio.run(scenario())
        assert source.calls.count("DELETE") == (0 if first == "theirs" else 1) and claims(app) == []
        assert source.listed == ([DOMAIN] if first == "theirs" else [])


def test_the_daily_limit_holds_for_requests_sent_at_the_same_moment(tmp_path, monkeypatch):
    """Eight at once with a limit of four, the first held at the source while the others arrive: four open, four
    wait for a person, and each kept its assessment although it had to wait its turn."""
    with started(tmp_path, rule=True) as (app, _client, member, _admin):
        source = Source(monkeypatch, hold=(2, "after"))
        with app.state.session_factory() as db:
            one = db.get(Observation, "dns:block:one")
            db.add_all(Observation(id=f"dns:block:b{n}", **{name: getattr(one, name) for name in (
                "integration_id", "device_id", "device_name", "domain", "source", "reason", "reason_codes",
                "observed_at", "expires_at", "evidence_kind", "attribution", "risk_explanation")}) for n in range(8))
            db.commit()

        async def scenario():
            async with console(app, member) as sam:
                asking = asyncio.gather(*(sam.post("/api/requests", json=ask(f"b{n}")) for n in range(8)))
                await asyncio.wait_for(source.reached.wait(), 5)
                await asyncio.sleep(0.6)  # The other seven are past the first count and waiting their turn.
                source.go.set()
                return [answer.json() for answer in await asking]

        made = asyncio.run(scenario())
        assert sorted(row["status"] for row in made) == ["auto_approved"] * 4 + ["pending"] * 4
        assert all("today's limit of 4" in row["decision_note"] for row in made if row["status"] == "pending")
        assert all(row["risk_score"] is not None for row in made)
        assert source.calls.count("POST") == 1 and claims(app) == []


def test_an_attempt_is_on_record_when_the_address_was_already_there_and_the_adds_own_answer_wins(tmp_path,
                                                                                              monkeypatch):
    """Asked first: already there. A person removes it in that second, Nyctr's add is sent and the read-back fails:
    the entry is Nyctr's, on record, and removed. One that stays there is never removed, also after a kill."""
    with started(tmp_path) as (app, _client, member, admin):
        source = Failing(monkeypatch, fail={3}, watch=lambda: [(row[0], row[2]) for row in rows(app)])
        source.listed.append(DOMAIN)
        real = source.answer

        async def answer(request):
            if len(source.calls) == 1:
                source.listed.clear()  # The person takes it out between Nyctr's question and the add's own read.
            return await real(request)
        source.answer = answer

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                assert (await review(owner, made)).status_code == 502
            assert source.seen[0] == [] and source.seen[1] == [("unconfirmed", False)]  # On record before the add.
            assert source.calls == ["GET", "GET", "POST", "GET", "GET", "DELETE", "GET"] and source.listed == []
            assert trail(app) == [("access.open_unconfirmed", "failed"), ("access.closed", "applied"),
                                  ("access.approve_failed", None)]
            source.fail.clear()
            source.listed.append(DOMAIN)
            with app.state.session_factory() as db:  # A copy killed after asking: the address really was there.
                await access.hold_entry(db, app.state.settings, db.get(Integration, "dns"), DOMAIN)
                age(app, "ending:")
                db.execute(update(Lease).where(Lease.status == "unconfirmed").values(expires_at=utcnow()))
                db.commit()
                assert await access.reconcile(db, app.state.settings) == 1
            assert source.listed == [DOMAIN] and source.calls.count("DELETE") == 1
            assert rows(app)[-1] == ("ended", "not_confirmed", False)

        asyncio.run(scenario())
    monkeypatch.setattr(actions, "CHANGE_SECONDS", 0.3)
    slow = Source(monkeypatch, stuck={"allowlist"})

    async def cut_off():
        real = slow.answer

        async def answer(request):  # The add's own read answers; its add is accepted and never answered.
            slow.stuck = set() if len(slow.calls) == 0 else {"allowlist"}
            return await real(request)
        slow.answer = answer
        with pytest.raises(IntegrationError) as error:
            await actions.nextdns_allow({"profile_id": "abc123"}, "key", "slow.example", allowed=True)
        assert error.value.add_sent is True and slow.calls == ["GET", "POST"]

    asyncio.run(cut_off())


def test_who_is_refused_is_unchanged_and_a_denial_needs_no_fresh_evidence(tmp_path, monkeypatch):
    """Not fresh: an approval is refused before any claim or call; a denial of the same request goes through."""
    with started(tmp_path) as (app, _client, member, admin):
        source = Source(monkeypatch)

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                with app.state.session_factory() as db:
                    db.execute(update(Observation).values(expires_at=utcnow() - timedelta(seconds=1)))
                    db.commit()
                before, stale = note(app, made), await review(owner, made)
                assert stale.status_code == 409 and "no longer current" in stale.json()["detail"]
                assert source.calls == [] and claims(app) == [] and gates(app) == [] and note(app, made) == before
                assert (await review(sam, made, "denied")).status_code == 403
                assert (await review(owner, made, "denied")).status_code == 200
                assert (await review(owner, made, "reviewed")).status_code == 409 and gates(app) == []

        asyncio.run(scenario())
        with app.state.session_factory() as db:
            assert db.scalar(select(AccessRequest.status)) == "denied"


def test_a_persons_decision_while_the_rule_is_opening_is_refused_and_never_overwritten(tmp_path, monkeypatch):
    """The request is listed as waiting while the rule's opening is at the source: a denial then is told it is
    being approved, and the rule's decision stands alone, with one exception."""
    with started(tmp_path, rule=True) as (app, _client, member, admin):
        source = Source(monkeypatch, hold=(2, "after"))

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                asking = asyncio.create_task(sam.post("/api/requests", json=ask("one")))
                await asyncio.wait_for(source.reached.wait(), 5)
                made = (await owner.get("/api/requests")).json()[0]
                refused = await review(owner, made["id"], "denied")
                assert made["status"] == "pending" and refused.status_code == 409
                assert refused.json()["detail"] == access.REVIEWING
                source.go.set()
                assert (await asking).json()["status"] == "auto_approved"

        asyncio.run(scenario())
        assert rows(app) == [("active", None, True)] and gates(app) == [] and claims(app) == []


@pytest.mark.parametrize("by_rule", [False, True])
def test_a_decision_stored_just_before_the_requests_claim_is_taken_is_left_alone(tmp_path, monkeypatch, by_rule):
    """A copy that does not know the claim denies the request in that instant: neither an approval nor the access
    rule then opens anything or writes over it."""
    with started(tmp_path, rule=by_rule) as (app, _client, member, admin):
        source, real = Source(monkeypatch), access.hold_review

        def decided_first(db, request_id):
            db.execute(update(AccessRequest).where(AccessRequest.id == request_id).values(status="denied"))
            db.commit()
            return real(db, request_id)

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                if by_rule:
                    monkeypatch.setattr(access, "hold_review", decided_first)
                    return (await sam.post("/api/requests", json=ask("one"))).json()["status"]
                made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                monkeypatch.setattr(access, "hold_review", decided_first)
                answer = await review(owner, made)
                assert answer.status_code == 409 and "already been reviewed" in answer.json()["detail"]
                return note(app, made)[0]

        assert asyncio.run(scenario()) == "denied"
        assert source.calls == [] and rows(app) == [] and gates(app) == [] and claims(app) == []


@pytest.mark.parametrize("first", ["own", "other"])
def test_one_pass_that_ends_both_exceptions_of_an_entry_removes_it_whichever_comes_first(tmp_path, monkeypatch,
                                                                                        first):
    """Both run out together and one pass reads both before it ends either (the list of exceptions): the duty
    passed on while ending Nyctr's own is seen when the other is ended, and the entry is removed once."""
    with started(tmp_path) as (app, *_):
        source, past = Source(monkeypatch), utcnow() - timedelta(seconds=1)
        source.listed.append(DOMAIN)

        async def scenario():
            with app.state.session_factory() as db:
                for owned in ((True, False) if first == "own" else (False, True)):
                    db.add(Lease(integration_id="dns", domain=DOMAIN, execution="applied", owned=owned, expires_at=past))
                    db.commit()
                assert [row.owned for row in db.scalars(select(Lease))] == [first == "own", first != "own"]
                assert await access.reconcile(db, app.state.settings) == 2

        asyncio.run(scenario())
        # Ending Nyctr's own first, the source is asked whether the entry is there before the duty is passed on.
        assert source.calls == ["GET"] * (first == "own") + ["GET", "DELETE", "GET"]
        assert source.listed == [] and claims(app) == [] and [row[0] for row in rows(app)] == ["ended", "ended"]


@pytest.mark.parametrize("moment", ["passed on while ending", "ended while claiming"])
def test_an_ending_acts_on_what_is_stored_when_another_copy_changes_it_in_the_middle(tmp_path, monkeypatch, moment):
    """Another copy passes the duty to an exception this copy is ending as "not Nyctr's": it is ended as Nyctr's
    own and the entry removed. Another copy ends the exception this one is about to end, and a person's entry
    then backs a new exception: nothing is passed on to it, and the person's entry is never removed."""
    with started(tmp_path) as (app, *_):
        source, past = Source(monkeypatch), utcnow() - timedelta(seconds=1)
        source.listed.append(DOMAIN)
        mine = opened(app, [], DOMAIN, past)

        def other_copy(change):
            with app.state.session_factory() as db:
                change(db)
                db.commit()

        async def scenario():
            with app.state.session_factory() as db:
                lease = db.get(Lease, mine)
                if moment == "passed on while ending":
                    lease.owned, real = False, access.still_open
                    db.commit()

                    def passed_on_first(session, key):
                        session.commit()  # Nothing is unsaved here; SQLite lets the other copy write only then.
                        other_copy(lambda other: other.execute(update(Lease).values(owned=True)))
                        return real(session, key)
                    monkeypatch.setattr(access, "still_open", passed_on_first)
                else:
                    real = access._claim_entry

                    def ended_first(session, entry):  # The other copy ended it; the entry now there is a person's.
                        other_copy(lambda other: (other.execute(update(Lease).values(status="ended")), other.add(
                            Lease(integration_id="dns", domain=DOMAIN, execution="applied", owned=False))))
                        return real(session, entry)
                    monkeypatch.setattr(access, "_claim_entry", ended_first)
                assert await access.end_lease(db, app.state.settings, lease, "expired")
                db.commit()

        asyncio.run(scenario())
        if moment == "passed on while ending":
            assert source.calls == ["GET", "DELETE", "GET"] and source.listed == []
        else:
            assert source.calls == [] and source.listed == [DOMAIN] and rows(app)[-1] == ("active", None, False)
        assert claims(app) == []


@pytest.mark.parametrize("person", ["removes", "adds"])
def test_a_store_that_fails_after_the_source_answered_goes_by_what_the_add_itself_found(tmp_path, monkeypatch, person):
    """Between Nyctr's question and the add's own read a person removes the address (the add adds it: Nyctr's, on
    record, removed) or adds it (the add finds it there and sends nothing: no record, never removed)."""
    with started(tmp_path) as (app, _client, member, admin):
        source, now = Source(monkeypatch), [utcnow()]
        source.listed.extend([DOMAIN] * (person == "removes"))
        real = source.answer

        async def answer(request):
            if len(source.calls) == 1:
                source.listed[:] = [] if person == "removes" else [DOMAIN]
            return await real(request)
        source.answer = answer

        def broken(*_args, **_more):
            raise RuntimeError("fabricated storage failure")

        async def scenario():
            Sources(monkeypatch)
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                with monkeypatch.context() as patch, pytest.raises(RuntimeError):
                    patch.setattr("nyctr.main.audit", broken)
                    await review(owner, made)
                assert rows(app) == ([("unconfirmed", None, True)] if person == "removes" else [])
                up, now[0] = upkeep(app, now), utcnow() + access.ENDING_HOLD + timedelta(seconds=1)
                up.tick()
                await asyncio.gather(*up.ending.values())
                await up.stop()

        asyncio.run(scenario())
        if person == "removes":
            assert source.calls == ["GET", "GET", "POST", "GET", "GET", "DELETE", "GET"] and source.listed == []
        else:
            assert source.calls == ["GET", "GET"] and source.listed == [DOMAIN] and rows(app) == []
        assert claims(app) == [] and gates(app) == []


@pytest.mark.parametrize("by_rule", [False, True])
def test_a_decision_by_a_copy_that_does_not_know_the_claim_while_the_opening_is_at_the_source_stands(
        tmp_path, monkeypatch, by_rule):
    """An older copy denies the request while the add is at the source. The final write finds it decided: nothing
    is stored over the denial, and what was added stays on record and is removed."""
    with started(tmp_path, rule=by_rule) as (app, _client, member, admin):
        source = Source(monkeypatch, hold=(2, "after"))

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                if by_rule:
                    opening = asyncio.create_task(sam.post("/api/requests", json=ask("one")))
                else:
                    made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                    opening = asyncio.create_task(review(owner, made))
                await asyncio.wait_for(source.reached.wait(), 5)
                with app.state.session_factory() as db:
                    db.execute(update(AccessRequest).values(status="denied"))
                    db.commit()
                source.go.set()
                answer = await opening
                assert (answer.json()["status"] == "denied") if by_rule else (
                    answer.status_code == 409 and "already been reviewed" in answer.json()["detail"])
                assert rows(app) == [("unconfirmed", None, True)] and source.listed == [DOMAIN]
                with app.state.session_factory() as db:
                    assert await access.reconcile(db, app.state.settings) == 1 and db.scalar(
                        select(AccessRequest.status)) == "denied"

        asyncio.run(scenario())
        assert source.listed == [] and rows(app) == [("ended", "not_confirmed", True)]
        assert claims(app) == [] and gates(app) == []


def test_a_turn_that_does_not_come_is_said_as_that_and_not_as_a_failure_of_the_source(tmp_path, monkeypatch):
    """The person's earlier automatic openings are still going when the wait runs out: a person decides, and the
    note says why. Nothing is sent and nothing is left held."""
    with started(tmp_path, rule=True) as (app, _client, member, _admin):
        source, real = Source(monkeypatch), access._claim
        monkeypatch.setattr(access, "OPENING_WAITS", 0.3)
        monkeypatch.setattr(access, "_claim", lambda db, name: db.rollback() if name.startswith(
            "ending:auto:") else real(db, name))

        async def scenario():
            async with console(app, member) as sam:
                return (await sam.post("/api/requests", json=ask("one"))).json()

        made = asyncio.run(scenario())
        assert made["status"] == "pending" and made["risk_score"] is not None
        assert made["decision_note"] == "Nyctr was still opening your earlier requests, so a person decides this one."
        assert source.calls == [] and rows(app) == [] and gates(app) == [] and claims(app) == []


@pytest.mark.parametrize("failure, sent", [("no connection", False), ("refused before sending", False),
                                           ("the source answers 500", True), ("the read-back fails", True),
                                           ("its own read fails", False)])
def test_the_add_marks_its_error_only_when_its_add_was_sent(monkeypatch, failure, sent):
    """Sent after its own read found the address absent: marked as sent. Never left, or failed before that:
    marked as not sent, so that core keeps no record of an entry of its own."""
    source = Source(monkeypatch)
    real = source.answer

    async def answer(request):
        call = len(source.calls)
        if failure == "no connection" and call == 1:
            raise httpx.ConnectError("fabricated: no connection", request=request)
        reply = await real(request)
        return httpx.Response(500) if call == {"the source answers 500": 1, "the read-back fails": 2,
                                               "its own read fails": 0}.get(failure) else reply
    source.answer = answer
    if failure == "refused before sending":
        monkeypatch.setattr(core, "MAX_REQUESTS", 1)

    async def add():
        with pytest.raises(IntegrationError) as error:
            await actions.nextdns_allow({"profile_id": "abc123"}, "key", "slow.example", allowed=True)
        return getattr(error.value, "add_sent", None)

    assert asyncio.run(add()) is sent
    assert source.calls.count("POST") == (1 if sent else 0) and (source.listed == ["slow.example"]) == bool(sent)


def test_why_an_approval_opened_nothing_is_kept_for_administrators_and_no_member_can_read_it(tmp_path, monkeypatch):
    """The reason is in the audit record. The member reads their own sentence and nothing else, by any route."""
    with started(tmp_path) as (app, _client, member, admin):
        Failing(monkeypatch, fail=set(range(99)))
        why = "Provider returned HTTP 500."

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                failed = await review(owner, made)
                assert failed.status_code == 502 and failed.json()["detail"] == why
                kept = [row for row in (await owner.get("/api/audit")).json() if row["action"] == "access.approve_failed"]
                assert [(row["target_id"], row["details"]) for row in kept] == [(made, {"domain": DOMAIN, "why": why})]
                assert (await owner.get("/api/requests")).json()[0]["decision_note"] == access.NOT_OPENED
                assert (await sam.get("/api/audit")).status_code == 403
                read = [await sam.get(path) for path in ("/api/requests", "/api/leases", "/api/blocks", "/api/me")]
                read.append(await sam.post("/api/requests", json=ask("one")))  # The same request, asked again.
                assert read[0].json()[0]["decision_note"] == access.NOT_OPENED
                assert all(why not in answer.text and "Provider" not in answer.text for answer in read)
                assert (await sam.post("/api/graph/query", json={"query": "{ leases { id } }"})).status_code == 403

        asyncio.run(scenario())


def test_the_tick_leaves_a_claim_on_a_request_that_another_copy_took_over_in_that_instant(tmp_path, monkeypatch):
    """Old enough to be a killed copy's when the tick read it, taken over before the tick deleted it: it stays,
    and the request gets no note."""
    with started(tmp_path) as (app, _client, member, _admin):
        Source(monkeypatch)

        async def scenario():
            async with console(app, member) as sam:
                return (await sam.post("/api/requests", json=ask("one"))).json()

        made = asyncio.run(scenario())
        with app.state.session_factory() as db, app.state.session_factory() as other:
            assert access.hold_review(db, made["id"])
            age(app, "review:")
            real = db.scalars

            def read_then_taken_over(query):
                found = real(query).all()
                taken = access.hold_review(other, made["id"])
                assert taken and found
                return type("Rows", (), {"all": lambda self: found})()
            monkeypatch.setattr(db, "scalars", read_then_taken_over)
            access.clear_stale_reviews(db)
        assert len(gates(app)) == 1 and note(app, made["id"])[1] == made["decision_note"]


def test_a_member_is_given_no_note_that_is_no_longer_true_and_none_written_for_an_administrator(tmp_path, monkeypatch):
    """An approval fails and a later one opens: the "not opened" note is gone. An exception of the member's whose
    undo failed carries a sentence for the administrator: the member's own list does not."""
    with started(tmp_path) as (app, _client, member, admin):
        source = Failing(monkeypatch, fail={1})
        by_hand = "Remove the exception for late.example at that source by hand."

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()
                assert (await review(owner, made["id"])).status_code == 502
                assert note(app, made["id"]) == ("pending", access.NOT_OPENED)
                source.fail.clear()
                assert (await review(owner, made["id"])).status_code == 200
                assert note(app, made["id"]) == ("approved", "")
                with app.state.session_factory() as db:
                    db.add(Lease(integration_id="dns", domain="late.example", execution="applied", owned=True,
                                 requester_id=made["requester_id"], last_error=by_hand))
                    db.commit()
                mine, all_of_them = (await sam.get("/api/leases")).json(), (await owner.get("/api/leases")).json()
                assert sorted(row["domain"] for row in mine) == sorted([DOMAIN, "late.example"])
                assert all(row["last_error"] is None for row in mine) and "by hand" not in str(mine)
                assert by_hand in [row["last_error"] for row in all_of_them]

        asyncio.run(scenario())


def test_a_store_that_fails_after_the_claim_was_taken_over_leaves_the_entry_to_a_person(tmp_path, monkeypatch):
    """The source accepted the add, storing failed, and by then another attempt holds the claim: the same check
    applies. The record says not known and Nyctr sends nothing more."""
    with started(tmp_path) as (app, _client, member, admin):
        source, real, now = Source(monkeypatch), access.release_entry, [utcnow()]

        def broken(*_args, **_more):
            raise RuntimeError("fabricated storage failure")

        def taken_over_first(db, claim, unstored=False):
            if not unstored:
                return real(db, claim, unstored)
            age(app, "ending:")
            with app.state.session_factory() as other:
                theirs = access._claim(other, str(claim))
                assert theirs
                real(db, claim, unstored)  # While the other attempt still holds it.
                real(other, theirs)

        async def scenario():
            Sources(monkeypatch)
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                monkeypatch.setattr("nyctr.main.audit", broken)
                monkeypatch.setattr(access, "release_entry", taken_over_first)
                with pytest.raises(RuntimeError):
                    await review(owner, made)
                up, now[0] = upkeep(app, now), utcnow() + access.ENDING_HOLD + timedelta(seconds=1)
                up.tick()
                await up.stop()

        asyncio.run(scenario())
        assert rows(app) == [("unconfirmed", None, False)] and source.calls == ["GET", "GET", "POST", "GET"]
        assert source.listed == [DOMAIN] and claims(app) == [] and gates(app) == []


@pytest.mark.parametrize("add", ["never sent", "sent"])
def test_no_record_is_kept_when_the_add_itself_says_nothing_was_sent(tmp_path, monkeypatch, add):
    """The add's own read fails, so no add is sent: nothing is on record, and an entry a person then writes by
    hand is not touched, however long the source goes on failing. An add that was sent and not confirmed is on
    record, removed, and its row says what settling it did."""
    with started(tmp_path, rule=True) as (app, _client, member, admin):
        source = Failing(monkeypatch, fail={1, 2} if add == "never sent" else {3})

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                made = (await sam.post("/api/requests", json=ask("one"))).json()
                assert made["status"] == "pending" and ("POST" in source.calls) == (add == "sent")
                if add == "never sent":
                    assert rows(app) == [] and source.calls == ["GET", "GET"] and trail(app) == []
                    source.fail = set(range(99))
                    source.listed.append(DOMAIN)  # A person adds it at the source by hand.
                listed = (await owner.get("/api/leases")).json()
                return [(row["status"], row["execution"]) for row in listed]

        listed = asyncio.run(scenario())
        if add == "never sent":
            assert listed == [] and source.listed == [DOMAIN] and "DELETE" not in source.calls
        else:
            assert listed == [("ended", "applied")] and source.listed == []
        assert claims(app) == []


@pytest.mark.parametrize("source_says", ["there", "not there", "the read fails"])
def test_an_entry_is_passed_on_only_when_the_source_says_it_is_there(tmp_path, monkeypatch, source_says):
    """A record is settled beside an open exception recorded as not Nyctr's. There: that exception carries the
    entry from now on. Not there: nothing is marked, and a person's entry written later is never removed. The
    read fails: the record stays unsettled and nothing is marked."""
    with started(tmp_path) as (app, _client, _member, admin):
        source = Failing(monkeypatch)

        async def scenario():
            with app.state.session_factory() as db:
                db.add(Lease(integration_id="dns", domain=DOMAIN, execution="applied", owned=False,
                             created_at=utcnow() - timedelta(minutes=5)))
                db.commit()
                await access.hold_entry(db, app.state.settings, db.get(Integration, "dns"), DOMAIN)  # Then killed.
                age(app, "ending:")
                db.execute(update(Lease).where(Lease.status == "unconfirmed").values(expires_at=utcnow()))
                db.commit()
                source.listed.extend([DOMAIN] * (source_says == "there"))
                source.fail = set(range(99)) if source_says == "the read fails" else set()
                assert await access.reconcile(db, app.state.settings) == (source_says != "the read fails")
                kept = removal.plan(db, db.get(Integration, "dns"), [])["keep"]["exceptions"]
            if source_says == "not there":
                source.listed.append(DOMAIN)  # A person writes it by hand afterwards.
            async with console(app, admin) as owner:
                old = next(row for row in (await owner.get("/api/leases")).json() if row["status"] == "active")
                assert old["owned"] == (source_says == "there") and kept == 1  # The record is not an exception kept.
                if source_says == "the read fails":
                    record = next(row for row in (await owner.get("/api/leases")).json() if row["status"] != "active")
                    refused = await owner.post(f"/api/leases/{record['id']}/end")
                    assert refused.status_code == 502 and "stays listed as not confirmed" in refused.json()["detail"]
                    source.fail = set()
                assert (await owner.post(f"/api/leases/{old['id']}/end")).status_code == 200

        asyncio.run(scenario())
        assert ("DELETE" in source.calls) == (source_says == "there")
        assert source.listed == ([DOMAIN] if source_says == "not there" else [])
        assert [row[0] for row in rows(app)].count("unconfirmed") == (source_says == "the read fails")


@pytest.mark.parametrize("says", [False, None])
def test_a_source_without_the_first_read_leaves_no_record_when_its_add_says_nothing_was_sent(tmp_path, monkeypatch,
                                                                                            says):
    """Nothing was asked first, so only the add's own word can tell. Not sent: no record. No word: a record a
    person checks, as before."""
    class NoRead:
        async def allow_domain(self, config, key, domain, *, allowed):
            error = IntegrationError("The source did not answer.")
            if says is not None:
                error.add_sent = says
            raise error

    with started(tmp_path, rule=True) as (app, _client, member, _admin):
        Source(monkeypatch)
        monkeypatch.setattr(access, "_opener", lambda integration: NoRead())

        async def scenario():
            async with console(app, member) as sam:
                return (await sam.post("/api/requests", json=ask("one"))).json()["status"]

        assert asyncio.run(scenario()) == "pending" and claims(app) == []
        assert rows(app) == ([] if says is False else [("unconfirmed", None, False)])
