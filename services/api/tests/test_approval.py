"""An approval holds nothing unsaved while it calls a source, and an entry Nyctr added always has someone to remove it.

The stand-in source holds one chosen call until the test lets it go, so a second decision, a takeover of the
claim or the removal of the source can arrive in the middle of an opening.
"""

import asyncio
from datetime import timedelta

import pytest
from sqlalchemy import select, update
from test_crossing import DOMAIN, Source, ask, claims, console, started
from test_unconfirmed import Failing, rows, trail
from test_upkeep import Sources, opened, upkeep

from nyctr import access
from nyctr.integrations import IntegrationError, actions
from nyctr.models import AccessRequest, Integration, Lease, Observation, Setting, utcnow

GONE = {"name": "Home DNS"}


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
                assert note(app, made) == ("pending", "An approval did not go through, so this is still waiting. "
                                                      "Nyctr met an error. Nothing was recorded as opened.")
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
                assert gates(app) == [] and "Nyctr was stopped while" in note(app, made)[1]
                assert (await review(owner, made, "denied")).status_code == 200

        asyncio.run(scenario())


@pytest.mark.parametrize("by_rule", [False, True])
def test_a_source_removed_while_an_opening_waits_is_refused_as_removed_and_leaves_no_claim(tmp_path, monkeypatch,
                                                                                         by_rule):
    """Another change holds the address; the source is removed during the wait; the claim comes free."""
    with started(tmp_path, rule=by_rule) as (app, _client, member, admin):
        source = Source(monkeypatch)

        async def scenario():
            async with console(app, member) as sam, console(app, admin) as owner:
                with app.state.session_factory() as db:
                    held = access._claim_entry(db, Lease(integration_id="dns", domain=DOMAIN))
                    if by_rule:
                        waiting = asyncio.create_task(sam.post("/api/requests", json=ask("one")))
                    else:
                        made = (await sam.post("/api/requests", json=ask("one"))).json()["id"]
                        waiting = asyncio.create_task(review(owner, made))
                    await asyncio.sleep(0.6)
                    assert (await owner.request("DELETE", "/api/integrations/dns", json=GONE)).status_code == 200
                    access.release_entry(db, held)
                answer = await waiting
                made = answer.json()["id"] if by_rule else made
                assert answer.status_code == (201 if by_rule else 409)
                assert "was removed from Nyctr while" in (answer.json().get("detail") or answer.json()["decision_note"])
                status, why = note(app, made)
                assert status == "pending" and "was removed from Nyctr while" in why

        asyncio.run(scenario())
        assert source.calls == [] and claims(app) == [] and gates(app) == [] and rows(app) == []


@pytest.mark.parametrize("taken_by", ["opening", "ending"])
def test_an_opening_whose_claim_was_taken_over_stores_nothing_on_trust(tmp_path, monkeypatch, taken_by):
    """It stood still past the hold. Taken over by a second opening after its add: one exception and one entry.
    Taken over by the ending of an older exception whose entry it had read: no exception and no entry."""
    with started(tmp_path) as (app, _client, member, admin):
        source = Source(monkeypatch, hold=(2, "after") if taken_by == "opening" else (1, "after"))

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
                        assert await access.reconcile(db, app.state.settings) == 1
                    assert source.listed == []
                source.go.set()
                late = await stalled
                assert late.status_code == 409 and "took too long" in late.json()["detail"]
                assert note(app, one)[0] == "pending" and "took too long" in note(app, one)[1]

        asyncio.run(scenario())
        assert claims(app) == [] and gates(app) == []
        if taken_by == "opening":
            assert source.listed == [DOMAIN] and "DELETE" not in source.calls[10:]
            assert sorted(row[0] for row in rows(app)) == ["active", "ended", "ended"]
        else:
            assert source.listed == [] and [row[0] for row in rows(app)] == ["ended"]


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
    """Eight at once with a limit of four: four open, four wait for a person, and each kept its assessment
    although it had to wait its turn."""
    with started(tmp_path, rule=True) as (app, _client, member, _admin):
        source = Source(monkeypatch)
        with app.state.session_factory() as db:
            one = db.get(Observation, "dns:block:one")
            db.add_all(Observation(id=f"dns:block:b{n}", **{name: getattr(one, name) for name in (
                "integration_id", "device_id", "device_name", "domain", "source", "reason", "reason_codes",
                "observed_at", "expires_at", "evidence_kind", "attribution", "risk_explanation")}) for n in range(8))
            db.commit()

        async def scenario():
            async with console(app, member) as sam:
                return [answer.json() for answer in await asyncio.gather(*(
                    sam.post("/api/requests", json=ask(f"b{n}")) for n in range(8)))]

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
            assert trail(app) == [("access.open_unconfirmed", "failed"), ("access.closed", "applied")]
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
