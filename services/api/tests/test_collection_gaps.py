"""A collection records what it could not read, whoever started it, and the source list says so."""

import asyncio
import json

import httpx
import pytest
from conftest import LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import select

from nyctr import worker
from nyctr.assistant import evidence_pack
from nyctr.integrations import IntegrationError, Snapshot, core, registry
from nyctr.models import Audit, Integration, utcnow

GAP = "nextdns_log_settings_unknown"
OTHER = "nextdns_policy_fields_missing"
NOTES = registry.find("nextdns").gap_notes


def source_hits(monkeypatch, runs):
    """Make the DNS source's next reads hit the given gaps: each run is {code: cause or None}, or an error."""
    async def collect(provider, integration_id, config, api_key):
        run = runs.pop(0) if integration_id == "dns" and runs else {}
        if isinstance(run, Exception):
            raise run
        for code, cause in run.items():
            core._fault(cause)
            core.record_gap(code)
        core.record_capability("profile:read")
        return Snapshot()

    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_DNS", "fabricated-key")
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", "fabricated-key")
    monkeypatch.setattr("nyctr.integrations.collect", collect)


def by_person(app, client, headers):
    """Collect the DNS source as an administrator pressing the button."""
    response = client.post("/api/integrations/dns/sync", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def by_schedule(app, client, headers):
    """Collect every source as the schedule does."""
    assert asyncio.run(worker.tick(app.state.session_factory, app.state.settings, utcnow())) is True


def by_nudge(app, client, headers):
    """Collect every source as a nudge from the network console does."""
    asyncio.run(worker.collect_all(app.state.session_factory, app.state.settings))


def listed(client, source="dns"):
    """Read one source as the Sources page receives it."""
    return next(row for row in client.get("/api/integrations").json() if row["id"] == source)


def collected(app):
    """Read the details of every stored collection of the DNS source, oldest first."""
    with app.state.session_factory() as db:
        return [row.details for row in db.scalars(select(Audit).where(
            Audit.action == "integration.collected", Audit.target_id == "dns").order_by(Audit.created_at))]


@pytest.mark.parametrize("start", [by_person, by_schedule, by_nudge])
def test_every_collection_records_its_gaps_in_the_words_the_connection_test_uses(tmp_path, monkeypatch, start):
    """Whoever starts it, the audit record lists the codes and the source list carries the integration's texts."""
    source_hits(monkeypatch, [{GAP: None, OTHER: None}, {GAP: None, OTHER: None}])
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        headers = live_signin(client)
        result = start(app, client, headers)
        assert result is None or result["gaps"] == 2
        assert collected(app)[-1]["gaps"] == [GAP, OTHER]
        row = listed(client)
        assert row["status"] == "connected"
        assert row["gaps"] == [{"id": code, "title": NOTES[code][0], "summary": NOTES[code][1]}
                               for code in (GAP, OTHER)]
        assert listed(client, "unifi")["gaps"] == []
        # The connection test still shows the same codes, titles and texts.
        report = client.post("/api/integrations/dns/diagnostics", headers=headers).json()
        shown = {gap["id"]: gap for gap in report["evidence_gaps"]}
        assert all(shown[gap["id"]] == gap for gap in row["gaps"])


def test_gaps_are_those_of_the_last_collection_that_stored_data(tmp_path, monkeypatch):
    """A failed collection leaves the recorded gaps alone; the next stored one replaces them."""
    source_hits(monkeypatch, [{GAP: None}, IntegrationError("Denied.", category="authentication"), {OTHER: None}, {}])
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        headers = live_signin(client)
        by_person(app, client, headers)
        assert [gap["id"] for gap in listed(client)["gaps"]] == [GAP]
        assert client.post("/api/integrations/dns/sync", headers=headers).status_code == 502
        row = listed(client)
        assert row["status"] == "error" and [gap["id"] for gap in row["gaps"]] == [GAP]
        by_person(app, client, headers)
        assert [gap["id"] for gap in listed(client)["gaps"]] == [OTHER]
        assert by_person(app, client, headers)["gaps"] == 0
        assert listed(client)["gaps"] == [] and collected(app)[-1]["gaps"] == []


def test_a_source_error_is_told_apart_from_a_refusal(tmp_path, monkeypatch):
    """Both are recorded with their cause and shown in different words; neither fails the collection."""
    source_hits(monkeypatch, [{GAP: "source_error", OTHER: "refused"}])
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        by_person(app, client, live_signin(client))
        assert collected(app)[-1]["gap_causes"] == {GAP: ["source_error"], OTHER: ["refused"]}
        texts = {gap["id"]: gap["summary"] for gap in listed(client)["gaps"]}
        assert texts[GAP] == f"{NOTES[GAP][1]} {core.GAP_CAUSES['source_error']}"
        assert texts[OTHER] == f"{NOTES[OTHER][1]} {core.GAP_CAUSES['refused']}"
        assert "had an error" in texts[GAP] and "this key may not read it" in texts[OTHER]


def test_nothing_recorded_repeats_the_source_and_a_member_sees_none_of_it(tmp_path, monkeypatch):
    """Only fixed codes are stored, a code this release cannot describe is still shown, and members are refused."""
    source_hits(monkeypatch, [{GAP: "source_error", "retired_code": None}])
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        by_person(app, client, live_signin(client))
        details = collected(app)[-1]
        assert details["gaps"] == [GAP, "retired_code"] and details["gap_causes"] == {GAP: ["source_error"]}
        with app.state.session_factory() as db:
            source = db.get(Integration, "dns")
            stored = json.dumps([details, listed(client)["gaps"]])
            assert source.secret_ref not in stored and "abc123" not in stored and "fabricated-key" not in stored
        assert listed(client)["gaps"][1] == {"id": "retired_code", "title": core.UNDESCRIBED_GAP[0],
                                             "summary": core.UNDESCRIBED_GAP[1]}
        client.post("/api/auth/logout", headers=live_signin(client))
        live_signin(client, LIVE_MEMBER)
        assert client.get("/api/integrations").status_code == 403
        assert client.get("/api/audit").status_code == 403


def test_the_attention_list_names_sources_that_stored_only_part_and_the_assistant_gets_none_of_it(
        tmp_path, monkeypatch):
    """A partial source and one with gaps are ranked for every reader of the list; a failed one is listed once.

    The assistant's evidence pack is built apart from this list and says of a source only what it said before.
    """
    source_hits(monkeypatch, [{GAP: "source_error", OTHER: None}])
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        by_person(app, client, live_signin(client))
        with app.state.session_factory() as db:
            db.get(Integration, "unifi").status = "partial"
            db.commit()
        about = {(item["id"], item.get("action")): item for item in client.get("/api/attention").json()
                 if item["kind"] == "source"}
        assert set(about) == {("dns", "card"), ("unifi", "edit")}
        assert about["dns", "card"] == {
            "kind": "source", "id": "dns", "severity": "medium", "at": None, "action": "card",
            "title": "Home DNS could not read everything", "detail": f"{NOTES[GAP][0]}. {NOTES[OTHER][0]}."}
        assert "shorter time window" in about["unifi", "edit"]["detail"]
        with app.state.session_factory() as db:
            pack, _refs = evidence_pack(db, app.state.settings)
            dns = next(item for item in pack["sources"] if item["name"] == "Home DNS")
            assert set(dns) == {"ref", "kind", "name", "provider", "status", "last_collected"}
            sent = json.dumps(pack)
            assert all(text not in sent for text in (GAP, OTHER, NOTES[GAP][0], NOTES[GAP][1], "could not read"))
            # Once it fails, the one "is not collecting" entry covers it.
            db.get(Integration, "dns").status = "error"
            db.commit()
        assert [item["title"] for item in client.get("/api/attention").json() if item["id"] == "dns"] == [
            "Home DNS is not collecting"]
        client.post("/api/auth/logout", headers=live_signin(client))
        live_signin(client, LIVE_MEMBER)
        assert client.get("/api/attention").status_code == 403


def optional_read(status):
    """Make one optional read against a fabricated source that answers with `status`; return the evidence."""
    async def read():
        transport = httpx.MockTransport(lambda request: httpx.Response(status, json={"secret": "10.1.2.3"}))
        async with httpx.AsyncClient(transport=transport) as client:
            reader = core.ReadClient(client, "https://source.example")
            with core.capture_probe() as evidence:
                try:
                    await reader.get("/optional")
                except IntegrationError as error:
                    if core.must_stop(error):
                        raise
                    core.record_gap("optional_unavailable")
                # A limit reached afterwards has no cause of its own.
                core.record_gap("detail_limit")
                return evidence
    return asyncio.run(read())


@pytest.mark.parametrize("status, cause", [(500, {"source_error"}), (503, {"source_error"}), (401, {"refused"}),
                                           (403, {"refused"}), (404, None)])
def test_the_recorder_keeps_why_an_optional_read_was_not_made(status, cause):
    """A server error and a refusal each leave their cause on the gap; another answer leaves none."""
    evidence = optional_read(status)
    assert evidence.gaps == {"optional_unavailable", "detail_limit"}
    assert evidence.gap_causes == ({"optional_unavailable": cause} if cause else {})


def test_a_rate_limit_still_fails_the_collection():
    """A rate limit on an optional read is not a gap."""
    with pytest.raises(IntegrationError) as raised:
        optional_read(429)
    assert raised.value.category == "rate_limit"
