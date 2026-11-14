"""What a screen is told about a guest or an exception matches the record: only an applied change reads as done."""

import pytest
from sqlalchemy import select

from nyctr import assistant
from nyctr.analysis import refresh_findings
from nyctr.models import Audit, GuestAction, Lease, Resource, utcnow


def record(app, device, action, execution, actor="rule"):
    """Store one guest action with a given outcome at the source, then re-run the finding rules."""
    with app.state.session_factory() as db:
        db.add(GuestAction(device_id=device, action=action, actor=actor, execution=execution, created_at=utcnow(),
                           reason="3 lookups of threat-listed addresses in 5 minutes"))
        db.flush()
        refresh_findings(db)
        db.commit()


def told(client, device):
    """Everything the console is told about one guest: its record, its Needs-you rows, its findings, its Map card."""
    guest = next(x for x in client.get("/api/guests").json()["devices"] if x["id"] == device)
    rows = [x for x in client.get("/api/attention").json() if x["id"] == device or x["id"].endswith(":" + device)]
    findings = [x for x in client.get("/api/findings").json() if device in x["resource_ids"] and x["status"] == "open"
                and x["id"].startswith("auto:")]
    card = next(x for x in client.get("/api/graph").json()["nodes"] if x["id"] == device)
    return guest, rows, findings, card


def test_a_simulated_cut_off_is_never_said_as_done(client, admin_headers):
    """The demo's cut-off was simulated: the state says so, and no headline says the device was cut off."""
    guest, rows, findings, card = told(client, "guest-pixel")
    assert (guest["state"], guest["simulated"], guest["attempt"]) == ("cut", True, None)
    assert card["guest_state"] == {"state": "cut", "simulated": True, "attempt": None}
    assert [x["title"] for x in rows] == ["Simulated: Pixel 8 cut off the guest Wi-Fi"]
    assert rows[0]["detail"].startswith("Demo mode never contacts a source, so nothing changed there.")
    assert [x["title"] for x in findings] == ["Simulated: Pixel 8 cut off the guest Wi-Fi"]
    assert "decided to cut this device off. Simulated" in findings[0]["summary"]
    assert "removed this device's guest access" not in findings[0]["summary"]
    answers = [client.post("/api/assistant/ask", headers=admin_headers, json={"question": q}).json()["answer"]
               for q in ("What needs me first?", "Who is on the guest Wi-Fi?")]
    assert "Pixel 8 is cut off (simulated: nothing changed at the source)" in answers[0]
    assert "Pixel 8 is cut off (simulated: nothing changed at the source) at Ground floor access point" in answers[1]
    assert not any("was cut off" in text for text in [*answers, str(rows), str(findings)])


def test_an_applied_cut_off_and_lock_out_read_as_done(client, app, admin_headers):
    """Applied at the source, a cut-off is said plainly, and a lock-out is said as a lock-out, not as a decision due."""
    record(app, "guest-pixel", "cut", "applied")
    guest, rows, findings, card = told(client, "guest-pixel")
    assert (guest["state"], guest["simulated"]) == ("cut", False) and card["guest_state"]["simulated"] is False
    assert [(x["title"], x["severity"], x["detail"]) for x in rows] == [
        ("Pixel 8 was cut off the guest Wi-Fi", "high", "Decide whether to let it back on or lock it out.")]
    assert findings[0]["title"] == "Pixel 8 was cut off the guest Wi-Fi"
    assert "removed this device's guest access" in findings[0]["summary"]
    record(app, "guest-pixel", "lock", "applied", actor="user-admin")
    guest, rows, findings, _card = told(client, "guest-pixel")
    assert (guest["state"], guest["simulated"]) == ("locked", False)
    assert [(x["title"], x["severity"], x["detail"]) for x in rows] == [
        ("Pixel 8 is locked out of the guest Wi-Fi", "low", "It stays locked out until someone lets it back on.")]
    assert findings[0]["title"] == "Pixel 8 is locked out of the guest Wi-Fi"


def test_a_simulated_lock_out_and_letting_on_say_simulated(client, admin_headers):
    """In demo a lock-out and a let-on change nothing at a source, and the state carries that."""
    client.post("/api/guests/actions", headers=admin_headers, json={"device_id": "guest-pixel", "action": "lock"})
    guest, rows, findings, _card = told(client, "guest-pixel")
    assert (guest["state"], guest["simulated"]) == ("locked", True)
    assert [x["title"] for x in rows] == ["Simulated: Pixel 8 locked out of the guest Wi-Fi"]
    assert findings[0]["title"] == "Simulated: Pixel 8 locked out of the guest Wi-Fi"
    client.post("/api/guests/actions", headers=admin_headers, json={"device_id": "guest-pixel", "action": "restore"})
    guest, rows, _findings, _card = told(client, "guest-pixel")
    assert (guest["state"], guest["simulated"]) == ("online", True) and rows == []
    # A state nothing was done to is as the source reported it.
    assert told(client, "guest-priya")[0]["simulated"] is False


@pytest.mark.parametrize("execution", ["not_applied", "failed"])
def test_a_cut_off_that_changed_nothing_leaves_the_device_online(client, app, admin_headers, execution):
    """Decided while read-only, or refused: the device stays as collected and the attempt is told apart."""
    record(app, "guest-hvac", "cut", execution)
    guest, rows, findings, card = told(client, "guest-hvac")
    assert (guest["state"], guest["simulated"]) == ("online", False)
    assert guest["attempt"] == card["guest_state"]["attempt"] == {"action": "cut", "execution": execution}
    assert [x["title"] for x in findings] == ["HVAC-Laptop matched the cut-off rule but is still online"]
    assert [x["title"] for x in rows] == ["HVAC-Laptop matched the cut-off rule but is still online"]


def test_the_map_is_told_a_waiting_guest_apart_from_one_cut_off(client, admin_headers):
    """A guest on the sign-in page never had access taken away; only guests carry a guest state at all."""
    nodes = {x["id"]: x for x in client.get("/api/graph").json()["nodes"]}
    assert nodes["guest-galaxy"]["attributes"]["guest"] == {"authorized": False}
    assert nodes["guest-galaxy"]["guest_state"] == {"state": "waiting", "simulated": False, "attempt": None}
    assert nodes["guest-priya"]["guest_state"]["state"] == "online"
    assert "guest_state" not in nodes["gateway"] and "guest_state" not in nodes["laptop-jamie"]


@pytest.mark.parametrize("execution,open_", [("applied", True), ("simulated", False), ("not_applied", False),
                                             ("failed", False)])
def test_only_an_applied_exception_is_told_to_the_assistant_as_open(client, app, admin_headers, execution, open_):
    """The evidence pack and the sample answer call an exception open only when a source was changed."""
    with app.state.session_factory() as db:
        lease = db.scalars(select(Lease).where(Lease.status == "active")).one()
        lease.execution = execution
        db.commit()
        pack, _refs = assistant.evidence_pack(db, app.state.settings)
    assert [x["domain"] for x in pack["access_open_now"]] == (["assets.supplier-catalogue.example"] if open_ else [])
    assert [x["provider_result"] for x in pack["decided_not_changed_at_source"]] == ([] if open_ else [execution])
    answer = client.post("/api/assistant/ask", headers=admin_headers,
                         json={"question": "What is open right now?"}).json()["answer"]
    if open_:
        assert answer.startswith("1 exception is open.") and "changed nothing" not in answer
    else:
        assert answer.startswith("Nothing is open at a source right now. 1 decided here changed nothing at a source")
        assert "exception is open" not in answer


def test_a_decision_with_no_note_keeps_the_note_empty(client, admin_headers):
    """No note typed means no note stored: the member is not shown the decision repeated as a note."""
    done = client.post("/api/requests/request-stream/review", headers=admin_headers, json={"decision": "denied"})
    assert done.status_code == 200 and done.json()["status"] == "denied" and done.json()["review_note"] == ""


@pytest.mark.parametrize("names_read,gap,unread", [(False, True, ["Northgate UniFi Network"]), (False, False, []),
                                                   (True, True, [])])
def test_wifi_names_that_could_not_be_read_are_told_apart_from_no_sign_in_page(client, app, admin_headers,
                                                                             names_read, gap, unread):
    """A site with no Wi-Fi names after a collection that recorded a gap: the names were not read there."""
    with app.state.session_factory() as db:
        site = db.get(Resource, "site-home")
        if not names_read:
            site.attributes = {key: value for key, value in site.attributes.items() if key != "wifi"}
        if gap:
            db.add(Audit(action="integration.collected", target_id="demo-unifi", details={"gaps": ["fabricated_gap"]}))
        db.commit()
    portal = client.get("/api/guests").json()["portal"]
    assert portal["unread"] == unread and bool(portal["wifi"]) is names_read
