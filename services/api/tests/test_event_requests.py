"""An ordinary event request stays the row with no device, beside any planted device row."""

import pytest
from conftest import signin
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session
from test_tiers import postgres_database

from nyctr.config import Settings
from nyctr.main import create_app
from nyctr.models import AccessRequest, Audit

BOTH = pytest.mark.parametrize("database", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])


def open_demo(database, tmp_path, request, name, **overrides):
    """A demo API on this case's own database. PostgreSQL is skipped when no server is named."""
    if database == "sqlite":
        url = f"sqlite:///{tmp_path}/{name}.db"
    else:
        url = postgres_database(request)
        if not url:
            pytest.skip("No PostgreSQL server is named in NYCTR_TEST_POSTGRES")
    values = {"mode": "demo", "database_url": url, "public_url": "http://testserver",
              "cookie_secure": False, "worker_enabled": False}
    values.update(overrides)
    return create_app(Settings(**values))


def _plant_request(app, id_, block_id, device_id, device_name, domain, *, requester="user-jamie",
                   basis="statement", status="analysing", reason="Named on this device"):
    """Store one request directly. A statement names its device. An event leaves the device empty."""
    with app.state.session_factory() as db:
        db.add(AccessRequest(
            id=id_, block_id=block_id, domain=domain, device_name=device_name, device_id=device_id,
            requester_id=requester, reason=reason, duration_minutes=60, status=status, basis=basis))
        db.commit()


def _clear_basis(app, request_id):
    """Leave the basis empty, as a row stored before that column was."""
    with app.state.session_factory() as db:
        db.execute(text("UPDATE access_requests SET basis = NULL WHERE id = :id"), {"id": request_id})
        db.commit()


def _block_rows(app, block_id):
    """Every stored request for this block, and how many there are."""
    with app.state.session_factory() as db:
        rows = list(db.scalars(select(AccessRequest).where(AccessRequest.block_id == block_id)
                               .order_by(AccessRequest.id)))
        count = db.scalar(select(func.count()).select_from(AccessRequest).where(AccessRequest.block_id == block_id))
        stored = [(row.id, row.requester_id, row.device_id, row.basis, row.status, row.reason,
                   row.device_name) for row in rows]
    return count, stored


def _basis_of(app, request_id):
    """The basis as stored, so a loaded copy cannot fill the column's usual value."""
    with app.state.session_factory() as db:
        return db.execute(text("SELECT basis FROM access_requests WHERE id = :id"), {"id": request_id}).scalar()


def _ask_event(client, headers, block_id, reason):
    """File the event for a block the member can already see."""
    return client.post("/api/requests", headers=headers, json={
        "block_id": block_id, "reason": reason, "duration_minutes": 60})


@BOTH
def test_an_event_request_stays_the_event_beside_statements(tmp_path, database, request, monkeypatch):
    """A statement for another device is not the event, whichever row was stored first.

    The same member can have a statement on two devices and one event. Asking again
    returns that event. A row with no basis is still that event. A hidden or expired
    block is still refused.
    """
    app = open_demo(database, tmp_path, request, "event-beside")
    started = []

    async def record(_app, request_id):
        started.append(request_id)

    monkeypatch.setattr("nyctr.main._finish_request", record)
    with TestClient(app) as client:
        headers = signin(client, member=True)
        first = _ask_event(client, headers, "block-fonts", "Need the fonts")
        assert first.status_code == 201, first.text
        event_id = first.json()["id"]
        assert first.json()["status"] == "analysing" and first.json()["device_name"] == "Jamie's MacBook"
        assert first.json()["reason"] == "Need the fonts" and started == [event_id]
        _plant_request(app, "stmt-fonts-phone", "block-fonts", "phone-jamie", "AAA phone",
                       "fonts.partner-metrics.example")
        _plant_request(app, "stmt-fonts-laptop", "block-fonts", "laptop-jamie", "Lobby handset",
                       "fonts.partner-metrics.example")
        _plant_request(app, "stmt-fonts-admin", "block-fonts", "workstation", "Alex's workstation",
                       "fonts.partner-metrics.example", requester="user-admin", reason="Named for someone else")
        again = _ask_event(client, headers, "block-fonts", "Need the fonts")
        assert again.status_code == 201, again.text
        assert again.json()["id"] == event_id and again.json()["reason"] == "Need the fonts"
        assert "stmt-fonts-phone" not in again.text and "stmt-fonts-laptop" not in again.text
        assert "AAA phone" not in again.text and "Lobby handset" not in again.text
        assert "Named on this device" not in again.text and started == [event_id]
        count, rows = _block_rows(app, "block-fonts")
        assert count == 4 and len(rows) == 4
        assert (event_id, "user-jamie", None, "event", "analysing", "Need the fonts", "Jamie's MacBook") in rows
        assert ("stmt-fonts-phone", "user-jamie", "phone-jamie", "statement", "analysing",
                "Named on this device", "AAA phone") in rows
        assert ("stmt-fonts-laptop", "user-jamie", "laptop-jamie", "statement", "analysing",
                "Named on this device", "Lobby handset") in rows
        assert ("stmt-fonts-admin", "user-admin", "workstation", "statement", "analysing",
                "Named for someone else", "Alex's workstation") in rows
        _clear_basis(app, event_id)
        emptied = _ask_event(client, headers, "block-fonts", "Need the fonts")
        assert emptied.status_code == 201 and emptied.json()["id"] == event_id
        assert started == [event_id] and _basis_of(app, event_id) is None
        count, rows = _block_rows(app, "block-fonts")
        assert count == 4
        kept = next(row for row in rows if row[0] == event_id)
        assert kept[2] is None and kept[3] is None and kept[4] == "analysing"

        _plant_request(app, "stmt-gallery-phone", "block-gallery", "phone-jamie", "AAA phone",
                       "click.proofing-studio.example")
        _plant_request(app, "stmt-gallery-laptop", "block-gallery", "laptop-jamie", "Lobby handset",
                       "click.proofing-studio.example")
        _plant_request(app, "stmt-gallery-admin", "block-gallery", "workstation", "Alex's workstation",
                       "click.proofing-studio.example", requester="user-admin", reason="Named for someone else")
        filed = _ask_event(client, headers, "block-gallery", "Need the picture")
        assert filed.status_code == 201, filed.text
        gallery_id = filed.json()["id"]
        assert gallery_id not in {"stmt-gallery-phone", "stmt-gallery-laptop", "stmt-gallery-admin"}
        assert filed.json()["status"] == "analysing" and filed.json()["reason"] == "Need the picture"
        assert filed.json()["device_name"] == "Jamie's MacBook"
        assert "stmt-gallery-phone" not in filed.text and "AAA phone" not in filed.text
        assert "Named on this device" not in filed.text and started == [event_id, gallery_id]
        count, rows = _block_rows(app, "block-gallery")
        assert count == 4 and len(rows) == 4
        assert (gallery_id, "user-jamie", None, "event", "analysing", "Need the picture",
                "Jamie's MacBook") in rows
        assert ("stmt-gallery-phone", "user-jamie", "phone-jamie", "statement", "analysing",
                "Named on this device", "AAA phone") in rows
        assert ("stmt-gallery-laptop", "user-jamie", "laptop-jamie", "statement", "analysing",
                "Named on this device", "Lobby handset") in rows
        assert ("stmt-gallery-admin", "user-admin", "workstation", "statement", "analysing",
                "Named for someone else", "Alex's workstation") in rows
        repeat = _ask_event(client, headers, "block-gallery", "Need the picture")
        assert repeat.status_code == 201 and repeat.json()["id"] == gallery_id
        assert started == [event_id, gallery_id]
        count_again, _rows = _block_rows(app, "block-gallery")
        assert count_again == 4
        hidden = _ask_event(client, headers, "block-washer", "Need the display")
        assert hidden.status_code == 404 and hidden.json()["detail"] == "Block event not found"
        assert "stmt-gallery-phone" not in hidden.text and gallery_id not in hidden.text
        expired = _ask_event(client, headers, "block-expired", "Need the archive")
        assert expired.status_code == 409
        assert expired.json()["detail"] == "This block event has expired. Try accessing the site again."
        assert "stmt-gallery-phone" not in expired.text and gallery_id not in expired.text
        assert _block_rows(app, "block-gallery")[0] == 4 and started == [event_id, gallery_id]

        plain = _ask_event(client, headers, "block-print", "Need the page")
        assert plain.status_code == 201, plain.text
        print_id = plain.json()["id"]
        same = _ask_event(client, headers, "block-print", "Need the page")
        assert same.status_code == 201 and same.json()["id"] == print_id
        assert started == [event_id, gallery_id, print_id]
        count, rows = _block_rows(app, "block-print")
        assert count == 1 and rows[0][0] == print_id and rows[0][2] is None and rows[0][3] == "event"


@BOTH
def test_a_conflicting_event_returns_the_stored_event(tmp_path, database, request, monkeypatch):
    """When two event filings meet, the stored event comes back, not a statement on that block.

    The first look is made to miss, as it would if the other filing had not committed yet.
    The insert then hits the existing event. The row that was stored before the basis
    column is the one returned, and neither statement changes.
    """
    app = open_demo(database, tmp_path, request, "event-conflict")
    started = []

    async def record(_app, request_id):
        started.append(request_id)

    monkeypatch.setattr("nyctr.main._finish_request", record)
    state = {"hidden": 0}
    real = Session.scalar

    def hide_first_event(self, statement, params=None, **kwargs):
        sql = str(statement)
        if state["hidden"] == 0 and "access_requests" in sql and "device_id IS NULL" in sql:
            state["hidden"] = 1
            return None
        return real(self, statement, params, **kwargs)

    with TestClient(app) as client:
        headers = signin(client, member=True)
        _plant_request(app, "stmt-print-phone", "block-print", "phone-jamie", "AAA phone", "cdn.printshop.example")
        _plant_request(app, "stmt-print-laptop", "block-print", "laptop-jamie", "Lobby handset",
                       "cdn.printshop.example")
        _plant_request(app, "event-print", "block-print", None, "Jamie's MacBook", "cdn.printshop.example",
                       basis="event", status="pending", reason="Already filed")
        _clear_basis(app, "event-print")
        assert _basis_of(app, "event-print") is None
        monkeypatch.setattr(Session, "scalar", hide_first_event)
        filed = _ask_event(client, headers, "block-print", "Need the page")
        assert filed.status_code == 201, filed.text
        assert state["hidden"] == 1
        assert filed.json()["id"] == "event-print"
        assert filed.json()["status"] == "pending" and filed.json()["reason"] == "Already filed"
        assert filed.json()["device_name"] == "Jamie's MacBook"
        assert "stmt-print-phone" not in filed.text and "stmt-print-laptop" not in filed.text
        assert "AAA phone" not in filed.text and "Named on this device" not in filed.text
        assert started == []
        count, rows = _block_rows(app, "block-print")
        assert count == 3 and len(rows) == 3
        assert ("event-print", "user-jamie", None, None, "pending", "Already filed", "Jamie's MacBook") in rows
        assert ("stmt-print-phone", "user-jamie", "phone-jamie", "statement", "analysing",
                "Named on this device", "AAA phone") in rows
        assert ("stmt-print-laptop", "user-jamie", "laptop-jamie", "statement", "analysing",
                "Named on this device", "Lobby handset") in rows
        assert _basis_of(app, "event-print") is None
        with app.state.session_factory() as db:
            audits = list(db.scalars(select(Audit).where(
                Audit.action == "access.requested", Audit.target_id == "event-print")))
        assert audits == []
