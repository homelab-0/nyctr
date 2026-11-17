"""Notices: one outbox row with the thing it reports, sent off the server's loop."""

import asyncio
import json
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
from conftest import LIVE_ADMIN, LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import OperationalError
from test_collection_store import POSTGRES, postgres_database

from nyctr import access, assistant, notices, worker
from nyctr.config import Settings
from nyctr.database import make_engine, migrate, session_factory
from nyctr.models import Lease, Notice, utc, utcnow

SECRET = "notice-secret-VALUE-99"
ASK = {"block_id": "dns:block:one", "reason": "Please allow this", "duration_minutes": 30}


class _Receiver(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        touch = "ok"
        if getattr(self.server, "touch", None):
            try:
                self.server.touch()
            except Exception as error:  # noqa: BLE001 - the test records the failure instead of dropping it
                touch = type(error).__name__
        self.server.hits.append({"body": body, "path": self.path,
                                  "headers": {key.lower(): value for key, value in self.headers.items()},
                                  "thread": threading.get_ident(), "touch": touch})
        raw = getattr(self.server, "raw", None)
        if raw is not None:
            self.connection.sendall(raw)
            self.close_connection = True
            return
        if getattr(self.server, "trickle_head", False):
            blob = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
            for piece in blob:
                end = time.monotonic() + 0.4
                while time.monotonic() < end:
                    if getattr(self.server, "stop", False):
                        return
                    time.sleep(0.05)
                try:
                    self.connection.sendall(bytes([piece]))
                except OSError:
                    return
            return
        if getattr(self.server, "trickle", False):
            self.send_response(200)
            self.send_header("Content-Length", "30")
            self.end_headers()
            for _ in range(30):
                end = time.monotonic() + 0.5
                while time.monotonic() < end:
                    if getattr(self.server, "stop", False):
                        return
                    time.sleep(0.05)
                try:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                except OSError:
                    return
            self.server.finished = True
            return
        code = self.server.codes.pop(0) if self.server.codes else 204
        data = b"" if code in range(300, 400) or code == 204 else b"ok"
        self.send_response(code)
        if 300 <= code < 400:
            self.send_header("Location", self.server.location)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def log_message(self, *_args):
        return


def _serve(codes, location="http://127.0.0.1:9/nowhere"):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Receiver)
    server.codes, server.hits, server.location, server.touch = list(codes), [], location, None
    server.raw, server.trickle, server.trickle_head = None, False, False
    server.finished, server.stop = False, False
    threading.Thread(target=server.serve_forever, daemon=True).start()
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(server.server_address, 0.2):
                return server
        except OSError:
            time.sleep(0.01)
    server.shutdown()
    raise RuntimeError("receiver did not start")


def _close(server):
    server.stop = True
    server.shutdown()
    server.server_close()


def _engine(tmp_path, url=None):
    engine = make_engine(url or f"sqlite:///{tmp_path}/notices.db")
    migrate(engine)
    return engine, session_factory(engine)


def _settings(origin):
    return Settings(mode="live", database_url="sqlite:///:memory:", public_url="https://console.example",
                    cookie_secure=False, worker_enabled=False, notice_hosts=origin)


def _arm(factory, settings, origin, secret_ref=""):
    with factory() as db:
        notices.save(db, settings, notices.PutBody(target=f"{origin}/hook", secret_ref=secret_ref))
        notice = notices._queue_test(db, settings)
        db.commit()
        return notice.id


@pytest.fixture(autouse=True)
def _reset():
    notices.pause = None
    yield
    notices.pause = None


def test_a_waiting_request_writes_one_notice_and_a_rolled_back_request_writes_none(tmp_path):
    """A request that waits writes one notice. Asking again does not write a second."""
    app = live_app(tmp_path, public_url="https://console.example")
    with TestClient(app) as client:
        seed_live_member(app)
        member = live_signin(client, LIVE_MEMBER)
        made = client.post("/api/requests", headers=member, json=ASK)
        assert made.status_code == 201, made.text
        again = client.post("/api/requests", headers=member, json=ASK)
        assert again.status_code == 201
        with app.state.session_factory() as db:
            rows = db.scalars(select(Notice)).all()
            assert len(rows) == 1 and rows[0].kind == "request_waiting" and rows[0].subject == made.json()["id"]
            body = json.dumps(rows[0].payload)
            assert rows[0].payload["request"]["score"] == made.json()["risk_score"]
            assert rows[0].payload["request"]["score"] != 0 or made.json()["risk_score"] == 0
            assert "10.0.0.9" not in body and "token=" not in rows[0].payload["link"]
            assert rows[0].payload["link"] == f"https://console.example/#/requests?id={made.json()['id']}"
            assert list(parse_qs(rows[0].payload["link"].split("?", 1)[1])) == ["id"]
            from nyctr.models import AccessRequest
            stored = db.scalar(select(AccessRequest))
            stored.status = "approved"
            assert notices.waiting(db, app.state.settings, stored) is None
            assert len(db.scalars(select(Notice)).all()) == 1


def test_a_failed_call_rolls_the_notice_back_with_the_decision(tmp_path, monkeypatch):
    """A request whose decision does not commit leaves the request without a notice."""
    app = live_app(tmp_path)
    real = notices.waiting

    def boom(db, settings, row):
        real(db, settings, row)
        raise RuntimeError("stop")

    monkeypatch.setattr(notices, "waiting", boom)
    with TestClient(app) as client:
        seed_live_member(app)
        member = live_signin(client, LIVE_MEMBER)
        with pytest.raises(RuntimeError, match="stop"):
            client.post("/api/requests", headers=member, json=ASK)
    with app.state.session_factory() as db:
        from nyctr.models import AccessRequest
        stored = db.scalar(select(AccessRequest))
        assert stored is not None and stored.decision_note is None
        assert db.scalars(select(Notice)).all() == []


def test_an_opening_that_cannot_be_removed_writes_one_notice(tmp_path):
    """A removal that fails, and a source that is gone, each leave one notice. A later try adds none."""
    app = live_app(tmp_path, public_url="https://console.example")
    with TestClient(app):
        seed_live_member(app)
        with app.state.session_factory() as db:
            db.add(Lease(id="open-1", integration_id="dns", domain="click.proofing-studio.example",
                         execution="applied", owned=True, status="active"))
            db.add(Lease(id="open-2", integration_id="missing", domain="gone.example",
                         execution="applied", owned=True, status="active"))
            db.commit()

        async def close(lease_id):
            with app.state.session_factory() as db:
                lease = db.get(Lease, lease_id)
                assert await access.end_lease(db, app.state.settings, lease, "expired") is False
                db.commit()

        asyncio.run(close("open-1"))
        asyncio.run(close("open-1"))
        asyncio.run(close("open-2"))
        asyncio.run(close("open-2"))
        with app.state.session_factory() as db:
            rows = db.scalars(select(Notice).where(Notice.kind == "lease_stuck").order_by(Notice.subject)).all()
            assert [row.subject for row in rows] == ["open-1", "open-2"]
            dumped = json.dumps([row.payload for row in rows])
            assert "not configured" not in dumped and "by hand" not in dumped and "10.0.0.9" not in dumped

        async def abort():
            with app.state.session_factory() as db:
                lease = Lease(id="open-3", integration_id="missing", domain="other.example",
                              execution="applied", owned=True, status="active")
                db.add(lease)
                db.commit()
                assert await access.end_lease(db, app.state.settings, db.get(Lease, "open-3"), "expired") is False
                db.rollback()

        asyncio.run(abort())
        with app.state.session_factory() as db:
            assert db.get(Notice, "open-3") is None
            assert db.scalar(select(Notice.id).where(Notice.subject == "open-3")) is None


def _clock(start):
    box = [start]

    def now():
        return box[0]
    return box, now


def test_retries_follow_the_schedule_and_giving_up_is_listed(tmp_path):
    """Five tries: at once, then after 1, 5, 15 and 60 minutes. The fifth failure is listed."""
    server = _serve([500, 500, 500, 500, 500])
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _engine_done, factory = _engine(tmp_path)
        settings = _settings(origin)
        start = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
        box, now = _clock(start)
        with factory() as db:
            notices.save(db, settings, notices.PutBody(target=f"{origin}/hook"))
            db.add(Notice(id="n-retry", kind="test", subject="test", state="due", attempts=0, next_try_at=start,
                          created_at=start, payload={"v": 1, "id": "n-retry", "kind": "test", "at": start.isoformat(),
                                                     "nyctr": "0.1.0-alpha.6", "title": "Waiting", "lines": ["One."],
                                                     "request": None, "link": "https://console.example/#/setup?tab=system"}))
            db.commit()
        assert notices.DELAYS == (60, 300, 900, 3600) and notices.TRIES == 5
        for delay in notices.DELAYS:
            notices.deliver_due(factory, settings, now)
            box[0] = box[0] + timedelta(seconds=delay - 1)
            quiet = len(server.hits)
            notices.deliver_due(factory, settings, now)
            assert len(server.hits) == quiet
            box[0] = box[0] + timedelta(seconds=1)
        notices.deliver_due(factory, settings, now)
        assert len(server.hits) == 5
        with factory() as db:
            row = db.get(Notice, "n-retry")
            assert row.state == "gave_up" and row.attempts == 5
            assert any(item["kind"] == "notice" and item["id"] == "n-retry"
                       for item in assistant.attention(db, settings))
            assert "five times" in notices.words(row)
    finally:
        _close(server)


@pytest.mark.parametrize("status,state", [(201, "sent"), (204, "sent"), (400, "gave_up"), (302, "gave_up"),
                                           (408, "due"), (429, "due")])
def test_the_status_either_sends_retries_or_gives_up(tmp_path, status, state):
    """A 2xx is sent. 408 and 429 are tried again. Any other 4xx, and a redirect, gives up at once."""
    other = _serve([])
    server = _serve([status], location=f"http://127.0.0.1:{other.server_address[1]}/gone")
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _done, factory = _engine(tmp_path)
        settings = _settings(origin)
        notice_id = _arm(factory, settings, origin)
        assert notices.deliver_due(factory, settings) == [state]
        with factory() as db:
            row = db.get(Notice, notice_id)
            assert row.state == state and row.last_status == status
            if state == "gave_up" and status == 400:
                assert "refused" in notices.words(row)
            if status == 302:
                assert "somewhere else" in notices.words(row)
        assert other.hits == []
        assert len(server.hits) == 1
    finally:
        _close(server)
        _close(other)


def test_a_restart_between_tries_sends_the_notice_once(tmp_path):
    """A claim left by a dead copy is not taken while it is fresh, and is sent once it is old."""
    server = _serve([204])
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _done, factory = _engine(tmp_path)
        settings = _settings(origin)
        start = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
        box, now = _clock(start)
        with factory() as db:
            notices.save(db, settings, notices.PutBody(target=f"{origin}/hook"))
            db.add(Notice(id="n-dead", kind="test", subject="n-dead", state="sending", attempts=0,
                          next_try_at=start, created_at=start, claimed_by="dead", claimed_at=start,
                          payload=_tiny("n-dead")))
            db.commit()
        assert notices.deliver_due(factory, settings, now) == []
        assert server.hits == []
        box[0] = start + timedelta(seconds=notices.CLAIM_TTL + 1)
        assert notices.deliver_due(factory, settings, now) == ["sent"]
        assert notices.deliver_due(factory, settings, now) == []
        assert len(server.hits) == 1
        assert server.hits[0]["headers"]["x-nyctr-notice-id"] == "n-dead"
    finally:
        _close(server)


def test_the_signature_matches_the_body_and_a_missing_secret_is_unsigned(tmp_path, monkeypatch):
    """The header verifies with the secret and fails when the body changes. With no secret, nothing is signed."""
    body = b'{"v":1,"kind":"test"}'
    header = notices.signature(SECRET, body, 1_700_000_000)
    assert notices.verify(SECRET, body, header)
    assert not notices.verify(SECRET, body + b" ", header)
    assert not notices.verify(SECRET, body, "t=1700000001,v1=" + header.split("v1=", 1)[1])
    assert not notices.verify("other-secret-value", body, header)
    server = _serve([204, 204])
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _done, factory = _engine(tmp_path)
        settings = _settings(origin)
        monkeypatch.setenv("NYCTR_NOTICE_SECRET_TEST", SECRET)
        signed = _arm(factory, settings, origin, "NYCTR_NOTICE_SECRET_TEST")
        notices.deliver_due(factory, settings)
        hit = server.hits[0]
        assert notices.verify(SECRET, hit["body"], hit["headers"]["x-nyctr-signature"])
        assert SECRET not in hit["body"].decode()
        with factory() as db:
            described = notices.describe(db, settings)
            assert described["unsigned"] is False and described["secret_ref"] == "NYCTR_NOTICE_SECRET_TEST"
            assert SECRET not in json.dumps(described)
        monkeypatch.delenv("NYCTR_NOTICE_SECRET_TEST")
        with factory() as db:
            notices.save(db, settings, notices.PutBody(target=f"{origin}/hook", secret_ref=""))
            notice = notices._queue_test(db, settings)
            db.commit()
            described = notices.describe(db, settings)
            assert described["unsigned"] is True and "without a signature" in described["signing"]
            plain = notice.id
        notices.deliver_due(factory, settings, only=frozenset({plain}))
        assert "x-nyctr-signature" not in server.hits[-1]["headers"]
        assert server.hits[-1]["headers"]["x-nyctr-notice-id"] == plain
        # A named secret that holds a line break is not sent, and not sent unsigned.
        monkeypatch.setenv("NYCTR_NOTICE_SECRET_TEST", "line\nbreak")
        with factory() as db:
            notices.save(db, settings, notices.PutBody(target=f"{origin}/hook", secret_ref="NYCTR_NOTICE_SECRET_TEST"))
            held = notices._queue_test(db, settings)
            db.commit()
            assert "cannot be used" in (notices.describe(db, settings)["problem"] or "")
            held_id = held.id
        assert notices.deliver_due(factory, settings) == []
        with factory() as db:
            assert db.get(Notice, held_id).state == "due" and db.get(Notice, held_id).attempts == 0
            assert db.get(Notice, signed).state == "sent"
        assert len(server.hits) == 2
    finally:
        _close(server)


def test_a_notice_goes_only_where_it_is_allowed(tmp_path, monkeypatch):
    """Plain HTTP, a redirect, a non-public address and a password in the address are refused unless listed."""
    settings = _settings("")
    with pytest.raises(notices.Refused):
        notices.vet("http://hooks.example/hook", settings, lookup=lambda *_a: ["1.1.1.1"])
    with pytest.raises(notices.Refused):
        notices.vet("https://user:s3cret-pass@hooks.example/hook", settings, lookup=lambda *_a: ["1.1.1.1"])
    with pytest.raises(notices.Refused):
        notices.vet("https://hooks.example/hook?token=1", settings, lookup=lambda *_a: ["1.1.1.1"])
    for blocked in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "::ffff:10.0.0.1", "::127.0.0.1",
                    "::ffff:0:7f00:1", "::ffff:0:1.1.1.1", "64:ff9b::7f00:1", "64:ff9b::a00:1",
                    "64:ff9b::101:101", "::", "224.0.0.1", "ff02::1"):
        with pytest.raises(notices.Refused):
            notices.vet(f"https://{blocked}/hook" if ":" not in blocked else f"https://[{blocked}]/hook", settings)
    with pytest.raises(notices.Refused):
        notices.vet("https://metadata.google.internal/hook", settings, lookup=lambda *_a: ["1.1.1.1"])
    with pytest.raises(notices.Refused):
        notices.vet("https://hooks.example/hook", settings, lookup=lambda *_a: ["1.1.1.1", "10.9.8.7"])
    allowed = Settings(mode="live", database_url="sqlite:///:memory:", public_url="https://console.example",
                       cookie_secure=False, worker_enabled=False,
                       notice_hosts="https://metadata.google.internal, https://10.0.0.1, http://hooks.example")
    assert notices.vet("https://metadata.google.internal/hook", allowed, lookup=lambda *_a: ["1.1.1.1"]).listed
    assert notices.vet("http://hooks.example/hook", allowed, lookup=lambda *_a: ["1.1.1.1"]).scheme == "http"
    assert notices.vet("https://10.0.0.1/hook", allowed).ip == "10.0.0.1"
    plan = notices.vet("https://hooks.example/hook", settings, lookup=lambda *_a: ["1.1.1.1"])
    assert plan.ip == "1.1.1.1" and ipaddress_is_global(plan.ip)

    server = _serve([204, 302, 204])
    other = _serve([])
    server.location = f"http://127.0.0.1:{other.server_address[1]}/gone"
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _done, factory = _engine(tmp_path)
        bare = _settings("")
        with factory() as db:
            # The address is stored only when the shape is allowed, so this one is written past the form.
            db.add(notices_setting(f"http://127.0.0.1:{server.server_address[1]}/hook"))
            db.add(Notice(id="blocked", kind="test", subject="t", state="due", attempts=0, next_try_at=utcnow(),
                          created_at=utcnow(), payload=_tiny("blocked")))
            db.commit()
        assert notices.deliver_due(factory, bare) == ["gave_up"]
        assert server.hits == []
        listed = _settings(origin)
        with factory() as db:
            notices.save(db, listed, notices.PutBody(target=f"http://user:s3cret-pass@{origin.split('://', 1)[1]}/hook"))
            db.add(Notice(id="plain", kind="test", subject="t2", state="due", attempts=0, next_try_at=utcnow(),
                          created_at=utcnow(), payload=_tiny("plain")))
            db.commit()
            assert "s3cret-pass" not in notices.describe(db, listed)["target"]
        notices.deliver_due(factory, listed, only=frozenset({"plain"}))
        notices.deliver_due(factory, listed)  # the redirect, then nothing else is due
        assert other.hits == []
        shown = [{**hit, "body": hit["body"].decode()} for hit in server.hits]
        assert all("s3cret-pass" not in json.dumps(item) for item in shown)
        monkeypatch.setattr(notices.socket, "create_connection", lambda *_a, **_k: _peer("10.0.0.2"))
        with pytest.raises(notices.Refused):
            notices._post(notices.Plan("http", "127.0.0.1", 9, "/", "127.0.0.1", True), b"{}", {})
    finally:
        _close(server)
        _close(other)


def ipaddress_is_global(value):
    import ipaddress
    return ipaddress.ip_address(value).is_global


def notices_setting(target):
    from nyctr.models import Setting
    return Setting(key=notices.KEY, value={"target": target, "secret_ref": ""})


def _tiny(notice_id):
    return {"v": 1, "id": notice_id, "kind": "test", "at": "2026-11-16T12:00:00+00:00", "nyctr": "0.1.0-alpha.6",
            "title": "Test", "lines": ["One."], "request": None, "link": "https://console.example/#/setup?tab=system"}


def _peer(address):
    class Sock:
        def getpeername(self):
            return (address, 9)

        def settimeout(self, _timeout):
            return None

        def close(self):
            return None

        def sendall(self, _data):
            raise AssertionError("sent")
    return Sock()


def test_the_payload_has_no_secret_and_the_link_has_no_token(tmp_path, monkeypatch):
    """Whatever is written into the request, the body keeps none of it and the link has one id."""
    import random

    monkeypatch.setenv("NYCTR_NOTICE_SECRET_TEST", SECRET)
    engine, factory = _engine(tmp_path)
    settings = Settings(mode="live", database_url="sqlite:///:memory:", public_url="https://console.example",
                        cookie_secure=False, worker_enabled=False)
    junk = [SECRET, "203.0.113.10", "2001:db8::99", "aa:bb:cc:dd:ee:ff", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff",
            "person@example.com"]
    rng = random.Random(20261115)
    with factory() as db:
        from nyctr.models import Integration, Observation, User
        db.add(Integration(id="dns", provider="acme_dns", name="Office DNS", status="connected"))
        db.add(User(id="sam", email="sam@example.net", name="Sam", role="member"))
        notices.save(db, settings, notices.PutBody(secret_ref="NYCTR_NOTICE_SECRET_TEST"))
        db.commit()
        fields = notices._request_fields(SimpleNamespace(id="r", domain="a.example", device_name="lap",
                                                         risk_score=True, duration_minutes=True), "Sam", "because", "")
        assert fields["score"] is None and fields["minutes"] is None
        assert notices._request_fields(SimpleNamespace(id="r", domain="a.example", device_name="lap", risk_score=0,
                                                       duration_minutes=15), "Sam", "because", "")["score"] == 0
        for number in range(12):
            picked = rng.sample(junk, k=4)
            db.add(User(id=f"u{number}", email=f"u{number}@example.net", name=picked[0], role="member"))
            db.add(Observation(id=f"b{number}", integration_id="dns", device_name=picked[1], domain=picked[2],
                               source="acme_dns", reason=picked[3], observed_at=utcnow(),
                               expires_at=utcnow() + timedelta(hours=1), evidence_kind="observed",
                               attribution="assigned", risk_score=None, risk_explanation=""))
            db.flush()
            from nyctr.models import AccessRequest
            row = AccessRequest(id=f"r{number}" if number else "a&token=1", block_id=f"b{number}", domain=picked[2],
                                device_name=picked[1], requester_id=f"u{number}", reason="because the member asked",
                                duration_minutes=30, status="pending", decision_note=f"{picked[0]}\n{picked[3]}",
                                risk_score=None)
            db.add(row)
            db.flush()
            notice = notices.waiting(db, settings, row)
            db.commit()
            payload = db.get(Notice, notice.id).payload
            dumped = json.dumps(payload)
            for piece in junk:
                assert piece not in dumped
            assert payload["request"]["score"] is None
            assert set(payload["request"]) == {"id", "address", "device", "person", "reason", "score", "minutes"}
            assert len(payload["lines"]) <= 3 and all(len(line) <= 120 for line in payload["lines"])
            query = parse_qs(payload["link"].split("?", 1)[1])
            assert list(query) == ["id"] and "token=" not in payload["link"]
            assert payload["link"].startswith("https://console.example/#/requests?id=")
    engine.dispose()


def test_routes_refuse_a_member_the_portal_and_no_session_and_the_test_sends(tmp_path, monkeypatch):
    """Only an administrator on the console can read, save or test. The test sends one notice of kind test."""
    server = _serve([204])
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        app = live_app(tmp_path, public_url="http://console.test", portal_url="http://portal.test", notice_hosts=origin)
        with TestClient(app, base_url="http://console.test") as desk, \
                TestClient(app, base_url="http://portal.test") as portal:
            seed_live_member(app)
            for method, path in (("GET", "/api/notices"), ("PUT", "/api/notices"), ("POST", "/api/notices/test")):
                assert desk.request(method, path, json={}).status_code == 401
                assert portal.request(method, path, json={}).status_code == 401
            member = live_signin(portal, LIVE_MEMBER)
            owner = live_signin(portal, LIVE_ADMIN)
            for method, path in (("GET", "/api/notices"), ("PUT", "/api/notices"), ("POST", "/api/notices/test")):
                assert portal.request(method, path, headers=member, json={}).status_code == 403
                assert portal.request(method, path, headers=owner, json={}).status_code == 403
            admin = live_signin(desk, LIVE_ADMIN)
            assert desk.put("/api/notices", json={"target": f"{origin}/hook"}).status_code == 403
            typed = "typed-secret-value-not-a-name"
            refused = desk.put("/api/notices", headers=admin, json={"target": f"{origin}/hook", "secret": typed})
            assert refused.status_code == 422 and typed not in refused.text
            assert desk.post("/api/notices/test", headers=admin).status_code == 409
            saved = desk.put("/api/notices", headers=admin, json={"target": f"{origin}/hook", "secret_ref": ""})
            assert saved.status_code == 200 and saved.json()["unsigned"] is True
            monkeypatch.setenv("NYCTR_NOTICE_SECRET_TEST", SECRET)
            named = desk.put("/api/notices", headers=admin,
                             json={"target": f"{origin}/hook", "secret_ref": "NYCTR_NOTICE_SECRET_TEST"})
            assert named.status_code == 200 and SECRET not in named.text
            tested = desk.post("/api/notices/test", headers=admin)
            assert tested.status_code == 200, tested.text
            assert tested.json()["recent"][0]["kind"] == "test" and tested.json()["recent"][0]["words"] == "Sent."
            assert SECRET not in tested.text
            monkeypatch.setenv("NYCTR_NOTICE_SECRET_TEST", "a\nb")
            broken = desk.post("/api/notices/test", headers=admin)
            assert broken.status_code == 409 and "cannot be used" in broken.text
            assert "not set on the server" not in broken.text
        assert len(server.hits) == 1 and notices.verify(SECRET, server.hits[0]["body"],
                                                        server.hits[0]["headers"]["x-nyctr-signature"])
        with app.state.session_factory() as db:
            from nyctr.models import Audit
            audits = db.scalars(select(Audit).where(Audit.action.in_(("notices.changed", "notices.tested")))).all()
            assert audits and SECRET not in json.dumps([row.details for row in audits])
    finally:
        _close(server)


def test_the_demo_workspace_cannot_set_a_notice(client, admin_headers):
    """The demo password is public, so nothing there can point Nyctr at an address."""
    assert client.put("/api/notices", headers=admin_headers, json={"target": "https://hooks.example/hook"}).status_code == 409
    assert client.post("/api/notices/test", headers=admin_headers).status_code == 409


def test_upkeep_sends_off_the_loop(tmp_path, monkeypatch):
    """The tick's send runs on a worker thread, not on the loop that started it."""
    server = _serve([204])
    threads, loop_thread = [], []

    async def quiet(*_args, **_kwargs):
        return False

    monkeypatch.setattr(worker, "collection_pass", quiet)
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        app = live_app(tmp_path, public_url="https://console.example", notice_hosts=origin)
        with TestClient(app):
            with app.state.session_factory() as db:
                notices.save(db, app.state.settings, notices.PutBody(target=f"{origin}/hook"))
                notice = notices._queue_test(db, app.state.settings)
                db.commit()
                notice_id = notice.id

            def mark(step):
                if step == "sending":
                    threads.append(threading.get_ident())

            notices.pause = mark

            async def run():
                loop_thread.append(threading.get_ident())
                upkeep = worker.Upkeep(app.state.session_factory, app.state.settings)
                upkeep.tick()
                assert upkeep.notifying is not None
                await upkeep.notifying
                await upkeep.stop()

            asyncio.run(run())
            with app.state.session_factory() as db:
                assert db.get(Notice, notice_id).state == "sent"
            assert threads and threads[0] != loop_thread[0]
            assert server.hits[0]["thread"] != loop_thread[0]
    finally:
        notices.pause = None
        _close(server)


def _touch(engine, notice_id):
    kwargs = {"connect_args": {"timeout": 0}} if engine.dialect.name == "sqlite" else {}
    other = create_engine(engine.url, **kwargs)
    try:
        with other.begin() as conn:
            if engine.dialect.name == "sqlite":
                conn.execute(text("UPDATE notices SET attempts = attempts WHERE id = :id"), {"id": notice_id})
            else:
                conn.execute(text("SELECT id FROM notices WHERE id = :id FOR UPDATE NOWAIT"), {"id": notice_id})
    finally:
        other.dispose()


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_a_send_does_not_hold_the_database_across_the_call(tmp_path, request, engine_kind):
    """A second writer is stopped while the notice is claimed or recorded, and proceeds during the call."""
    place = postgres_database(request) if engine_kind == "postgresql" else {"database_url": f"sqlite:///{tmp_path}/lock.db"}
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    server = _serve([204])
    engine, factory = _engine(tmp_path, place["database_url"])
    seen = {}
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        settings = _settings(origin)
        notice_id = _arm(factory, settings, origin)

        def mark(step):
            try:
                _touch(engine, notice_id)
            except OperationalError:
                seen[step] = "locked"
            else:
                seen[step] = "free"

        server.touch = lambda: _touch(engine, notice_id)
        notices.pause = mark
        assert notices.deliver_due(factory, settings) == ["sent"]
        assert seen == {"picking": "free", "claiming": "locked", "claimed": "free", "checked": "free",
                        "sending": "free", "writing": "locked"}
        assert server.hits[0]["touch"] == "ok"
    finally:
        notices.pause = None
        _close(server)
        engine.dispose()


def test_two_sends_at_once_deliver_the_notice_once(tmp_path):
    """A second send started while the first is on the network does not send the notice again."""
    server = _serve([204])
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _done, factory = _engine(tmp_path)
        settings = _settings(origin)
        _arm(factory, settings, origin)

        def overlap(step):
            if step == "sending" and not getattr(overlap, "ran", False):
                overlap.ran = True
                notices.deliver_due(factory, settings)

        notices.pause = overlap
        assert notices.deliver_due(factory, settings) == ["sent"]
        assert len(server.hits) == 1
    finally:
        notices.pause = None
        _close(server)


_COPY = """
import os
from nyctr import notices
from nyctr.config import Settings
from nyctr.database import make_engine, session_factory
url = os.environ["NOTICE_DB"]
origin = os.environ["NOTICE_ORIGIN"]
engine = make_engine(url)
factory = session_factory(engine)
settings = Settings(mode="live", database_url=url, public_url="https://console.example",
                    cookie_secure=False, worker_enabled=False, notice_hosts=origin)
print("COPIES", notices.deliver_due(factory, settings))
engine.dispose()
"""


def _place(tmp_path, request, engine_kind, name):
    place = postgres_database(request) if engine_kind == "postgresql" else {"database_url": f"sqlite:///{tmp_path}/{name}.db"}
    if not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    return place["database_url"]


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_two_copies_send_one_notice_once(tmp_path, request, engine_kind):
    """A second process does not send a notice a live claim already holds."""
    server = _serve([204, 204])
    url = _place(tmp_path, request, engine_kind, "copies")
    engine, factory = _engine(tmp_path, url)
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        settings = _settings(origin)
        notice_id = _arm(factory, settings, origin)

        def hold(step):
            if step != "sending" or getattr(hold, "ran", False):
                return
            hold.ran = True
            env = os.environ.copy()
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
            env["NOTICE_DB"] = url
            env["NOTICE_ORIGIN"] = origin
            done = subprocess.run([sys.executable, "-c", _COPY], cwd=Path(__file__).resolve().parents[3],
                                  env=env, check=True, capture_output=True, text=True)
            assert "COPIES []" in done.stdout

        notices.pause = hold
        assert notices.deliver_due(factory, settings) == ["sent"]
        assert len(server.hits) == 1
        assert server.hits[0]["headers"]["x-nyctr-notice-id"] == notice_id
    finally:
        notices.pause = None
        _close(server)
        engine.dispose()


def test_a_reply_that_is_not_http_spends_tries_and_gives_up(tmp_path):
    """A garbage reply is a failed try. After five, the notice is given up and listed."""
    server = _serve([])
    server.raw = b"HELLO NOT HTTP\r\n"
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _done, factory = _engine(tmp_path)
        settings = _settings(origin)
        start = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
        box, now = _clock(start)
        with factory() as db:
            notices.save(db, settings, notices.PutBody(target=f"{origin}/hook"))
            db.add(Notice(id="n-garbage", kind="test", subject="n-garbage", state="due", attempts=0,
                          next_try_at=start, created_at=start, payload=_tiny("n-garbage")))
            db.commit()
        for delay in notices.DELAYS:
            assert notices.deliver_due(factory, settings, now) == ["due"]
            box[0] = box[0] + timedelta(seconds=delay)
        assert notices.deliver_due(factory, settings, now) == ["gave_up"]
        assert len(server.hits) == 5
        with factory() as db:
            row = db.get(Notice, "n-garbage")
            assert row.state == "gave_up" and row.attempts == 5 and row.claimed_by is None
            assert any(item["kind"] == "notice" and item["id"] == "n-garbage"
                       for item in assistant.attention(db, settings))
    finally:
        _close(server)


def test_a_path_that_is_not_plain_letters_is_refused_when_saved(tmp_path):
    """A path outside plain letters is refused as it is saved, and a stored one is given up."""
    server = _serve([204])
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _done, factory = _engine(tmp_path)
        settings = _settings(origin)
        with factory() as db:
            with pytest.raises(notices.Refused, match="plain letters"):
                notices.save(db, settings, notices.PutBody(target=f"{origin}/b\u00fccher"))
            db.add(notices_setting(f"{origin}/b\u00fccher"))
            db.add(Notice(id="n-letters", kind="test", subject="n-letters", state="due", attempts=0,
                          next_try_at=utcnow(), created_at=utcnow(), payload=_tiny("n-letters")))
            db.commit()
        assert notices.deliver_due(factory, settings) == ["gave_up"]
        assert server.hits == []
        with factory() as db:
            row = db.get(Notice, "n-letters")
            assert row.state == "gave_up" and row.attempts == 1
    finally:
        _close(server)


def test_a_failed_claim_does_not_hide_the_notice(tmp_path):
    """A claim that does not commit leaves the notice due, and the next tick sends it."""
    server = _serve([204])
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _done, factory = _engine(tmp_path)
        settings = _settings(origin)
        notice_id = _arm(factory, settings, origin)

        def boom(step):
            if step == "claiming":
                raise OperationalError("database is locked", None, None)

        notices.pause = boom
        with pytest.raises(OperationalError):
            notices.deliver_due(factory, settings)
        with factory() as db:
            row = db.get(Notice, notice_id)
            assert row.state == "due" and row.attempts == 0 and row.claimed_by is None
        notices.pause = None
        assert notices.deliver_due(factory, settings) == ["sent"]
        assert len(server.hits) == 1
    finally:
        notices.pause = None
        _close(server)


def test_the_whole_send_stops_when_the_reply_keeps_coming(tmp_path, monkeypatch):
    """A body that arrives one byte at a time does not hold the send open past the deadline."""
    server = _serve([])
    server.trickle = True
    monkeypatch.setattr(notices, "TIMEOUT", 1)
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _done, factory = _engine(tmp_path)
        settings = _settings(origin)
        _arm(factory, settings, origin)
        started = time.monotonic()
        notices.deliver_due(factory, settings)
        assert time.monotonic() - started < 8
        assert server.finished is False
    finally:
        _close(server)


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_two_writers_queue_one_notice_for_one_opening(tmp_path, request, engine_kind):
    """Two overlapping writes for one opening leave a single lease_stuck notice."""
    url = _place(tmp_path, request, engine_kind, "stuck")
    engine, factory = _engine(tmp_path, url)
    settings = _settings("")
    try:
        with factory() as db:
            db.add(Lease(id="open-1", domain="a.example", status="active", execution="not_applied"))
            db.commit()

        def hold(step):
            if step != "adding" or getattr(hold, "ran", False):
                return
            hold.ran = True
            with factory() as other:
                row = other.get(Lease, "open-1")
                assert notices.stuck(other, settings, row) is not None
                other.commit()

        notices.pause = hold
        with factory() as db:
            row = db.get(Lease, "open-1")
            notices.stuck(db, settings, row)
            db.commit()
        with factory() as db:
            rows = db.scalars(select(Notice).where(Notice.kind == "lease_stuck")).all()
            assert len(rows) == 1 and rows[0].subject == "open-1"
    finally:
        notices.pause = None
        engine.dispose()


def test_a_missing_secret_is_on_the_attention_list(tmp_path, monkeypatch):
    """A named secret that is not on the server is an attention item, and an empty name is not."""
    _done, factory = _engine(tmp_path)
    settings = _settings("")
    monkeypatch.delenv("NYCTR_NOTICE_SECRET_TEST", raising=False)
    with factory() as db:
        notices.save(db, settings, notices.PutBody(secret_ref=""))
        db.commit()
        assert all(item["id"] != notices.KEY for item in notices.attention_items(db))
        notices.save(db, settings, notices.PutBody(secret_ref="NYCTR_NOTICE_SECRET_TEST"))
        db.commit()
        items = assistant.attention(db, settings)
        match = [item for item in items if item["kind"] == "notice" and item["id"] == notices.KEY]
        assert len(match) == 1 and "not set" in match[0]["detail"] and match[0]["title"]


def test_the_path_is_sent_but_only_the_server_is_shown(tmp_path, monkeypatch):
    """A secret in the path is posted, and neither Setup nor the activity record shows it."""
    server = _serve([204])
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        app = live_app(tmp_path, public_url="http://console.test", notice_hosts=origin)
        hidden = "s3cret-path-value"
        with TestClient(app, base_url="http://console.test") as desk:
            seed_live_member(app)
            admin = live_signin(desk, LIVE_ADMIN)
            monkeypatch.setenv("NYCTR_NOTICE_SECRET_TEST", SECRET)
            saved = desk.put("/api/notices", headers=admin,
                             json={"target": f"{origin}/hook/{hidden}", "secret_ref": "NYCTR_NOTICE_SECRET_TEST"})
            assert saved.status_code == 200, saved.text
            assert saved.json()["target"] == origin and hidden not in saved.text
            again = desk.put("/api/notices", headers=admin,
                             json={"target": saved.json()["target"], "secret_ref": "NYCTR_NOTICE_SECRET_TEST"})
            assert again.status_code == 200 and hidden not in again.text
            tested = desk.post("/api/notices/test", headers=admin)
            assert tested.status_code == 200, tested.text
            assert hidden not in tested.text
        assert len(server.hits) == 1 and server.hits[0]["path"] == f"/hook/{hidden}"
        with app.state.session_factory() as db:
            from nyctr.models import Audit
            audits = db.scalars(select(Audit).where(Audit.action == "notices.changed")).all()
            shown = json.dumps([row.details for row in audits])
            assert audits and hidden not in shown and origin in shown
    finally:
        _close(server)


def test_the_sent_time_is_left_as_it_was_written(tmp_path):
    """The generated timestamp is sent whole. The same time of day in a title is still removed."""
    server = _serve([204])
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _done, factory = _engine(tmp_path)
        settings = _settings(origin)
        stamp = "2026-11-16T12:00:00+00:00"
        start = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
        payload = _tiny("n-stamp")
        payload["at"] = stamp
        payload["title"] = stamp
        with factory() as db:
            notices.save(db, settings, notices.PutBody(target=f"{origin}/hook"))
            db.add(Notice(id="n-stamp", kind="test", subject="n-stamp", state="due", attempts=0,
                          next_try_at=start, created_at=start, payload=payload))
            db.commit()
        assert notices.deliver_due(factory, settings) == ["sent"]
        body = json.loads(server.hits[0]["body"])
        assert body["at"] == stamp
        assert stamp not in body["title"] and "[removed]" in body["title"]
    finally:
        _close(server)


def test_a_trickled_status_line_ends_the_read(tmp_path, monkeypatch):
    """An unfinished status line does not leave the send thread running, and the try is spent."""
    server = _serve([])
    server.trickle_head = True
    monkeypatch.setattr(notices, "TIMEOUT", 1)
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        _done, factory = _engine(tmp_path)
        settings = _settings(origin)
        notice_id = _arm(factory, settings, origin)
        before = {thread.ident for thread in threading.enumerate()}
        started = time.monotonic()
        assert notices.deliver_due(factory, settings) == ["due"]
        assert time.monotonic() - started < 8
        deadline = time.monotonic() + 2
        stuck = [thread for thread in threading.enumerate() if thread.ident not in before and thread.is_alive()]
        while stuck and time.monotonic() < deadline:
            time.sleep(0.05)
            stuck = [thread for thread in threading.enumerate() if thread.ident not in before and thread.is_alive()]
        assert stuck == []
        with factory() as db:
            row = db.get(Notice, notice_id)
            assert row.state == "due" and row.attempts == 1
    finally:
        _close(server)


def _queue(factory, settings, origin, names, start):
    with factory() as db:
        notices.save(db, settings, notices.PutBody(target=f"{origin}/hook"))
        for offset, name in enumerate(names):
            when = start + timedelta(seconds=offset)
            db.add(Notice(id=name, kind="test", subject=name, state="due", attempts=0, next_try_at=start,
                          created_at=when, payload=_tiny(name)))
        db.commit()


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_a_rescheduled_notice_is_not_sent_before_its_next_try(tmp_path, request, engine_kind):
    """A row given a later try after it was read, and before it is claimed, waits."""
    server = _serve([204])
    url = _place(tmp_path, request, engine_kind, "later")
    engine, factory = _engine(tmp_path, url)
    start = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    later = start + timedelta(minutes=5)
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        settings = _settings(origin)
        _queue(factory, settings, origin, ("n-later",), start)

        def hold(step):
            if step != "picking" or getattr(hold, "ran", False):
                return
            hold.ran = True
            with factory() as db:
                row = db.get(Notice, "n-later")
                row.next_try_at = later
                db.commit()

        notices.pause = hold
        assert notices.deliver_due(factory, settings, lambda: start) == []
        assert server.hits == []
        with factory() as db:
            row = db.get(Notice, "n-later")
            assert row.state == "due" and utc(row.next_try_at) == later
        notices.pause = None
        assert notices.deliver_due(factory, settings, lambda: later) == ["sent"]
        assert len(server.hits) == 1
    finally:
        notices.pause = None
        _close(server)
        engine.dispose()


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_a_late_failure_does_not_replace_a_notice_another_copy_sent(tmp_path, request, engine_kind):
    """After the claim lapses, a failure from the first copy does not undo the send."""
    server = _serve([204, 500])
    url = _place(tmp_path, request, engine_kind, "late")
    engine, factory = _engine(tmp_path, url)
    start = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    box, now = _clock(start)
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        settings = _settings(origin)
        _queue(factory, settings, origin, ("n-late",), start)

        def during():
            if getattr(during, "ran", False):
                return
            during.ran = True
            box[0] = start + timedelta(seconds=notices.CLAIM_TTL + 1)
            assert notices.deliver_due(factory, settings, now) == ["sent"]

        server.touch = during
        assert notices.deliver_due(factory, settings, now) == ["sent"]
        assert len(server.hits) == 2 and {hit["touch"] for hit in server.hits} == {"ok"}
        with factory() as db:
            row = db.get(Notice, "n-late")
            assert row.state == "sent" and row.attempts == 0 and row.last_status == 204
            assert row.claimed_by is None
    finally:
        notices.pause = None
        _close(server)
        engine.dispose()


@pytest.mark.parametrize("engine_kind", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_a_slow_send_does_not_let_another_copy_send_the_queue_twice(tmp_path, request, engine_kind):
    """Several notices are claimed one at a time. A slow first send does not send the others twice."""
    server = _serve([204, 204, 204, 204, 204, 204])
    url = _place(tmp_path, request, engine_kind, "queue")
    engine, factory = _engine(tmp_path, url)
    start = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    box, now = _clock(start)
    names = ("n-one", "n-two", "n-three")
    try:
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        settings = _settings(origin)
        _queue(factory, settings, origin, names, start)

        def hold(step):
            if step != "sending" or getattr(hold, "ran", False):
                return
            hold.ran = True
            box[0] = start + timedelta(seconds=notices.CLAIM_TTL + 1)
            notices.deliver_due(factory, settings, now)

        notices.pause = hold
        assert notices.deliver_due(factory, settings, now) == ["sent"]
        sent = [json.loads(hit["body"])["id"] for hit in server.hits]
        assert sent == list(names)
        with factory() as db:
            for name in names:
                row = db.get(Notice, name)
                assert row.state == "sent" and row.attempts == 0
    finally:
        notices.pause = None
        _close(server)
        engine.dispose()
