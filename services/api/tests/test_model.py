"""The model in the console: who may connect it, where its key may go, and what a trace carries."""

import ast
import asyncio
import hmac
import json
import logging
import random
import re
import threading
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx
import pytest
from conftest import LIVE_ADMIN, LIVE_MEMBER, live_app, live_signin, seed_live_member, signin
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.exc import TimeoutError as DatabaseTimeout
from sqlalchemy.orm import Session
from test_collection_store import POSTGRES, postgres_database

from nyctr import model
from nyctr.config import Settings
from nyctr.main import create_app
from nyctr.models import Audit, Finding, Setting

SECRET = "fabricated-model-key-4f1c9a"
GOOD = {"endpoint": "https://llm.example/v1", "model": "local/reasoner", "secret_ref": "NYCTR_MODEL_SECRET_MAIN",
        "trace": "proxy", "timeout_seconds": 30}
ROUTES = (("GET", "/api/model"), ("PUT", "/api/model"), ("POST", "/api/model/test"))
ASK = {"question": "What is open?"}
# The headers any request carries, and the ones a trace adds.
PLAIN = {"host", "accept", "accept-encoding", "connection", "user-agent", "content-length", "content-type",
         "authorization"}
PROXY = {"traceparent", "langfuse_trace_id", "langfuse_trace_name", "langfuse_session_id",
         "langfuse_trace_metadata", "langfuse_trace_release"}


def answer(text="ready"):
    """A well-formed reply from a chat endpoint."""
    return httpx.Response(200, json={"choices": [{"message": {"content": text}}]})


class StandIn:
    """A stand-in endpoint: it keeps every request it was sent and replies what the test says."""

    def __init__(self):
        self.requests, self.reply = [], lambda request: answer()

    async def __call__(self, request):
        self.requests.append(request)
        reply = self.reply(request)
        return await reply if asyncio.iscoroutine(reply) else reply


@pytest.fixture(autouse=True)
def endpoint(monkeypatch):
    """Every test in this file talks to the stand-in, never to the network."""
    stand_in = StandIn()
    monkeypatch.setattr(model, "transport", httpx.MockTransport(stand_in))
    monkeypatch.setenv("NYCTR_MODEL_SECRET_MAIN", SECRET)
    return stand_in


def console(tmp_path, **overrides):
    """A live installation whose operator allows two servers for the model, each on HTTPS and port 443 only."""
    return live_app(tmp_path, **{"model_hosts": "llm.example, proxy.internal.example", **overrides})


ENGINES = ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)]


def installation(tmp_path, request, engine_kind):
    """A live installation on SQLite, or on a PostgreSQL database of this test's own."""
    if engine_kind == "sqlite":
        return console(tmp_path)
    found = postgres_database(request)
    if not found:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    return console(tmp_path, **found)


def server_set(settings):
    """The connection in force for an installation that has only the server's own settings."""
    return model.InForce(settings.ai_base_url, settings.ai_model, trace=settings.ai_trace, source="deployment")


def nothing_saved(app):
    """Say that no connection was stored and no change was audited."""
    with app.state.session_factory() as db:
        return db.get(Setting, model.KEY) is None and db.scalar(
            select(Audit).where(Audit.action == "model.changed")) is None


# Denial paths first: each refusal stores nothing, audits nothing and sends nothing.

def test_a_secret_name_outside_the_models_own_pattern_is_refused(tmp_path, monkeypatch, endpoint):
    """Only NYCTR_MODEL_SECRET_* can be named, so the model can never be pointed at a source's key."""
    others = ("NYCTR_CONNECTOR_SECRET_DNS", "NYCTR_AI_API_KEY", "NYCTR_BOOTSTRAP_ADMIN_PASSWORD")
    for variable in others:  # each is set on the server, so only the pattern stands in the way
        monkeypatch.setenv(variable, "another-fabricated-secret")
    app = console(tmp_path)
    with TestClient(app) as client:
        headers = live_signin(client)
        for name in (*others, "PATH", "NYCTR_MODEL_SECRET_", "nyctr_model_secret_main", "XNYCTR_MODEL_SECRET_MAIN",
                     "NYCTR_MODEL_SECRET_MAIN ; NYCTR_CONNECTOR_SECRET_DNS", "NYCTR_MODEL_SECRET_MAIN\nX", SECRET):
            refused = client.put("/api/model", headers=headers, json={**GOOD, "secret_ref": name})
            assert refused.status_code == 422 and "NYCTR_MODEL_SECRET_" in refused.json()["detail"], name
            # A key pasted here by mistake is not repeated (the bare prefix is the rule's own words).
            assert name == "NYCTR_MODEL_SECRET_" or name not in refused.text, name
        # The other direction: a source cannot be pointed at the model's key.
        assert client.post("/api/integrations", headers=headers, json={
            "provider": "pihole", "name": "Resolver", "config": {"base_url": "https://dns.example"},
            "secret_ref": "NYCTR_MODEL_SECRET_MAIN"}).status_code == 422
        assert nothing_saved(app) and endpoint.requests == []


def test_a_secret_name_that_is_not_set_on_the_server_is_refused(tmp_path, monkeypatch, endpoint):
    """A well-formed name with nothing behind it is refused when saving, and again when calling."""
    monkeypatch.setenv("NYCTR_MODEL_SECRET_EMPTY", "")
    app = console(tmp_path)
    with TestClient(app) as client:
        headers = live_signin(client)
        for name in ("NYCTR_MODEL_SECRET_ABSENT", "NYCTR_MODEL_SECRET_EMPTY"):
            refused = client.put("/api/model", headers=headers, json={**GOOD, "secret_ref": name})
            assert refused.status_code == 422 and "is not set on the server" in refused.json()["detail"]
        assert nothing_saved(app)
        # Saved while the secret was there; the operator then takes it away.
        assert client.put("/api/model", headers=headers, json=GOOD).status_code == 200
        monkeypatch.delenv("NYCTR_MODEL_SECRET_MAIN")
        assert "is not set on the server" in client.get("/api/model").json()["problem"]
        assert client.post("/api/model/test", headers=headers).status_code == 409
        assert client.post("/api/assistant/ask", headers=headers, json=ASK).status_code == 409
        assert endpoint.requests == []


def test_an_endpoint_on_a_host_the_operator_did_not_name_is_refused(tmp_path, endpoint):
    """The key and the evidence go only to a server on the operator's list: its name, its scheme and its port."""
    app = console(tmp_path)
    with TestClient(app) as client:
        headers = live_signin(client)
        for address in ("https://elsewhere.example/v1",  # a host off the list
                        "http://elsewhere.example/v1",  # plain HTTP to an unlisted host
                        "https://llm.example.elsewhere.example/v1", "https://elsewhere.example/llm.example",
                        "https://[::1]/v1", "https://localhost/v1", "https://LLM.EXAMPLE.elsewhere.example/v1",
                        # A listed name is HTTPS on port 443 and nothing else: no clear text, no other port.
                        "http://llm.example/v1", "http://llm.example:443/v1", "https://llm.example:8443/v1",
                        "http://llm.example:22/v1", "https://llm.example:0/v1", "https://llm.example:80/v1"):
            refused = client.put("/api/model", headers=headers, json={**GOOD, "endpoint": address})
            assert refused.status_code == 422 and "not allowed" in refused.json()["detail"], address
        for address in ("https://169.254.169.254/v1", "https://metadata.google.internal/v1"):
            refused = client.put("/api/model", headers=headers, json={**GOOD, "endpoint": address})
            assert refused.status_code == 422 and "metadata" in refused.json()["detail"], address
        assert nothing_saved(app) and endpoint.requests == []


def test_plain_http_and_another_port_are_taken_only_where_the_operator_wrote_them(tmp_path, endpoint):
    """A proxy inside the cluster may be plain HTTP on its own port because the operator wrote exactly that."""
    app = console(tmp_path, model_hosts="http://proxy.internal.example:4000, https://llm.example:8443, "
                                        "169.254.169.254, metadata.google.internal, http://[::1]:11434")
    with TestClient(app) as client:
        headers = live_signin(client)
        assert client.get("/api/model").json()["hosts"] == [
            "http://[::1]:11434", "http://proxy.internal.example:4000", "https://169.254.169.254",
            "https://llm.example:8443", "https://metadata.google.internal"]
        for address in ("http://proxy.internal.example:4000/v1", "https://llm.example:8443/v1",
                        "http://[::1]:11434/v1"):
            saved = client.put("/api/model", headers=headers, json={**GOOD, "endpoint": address})
            assert saved.status_code == 200 and saved.json()["endpoint"] == address, address
        for address in ("https://proxy.internal.example:4000/v1", "http://proxy.internal.example/v1",
                        "http://proxy.internal.example:4001/v1", "https://llm.example/v1", "http://llm.example:8443/v1",
                        "https://[::1]:11434/v1",
                        # A metadata or link-local address is refused even where the operator listed it.
                        "https://169.254.169.254/v1", "https://metadata.google.internal/v1"):
            refused = client.put("/api/model", headers=headers, json={**GOOD, "endpoint": address})
            assert refused.status_code == 422, address
        assert client.get("/api/model").json()["endpoint"] == "http://[::1]:11434/v1"


def test_an_endpoint_holding_a_name_a_password_or_anything_but_a_plain_address_is_refused(tmp_path, endpoint):
    """A key belongs in a named secret. An address that carries one is refused and is not repeated."""
    app = console(tmp_path)
    with TestClient(app) as client:
        headers = live_signin(client)
        for address in ("https://someone:hunter2-fabricated@llm.example/v1", "https://someone@llm.example/v1",
                        "https://:hunter2-fabricated@llm.example/v1", "https://llm.example:443@elsewhere.example/v1",
                        "https://llm.example/v1?key=hunter2-fabricated", "https://llm.example/v1#hunter2-fabricated",
                        "ftp://llm.example/v1", "llm.example/v1", "https:///v1", "https://llm.example:99999/v1",
                        "https://llm.example/v1 extra", "https://llm.example\\@elsewhere.example/v1",
                        "https://llm.example/" + "v" * 300, "",
                        # Control characters: such a value would be stored and could never be reached.
                        "\x01https://llm.example/v1", "https://llm.example/v1\x00", "https://llm.example/\x7f",
                        "https://llm.example/\u2028v1", "https://llm.example/\tv1"):
            refused = client.put("/api/model", headers=headers, json={**GOOD, "endpoint": address})
            assert refused.status_code == 422 and "hunter2-fabricated" not in refused.text, address
        assert nothing_saved(app) and endpoint.requests == []


def test_a_redirect_from_the_endpoint_is_never_followed(tmp_path, endpoint):
    """The endpoint points somewhere else: one request each was sent, and the key went nowhere new."""
    endpoint.reply = lambda request: httpx.Response(307, headers={"Location": "https://elsewhere.example/v1/take"})
    with TestClient(console(tmp_path)) as client:
        headers = live_signin(client)
        assert client.put("/api/model", headers=headers, json=GOOD).status_code == 200
        assert client.post("/api/model/test", headers=headers).json() == {"outcome": "refused", "status": 307}
        assert client.post("/api/assistant/ask", headers=headers, json=ASK).status_code == 502
    assert [str(request.url) for request in endpoint.requests] == ["https://llm.example/v1/chat/completions"] * 2


def test_a_member_a_portal_session_and_no_session_are_all_refused(tmp_path, endpoint):
    """Only an administrator on the console address reads, saves or tests the model."""
    app = console(tmp_path, public_url="http://console.test", portal_url="http://portal.test")
    with TestClient(app, base_url="http://console.test") as desk, TestClient(app, base_url="http://portal.test") as portal:
        seed_live_member(app)
        for method, path in ROUTES:  # no session, on either address
            assert desk.request(method, path, json=GOOD).status_code == 401
            assert portal.request(method, path, json=GOOD).status_code == 401
        member = live_signin(portal, LIVE_MEMBER)
        for method, path in ROUTES:
            assert portal.request(method, path, headers=member, json=GOOD).status_code == 403
        # An administrator's account has member rights on the portal address.
        owner = live_signin(portal, LIVE_ADMIN)
        for method, path in ROUTES:
            assert portal.request(method, path, headers=owner, json=GOOD).status_code == 403
        # On the console address the same account may, but not without the request token.
        admin = live_signin(desk, LIVE_ADMIN)
        assert desk.put("/api/model", json=GOOD).status_code == 403
        assert desk.post("/api/model/test").status_code == 403
        assert nothing_saved(app) and endpoint.requests == []
        assert desk.put("/api/model", headers=admin, json=GOOD).status_code == 200


def test_the_demo_workspace_cannot_connect_a_model(client, admin_headers, endpoint):
    """The demo's administrator password is public, so nothing there can point Nyctr at an endpoint."""
    assert client.put("/api/model", headers=admin_headers, json=GOOD).status_code == 409
    assert client.post("/api/model/test", headers=admin_headers).status_code == 409
    assert endpoint.requests == []


def test_a_trace_style_a_time_limit_or_a_model_name_off_the_rules_is_refused(tmp_path):
    """The trace style is one of four, the time limit is 5 to 120 seconds, and no other field is taken."""
    app = console(tmp_path)
    with TestClient(app) as client:
        headers = live_signin(client)
        for change in ({"trace": "everything"}, {"trace": ""}, {"timeout_seconds": 4}, {"timeout_seconds": 121},
                       {"timeout_seconds": "30"}, {"timeout_seconds": True}, {"model": ""}, {"model": "m" * 201},
                       {"model": "two\nlines"}, {"model": "bell\x07"}, {"user": "sam"}):
            assert client.put("/api/model", headers=headers, json={**GOOD, **change}).status_code == 422, change
        # A body of another shape is refused in fixed words: a key sent in the wrong place is not repeated.
        typed = "typed-by-mistake-" + SECRET
        for body in ({**GOOD, "api_key": typed}, {**GOOD, typed: 1}, {**GOOD, "timeout_seconds": typed},
                     {**GOOD, "endpoint": [typed]}, {"model": typed}, [typed], typed, None, 7):
            refused = client.put("/api/model", headers=headers, json=body)
            assert refused.status_code == 422 and refused.json() == {"detail": f"Not saved. {model.SHAPE}"}, body
            assert SECRET not in refused.text
        assert nothing_saved(app)


def test_the_host_list_is_checked_again_before_every_call(tmp_path, endpoint):
    """A host the operator later takes off the list gets nothing more, though it was saved while allowed."""
    app = console(tmp_path)
    with TestClient(app) as client:
        headers = live_signin(client)
        assert client.put("/api/model", headers=headers, json=GOOD).status_code == 200
        app.state.settings.model_hosts = "proxy.internal.example"
        assert "not allowed" in client.get("/api/model").json()["problem"]
        assert client.post("/api/model/test", headers=headers).status_code == 409
        assert client.post("/api/assistant/ask", headers=headers, json=ASK).status_code == 409
    assert endpoint.requests == []


def test_the_servers_own_key_goes_only_to_the_servers_own_endpoint(tmp_path, endpoint):
    """NYCTR_AI_API_KEY is never sent to another host an administrator picks, even an allowed one."""
    app = console(tmp_path, ai_base_url="https://llm.example/v1", ai_model="first", ai_api_key=SECRET,
                  model_hosts="proxy.internal.example, https://llm.example:8443, http://llm.example:443")
    with TestClient(app) as client:
        headers = live_signin(client)
        # Another allowed server, then another port of the server's own host, then plain HTTP on its
        # own host and port: each is another place, so none of them gets the server's key.
        for elsewhere in ("https://proxy.internal.example/v1", "https://llm.example:8443/v1",
                          "http://llm.example:443/v1"):
            keyless = {**GOOD, "secret_ref": "", "endpoint": elsewhere}
            assert client.put("/api/model", headers=headers, json=keyless).json()["key"] == "none", elsewhere
            assert client.post("/api/model/test", headers=headers).json() == {"outcome": "reachable", "status": None}
            assert "authorization" not in endpoint.requests[-1].headers, elsewhere
        # Back on the server's own address, with no name given, the server's key is used again.
        own = client.put("/api/model", headers=headers, json={**GOOD, "secret_ref": "", "model": "second"})
        assert own.json()["key"] == "server"
        client.post("/api/model/test", headers=headers)
        assert endpoint.requests[-1].headers["authorization"] == f"Bearer {SECRET}"
        assert json.loads(endpoint.requests[-1].content)["model"] == "second"


def test_a_key_with_a_line_break_is_neither_sent_nor_logged(tmp_path, monkeypatch, endpoint, caplog):
    """A key holding a line break could write a header of its own. It is refused and never logged."""
    caplog.set_level(logging.DEBUG)
    with TestClient(console(tmp_path)) as client:
        headers = live_signin(client)
        assert client.put("/api/model", headers=headers, json=GOOD).status_code == 200
        monkeypatch.setenv("NYCTR_MODEL_SECRET_MAIN", SECRET + "\r\nX-Extra: 1")
        assert client.put("/api/model", headers=headers, json={**GOOD, "model": "other"}).status_code == 422
        refused = client.post("/api/model/test", headers=headers)
        assert refused.status_code == 409 and SECRET not in refused.text
    assert endpoint.requests == [] and SECRET not in caplog.text


def test_settings_refuse_a_host_list_entry_that_is_not_a_server():
    """An entry that is not a server would silently match nothing, so it stops the server from starting."""
    for value in ("llm.example:4000", "abc:4000", "llm.example/v1", "llm example", "https://llm.example/v1",
                  "ftp://llm.example", "https://someone@llm.example", "https://llm.example?x=1", "https://",
                  "https://llm.example:99999", "https://llm.example:0", "//llm.example", "https://llm.example\x00",
                  # Written in full, a name is held to the same form as a bare one: these match nothing an
                  # administrator can type, so they are a typing mistake to stop on, as the bare forms are.
                  "https://*.example", "*.example", "https:// llm.example", "https://llm.example.", "llm.example.",
                  "http://-llm.example:4000", "https://llm-.example", "https://llm..example:8443/", "llm..example"):
        with pytest.raises(ValueError, match="NYCTR_MODEL_HOSTS"):
            Settings(mode="demo", model_hosts=value)
    # A bare name is HTTPS on port 443. Anything else is what the operator wrote, and nothing more.
    listed = Settings(mode="demo", model_hosts=" LLM.example , ,::1, http://Proxy.internal.example:4000/, "
                                               "https://llm.example:8443, http://plain.example, "
                                               "http://model_gateway:4000, https://[2001:db8::9]:8443 ")
    assert listed.model_origins == {("https", "llm.example", 443), ("https", "::1", 443),
                                    ("http", "proxy.internal.example", 4000), ("https", "llm.example", 8443),
                                    ("http", "plain.example", 80), ("http", "model_gateway", 4000),
                                    ("https", "2001:db8::9", 8443)}


def test_a_saved_value_that_cannot_be_read_turns_the_model_off_and_never_goes_back_to_the_servers_key(
        tmp_path, endpoint):
    """The console's value replaced the server's. If it cannot be read, nothing is sent anywhere, and it says so."""
    app = console(tmp_path, ai_base_url="https://first.example/v1", ai_model="first", ai_api_key="first-fabricated")
    with TestClient(app) as client:
        headers = live_signin(client)
        assert client.put("/api/model", headers=headers, json=GOOD).status_code == 200
        for stored in ({**GOOD, "retries": 3},  # a field a later version added, left behind by a rollback
                       {key: value for key, value in GOOD.items() if key != "model"}, {**GOOD, "timeout_seconds": "30"},
                       {**GOOD, "endpoint": ""}, {}, ["not", "an", "object"]):
            with app.state.session_factory() as db:
                db.get(Setting, model.KEY).value = stored
                db.commit()
            now = client.get("/api/model").json()
            assert (now["connected"], now["source"], now["key"], now["endpoint"]) == (False, "console", "none", ""), stored
            assert now["problem"] == model.UNREADABLE and "Save it again" in now["problem"]
            assert client.get("/api/assistant").json() == {"provider": "off", "model": ""}
            for path, body in (("/api/model/test", None), ("/api/assistant/ask", ASK)):
                refused = client.post(path, headers=headers, json=body)
                assert refused.status_code == 409 and refused.json()["detail"] == model.UNREADABLE, (path, stored)
            (line,) = [item for item in client.get("/api/attention").json() if item["kind"] == "model"]
            assert line["title"] == "The assistant is off: the model's setting cannot be used"
            assert line["detail"] == model.UNREADABLE and line["severity"] == "medium"
        assert endpoint.requests == []  # nothing went to the server's own endpoint, or anywhere
        # Saving again is the way out, and the line goes with it.
        assert client.put("/api/model", headers=headers, json=GOOD).json()["problem"] is None
        assert [item for item in client.get("/api/attention").json() if item["kind"] == "model"] == []
        assert client.post("/api/model/test", headers=headers).json()["outcome"] == "reachable"
        assert endpoint.requests[-1].url.host == "llm.example"


def test_a_saved_model_that_may_no_longer_be_used_is_on_the_attention_list(tmp_path, monkeypatch):
    """A secret or a server taken away later leaves the assistant off; the list says so in the rule's own words."""
    app = console(tmp_path)
    with TestClient(app) as client:
        headers = live_signin(client)
        assert [item for item in client.get("/api/attention").json() if item["kind"] == "model"] == []
        client.put("/api/model", headers=headers, json=GOOD)
        monkeypatch.delenv("NYCTR_MODEL_SECRET_MAIN")
        (line,) = [item for item in client.get("/api/attention").json() if item["kind"] == "model"]
        assert "is not set on the server" in line["detail"] and SECRET not in str(line)


def test_a_servers_own_address_that_cannot_be_used_is_said_plainly_and_breaks_nothing(tmp_path, endpoint):
    """A port that is no port, or no server name: the server starts, the card says so, and a save still works."""
    for folder, address in (("over", "https://own.example:99999/v1"), ("letters", "https://own.example:abc/v1"),
                            ("zero", "https://own.example:0/v1"), ("nameless", "https://:8443/v1")):
        (tmp_path / folder).mkdir()
        app = console(tmp_path / folder, ai_base_url=address, ai_model="first", ai_api_key="first-fabricated")
        with TestClient(app) as client:
            headers = live_signin(client)
            read = client.get("/api/model")
            assert read.status_code == 200, address
            now = read.json()
            assert (now["connected"], now["source"], now["key"], now["endpoint"]) == (False, "deployment", "none", "")
            assert now["problem"] == model.SERVER_SETTING and "NYCTR_AI_BASE_URL" in now["problem"]
            assert now["hosts"] == ["https://llm.example", "https://proxy.internal.example"]  # the list alone
            assert client.get("/api/assistant").json() == {"provider": "off", "model": ""}
            for path, body in (("/api/model/test", None), ("/api/assistant/ask", ASK)):
                refused = client.post(path, headers=headers, json=body)
                assert refused.status_code == 409 and refused.json()["detail"] == model.SERVER_SETTING, (path, address)
            (line,) = [item for item in client.get("/api/attention").json() if item["kind"] == "model"]
            assert line["detail"] == model.SERVER_SETTING
            assert endpoint.requests == []
            # An administrator can still connect a model on a server the operator listed.
            saved = client.put("/api/model", headers=headers, json=GOOD)
            assert saved.status_code == 200 and saved.json()["problem"] is None, address
            assert client.post("/api/model/test", headers=headers).json()["outcome"] == "reachable"
            assert endpoint.requests[-1].headers["authorization"] == f"Bearer {SECRET}"
            assert "first-fabricated" not in read.text + saved.text + client.get("/api/audit").text
            endpoint.requests.clear()


def test_the_demo_workspace_ignores_a_saved_connection(client, app, admin_headers, endpoint):
    """Nothing in a demo database can point Nyctr at an endpoint, even a row put there by another route."""
    with app.state.session_factory() as db:
        db.add(Setting(key=model.KEY, value=GOOD))
        db.commit()
    now = client.get("/api/model").json()
    assert (now["connected"], now["source"], now["editable"]) == (False, "none", False)
    assert client.get("/api/assistant").json() == {"provider": "sample", "model": ""}
    assert client.post("/api/assistant/ask", headers=admin_headers, json=ASK).json()["provider"] == "sample"
    assert endpoint.requests == []


def test_the_environments_proxy_settings_are_never_used_for_the_model(monkeypatch):
    """A proxy named in the server's environment would be handed the key. The call goes straight to the endpoint.

    Run over two loopback sockets, not the stand-in: the environment's proxy
    settings only ever apply on the real network path.
    """
    seen = {"endpoint": [], "proxy": []}

    def listen(name, status, body):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("content-length", 0)))
                seen[name].append(self.headers.get("authorization"))
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    target = listen("endpoint", 200, json.dumps({"choices": [{"message": {"content": "ready"}}]}).encode())
    proxy = listen("proxy", 502, b"{}")
    try:
        for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{proxy.server_port}")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        monkeypatch.setattr(model, "transport", None)
        settings = Settings(mode="live", ai_base_url=f"http://127.0.0.1:{target.server_port}/v1", ai_model="m",
                            ai_api_key=SECRET)
        assert asyncio.run(model.probe(server_set(settings), settings)) == {"outcome": "reachable", "status": None}
    finally:
        for server in (target, proxy):
            server.shutdown()
            server.server_close()
    assert seen == {"endpoint": [f"Bearer {SECRET}"], "proxy": []}


def test_a_servers_own_key_with_a_line_break_is_refused_before_anything_is_sent(endpoint):
    """The check made at save time never sees the server's own key, so it is made again just before a call."""
    settings = Settings(mode="live", ai_base_url="https://llm.example/v1", ai_model="m",
                        ai_api_key=SECRET + "\r\nX-Extra: 1")
    with pytest.raises(model.Refused) as refusal:
        asyncio.run(model.probe(server_set(settings), settings))
    assert SECRET not in str(refusal.value) and endpoint.requests == []


def test_the_test_button_shares_the_assistants_limit(tmp_path, monkeypatch, endpoint):
    """Thirty model calls in ten minutes for one administrator, tests included; the next is refused unsent."""
    from nyctr import assistant

    monkeypatch.setattr(assistant, "_calls", {})
    with TestClient(console(tmp_path)) as client:
        headers = live_signin(client)
        client.put("/api/model", headers=headers, json=GOOD)
        assert {client.post("/api/model/test", headers=headers).status_code for _ in range(30)} == {200}
        assert client.post("/api/model/test", headers=headers).status_code == 429
        assert client.post("/api/assistant/ask", headers=headers, json=ASK).status_code == 429
    assert len(endpoint.requests) == 30


# What an administrator can do.

def test_an_administrator_saves_the_model_and_the_change_is_audited_without_the_key(tmp_path, endpoint):
    """The console's value is stored, wins over the server's, and the audit says who changed what."""
    app = console(tmp_path, ai_base_url="https://first.example/v1/", ai_model="first", ai_api_key="first-fabricated")
    with TestClient(app) as client:
        headers = live_signin(client)
        assert client.get("/api/model").json() == {
            "connected": True, "endpoint": "https://first.example/v1", "model": "first", "secret_ref": "",
            "key": "server", "trace": "off", "timeout_seconds": 60, "source": "deployment", "problem": None,
            "editable": True,
            "styles": ["off", "standard", "proxy", "proxy_body"], "seconds": [5, 120],
            "hosts": ["https://first.example", "https://llm.example", "https://proxy.internal.example"]}
        # No trace style is named: a connection saved in the console is traced for a proxy unless it says otherwise.
        unnamed = {key: value for key, value in GOOD.items() if key != "trace"}
        saved = client.put("/api/model", headers=headers, json={**unnamed, "endpoint": "https://llm.example/v1/"})
        assert saved.status_code == 200 and saved.json()["trace"] == "proxy"
        now = client.get("/api/model").json()
        assert now == saved.json() and (now["source"], now["key"]) == ("console", "reference")
        assert {key: now[key] for key in GOOD} == GOOD
        assert client.get("/api/assistant").json() == {"provider": "model", "model": "local/reasoner"}
        client.put("/api/model", headers=headers, json={**GOOD, "trace": "off", "timeout_seconds": 120})
        with app.state.session_factory() as db:
            first, second = db.scalars(select(Audit).where(Audit.action == "model.changed")
                                       .order_by(Audit.created_at))
            assert db.get(Setting, model.KEY).value == {**GOOD, "trace": "off", "timeout_seconds": 120}
        assert first.actor_id == second.actor_id and first.actor_id
        assert first.details == {"old": {"endpoint": "https://first.example/v1", "model": "first", "secret_ref": "",
                                         "trace": "off", "timeout_seconds": 60, "source": "deployment"},
                                 "new": GOOD}
        assert second.details == {"old": {**GOOD, "source": "console"},
                                  "new": {**GOOD, "trace": "off", "timeout_seconds": 120}}
        assert "first-fabricated" not in client.get("/api/audit").text + saved.text
    assert endpoint.requests == []  # saving sends nothing


def test_with_no_model_anywhere_the_assistant_is_off_as_before(tmp_path, endpoint):
    """Nothing set on the server and nothing saved: no model, and the routes say so."""
    with TestClient(console(tmp_path)) as client:
        headers = live_signin(client)
        body = client.get("/api/model").json()
        assert (body["connected"], body["source"], body["key"], body["endpoint"]) == (False, "none", "none", "")
        assert client.get("/api/assistant").json() == {"provider": "off", "model": ""}
        assert client.post("/api/model/test", headers=headers).status_code == 409
        asked = client.post("/api/assistant/ask", headers=headers, json=ASK)
        assert asked.status_code == 409 and "Setup" in asked.json()["detail"]
    assert endpoint.requests == []


def test_an_install_with_only_the_servers_settings_sends_what_it_always_sent(tmp_path, endpoint):
    """Nothing new set: the same address, model, key, headers and body as before this change, with no host list."""
    app = live_app(tmp_path, ai_base_url="http://gateway.internal.example:4000/v1", ai_model="local/reasoner",
                   ai_api_key=SECRET)
    endpoint.reply = lambda request: answer("Nothing is open.")
    with TestClient(app) as client:
        result = client.post("/api/assistant/ask", headers=live_signin(client), json=ASK)
        assert result.json() == {"answer": "Nothing is open.", "references": [], "provider": "model",
                                 "model": "local/reasoner"}
    (request,) = endpoint.requests
    assert str(request.url) == "http://gateway.internal.example:4000/v1/chat/completions"
    assert request.method == "POST" and request.headers["authorization"] == f"Bearer {SECRET}"
    assert request.headers["content-type"] == "application/json"
    assert set(request.headers) <= PLAIN  # no trace header: none was sent before this change
    with app.state.session_factory() as db:
        stored = db.get(Setting, model.TRACE_KEY)  # made at start-up, even when this call sends no session
        assert stored is not None and len(bytes.fromhex(stored.value["key"])) == 32
        assert stored.value["key"] not in request.content.decode() and stored.value["key"] not in str(request.headers)
    body = json.loads(request.content)
    assert set(body) == {"model", "temperature", "max_tokens", "messages"}
    assert (body["model"], body["temperature"], body["max_tokens"]) == ("local/reasoner", 0.2, 700)
    assert [message["role"] for message in body["messages"]] == ["system", "user"]
    assert body["messages"][1]["content"].endswith("QUESTION:\nWhat is open?")


def test_the_operator_can_turn_tracing_on_for_the_servers_own_settings(tmp_path, endpoint):
    """NYCTR_AI_TRACE is the only way a trace is sent before an administrator saves; it takes the four styles."""
    for style, expected in (("standard", {"traceparent"}), ("proxy", PROXY - {"langfuse_session_id"})):
        (tmp_path / style).mkdir()
        app = live_app(tmp_path / style, ai_base_url="https://llm.example/v1", ai_model="m", ai_trace=style)
        with TestClient(app) as client:
            headers = live_signin(client)
            assert client.get("/api/model").json()["trace"] == style
            assert client.post("/api/model/test", headers=headers).json()["outcome"] == "reachable"
        assert set(endpoint.requests[-1].headers) - PLAIN == expected
    with pytest.raises(ValueError):
        Settings(mode="live", ai_base_url="https://llm.example/v1", ai_model="m", ai_trace="everything")


def test_the_test_says_how_it_went_and_repeats_nothing_the_endpoint_said(tmp_path, endpoint, caplog):
    """One tiny fixed question; the answer is one of five outcomes, and the key shows up nowhere."""
    def fail(error):
        def reply(request):
            raise error
        return reply

    caplog.set_level(logging.DEBUG)
    app = console(tmp_path)
    with TestClient(app) as client:
        headers = live_signin(client)
        client.put("/api/model", headers=headers, json=GOOD)
        for reply, outcome, status in (
                (lambda request: answer("ready, and here is a long story"), "reachable", None),
                (lambda request: httpx.Response(401, text="bad key " + request.headers["authorization"]),
                 "refused", 401),
                (lambda request: httpx.Response(503, json={"error": "upstream said SENTINEL-TEXT"}), "refused", 503),
                (lambda request: httpx.Response(200, text="<html>SENTINEL-TEXT</html>"), "wrong_shape", None),
                (lambda request: httpx.Response(200, json={"choices": []}), "wrong_shape", None),
                (lambda request: answer("x" * 600_000), "wrong_shape", None),  # well formed, over 512 kB
                (lambda request: httpx.Response(200, content=b"[" * 100_000), "wrong_shape", None),  # nested deep
                (lambda request: answer("your key is " + request.headers["authorization"]), "wrong_shape", None),
                (fail(httpx.ConnectError("no route to SENTINEL-TEXT")), "not_reachable", None),
                (fail(httpx.ReadTimeout("SENTINEL-TEXT took too long")), "too_slow", None)):
            endpoint.reply = reply
            endpoint.requests.clear()
            tested = client.post("/api/model/test", headers=headers)
            assert tested.status_code == 200 and tested.json() == {"outcome": outcome, "status": status}
            with app.state.session_factory() as db:
                record = db.scalars(select(Audit).where(Audit.action == "model.tested")
                                    .order_by(Audit.created_at.desc())).first()
                assert record.details == tested.json() and record.actor_id
            (request,) = endpoint.requests
            assert request.headers["authorization"] == f"Bearer {SECRET}"
            assert json.loads(request.content)["max_tokens"] == 8
            assert request.headers["langfuse_trace_name"] == "nyctr.test"
            assert "langfuse_session_id" not in request.headers
            seen = tested.text + client.get("/api/model").text + client.get("/api/audit").text + caplog.text
            assert SECRET not in seen and "SENTINEL-TEXT" not in seen and "long story" not in seen, outcome


def test_an_endpoint_that_never_answers_is_cut_off_at_the_time_limit(endpoint):
    """The limit covers the whole call, so an answer that never comes is `too_slow`, however busy the machine."""
    async def never(request):
        await asyncio.Event().wait()

    endpoint.reply = never
    settings = Settings(mode="live", ai_base_url="https://llm.example/v1", ai_model="m")
    stuck = model.InForce("https://llm.example/v1", "m", timeout_seconds=0.05, source="deployment")
    assert asyncio.run(model.probe(stuck, settings)) == {"outcome": "too_slow", "status": None}


def test_the_key_never_reaches_an_answer_the_audit_or_a_log_when_the_assistant_fails(tmp_path, endpoint, caplog):
    """A question and an explanation that fail say only that no usable answer came back."""
    caplog.set_level(logging.DEBUG)
    app = create_app(Settings(mode="demo", database_url=f"sqlite:///{tmp_path}/ai.db", public_url="http://testserver",
                              cookie_secure=False, ai_base_url="https://llm.example/v1", ai_model="test-model",
                              ai_api_key=SECRET))
    replies = [httpx.Response(500, text=f"trace: Bearer {SECRET}"), answer(f"the key is {SECRET}"),
               httpx.Response(302, headers={"Location": f"https://elsewhere.example/?k={SECRET}"}),
               httpx.Response(200, content=b"[" * 100_000), httpx.Response(200, content=b"[" * 100_000)]
    endpoint.reply = lambda request: replies[len(endpoint.requests) - 1]
    with TestClient(app) as client:
        headers, seen = signin(client), ""
        for path, body in (("/api/assistant/ask", ASK), ("/api/assistant/ask", {"question": "And now?"}),
                           ("/api/findings/finding-guest-management/insight", None),
                           # An answer nested too deep to read is a failed answer, never a server error.
                           ("/api/assistant/ask", {"question": "And a deep one?"}),
                           ("/api/findings/finding-guest-management/insight", None)):
            failed = client.post(path, headers=headers, json=body)
            assert failed.status_code == 502
            assert failed.json() == {"detail": "The model endpoint did not return a usable answer."}
            seen += failed.text
        seen += client.get("/api/audit").text + client.get("/api/assistant").text + client.get("/api/model").text
    assert len(endpoint.requests) == 5 and SECRET not in seen and SECRET not in caplog.text


# What a trace carries.

# A finding whose id holds a device's name and hardware address, as an id built from a source's ids can.
DEVICE_FINDING = "auto:guest-cut:gateway:client:sams-laptop:00:00:5e:00:53:99"
# What the session would be without this installation's key: a digest anyone can match against guessed ids.
UNKEYED = "finding:" + sha256(DEVICE_FINDING.encode()).hexdigest()[:16]
INSIGHT = '{"take": "t", "reasoning": ["r"], "next_steps": ["n"], "confidence": "low"}'
PEOPLE = ["Sam", "sam@example.net", "owner@example.net", "Sam's laptop", "sams-laptop", "00:00:5e:00:53:99",
          "10.0.0.9", "2001:db8::9", SECRET, "NYCTR_MODEL_SECRET_MAIN"]


@pytest.fixture
def traced(tmp_path, endpoint):
    """A live installation with a person, a device and a finding about it; returns a way to send four calls."""
    app = console(tmp_path)
    endpoint.reply = lambda request: answer(INSIGHT)
    with TestClient(app) as client:
        seed_live_member(app)
        headers = live_signin(client)
        version = client.get("/api/health").json()["version"]

        def calls(style):
            """Save one trace style, then ask a question, ask about the finding, explain it, and test."""
            with app.state.session_factory() as db:
                db.merge(Finding(id=DEVICE_FINDING, title="Sam's laptop was cut off", severity="high",
                                 summary=f"Sam's laptop at 10.0.0.9 looked up threats ({style}).",
                                 evidence=["Observed: 3 lookups"]))
                db.commit()
            endpoint.requests.clear()
            assert client.put("/api/model", headers=headers, json={**GOOD, "trace": style}).status_code == 200
            ask = {"question": "What is Sam doing on 10.0.0.9, sam@example.net?"}
            assert client.post("/api/assistant/ask", headers=headers, json=ask).status_code == 200
            assert client.post("/api/assistant/ask", headers=headers,
                               json={**ask, "finding_id": DEVICE_FINDING}).status_code == 200
            assert client.post(f"/api/findings/{DEVICE_FINDING}/insight", headers=headers).status_code == 200
            assert client.post("/api/model/test", headers=headers).json()["outcome"] == "reachable"
            return list(endpoint.requests), version

        yield calls


def test_each_trace_style_sends_exactly_its_own_fields(traced):
    """`off` sends none, `standard` the W3C header, `proxy` the proxy's headers, `proxy_body` the body too."""
    names = ["nyctr.question", "nyctr.question", "nyctr.explanation", "nyctr.test"]
    for style in model.STYLES:
        requests, version = traced(style)
        ids = set()
        # Both calls about the finding carry one session, so a tracing proxy can group them. It is
        # made with this installation's key, so it is whatever the first of them carries.
        about_finding = requests[1].headers.get("langfuse_session_id")
        if style in ("proxy", "proxy_body"):
            assert re.fullmatch("finding:[0-9a-f]{16}", about_finding) and about_finding != UNKEYED
        else:
            assert about_finding is None
        for request, name, session in zip(requests, names, [None, about_finding, about_finding, None], strict=True):
            headers, body = request.headers, json.loads(request.content)
            assert "user" not in body  # the request's `user` field is never sent
            expected = {"off": set(), "standard": {"traceparent"}}.get(
                style, PROXY - ({"langfuse_session_id"} if name in ("nyctr.question", "nyctr.test") and
                                request is not requests[1] else set()))
            assert set(headers) - PLAIN == expected, (style, name)
            assert ("metadata" in body) == (style == "proxy_body")
            if style == "off":
                continue
            w3c, trace_id, span, flags = headers["traceparent"].split("-")
            assert (w3c, flags, len(span)) == ("00", "01", 16) and int(span, 16)
            assert len(trace_id) == 32 and set(trace_id) <= set("0123456789abcdef") and int(trace_id, 16)
            ids.add(trace_id)
            if style == "standard":
                continue
            about = {"nyctr_version": version, "prompt_version": "1", "purpose": name,
                     "subject_kind": "finding" if session else "none", "mode": "live"}
            assert (session is None) == (request is requests[0] or request is requests[3])
            assert headers["langfuse_trace_id"] == trace_id and headers["langfuse_trace_name"] == name
            assert headers.get("langfuse_session_id") == session and headers["langfuse_trace_release"] == version
            assert json.loads(headers["langfuse_trace_metadata"]) == about
            if style == "proxy_body":
                assert body["metadata"] == {"trace_id": trace_id, "trace_name": name, "trace_metadata": about,
                                            "trace_release": version, **({"session_id": session} if session else {})}
        assert len(ids) == (0 if style == "off" else 4)  # a new trace id for every call


def test_the_trace_session_is_keyed_by_this_installation_alone(tmp_path, endpoint, caplog):
    """The same finding gets another session on another installation, and the same one here, also after a restart.

    Without a key anyone who knows how a finding's id begins can match the
    digest against guessed device ids. The key is 32 random bytes this
    installation made; it is in no request, answer, audit record or log line.
    """
    caplog.set_level(logging.DEBUG)
    endpoint.reply = lambda request: answer("Nothing unusual.")
    sessions, keys = [], []
    for folder in ("one", "two", "one"):  # the third is the first installation started again on its own database
        (tmp_path / folder).mkdir(exist_ok=True)
        app = console(tmp_path / folder)
        with TestClient(app) as client:
            headers = live_signin(client)
            with app.state.session_factory() as db:
                stored = db.get(Setting, model.TRACE_KEY)  # made at start-up, before any call
                assert stored is not None and len(bytes.fromhex(stored.value["key"])) == 32
                db.merge(Finding(id=DEVICE_FINDING, title="A device was cut off", severity="high", summary="s",
                                 evidence=["Observed: 3 lookups"]))
                db.commit()
            assert client.put("/api/model", headers=headers, json=GOOD).status_code == 200
            for _ in range(2):
                asked = client.post("/api/assistant/ask", headers=headers, json={**ASK, "finding_id": DEVICE_FINDING})
                assert asked.status_code == 200
            first, second = (request.headers["langfuse_session_id"] for request in endpoint.requests[-2:])
            assert first == second  # stable within one installation
            with app.state.session_factory() as db:
                key = db.get(Setting, model.TRACE_KEY).value["key"]
            assert len(bytes.fromhex(key)) == 32 and key != SECRET
            assert first == "finding:" + hmac.new(bytes.fromhex(key), f"finding:{DEVICE_FINDING}".encode(),
                                                   sha256).hexdigest()[:16]
            shown = "".join(client.get(path).text for path in (
                "/api/model", "/api/audit", "/api/rules", "/api/attention", "/api/collection", "/api/assistant"))
            sent = "".join(str(request.headers) + request.content.decode() for request in endpoint.requests)
            assert key not in shown + sent + caplog.text and key[:32] not in shown + sent + caplog.text
            sessions.append(first)
            keys.append(key)
    assert sessions[0] == sessions[2] and keys[0] == keys[2]  # the same after a restart
    assert sessions[0] != sessions[1] and keys[0] != keys[1]  # another installation, another session
    assert UNKEYED not in sessions


def test_making_the_trace_key_neither_saves_nor_loses_work_the_caller_has_not_saved(tmp_path):
    """The key is made in a session of its own: the caller's unsaved work stays unsaved, and stays."""
    app = console(tmp_path)
    with TestClient(app):
        factory = app.state.session_factory
        with factory() as caller, factory() as other:
            caller.add(Setting(key="callers_unsaved_work", value={"n": 1}))
            key = model.trace_key(caller)
            assert len(key) == 32
            assert other.get(Setting, model.TRACE_KEY).value == {"key": key.hex()}  # the key itself is kept
            assert other.get(Setting, "callers_unsaved_work") is None  # not saved early
            assert [row.key for row in caller.new] == ["callers_unsaved_work"]  # and not lost
            caller.commit()
            assert other.get(Setting, "callers_unsaved_work").value == {"n": 1}
        # The other way round: a caller that then discards its work takes nothing of the key with it.
        with factory() as caller:
            caller.get(Setting, model.TRACE_KEY).value = {"key": "damaged"}
            caller.commit()
        with factory() as caller:
            caller.add(Setting(key="discarded", value={}))
            replaced = model.trace_key(caller)
            caller.rollback()
        with factory() as after:
            assert after.get(Setting, "discarded") is None
            assert model.trace_key(after) == replaced != key


def _ask_about_the_finding(db, settings):
    """One traced call about the finding, through the only function that builds a request."""
    return asyncio.run(model.call("nyctr.explanation", ("finding", DEVICE_FINDING), server_set(settings),
                                  settings, system="s", user="u", db=db))


@pytest.mark.parametrize("error", [
    OperationalError("select", {}, Exception("database is locked")),
    DatabaseTimeout("pool", {}, Exception("pool timeout")),
])
def test_a_database_error_while_reading_the_trace_key_costs_the_session_not_the_call(
        tmp_path, endpoint, monkeypatch, error):
    """A pool timeout, or any other database error while reading the key, still sends the call.

    The call does not make a key, does not save or discard the caller's unsaved work, and
    sends no session. An unkeyed digest is never sent, and the digest is not taken with an empty key.
    """
    app = console(tmp_path)
    settings = Settings(mode="live", ai_base_url="https://llm.example/v1", ai_model="m", ai_trace="proxy")
    made, digests, armed = [], [], {"on": False}
    real_new, real_get = hmac.new, Session.get

    def refuse_making(_db):
        made.append(True)
        raise AssertionError("a call must not make the trace key")

    def spy(key, msg=b"", digestmod=None):
        digests.append(key)
        return real_new(key, msg, digestmod)

    def get(self, entity, ident, **kwargs):
        key = ident[0] if isinstance(ident, tuple) else ident
        if key == model.TRACE_KEY and armed["on"]:
            armed["on"] = False
            raise error
        return real_get(self, entity, ident, **kwargs)

    with TestClient(app):
        factory = app.state.session_factory
        with factory() as before:
            kept = before.get(Setting, model.TRACE_KEY).value
        monkeypatch.setattr(model, "trace_key", refuse_making)
        monkeypatch.setattr(hmac, "new", spy)
        monkeypatch.setattr(Session, "get", get)
        armed["on"] = True
        with factory() as caller:
            caller.add(Setting(key="callers_unsaved_work", value={"n": 1}))
            assert _ask_about_the_finding(caller, settings) == "ready"
            sent = endpoint.requests[-1].headers
            assert sent["langfuse_trace_name"] == "nyctr.explanation" and "langfuse_session_id" not in sent
            assert UNKEYED not in str(sent) and b"" not in digests and made == []
            assert caller.get(Setting, "callers_unsaved_work") is not None
            caller.rollback()
        with factory() as after:
            assert after.get(Setting, model.TRACE_KEY).value == kept  # the empty or real key is not rewritten
            assert after.get(Setting, "callers_unsaved_work") is None


def test_an_empty_trace_key_is_not_rewritten_and_sends_no_session(tmp_path, endpoint, monkeypatch):
    """A stored key that is empty sends the call with no session, and the call does not replace it."""
    app = console(tmp_path)
    settings = Settings(mode="live", ai_base_url="https://llm.example/v1", ai_model="m", ai_trace="proxy")
    made, digests = [], []
    real_new = hmac.new

    def refuse_making(_db):
        made.append(True)
        raise AssertionError("a call must not make the trace key")

    def spy(key, msg=b"", digestmod=None):
        digests.append(key)
        return real_new(key, msg, digestmod)

    with TestClient(app):
        factory = app.state.session_factory
        monkeypatch.setattr(model, "trace_key", refuse_making)
        monkeypatch.setattr(hmac, "new", spy)
        with factory() as db:
            db.get(Setting, model.TRACE_KEY).value = {"key": ""}
            db.commit()
        with factory() as caller:
            caller.add(Setting(key="callers_unsaved_work", value={"n": 1}))
            assert _ask_about_the_finding(caller, settings) == "ready"
            sent = endpoint.requests[-1].headers
            assert "langfuse_session_id" not in sent and UNKEYED not in str(sent)
            assert b"" not in digests and made == []
            caller.rollback()
        with factory() as after:
            assert after.get(Setting, model.TRACE_KEY).value == {"key": ""}
            assert after.get(Setting, "callers_unsaved_work") is None


@pytest.mark.parametrize("engine_kind", ENGINES)
def test_two_copies_making_the_trace_key_at_the_same_moment_end_on_one_key(
        tmp_path, request, monkeypatch, engine_kind):
    """The first copy reads "no key"; the second makes one before the first writes; the first uses the second's."""
    app = installation(tmp_path, request, engine_kind)
    with TestClient(app):
        factory, real, second = app.state.session_factory, model.secrets.token_hex, []
        with factory() as db:
            db.delete(db.get(Setting, model.TRACE_KEY))  # start-up already made one; this is the race to make it
            db.commit()

        def between_read_and_write(size):
            if not second:  # the first copy is about to write its own key: the second copy gets in first
                second.append(b"")
                with factory() as other:
                    second.append(model.trace_key(other))
            return real(size)

        monkeypatch.setattr(model.secrets, "token_hex", between_read_and_write)
        with factory() as first:
            got = model.trace_key(first)
        assert len(got) == 32 and got == second[1]
        with factory() as db:
            (row,) = db.scalars(select(Setting).where(Setting.key == model.TRACE_KEY)).all()
            assert row.value == {"key": got.hex()}


@pytest.mark.parametrize("engine_kind", ENGINES)
def test_a_stored_trace_key_that_is_not_a_key_is_replaced_and_the_new_one_kept(tmp_path, request, engine_kind):
    """A damaged row never stops a call or sends a session under a weak key: a new key takes its place."""
    app = installation(tmp_path, request, engine_kind)
    with TestClient(app):
        factory = app.state.session_factory
        with factory() as db:
            last = model.trace_key(db)
        for damaged in ({}, {"key": ""}, {"key": "not hex"}, {"key": 7}, {"key": None}, {"key": "ab" * 31},
                        {"key": "ab" * 33}, {"other": last.hex()}, ["a", "list"], None):
            with factory() as db:
                db.get(Setting, model.TRACE_KEY).value = damaged
                db.commit()
            with factory() as db:
                fresh = model.trace_key(db)
                assert len(fresh) == 32 and fresh != last, damaged
                assert model.trace_key(db) == fresh
            with factory() as db:
                assert db.get(Setting, model.TRACE_KEY).value == {"key": fresh.hex()}
            last = fresh


@pytest.mark.parametrize("engine_kind", ENGINES)
def test_two_copies_replacing_a_damaged_trace_key_end_on_a_real_key(tmp_path, request, monkeypatch, engine_kind):
    """The first copy reads a damaged key; the second replaces it before the first writes; a real key remains."""
    app = installation(tmp_path, request, engine_kind)
    with TestClient(app):
        factory, real, second = app.state.session_factory, model.secrets.token_hex, []
        with factory() as db:
            db.get(Setting, model.TRACE_KEY).value = {"key": "damaged"}
            db.commit()

        def between_read_and_write(size):
            if not second:
                second.append(b"")
                with factory() as other:
                    second.append(model.trace_key(other))
            return real(size)

        monkeypatch.setattr(model.secrets, "token_hex", between_read_and_write)
        with factory() as first:
            got = model.trace_key(first)
        assert len(got) == 32 and len(second[1]) == 32
        with factory() as db:
            stored = bytes.fromhex(db.get(Setting, model.TRACE_KEY).value["key"])
        assert len(stored) == 32 and stored in {got, second[1]}


def test_start_up_makes_the_trace_key_and_a_call_only_reads_it(tmp_path):
    """The key exists before any call. Reading it again does not replace it."""
    app = console(tmp_path)
    with TestClient(app):
        with app.state.session_factory() as db:
            key = model.read_trace_key(db)
            assert len(key) == 32 and model.read_trace_key(db) == key


def test_a_database_error_at_start_up_does_not_stop_the_app(tmp_path, monkeypatch, caplog):
    """Start-up that cannot make the key still serves. The warning names neither the key nor the database error."""
    def boom(_db):
        raise OperationalError("SECRET-DB-MESSAGE", {}, Exception("SECRET-DB-MESSAGE"))

    monkeypatch.setattr(model, "trace_key", boom)
    caplog.set_level(logging.WARNING, logger="nyctr")
    app = console(tmp_path)
    with TestClient(app) as client:
        assert client.get("/api/health").status_code == 200
        with app.state.session_factory() as db:
            assert model.read_trace_key(db) == b""
    assert "The trace key could not be made at start-up. Calls still go out." in caplog.text
    assert "SECRET-DB-MESSAGE" not in caplog.text


def test_the_proxys_header_names_sit_in_one_table_and_purposes_are_a_fixed_set():
    """Free text cannot become a trace name, a subject kind or a version."""
    assert set(model.PROXY_HEADERS.values()) == PROXY - {"traceparent"}
    assert model.PURPOSES == {"nyctr.question", "nyctr.explanation", "nyctr.test", "nyctr.analysis"}
    for purpose, subject, style, version in (("Sam's question", None, "proxy", "1"),
                                             ("nyctr.question", ("device", "x"), "proxy", "1"),
                                             ("nyctr.question", None, "loud", "1"),
                                             ("nyctr.question", None, "proxy", "Sam's laptop")):
        with pytest.raises(ValueError):
            model.trace(purpose, subject, style, "live", version, b"k" * 32)
    # A subject is never sent under a plain digest: with no key, or a short one, there is no session at all.
    for key in (b"", b"short"):
        with pytest.raises(ValueError, match="key"):
            model.trace("nyctr.question", ("finding", "x"), "proxy", "live", "1", key)


def test_nothing_about_a_person_or_a_device_travels_in_a_trace(traced):
    """A property of every call: no name, email, device name, address or key in any trace value.

    The subjects drawn below are the worst a caller could pass: ids made of a
    person's name, an email, a device's name, a hardware address, a network
    address and the key itself, in every style and for every purpose.
    """
    draw = random.Random(53)
    for _ in range(400):
        ident = draw.choice(["", "finding-", "auto:guest-cut:"]) + draw.choice(PEOPLE) + draw.choice(["", ":x", " "])
        kind, purpose = draw.choice(sorted(model.SUBJECTS)), draw.choice(sorted(model.PURPOSES))
        for style in model.STYLES:
            headers, about = model.trace(purpose, (kind, ident), style, draw.choice(["demo", "live"]), "1",
                                         b"fabricated-key-of-32-bytes-12345")
            carried = " ".join(headers.values()) + json.dumps(about)
            assert not any(word in carried for word in PEOPLE), (ident, style)
            if "langfuse_session_id" in headers:
                assert headers["langfuse_session_id"][:-16] == f"{kind}:"
                assert headers["langfuse_session_id"][-16:] != sha256(ident.encode()).hexdigest()[:16]
    # And end to end: people and devices in the database, in the question and in the finding's id.
    for style in ("proxy", "proxy_body"):
        requests, _version = traced(style)
        for request in requests:
            carried = " ".join(value for name, value in request.headers.items() if name not in PLAIN)
            carried += json.dumps(json.loads(request.content).get("metadata"))
            assert not any(word in carried for word in [*PEOPLE, "laptop", "Office DNS"]), carried


def test_only_the_model_module_builds_a_request_to_the_model():
    """Structural: the modules that can send a request are a short list, and one alone knows the model's key.

    A new module that imports an HTTP client, reaches one through another
    module, reads the model's address or key, or imports the model module at
    all, fails here, so a second path to the model is added on purpose or not
    at all. It is a tripwire, not a proof: code written to get past it can.
    """
    root = Path(model.__file__).parent
    senders, readers, callers, importers = set(), set(), set(), set()
    for path in sorted(root.rglob("*.py")):
        name, text = path.relative_to(root).as_posix(), path.read_text()
        nodes = list(ast.walk(ast.parse(text)))
        froms = [node for node in nodes if isinstance(node, ast.ImportFrom)]
        imported = {alias.name for node in nodes if isinstance(node, ast.Import) for alias in node.names}
        imported |= {node.module for node in froms if node.module}
        # `from urllib import request` brings in urllib.request under a name of its own.
        imported |= {f"{node.module}.{alias.name}" for node in froms if node.module for alias in node.names}
        attributes = [node for node in nodes if isinstance(node, ast.Attribute)]
        named = {node.attr for node in attributes}
        if any(module.split(".")[0] in {"httpx", "httpcore", "requests", "aiohttp", "urllib3", "socket"}
               or module in {"urllib.request", "http.client"} for module in imported) or "httpx" in named:
            senders.add(name)  # the last: an HTTP client reached through another module, as in `model.httpx`
        if named & {"ai_api_key", "ai_base_url", "_key", "endpoint"} \
                or "chat/completions" in text or "NYCTR_MODEL_SECRET" in text:
            readers.add(name)
        if any(node.attr in {"call", "probe"} and isinstance(node.value, ast.Name) and node.value.id == "model"
               for node in attributes):
            callers.add(name)
        if "model" in {alias.name for node in froms if node.module in (None, "nyctr") for alias in node.names} \
                or imported & {"model", "nyctr.model"}:
            importers.add(name)
    # facts.py opens a connection to a domain registry and to the resolver. notices.py posts
    # a notice to the address an administrator set. Neither imports the model or reads its key.
    assert senders == {"model.py", "oidc.py", "integrations/core.py", "integrations/actions.py",
                       "facts.py", "notices.py"}
    assert readers == {"model.py", "config.py"}  # config.py declares the server's own settings and checks them
    assert callers == {"assistant.py", "main.py", "block_analysis.py"}  # the assistant, the console's test, a verdict
    # No other module can be handed the model's address, or call it under another name, without importing it.
    assert importers == {"assistant.py", "main.py", "block_analysis.py"}
    # The proxy's own header names are five entries of one table. No other code, in the API or the
    # console, names the proxy or what records its traces, so nothing can branch on which one is there.
    web = root.parents[2] / "apps" / "web" / "src"
    code = [*root.rglob("*.py"), *(path for path in web.rglob("*.ts*") if ".test." not in path.name)]
    named = {path.name: len(re.findall("langfuse|litellm", path.read_text(), re.I)) for path in code}
    assert {name: count for name, count in named.items() if count} == {"model.py": len(model.PROXY_HEADERS)}
