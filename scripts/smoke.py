"""Exercise the packaged demo against its real HTTP and database boundaries."""

import argparse
import http.cookiejar
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path

BASE = os.environ.get("NYCTR_SMOKE_URL", "http://127.0.0.1:8080").rstrip("/")
ORIGIN = os.environ.get("NYCTR_SMOKE_ORIGIN", "http://localhost:8080")
STATE = Path(os.environ.get("NYCTR_SMOKE_STATE", "/tmp/nyctr-smoke-state.json"))


class Client:
    def __init__(self):
        self.http = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        self.csrf = None

    def request(self, path, data=None, *, expected=200, csrf=True):
        headers = {"Accept": "application/json", "Origin": ORIGIN}
        if self.csrf and csrf:
            headers["X-CSRF-Token"] = self.csrf
        payload = None
        if data is not None:
            payload = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(BASE + path, data=payload, headers=headers)
        try:
            response = self.http.open(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        body = response.read()
        assert response.status == expected, (
            f"{path}: expected {expected}, received {response.status}: {body[:160]!r}"
        )
        if "application/json" in response.headers.get("Content-Type", ""):
            return json.loads(body)
        return body.decode()

    def login(self, email):
        self.request("/api/auth/login", {"email": email, "password": "nyctr-demo"})
        me = self.request("/api/auth/me")
        self.csrf = me["csrf_token"]
        return me


def wait_for_app():
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            return Client().request("/api/health")
        except (urllib.error.URLError, ConnectionError, TimeoutError, AssertionError):
            # Docker may accept a connection before a restarted app can answer.
            time.sleep(1)
    raise RuntimeError("Application did not become healthy within 90 seconds")


def run(verify_persistence):
    wait_for_app()
    anonymous = Client()
    config = anonymous.request("/api/auth/config")
    assert config["mode"] == "demo", "Smoke test is only for explicitly isolated demo mode"
    anonymous.request("/api/resources", expected=401)
    anonymous.request("/api/not-an-endpoint", expected=404)

    member = Client()
    assert member.login("jamie@nyctr.demo")["role"] == "member"
    member.request("/api/integrations", expected=403)
    blocks = member.request("/api/blocks")
    assert blocks and all(block["attribution"] == "assigned" for block in blocks)
    requests = member.request("/api/requests")

    if verify_persistence:
        state = json.loads(STATE.read_text())
        assert any(row["id"] == state["request_id"] for row in requests)
        print("PASS: access request persisted across application restart")
        return

    page = anonymous.request("/")
    assert "Nyctr" in page and 'id="root"' in page, "Compiled web entry point missing"
    asset = re.search(r'src="([^\"]+\.js)"', page)
    assert asset, "Compiled JavaScript reference missing"
    assert anonymous.request(asset.group(1)), "Compiled JavaScript not served"

    payload = {
        "block_id": blocks[0]["id"],
        "reason": "Container integration test: request family photo access.",
        "duration_minutes": 30,
    }
    member.request("/api/requests", payload, expected=403, csrf=False)
    created = member.request("/api/requests", payload, expected=201)
    assert created["status"] == "pending"
    STATE.write_text(json.dumps({"request_id": created["id"]}))

    admin = Client()
    assert admin.login("admin@nyctr.demo")["role"] == "admin"
    assert admin.request("/api/overview")["resource_count"] > 0
    graph = admin.request("/api/graph")
    ids = {node["id"] for node in graph["nodes"]}
    assert graph["edges"] and all(
        edge["source"] in ids and edge["target"] in ids for edge in graph["edges"]
    )
    assert any(row["id"] == created["id"] for row in admin.request("/api/requests"))
    assert admin.request("/api/audit"), "Persisted workflow audit is missing"
    member.request("/api/auth/logout", {})
    member.request("/api/auth/me", expected=401)
    print("PASS: compiled UI, cookies, CSRF, role isolation, graph, request and audit")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-persistence", action="store_true")
    run(parser.parse_args().verify_persistence)
