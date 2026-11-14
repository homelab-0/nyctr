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
    """Keep one smoke-test identity's cookies and CSRF state isolated."""

    def __init__(self):
        """Create a fresh browser-like cookie jar without an authenticated session."""
        self.http = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        self.csrf = None

    def request(self, path, data=None, *, expected=200, csrf=True):
        """Send a same-origin request and assert its expected HTTP outcome.

        JSON bodies select POST; requests without a body use GET. The caller may
        omit CSRF deliberately to exercise denial paths. Both HTTP errors and
        successful responses are decoded only after checking the status.
        """
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
        """Authenticate a demo identity and retain its server-issued CSRF token."""
        self.request("/api/auth/login", {"email": email, "password": "nyctr-demo"})
        me = self.request("/api/auth/me")
        self.csrf = me["csrf_token"]
        return me


def wait_for_app():
    """Wait up to 90 seconds for a healthy response across startup or restart.

    Retry transient connection failures and unhealthy HTTP responses. Raise if
    the deadline expires so a broken deployment cannot pass the smoke check.
    """
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            return Client().request("/api/health")
        except (urllib.error.URLError, ConnectionError, TimeoutError, AssertionError):
            # Docker may accept a connection before a restarted app can answer.
            time.sleep(1)
    raise RuntimeError("Application did not become healthy within 90 seconds")


def run(verify_persistence):
    """Exercise the packaged demo's HTTP, authorization, and durable-data boundaries.

    The first run records a request ID for the restart check. Persistence mode
    opens a new authenticated session and requires that same request to remain
    visible. Refuse live mode before submitting any demonstration credentials.
    """
    wait_for_app()
    anonymous = Client()
    config = anonymous.request("/api/auth/config")
    assert config["mode"] == "demo", "Smoke test is only for explicitly isolated demo mode"
    anonymous.request("/api/resources", expected=401)
    anonymous.request("/api/not-an-endpoint", expected=404)

    member = Client()
    assert member.login("jamie@nyctr.demo")["role"] == "member"
    member.request("/api/integrations", expected=403)
    blocks = member.request("/api/blocks")["rows"]
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

    # Every block carries a rule-based assessment; an unknown score is null, never low.
    assert all("risk_band" in block and "risk_factors" in block for block in blocks)
    risky = next(block for block in blocks if block["risk_band"] == "high")
    safe = next(block for block in blocks if block["risk_band"] == "low")
    payload = {
        "block_id": risky["id"],
        "reason": "Container integration test: request access to a picture gallery.",
        "duration_minutes": 30,
    }
    member.request("/api/requests", payload, expected=403, csrf=False)
    created = member.request("/api/requests", payload, expected=201)
    # A risky block is scored and left for a person, whatever the access rule allows.
    assert created["status"] == "pending" and created["risk_score"] > 60
    STATE.write_text(json.dumps({"request_id": created["id"]}))
    # A low-risk privacy-list block opens under the demo's written rule, and demo
    # mode records the provider change as simulated rather than applied.
    opened = member.request("/api/requests", {**payload, "block_id": safe["id"]}, expected=201)
    assert opened["status"] == "auto_approved" and opened["decided_by"] == "rule"
    lease = next(row for row in member.request("/api/leases") if row["request_id"] == opened["id"])
    assert lease["status"] == "active" and lease["execution"] == "simulated"
    member.request("/api/guests", expected=403)
    member.request("/api/rules", expected=403)

    admin = Client()
    assert admin.login("admin@nyctr.demo")["role"] == "admin"
    assert admin.request("/api/overview")["resource_count"] > 0
    graph = admin.request("/api/graph")
    ids = {node["id"] for node in graph["nodes"]}
    assert graph["edges"] and all(
        edge["source"] in ids and edge["target"] in ids for edge in graph["edges"]
    )
    assert any(edge["evidence_kind"] == "inferred" and edge["provider"] == "nyctr" for edge in graph["edges"])
    assert any(row["id"] == created["id"] for row in admin.request("/api/requests"))
    assert admin.request("/api/attention"), "The attention list is empty in the seeded demo"
    assert admin.request("/api/guests")["writes"] == "simulated"
    answer = admin.request("/api/graph/query", {"query": "{ workloads(firewall: false) { name } }"})
    assert answer["data"]["workloads"], "The read-only graph query returned no rows"
    assert admin.request("/api/assistant")["provider"] == "sample"
    assert admin.request("/api/audit"), "Persisted workflow audit is missing"
    member.request("/api/auth/logout", {})
    member.request("/api/auth/me", expected=401)
    print("PASS: compiled UI, cookies, CSRF, role isolation, graph, request and audit")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-persistence", action="store_true")
    run(parser.parse_args().verify_persistence)
