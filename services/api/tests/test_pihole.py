"""The Pi-hole adapter: signs in, reads blocked lookups, signs out, and claims nothing it cannot do."""

import asyncio
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from nyctr.integrations import IntegrationError, collect, core, registry, validate_config

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
PASSWORD = "app-password-must-not-leak"
CONFIG = {"base_url": "https://pihole.example"}


def query(minutes_ago, domain, status, client=None, **extra):
    """Build one synthetic query-log row."""
    return {"id": minutes_ago, "time": (NOW - timedelta(minutes=minutes_ago)).timestamp(), "type": "A",
            "domain": domain, "status": status, "client": client or {"ip": "192.168.1.20", "name": "kitchen-tv"},
            **extra}


def pihole(monkeypatch, rows, *, password_ok=True):
    """Serve a fake Pi-hole and record every call with the session header it carried."""
    calls = []

    def handler(request):
        """Enforce the session contract: no credential header, a session id on every read."""
        calls.append((request.method, request.url.path, request.headers.get("X-FTL-SID")))
        assert request.url.host == "pihole.example" and "X-Api-Key" not in request.headers
        assert "Authorization" not in request.headers
        if request.url.path == "/api/auth" and request.method == "POST":
            assert json.loads(request.content) == {"password": PASSWORD}
            if not password_ok:
                return httpx.Response(401, json={"error": {"key": "unauthorized"}})
            return httpx.Response(200, json={"session": {"valid": True, "sid": "c2Vzc2lvbi1pZA==", "validity": 300}})
        if request.url.path == "/api/auth" and request.method == "DELETE":
            return httpx.Response(204)
        assert request.method == "GET" and request.headers["X-FTL-SID"] == "c2Vzc2lvbi1pZA=="
        assert request.url.path == "/api/queries"
        start = int(request.url.params["start"])
        return httpx.Response(200, json={"queries": rows[start:start + 500], "recordsTotal": len(rows)})

    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "pihole.example")
    monkeypatch.setattr(core, "utc_now", lambda: NOW)

    def client(key, **options):
        """Build the mocked client and check the adapter asked for no credential header."""
        assert key == PASSWORD and options == {"send_key": False}
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False, trust_env=False)

    monkeypatch.setattr(core, "make_http_client", client)
    return calls


def test_reads_only_blocked_lookups_and_signs_out(monkeypatch):
    """Blocked statuses become unassigned block evidence; answered lookups and stale rows are ignored."""
    calls = pihole(monkeypatch, [
        query(5, "ads.example", "GRAVITY"),
        query(6, "Games.Example.", "DENYLIST", {"ip": "192.168.1.31", "name": ""}),
        query(7, "fine.example", "FORWARDED"),
        query(8, "cached.example", "CACHE"),
        query(9, "not a domain", "GRAVITY"),
        query(60 * 30, "old.example", "GRAVITY"),
        query(10, "noclient.example", "REGEX", {"ip": "not-an-address"}),
    ])
    snapshot = asyncio.run(collect("pihole", "ph", CONFIG, PASSWORD))
    assert [c[:2] for c in calls] == [("POST", "/api/auth"), ("GET", "/api/queries"), ("DELETE", "/api/auth")]
    assert calls[0][2] is None and calls[1][2] and calls[2][2]
    blocks = {b["domain"]: b for b in snapshot.blocks}
    assert set(blocks) == {"ads.example", "games.example", "noclient.example"}
    assert all(b["device_id"] is None and b["risk_score"] is None and b["source"] == "pihole"
               for b in blocks.values())
    assert blocks["ads.example"]["attribution"] == "unverified" and blocks["ads.example"]["device_name"] == "kitchen-tv"
    assert blocks["games.example"]["device_name"] == "192.168.1.31"
    assert blocks["noclient.example"]["attribution"] == "unattributed"
    assert blocks["noclient.example"]["source_device_id"] is None
    labels = [r for r in snapshot.resources if r["kind"] == "client"]
    assert {r["attributes"]["ip"] for r in labels} == {"192.168.1.20", "192.168.1.31"}
    assert all(r["attributes"]["identity_verified"] is False for r in labels)
    assert snapshot.passes is None and PASSWORD not in json.dumps(snapshot.blocks + snapshot.resources)


def test_a_wrong_password_is_an_authentication_failure_and_reads_nothing(monkeypatch):
    """A refused sign-in stops before any read and never leaks the password."""
    calls = pihole(monkeypatch, [], password_ok=False)
    with pytest.raises(IntegrationError) as caught:
        asyncio.run(collect("pihole", "ph", CONFIG, PASSWORD))
    assert caught.value.category == "authentication" and PASSWORD not in str(caught.value)
    assert [c[:2] for c in calls] == [("POST", "/api/auth")]


def test_sign_out_happens_even_when_a_read_fails(monkeypatch):
    """A malformed query log fails the collection, and the session is still closed."""
    calls = pihole(monkeypatch, ["not-an-object"])
    with pytest.raises(IntegrationError):
        asyncio.run(collect("pihole", "ph", CONFIG, PASSWORD))
    assert calls[-1][:2] == ("DELETE", "/api/auth")


def test_a_future_timestamp_is_rejected(monkeypatch):
    """Evidence dated in the future is refused instead of being kept past its real expiry."""
    pihole(monkeypatch, [query(-30, "ads.example", "GRAVITY")])
    with pytest.raises(IntegrationError, match="future"):
        asyncio.run(collect("pihole", "ph", CONFIG, PASSWORD))


@pytest.mark.parametrize("config", [
    {"base_url": "http://pihole.example"},
    {"base_url": "https://pihole.example/admin"},
    {"base_url": "https://elsewhere.example"},
    {"base_url": "https://pihole.example", "lookback_hours": 500},
    {"base_url": "https://pihole.example", "password": "x"},
])
def test_configuration_is_bounded_before_any_password_is_sent(monkeypatch, config):
    """Only HTTPS on an allowed host, the API root, and a bounded lookback are accepted."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "pihole.example")
    with pytest.raises(IntegrationError):
        validate_config("pihole", config)


def test_configuration_is_normalised(monkeypatch):
    """The address is stored as the API root with the default lookback."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "pihole.example")
    assert validate_config("pihole", {"base_url": "https://pihole.example/api/"}) == {
        "base_url": "https://pihole.example/api", "lookback_hours": 24}


def test_it_declares_blocks_and_nothing_nyctr_can_change():
    """The declaration is what keeps Nyctr from ever trying to open a Pi-hole block on its own."""
    provider = registry.get("pihole")
    assert provider.provides == {"dns.blocks"} and provider.changes == []
    assert provider.allow_domain is None and provider.status == "experimental"
