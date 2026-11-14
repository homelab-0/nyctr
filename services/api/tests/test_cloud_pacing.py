"""The cloud address: what is requested, what its errors mean, and staying inside its request limit."""

import asyncio
import time

import httpx
import pytest
from conftest import live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient
from sqlalchemy import select
from test_device_networks import big, gear, network
from test_integrations import KEY, mock_client

from nyctr import collection, integrations
from nyctr.collection import classify
from nyctr.diagnostics import diagnose_integration
from nyctr.integrations import IntegrationError, collect, core, registry, unifi
from nyctr.integrations.registry import Provider
from nyctr.models import Integration, Resource

CLOUD = "https://api.ui.com/v1/connector/consoles/0A1B2C3D0000:77/proxy/network/integration"
DIRECT = "https://unifi.example/proxy/network/integration"
PAGED = "?offset=0&limit=200"
SECRET = "NYCTR_CONNECTOR_SECRET_CLOUD"
GUEST = {"id": "g1", "name": "g1", "access": {"type": "GUEST", "authorized": True}}
SMALL = {"home": {"devices": [gear("gw", "10.0.1.1", ("gateway",))],
                  "networks": [network("lan", 1, "GATEWAY", "10.0.1.1")], "clients": [GUEST]}}
# 40 networks, 60 pieces of equipment, 50 devices, 45 of them guests, and guest passes enough for three
# pages. The lists read first are counted before the detail reads; a closing list that pages is not.
LARGE = {"home": {**big(40, 60, 50, guests=45),
                  "passes": [{"id": f"p{n}", "code": f"{n:010}"} for n in range(450)]}}


@pytest.fixture
def clock(monkeypatch):
    """Replace the pacer's clock and its waiting: a wait moves the clock and is recorded, nothing sleeps."""
    now, waits = [0.0], []

    async def pause(seconds):
        waits.append(seconds)
        now[0] += seconds

    monkeypatch.setattr(core, "monotonic", lambda: now[0])
    monkeypatch.setattr(core, "pause", pause)
    monkeypatch.setattr(core, "_turns", {})
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "api.ui.com,unifi.example")
    monkeypatch.setenv(SECRET, KEY)
    return now, waits


def serve(monkeypatch, sites, now=None, fault=None):
    """Answer the documented reads for fabricated sites, a page at a time; each answer takes 50 ms."""
    lists = {"/v1/sites": [{"id": sid, "name": sid} for sid in sites]}
    details = {}
    for sid, site in sites.items():
        base = f"/v1/sites/{sid}"
        lists.update({f"{base}/{kind}": [row for row, _detail in site[kind]] for kind in ("devices", "networks")})
        lists.update({f"{base}/firewall/policies": [], f"{base}/wifi/broadcasts": [],
                      f"{base}/hotspot/vouchers": site.get("passes", []), f"{base}/clients": site["clients"]})
        details.update({f"{base}/{kind}/{row['id']}": detail
                        for kind in ("devices", "networks") for row, detail in site[kind]})
        details.update({f"{base}/clients/{row['id']}": row for row in site["clients"]})
    sent = []

    def handler(request):
        if now:
            sent.append(now[0])
            now[0] += 0.05
        if fault and (answer := fault(request)) is not None:
            return answer
        path = request.url.path.split("/integration", 1)[1]
        if path not in lists:
            return httpx.Response(200, json=details[path])
        offset = int(request.url.params["offset"])
        rows = lists[path][offset:offset + 200]
        return httpx.Response(200, json={"data": rows, "offset": offset, "count": len(rows),
                                         "totalCount": len(lists[path])})

    return mock_client(monkeypatch, handler), sent


def run(base=CLOUD):
    return asyncio.run(collect("unifi_network", "one", {"base_url": base}, KEY))


def most_in_a_minute(sent):
    """The largest number of requests sent inside any 60 seconds."""
    return max(sum(start <= other < start + 60 for other in sent) for start in sent)


def test_a_collection_and_a_connection_test_through_the_cloud_address_request_only_the_documented_reads(clock):
    """Every request is a GET to the console's pass-through path on the allowed host, carrying the key."""
    monkeypatch = pytest.MonkeyPatch()
    try:
        calls, _sent = serve(monkeypatch, SMALL)  # mock_client asserts GET and the key on every request
        snapshot = run()
        report = asyncio.run(diagnose_integration("unifi_network", "one", {"base_url": CLOUD}, SECRET))
    finally:
        monkeypatch.undo()
    site = "/v1/sites/home"
    expected = [CLOUD + path for path in (
        "/v1/sites" + PAGED, f"{site}/devices{PAGED}", f"{site}/networks{PAGED}", f"{site}/clients{PAGED}",
        f"{site}/firewall/policies{PAGED}", f"{site}/networks/lan", f"{site}/devices/gw", f"{site}/clients/g1",
        f"{site}/hotspot/vouchers{PAGED}", f"{site}/wifi/broadcasts{PAGED}")]
    assert [str(call.url) for call in calls] == expected * 2
    assert {call.url.host for call in calls} == {"api.ui.com"}
    assert {node["kind"] for node in snapshot.resources} == {"site", "gateway", "network", "client"}
    assert report.outcome == "verified" and not [check for check in report.checks if check.status == "failed"]


@pytest.mark.parametrize("url", [
    CLOUD.replace("api.ui.com", "unifi.example"), CLOUD.replace("api.ui.com", "api.ui.com.example"),
    CLOUD.replace("/proxy/network", "/proxy/protect"), CLOUD.replace("0A1B2C3D0000:77", "a/b")])
def test_the_cloud_path_is_accepted_on_the_cloud_host_only(clock, monkeypatch, url):
    """The key never goes to another host under the cloud's path, or to another application behind it."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "api.ui.com,unifi.example,api.ui.com.example")
    calls, _sent = serve(monkeypatch, SMALL)
    with pytest.raises(IntegrationError):
        run(url)
    assert calls == []
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", "unifi.example")
    with pytest.raises(IntegrationError, match="not yet allowed to connect to"):
        run()
    assert calls == []


def cloud_error(status, code, message, headers=None):
    """The cloud's documented error answer, with text that must never be repeated."""
    return lambda request: httpx.Response(status, headers=headers or {}, json={
        "code": code, "httpStatusCode": status, "message": f"{message} private-detail", "traceId": "trace-private"})


@pytest.mark.parametrize("fault, category, may_pass, wait", [
    (cloud_error(429, "rate_limit", "rate limit exceeded, retry after 5.37s", {"Retry-After": "5"}),
     "rate_limit", True, 5),
    (cloud_error(429, "rate_limit", "rate limit exceeded"), "rate_limit", True, None),
    (cloud_error(408, "DeviceTimeout", "Device connection timeout"), "provider_contract", True, None),
    (cloud_error(502, "bad_gateway", "bad gateway"), "provider_contract", True, None),
    (cloud_error(403, "forbidden", "insufficient permissions or not the owner of the host"),
     "authentication", False, None),
    (cloud_error(401, "unauthorized", "unauthorized"), "authentication", False, None),
    (lambda request: httpx.Response(200, json={"data": [{"id": "x" * 4096}]}), "provider_contract", False, None),
], ids=["rate-limit-with-wait", "rate-limit", "device-timeout", "bad-gateway", "not-the-owner", "unauthorized",
        "too-large"])
def test_each_cloud_error_answer_fails_the_collection_by_its_meaning(clock, monkeypatch, fault, category, may_pass, wait):
    """A limit or a fault at the console may pass by waiting; a refusal will not. Nothing in the answer is repeated."""
    monkeypatch.setattr(core, "MAX_BODY_BYTES", 2048)
    calls, _sent = serve(monkeypatch, SMALL, fault=fault)
    with pytest.raises(IntegrationError) as caught:
        run()
    failure = classify(caught.value, str(caught.value))
    assert (caught.value.category, failure.may_pass, failure.retry_after) == (category, may_pass, wait)
    assert len(calls) == 1 and not any(word in str(caught.value) for word in ("private", "trace", "5.37", "owner"))


def test_a_collection_that_needs_more_than_the_limit_waits_for_its_turn_instead_of_failing(clock, monkeypatch):
    """98 requests through the cloud address: 96 in the first minute, one wait, then the rest."""
    now, waits = clock
    calls, sent = serve(monkeypatch, LARGE, now)
    run()
    assert len(calls) == 98 and most_in_a_minute(sent) == unifi.CLOUD_PACE == 96 < 100
    assert 55 < sum(waits) <= 60 and now[0] < 65
    # A second collection straight after shares the count: it waits where it must and still finishes.
    run()
    assert len(calls) == 196 and most_in_a_minute(sent) == 96 and sum(waits) <= 60 + core.LONGEST_WAIT


def test_collections_and_a_connection_test_of_one_console_share_one_count(clock, monkeypatch):
    """A test that would have to wait long says the limit is in use; someone is waiting for its answer."""
    now, waits = clock
    calls, sent = serve(monkeypatch, {"home": big(40, 60, 50, guests=45)}, now)
    run()
    assert len(calls) == 96 and waits == []
    report = asyncio.run(diagnose_integration("unifi_network", "two", {"base_url": CLOUD, "site_id": "home"}, SECRET))
    failed = [check for check in report.checks if check.status == "failed"]
    assert len(calls) == 96 and waits == [] and report.outcome == "failed"
    assert [check.category for check in failed] == ["rate_limit"] and "Try again shortly" in failed[0].guidance
    # A collection waits where the test would not, and another console has a count of its own.
    asyncio.run(collect("unifi_network", "three", {"base_url": CLOUD.replace(":77", ":78")}, KEY))
    assert len(calls) == 192 and waits == []
    run()
    assert len(calls) == 288 and waits and most_in_a_minute(sent[:96] + sent[192:]) == 96


def test_a_connection_test_that_used_the_whole_limit_itself_says_trying_again_cannot_help(clock, monkeypatch):
    """98 requests can never fit a test's 20 seconds of waiting, so the answer does not send the person round again."""
    now, waits = clock
    calls, _sent = serve(monkeypatch, LARGE, now)
    report = asyncio.run(diagnose_integration("unifi_network", "one", {"base_url": CLOUD, "site_id": "home"}, SECRET))
    failed = [check for check in report.checks if check.status == "failed"]
    assert len(calls) == 96 and waits == [] and [check.category for check in failed] == ["rate_limit"]
    assert "This test sent as many requests as the source allows" in failed[0].summary
    assert "Trying again will not help" in failed[0].guidance and "shortly" not in failed[0].guidance
    # With one place in the count taken by something else, trying again may help, and it says so as before.
    now[0] += 120
    core._turns[unifi.pace(CLOUD).key].append([now[0]])
    report = asyncio.run(diagnose_integration("unifi_network", "one", {"base_url": CLOUD, "site_id": "home"}, SECRET))
    failed = [check for check in report.checks if check.status == "failed"]
    assert [check.category for check in failed] == ["rate_limit"] and "Try again shortly" in failed[0].guidance


def test_the_backstop_is_longer_than_a_paced_collection_may_take_and_is_the_limit_in_force(monkeypatch, tmp_path):
    """Reading and waiting for a turn together must fit under the backstop, or a paced collection is cut off as failed."""
    assert integrations.READING_SECONDS + core.LONGEST_WAIT < collection.BACKSTOP_SECONDS < 300
    # The number checked above is the one a collection is held to: shortened, it stops a slow source.
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", KEY)
    monkeypatch.setattr(collection, "BACKSTOP_SECONDS", 0.2)

    async def slow(provider, integration_id, config, api_key):
        await asyncio.sleep(3)

    monkeypatch.setattr("nyctr.integrations.collect", slow)
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        started = time.monotonic()
        response = client.post("/api/integrations/unifi/sync", headers=live_signin(client))
        assert response.status_code == 502 and time.monotonic() - started < 2


def test_the_console_s_own_address_is_not_paced(clock, monkeypatch):
    """The limit belongs to the cloud address; the same collection on the direct address never waits."""
    now, waits = clock
    calls, sent = serve(monkeypatch, LARGE, now)
    run(DIRECT)
    run(DIRECT)
    assert unifi.pace(DIRECT) is None and unifi.pace(CLOUD) == core.Pace("unifi_network:0A1B2C3D0000:77", 96, 60.0)
    assert len(calls) == 196 and waits == [] and most_in_a_minute(sent) == 196


def fake_source(monkeypatch, pace, reads, answer_takes=0.0):
    """Register a source that only makes `reads` paced requests, each answered after `answer_takes` seconds."""
    async def answer(request):
        await asyncio.sleep(answer_takes)
        return httpx.Response(200, json={})

    async def collect_fake(integration_id, config, api_key):
        async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as client:
            reader = core.ReadClient(client, "https://paced.example", pace)
            for _ in range(reads):
                await reader.get("/read")
        return core.Snapshot()

    monkeypatch.setattr(registry, "_cache", {"paced": Provider(
        id="paced", name="Paced", summary="", letter="P", tone="blue", validate=dict, collect=collect_fake)})
    monkeypatch.setattr(core, "_turns", {})


def test_waiting_for_a_turn_does_not_count_as_reading_and_reading_is_still_limited(monkeypatch):
    """Real time, in tenths of a second: two waits outlast the reading limit; slow answers still end the collection."""
    monkeypatch.setattr(integrations, "READING_SECONDS", 0.3)
    fake_source(monkeypatch, core.Pace("slow", 1, 0.25), reads=3)
    started = core.monotonic()
    asyncio.run(collect("paced", "one", {}, KEY))
    assert core.monotonic() - started >= 0.5
    fake_source(monkeypatch, core.Pace("slow", 1, 0.25), reads=3, answer_takes=0.2)
    with pytest.raises(IntegrationError, match="timed out") as caught:
        asyncio.run(collect("paced", "one", {}, KEY))
    assert caught.value.category == "timeout"


def test_a_wait_longer_than_two_windows_ends_as_a_rate_limit_that_names_the_wait(clock, monkeypatch):
    """Six requests at two a minute wait twice; the seventh would wait a third time and is not sent."""
    _now, waits = clock
    fake_source(monkeypatch, core.Pace("tight", 2), reads=6)
    asyncio.run(collect("paced", "one", {}, KEY))
    assert waits == [60, 60]
    fake_source(monkeypatch, core.Pace("tight", 2), reads=7)
    with pytest.raises(IntegrationError) as caught:
        asyncio.run(collect("paced", "one", {}, KEY))
    failure = classify(caught.value, str(caught.value))
    assert (caught.value.category, failure.may_pass, failure.retry_after) == ("rate_limit", True, 60)
    assert waits == [60, 60, 60, 60] and str(caught.value) == "The source's request limit is in use. Try again shortly."


def test_detail_reads_are_shared_between_sites_and_each_site_cut_short_says_so(clock, monkeypatch):
    """A small site is read in full; two large ones get equal parts, where the first used to get everything."""
    sites = {"big-one": big(40, 60, 5), "small": big(2, 1, 5), "big-two": big(30, 30, 5)}
    calls, _sent = serve(monkeypatch, sites)
    with core.capture_probe() as evidence:
        snapshot = run(DIRECT)
    read = {sid: sum(f"/sites/{sid}/networks/" in call.url.path or f"/sites/{sid}/devices/" in call.url.path
                     for call in calls) for sid in sites}
    assert read == {"big-one": 37, "small": 3, "big-two": 37} and len(calls) == unifi.REQUEST_CEILING
    skipped = {node["source_id"]: node["attributes"].get("detail_reads_skipped")
               for node in snapshot.resources if node["kind"] == "site"}
    assert skipped == {"big-one": {"networks": 3, "devices": 60}, "small": None, "big-two": {"devices": 23}}
    assert "unifi_detail_limit" in evidence.gaps
    assert unifi._shares([100, 3, 60], 77) == [37, 3, 37] and unifi._shares([5, 5], 0) == [0, 0]
    assert unifi._shares([1, 1, 50, 50], 3) == [0, 0, 1, 1] and unifi._shares([4, 9], 40) == [4, 9]
    assert unifi._shares([1, 1, 1, 2], 3) == [0, 0, 0, 1] and unifi._shares([9, 2, 9], 12) == [5, 2, 5]


def test_a_collection_cut_short_by_the_request_limit_shows_that_gap_on_the_source(clock, monkeypatch, tmp_path):
    """An ordinary collection through the cloud address, not only a connection test, leaves the gap on the source."""
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_UNIFI", KEY)
    _calls, sent = serve(monkeypatch, LARGE, clock[0])
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app)
        with app.state.session_factory() as db:
            db.get(Integration, "unifi").config = {"base_url": CLOUD}
            db.commit()
        headers = live_signin(client)
        assert client.post("/api/integrations/unifi/sync", headers=headers).status_code == 200
        source = next(row for row in client.get("/api/integrations").json() if row["id"] == "unifi")
        title, summary = registry.find("unifi_network").gap_notes["unifi_detail_limit"]
        assert {"id": "unifi_detail_limit", "title": title, "summary": summary} in source["gaps"]
        with app.state.session_factory() as db:
            sites = db.scalars(select(Resource).where(Resource.integration_id == "unifi", Resource.kind == "site")).all()
        assert [site.attributes["detail_reads_skipped"] for site in sites] == [{"devices": 51}]
    # It was paced on the way: 98 requests, never more than the pace in any minute, under a minute of waiting.
    assert len(sent) == 98 and most_in_a_minute(sent) == unifi.CLOUD_PACE and 55 < sum(clock[1]) <= 60


def test_a_device_timeout_on_an_optional_read_is_a_gap_that_says_the_source_had_an_error(clock, monkeypatch):
    """The cloud's 408 on one network's detail keeps the collection and records why that read is missing."""
    timed_out = lambda request: (cloud_error(408, "DeviceTimeout", "Device connection timeout")(request)  # noqa: E731
                                 if request.url.path.endswith("/networks/lan") else None)
    serve(monkeypatch, SMALL, fault=timed_out)
    with core.capture_probe() as evidence:
        run()
    assert evidence.gap_causes == {"unifi_networks_details_unavailable": {"source_error"}}
