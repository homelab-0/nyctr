"""Sentences an administrator reads: refusals in the form's own words, every audit action worded, gaps that agree."""

import re
from pathlib import Path

import pytest
from test_collection import live_client

from nyctr import diagnostics, worker
from nyctr.integrations import IntegrationError, registry, validate_config
from nyctr.integrations.core import GAP_CAUSES, describe_gaps

API = Path(__file__).resolve().parents[1] / "nyctr"
ACTIVITY = Path(__file__).resolve().parents[3] / "apps" / "web" / "src" / "pages" / "Activity.tsx"
ALLOWED = "allowed.example.net,second.example.net"
# What a setting is called in storage or in the server's environment, never on the form.
RAW = re.compile(r"NYCTR|allowlist|\b[a-z]+_[a-z_]+\b")
WRONG = {
    "nextdns": [{"profile_id": "not-hex"}, {"profile_id": "abc123", "lookback_hours": 500},
                {"profile_id": "abc123", "api_key": "x"}],
    "pihole": [{"base_url": "https://elsewhere.example.org"}, {"base_url": "http://allowed.example.net"},
               {"base_url": "https://allowed.example.net/admin"}, {"base_url": "https://localhost"},
               {"base_url": "https://allowed.example.net", "lookback_hours": 0}, {"base_url": "https://127.0.0.1"},
               {"base_url": "https://allowed.example.net", "api_key": "x"}, {"base_url": 7}],
    "proxmox": [{"base_url": "https://elsewhere.example.org:8006"}, {"base_url": "https://allowed.example.net/x"},
                {"base_url": "https://allowed.example.net", "node": "x"}],
    "unifi_network": [{"base_url": "https://elsewhere.example.org/proxy/network/integration"},
                      {"base_url": "https://allowed.example.net/wrong"},
                      {"base_url": "https://allowed.example.net/proxy/network/integration", "site_id": "a b"},
                      {"base_url": "https://allowed.example.net/proxy/network/integration", "zone": "x"}],
}


@pytest.mark.parametrize("provider, config", [(name, config) for name, rows in WRONG.items() for config in rows])
def test_a_refused_setting_is_named_by_its_label_on_the_form(monkeypatch, provider, config):
    """No storage key, variable name, address or allowed host is repeated; a label from the form is."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", ALLOWED)
    with pytest.raises(IntegrationError) as refused:
        validate_config(provider, config)
    text = str(refused.value)
    assert not RAW.search(text), text
    assert any(field.label in text for field in registry.get(provider).fields), text
    for value in ("elsewhere.example.org", "allowed.example.net", "second.example.net"):
        assert value not in text


@pytest.mark.parametrize("address, said", [
    ("https:///proxy/network/integration", "is not an address Nyctr can read"),
    ("https://allowed.example.net:0/proxy/network/integration", "is not an address Nyctr can read"),
    ("https://allowed.example.net/" + "x" * 2048, "is too long"),
    ("https://allowed.example.net/v1/connector/consoles/abc/proxy/network/integration", "reached through the cloud"),
    ("http://allowed.example.net/proxy/network/integration", "must start with https://"),
])
def test_a_refused_address_is_told_what_is_wrong_with_it(monkeypatch, address, said):
    """No sentence asks for something the address already does, or lists mistakes it does not hold."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", ALLOWED)
    with pytest.raises(IntegrationError) as refused:
        validate_config("unifi_network", {"base_url": address})
    assert said in str(refused.value) and not RAW.search(str(refused.value))


def test_a_new_source_is_refused_in_the_same_words_as_an_edit(tmp_path, monkeypatch):
    """Saving answers with the integration's sentence and repeats no address, secret name or server setting."""
    monkeypatch.setenv("NYCTR_CONNECTOR_HOSTS", ALLOWED)
    monkeypatch.setenv("NYCTR_CONNECTOR_SECRET_RESOLVER", "CREATE_SECRET_SENTINEL")
    with live_client(tmp_path) as client:
        logged = client.post("/api/auth/login", json={"email": "owner@example.net",
                                                      "password": "secure password for tests"})
        headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
        body = {"provider": "pihole", "name": "Resolver", "secret_ref": "NYCTR_CONNECTOR_SECRET_RESOLVER",
                "config": {"base_url": "https://elsewhere.example.org"}}
        response = client.post("/api/integrations", headers=headers, json=body)
        assert response.status_code == 422
        detail = response.json()["detail"]
        assert detail.startswith("Not saved. Pi-hole address names a server Nyctr is not yet allowed to connect to.")
        assert "Check it for a typing mistake first. Only whoever runs the Nyctr server can change which" in detail
        assert not RAW.search(detail)
        for value in ("elsewhere.example.org", *ALLOWED.split(","), body["secret_ref"], "CREATE_SECRET_SENTINEL"):
            assert value not in response.text
        hours = client.post("/api/integrations", headers=headers, json={
            **body, "config": {"base_url": "https://allowed.example.net", "lookback_hours": 500}})
        assert hours.json()["detail"] == ("Not saved. Hours of blocked lookups to read must be a whole number "
                                          "between 1 and 72.")
        assert client.get("/api/integrations").json() == []


def test_every_audit_action_the_server_writes_has_a_sentence_on_the_activity_page():
    """Walk every `audit(...)` call in the server; a new action without wording on the page fails here."""
    source = "\n".join(path.read_text() for path in sorted(API.rglob("*.py")))
    calls = re.findall(r"\baudit\(\s*db,[^,]+,\s*([^,)]+)", source)
    written = {call.strip('"') for call in calls if re.fullmatch(r'"[a-z_.]+"', call)}
    built = sorted(call for call in calls if not re.fullmatch(r'"[a-z_.]+"', call) and call != "action: str")
    # The two names built at run time, spelled out here; a third fails until it is added.
    assert built == ['"access." + body.decision', 'f"guest.{action}"', 'f"guest.{action}"']
    written |= {f"access.{decision}" for decision in ("reviewed", "denied", "approved")}
    written |= {f"guest.{action}" for action in ("cut", "restore", "lock", "admit")}
    assert len(written) > 30
    worded = set(re.findall(r"^  '([a-z_]+\.[a-z_]+)':", ACTIVITY.read_text(), re.M))
    assert written - worded == set()


def test_every_reason_code_the_server_records_has_a_sentence_on_the_activity_page():
    """Walk every place a reason is given as a code; one with no wording on the page fails here."""
    source = "\n".join(path.read_text() for path in sorted(API.rglob("*.py")))
    given = re.findall(r"\bend_lease\(\s*db,[^,]+,[^,]+,\s*([^,)]+)", source)
    given += re.findall(r"\b_stop_retries\(\s*db,[^,]+,\s*([^,)]+)", source)
    given += re.findall(r"""\breason=("[^"]*"|[^,)\s]+)""", source)
    codes = {text.strip('"') for text in given if re.fullmatch(r'"[a-z_]+"', text)}
    # Anything else is a sentence a person or a rule wrote, or, for `error`, a code in worker.ENDED.
    names = sorted({text for text in given if not text.startswith('"')})
    assert names == ["body.reason", "error", "reason", "reason: str", "reason[:200]", "reason[:500]"]
    codes |= worker.ENDED
    assert {"expired", "revoked", "removed_by_hand", "schedule_off", "secret", "secret_ref"} <= codes
    reasons = re.search(r"^const REASONS: [^=]+= \{\n(.*?)^\};", ACTIVITY.read_text(), re.M | re.S).group(1)
    assert codes - set(re.findall(r"^  ([a-z_]+): '", reasons, re.M)) == set()


def test_a_gap_text_never_states_a_cause_the_sentence_beside_it_may_contradict():
    """Why a read was not made is said once, by the cause sentence; the integration says only what is missing."""
    for provider in registry.providers().values():
        for code, (_title, text) in provider.gap_notes.items():
            assert not re.search(r"refused|not available|unusable|failed|this key|error", text, re.I), (code, text)
            for cause, sentence in GAP_CAUSES.items():
                assert describe_gaps(provider.gap_notes, {code: [cause]})[0][2] == f"{text} {sentence}"


def test_a_request_limit_is_told_in_the_pages_own_words():
    """Whether Nyctr held a request back or the source turned one away, the sentence says source and collect."""
    core = (API / "integrations" / "core.py").read_text()
    raised = re.findall(r'IntegrationError\("([^"]+)",\s*category="rate_limit"', core)
    assert raised == ["The source's request limit is in use. Try again shortly.",
                      "The source's request limit was reached. Try collecting again later."]
    for text in (*raised, *diagnostics._FAILURES["rate_limit"]):
        assert "request limit" in text or text.startswith("Try again shortly.")
        assert not re.search(r"provider|sync|rate.limit|integration scope|frequency", text, re.I), text


HOUSEHOLD = re.compile(
    r"\b(home|house(hold)?|famil(y|ies)|kids?|child(ren)?|parents?|mum|dad|movie|laundry|kitchen|bedroom|basement"
    r"|upstairs|downstairs|garage|garden|weekend|part(y|ies)|front door|recipes?|photos?|media)\b|milkyway", re.I)
# The DNS product's own name for one of its categories, kept as the product writes it.
PRODUCT_WORDS = ("Parental Control: streaming",)
SHOWN = ("/api/integrations", "/api/resources", "/api/blocks", "/api/requests", "/api/leases", "/api/suggestions",
         "/api/guests", "/api/findings", "/api/users", "/api/devices", "/api/attention", "/api/overview")


def _words(value, key=""):
    """Every text a page could show from a response: values only, and never an id or a reference to one."""
    if isinstance(value, dict):
        for name, item in value.items():
            yield from _words(item, name)
    elif isinstance(value, list):
        for item in value:
            yield from _words(item, key)
    elif isinstance(value, str) and not re.search(r"(^|_)ids?$|^(uplink|source|target|email|href|link)$", key):
        yield value


def test_the_demo_names_no_real_installation_and_uses_no_home_wording(client, admin_headers):
    """Nothing the demo shows reads as a household: names, reasons, passes, findings and what needs attention."""
    names = {row["name"] for row in client.get("/api/integrations").json()}
    assert {"Northgate UniFi Network", "Office DNS on NextDNS"} <= names
    shown = [text for path in SHOWN for text in _words(client.get(path).json())]
    assert len(shown) > 400
    for word in PRODUCT_WORDS:
        shown = [text.replace(word, "") for text in shown]
    assert sorted({text for text in shown if HOUSEHOLD.search(text)}) == []
    surnames = [row["name"].split()[-1] for row in client.get("/api/users").json()]
    assert len(set(surnames)) == len(surnames), "people who share a surname read as one family"
