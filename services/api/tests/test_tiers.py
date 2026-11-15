"""Where a block lives, what kind it is, and the one function that says whether the rule may open it.

Denial paths first: what can never open, what the rule refuses to become, then what a request is told.
"""

import ast
import asyncio
import os
from dataclasses import fields, replace
from datetime import timedelta
from itertools import product
from pathlib import Path

import pytest
from conftest import LIVE_MEMBER, live_signin, signin
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import delete, select
from test_access import GALLERY, put_rule
from test_crossing import DOMAIN, Source, ask, console, started

from nyctr import access, layers, policy, risk
from nyctr.config import Settings
from nyctr.database import make_engine, migrate, session_factory
from nyctr.main import create_app
from nyctr.models import Audit, DeviceGrant, Lease, Observation, Resource, Setting, User
from nyctr.policy import AccessRule, AdTier, AnalysisInput, Facts, ThreatTier, may_open
from nyctr.security import hash_password

ROOT = Path(__file__).resolve().parents[1] / "nyctr"
ORDER = ["rule_on", "tier", "mode", "can_open", "changes_on", "match", "conditions", "declined", "analysis",
         "per_day", "daily_total"]
EVERY = [layers.Descriptor(layer, kind, origin)
         for layer, kind, origin in product(layers.LAYERS, layers.KINDS, layers.ORIGINS)]
AD, FEED = layers.Descriptor("dns_upstream", "list", "third_party"), layers.Descriptor("dns_upstream", "feed", "vendor")
# Present or not, every verdict and every risk, and a word outside the vocabulary for each.
ANALYSES = [AnalysisInput(present, verdict, level) for present, verdict, level in product(
    (False, True), (*policy.VERDICTS, "something else"), (*policy.RISKS, "something else"))]
GOOD = AnalysisInput(True, "not_justified", "low")
ON = AccessRule(enabled=True, ad_tracker=AdTier(mode="on"))
# Every switch position the model allows, with each limit at its lowest and its highest.
RULES = [AccessRule(enabled=enabled, per_day=per_day, daily_total=total, threat_feed=ThreatTier(max_minutes=15),
                    ad_tracker=AdTier(mode=mode, max_score=score, max_minutes=minutes))
         for enabled, mode, score, minutes, per_day, total in product(
             (False, True), ("off", "shadow", "on"), (0, 60), (15, 240), (1, 20), (1, 100))]
# What validation refuses today, forced past it: the threat tier recording or on, with everything else on.
FORCED = [ON.model_copy(update={"threat_feed": ThreatTier().model_copy(update={"mode": mode})})
          for mode in ("shadow", "on")]


def facts(*policies, **changes) -> Facts:
    """Everything in favour of opening, so that only what a test changes can stop it."""
    return replace(Facts(policies=policies, can_open=True, changes_on=True, match="assignment", score=0,
                         name_shape=False, registered_days=3650, declined=False, opened_today=0,
                         opened_today_all=0, asked_minutes=240), **changes)


def held(db) -> list[str]:
    """Every claim on a request or a source entry that is held right now."""
    return [key for key in db.scalars(select(Setting.key)) if key.startswith(("ending:", "review:"))]


class Unread:
    """Stands where the analysis goes and fails the test if anything looks at it."""

    def __getattr__(self, name):
        raise AssertionError(f"the analysis was read ({name})")


def test_layers_are_in_traffic_order_and_an_unstated_kind_or_origin_is_unknown():
    """The vocabulary is the core's own; a word outside it, or none, becomes unknown and never a guess."""
    assert layers.LAYERS == ("dns_gateway", "dns_upstream", "firewall", "intrusion")
    assert [f.name for f in fields(layers.Descriptor)] == ["layer", "kind", "origin", "ref", "name", "description"]
    assert layers.describe("dns_upstream") == layers.Descriptor("dns_upstream", "unknown", "unknown")
    assert layers.describe("firewall", "geo-fence", ["vendor"]).kind == "unknown"
    assert layers.describe("firewall", "geo-fence", ["vendor"]).origin == "unknown"
    with pytest.raises(ValueError):
        layers.describe("dns")
    assert layers.deliberate(layers.Descriptor("dns_upstream", "category", "vendor")) is True
    assert layers.deliberate(layers.Descriptor("firewall", "policy", "administrator")) is True
    assert layers.deliberate(AD) is False and layers.deliberate(FEED) is False
    assert layers.deliberate(layers.Descriptor("firewall", "policy", "vendor")) is None
    assert layers.deliberate(layers.describe("dns_upstream")) is None


def test_only_a_list_or_a_feed_at_a_dns_layer_can_ever_be_automatic():
    """The fixed table, spelled out: eight descriptors of 128 are in a tier that can be switched on."""
    automatic = {(d.layer, d.kind, d.origin): policy.tier_of(d) for d in EVERY
                 if policy.tier_of(d) in policy.AUTOMATIC}
    assert automatic == {(layer, kind, origin): tier
                         for layer in ("dns_gateway", "dns_upstream")
                         for kind, tier in (("list", "ad_tracker"), ("feed", "threat_feed"))
                         for origin in ("third_party", "vendor")}
    for origin in layers.ORIGINS:
        assert policy.tier_of(layers.Descriptor("dns_upstream", "category", origin)) == "category"
        assert policy.tier_of(layers.Descriptor("dns_gateway", "deny_entry", origin)) == "deny_entry"
        assert policy.tier_of(layers.Descriptor("dns_upstream", "signature", origin)) == "intrusion"
        assert {policy.tier_of(layers.Descriptor("firewall", kind, origin)) for kind in layers.KINDS} \
            == {"firewall_policy", "intrusion"}
        assert {policy.tier_of(layers.Descriptor("intrusion", kind, origin)) for kind in layers.KINDS} == {"intrusion"}
    assert policy.tier_of(layers.Descriptor("somewhere_new", "list", "third_party")) == "unknown"
    assert policy.block_tier(()) == "unknown"


def test_no_rule_and_no_analysis_opens_a_block_of_a_kind_that_is_never_automatic():
    """The whole space: every never descriptor, every rule the model allows, every analysis. None opens.

    Alone, and beside a reason that could be automatic. The analysis is not even looked at.
    """
    never = [d for d in EVERY if policy.tier_of(d) in policy.NEVER]
    assert len(never) == 120
    tried = 0
    for stated in never:
        for block, rules in (((stated,), RULES + FORCED), ((AD, stated), FORCED), ((stated, FEED), FORCED)):
            for asked, rule in product([facts(*block, analysis=analysis) for analysis in ANALYSES], rules):
                verdict = may_open(rule, asked)
                assert not verdict.allow and not verdict.would and verdict.minutes == 0
                assert verdict.failed in ("rule_on", "tier") and verdict.tier in policy.NEVER
                tried += 1
            assert may_open(FORCED[1], facts(*block, analysis=Unread())).failed == "tier"
    assert tried == 120 * (len(RULES) + 3 * len(FORCED)) * len(ANALYSES)
    assert may_open(FORCED[1], facts(analysis=GOOD)).failed == "tier"  # A block that states no reason at all.
    with pytest.raises(AssertionError, match="the analysis was read"):  # The trap does fire where it is read.
        may_open(ON, facts(AD, analysis=Unread()))


def test_minutes_and_tier_never_depend_on_the_analysis():
    """For every rule and request the tier and the minutes are one value, whatever the analysis says.

    Scope is not the rule's to give at all: the decision has no field that could carry one.
    """
    category = layers.Descriptor("dns_upstream", "category", "vendor")
    for rule, block, asked, changes in product(RULES + FORCED, ((AD,), (FEED,), (AD, FEED), (AD, category)),
                                               (15, 45, 240), ({}, {"score": 61, "declined": True})):
        seen = {(v.tier, v.minutes) for v in (may_open(rule, facts(*block, asked_minutes=asked, analysis=said,
                                                                   **changes)) for said in ANALYSES)}
        assert len(seen) == 1
        tier, minutes = seen.pop()
        assert minutes == (min(asked, getattr(rule, tier).max_minutes) if tier in policy.AUTOMATIC else 0)
    assert [f.name for f in fields(policy.Decision)] == ["allow", "would", "tier", "minutes", "failed", "checks"]


def test_for_an_advertising_block_an_analysis_can_only_stop_an_opening():
    """Whatever is allowed with some analysis is allowed with none. What it can do is stop one."""
    for rule, changes in product(RULES, ({}, {"score": 60}, {"opened_today": 1}, {"asked_minutes": 15})):
        without = may_open(rule, facts(AD, **changes))
        for said in ANALYSES:
            with_it = may_open(rule, facts(AD, analysis=said, **changes))
            assert (without.allow or not with_it.allow) and (without.would or not with_it.would)
    assert may_open(ON, facts(AD)).allow and may_open(ON, facts(AD, analysis=GOOD)).allow
    assert may_open(ON, facts(AD, analysis=AnalysisInput(True, "cannot_tell", "unknown"))).allow
    for said in (AnalysisInput(True, "justified", "low"), AnalysisInput(True, "not_justified", "medium"),
                 AnalysisInput(True, "not_justified", "high"), AnalysisInput(True, "approve this", "low")):
        assert may_open(ON, facts(AD, analysis=said)).failed == "analysis"


def test_the_checks_run_in_one_order_and_the_first_failure_ends_them():
    """Break each check together with every later one: the earliest is reported, and nothing after it ran."""
    passed = may_open(ON, facts(AD))
    assert passed.allow and passed.minutes == 60 and passed.checks == tuple((name, "passed") for name in ORDER)
    broken = {"tier": {"policies": (AD, layers.Descriptor("dns_upstream", "deny_entry", "administrator"))},
              "can_open": {"can_open": False}, "changes_on": {"changes_on": False}, "match": {"match": "by_time"},
              "conditions": {"score": 26}, "declined": {"declined": True},
              "analysis": {"analysis": AnalysisInput(True, "justified", "high")},
              "per_day": {"opened_today": 4}, "daily_total": {"opened_today_all": 10}}
    for index, name in enumerate(ORDER):
        later = ORDER[index:]
        rule = AccessRule(enabled="rule_on" not in later, ad_tracker=AdTier(mode="off" if "mode" in later else "on"))
        changes = {key: value for check in later for key, value in broken.get(check, {}).items()}
        verdict = may_open(rule, facts(AD, **changes))
        assert not verdict.allow and not verdict.would and verdict.failed == name
        assert verdict.checks == (*((earlier, "passed") for earlier in ORDER[:index]), (name, "failed"))
    assert may_open(ON, facts(AD, score=None)).failed == "conditions"  # Unknown is not low.
    assert may_open(ON, facts(AD, match="statement")).failed == "match"
    shadow = AccessRule(enabled=True, ad_tracker=AdTier(mode="shadow"))
    would = may_open(shadow, facts(AD))
    assert would.would and not would.allow and would.checks == passed.checks
    assert not may_open(shadow, facts(AD, score=26)).would


def test_the_threat_tier_stays_off_and_would_need_an_analysis_that_vouches():
    """No stored rule can switch it on yet. Forced on, only an analysis that is there and says so opens it."""
    for mode in ("shadow", "on"):
        with pytest.raises(ValidationError):
            ThreatTier(mode=mode)
    assert may_open(ON, facts(FEED, analysis=GOOD)).failed == "mode"
    forced = FORCED[1]
    opened = may_open(forced, facts(AD, FEED, analysis=GOOD))  # Beside an advertising list it is a threat block.
    assert opened.allow and opened.tier == "threat_feed" and opened.minutes == 30
    assert [said for said in ANALYSES if may_open(forced, facts(FEED, analysis=said)).allow] == [GOOD]
    for changes in ({"name_shape": True}, {"registered_days": None}, {"registered_days": 179}):
        assert may_open(forced, facts(FEED, analysis=GOOD, **changes)).failed == "conditions"
    assert may_open(forced, facts(FEED, analysis=GOOD, declined=True)).failed == "declined"
    assert may_open(forced, facts(FEED, analysis=GOOD, score=92)).allow  # The score is not its condition.


def test_the_decision_and_the_layers_reach_no_database_network_or_model():
    """`layers.py` imports nothing of Nyctr's. `may_open`, and all it calls, reads no name `policy.py`
    took from the database, and `policy.py` imports nothing else that could reach a source or a model."""
    def imports(tree):
        return {(node.module or "") if isinstance(node, ast.ImportFrom) else alias.name
                for node in ast.walk(tree) if isinstance(node, ast.Import | ast.ImportFrom) for alias in node.names}

    assert imports(ast.parse((ROOT / "layers.py").read_text())) == {"__future__", "dataclasses"}
    tree = ast.parse((ROOT / "policy.py").read_text())
    assert imports(tree) == {"__future__", "dataclasses", "typing", "pydantic", "sqlalchemy.orm", "layers", "models"}
    stored = {alias.asname or alias.name for node in tree.body if isinstance(node, ast.ImportFrom)
              and node.module in ("sqlalchemy.orm", "models") for alias in node.names}
    assert stored == {"Session", "Setting", "utcnow"}
    defined = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef | ast.ClassDef)}
    reached, queue = set(), ["may_open"]
    while queue:
        name = queue.pop()
        if name in reached:
            continue
        reached.add(name)
        used = {node.id for node in ast.walk(defined[name]) if isinstance(node, ast.Name)}
        assert not used & (stored | {"db", "get_rule", "put_rule", "get_list", "put_list"}), name
        queue += sorted(used & set(defined))
    assert {"may_open", "block_tier", "tier_of", "Decision", "AccessRule"} <= reached


@pytest.mark.parametrize("source,text,kind,origin,tier", [
    ("nextdns", "blocklist:hagezi-multi-pro-plusplus", "list", "third_party", "ad_tracker"),
    ("nextdns", "native:apple", "list", "vendor", "ad_tracker"),
    ("nextdns", "disguised-trackers", "list", "third_party", "ad_tracker"),
    ("nextdns", "threat-intelligence-feeds", "feed", "third_party", "threat_feed"),
    ("nextdns", "google-safe-browsing", "feed", "third_party", "threat_feed"),
    ("nextdns", "ai-threat-detection", "unknown", "vendor", "unknown"),
    ("nextdns", "cryptojacking", "unknown", "vendor", "unknown"),
    ("nextdns", "dns-rebinding", "unknown", "vendor", "unknown"),
    ("nextdns", "idn-homograph", "unknown", "vendor", "unknown"),
    ("nextdns", "typosquatting", "unknown", "vendor", "unknown"),
    ("nextdns", "dga", "unknown", "vendor", "unknown"),
    ("nextdns", "csam", "unknown", "third_party", "unknown"),
    ("nextdns", "nrd", "unknown", "vendor", "unknown"),
    ("nextdns", "ddns", "unknown", "vendor", "unknown"),
    ("nextdns", "parking", "unknown", "vendor", "unknown"),
    ("nextdns", "denylist", "deny_entry", "administrator", "deny_entry"),
    ("nextdns", "parentalcontrol:category:gambling", "category", "vendor", "category"),
    ("nextdns", "safesearch", "category", "vendor", "category"),
    ("nextdns", "something-nyctr-has-never-seen", "unknown", "unknown", "unknown"),
    ("pihole", "GRAVITY", "unknown", "third_party", "unknown"),
    ("pihole", "GRAVITY_CNAME", "unknown", "third_party", "unknown"),
    ("pihole", "DENYLIST", "deny_entry", "administrator", "deny_entry"),
    ("pihole", "REGEX_CNAME", "deny_entry", "administrator", "deny_entry"),
    ("pihole", "EXTERNAL_BLOCKED_NXRA", "unknown", "unknown", "unknown"),
    # A source that explains nothing is scored from a few plain words, and its kind is never guessed.
    ("something_new", "Advert tracker list", "unknown", "unknown", "unknown"),
    ("something_new", "Malware feed", "unknown", "unknown", "unknown"),
])
def test_every_reason_a_source_reports_is_placed(source, text, kind, origin, tier):
    """Each integration states kind and origin as facts; the core places the tier. Unstated is unknown."""
    stated = risk.assess("shop.example", "", [text], source).policies
    assert [(p.layer, p.kind, p.origin, p.ref) for p in stated] == [("dns_upstream", kind, origin, text)]
    assert policy.block_tier(stated) == tier


def test_a_block_takes_its_strictest_tier_and_one_unrecognised_reason_makes_it_unknown():
    """Opening an address lifts every reason on it at once, so every one of them has to be placed."""
    def tier(reason, codes, source="nextdns"):
        return policy.block_tier(risk.assess("shop.example", reason, codes, source).policies)

    assert tier("HaGeZi Multi PRO++", ["blocklist:x"]) == "ad_tracker"  # A free-form name beside an identifier.
    assert tier("", ["blocklist:x", "native:apple"]) == "ad_tracker"
    assert tier("", ["blocklist:x", "threat-intelligence-feeds"]) == "threat_feed"
    assert tier("HaGeZi Multi PRO++; Threat Intelligence Feeds", ["blocklist:x"]) == "threat_feed"
    assert tier("", ["blocklist:x", "threat-intelligence-feeds", "safesearch"]) == "category"
    assert tier("", ["blocklist:x", "denylist"]) == "deny_entry"
    assert tier("", ["blocklist:x", "newfeature:xyz"]) == "unknown"
    assert tier("Tracker blocklist; Something new", []) == "unknown"
    assert tier("", []) == "unknown"
    # Scored low from plain words, and still nothing the rule may open: its kind was never stated.
    plain = risk.assess("shop.example", "Advert tracker list", [], "something_new")
    verdict = may_open(ON, facts(*plain.policies, score=plain.score))
    assert plain.score == 16 and verdict.failed == "tier"
    assert access._left_to_a_person(verdict, ON, plain, None) \
        == "Nyctr cannot tell what kind of list blocked this, so a person decides."


@pytest.mark.parametrize("body", [
    *({"enabled": True, tier: {"mode": "on"}} for tier in policy.NEVER),
    {"enabled": True, "deny_entry": {"mode": "shadow", "max_minutes": 15}},
    {"threat_feed": {"mode": "shadow"}}, {"threat_feed": {"mode": "on"}},
    {"daily_total": 0}, {"daily_total": 101}, {"per_day": 21},
    {"ad_tracker": {"max_minutes": 15}},  # The threat tier's 30 minutes would then be the longer.
    {"ad_tracker": {"max_minutes": 60}, "threat_feed": {"max_minutes": 61}},
    {"ad_tracker": {"mode": "always"}}, {"ad_tracker": {"max_score": 61}}, {"ad_tracker": {"max_minutes": 241}},
    {"threat_feed": {"min_registered_days": 29}}, {"threat_feed": {"min_registered_days": 3651}},
    {"enabled": True, "max_score": 25, "max_minutes": 60, "per_day": 4},  # The older form is only ever read.
    {"enabled": True, "allow_statement": True},
])
def test_the_rule_cannot_be_written_wider_than_the_tiers_allow(client, admin_headers, body):
    """A mode on a never tier, the threat tier past off, a limit out of bounds: refused, and nothing stored."""
    before = client.get("/api/rules").json()["access"]
    assert client.put("/api/rules/access", headers=admin_headers, json=body).status_code == 422
    assert client.get("/api/rules").json()["access"] == before
    with pytest.raises(ValidationError):
        AccessRule(**body)


def test_only_an_administrator_on_the_console_address_writes_the_rule():
    """A member is refused, and so is an administrator's own session on the portal address."""
    console_url, portal_url = "http://console.test", "http://portal.test"
    app = create_app(Settings(mode="demo", database_url="sqlite:///:memory:", public_url=console_url,
                              portal_url=portal_url, cookie_secure=False))
    wider = {"enabled": True, "per_day": 20, "daily_total": 100, "ad_tracker": {"mode": "on", "max_score": 60}}
    with TestClient(app, base_url=console_url) as on_console, TestClient(app, base_url=portal_url) as on_portal:
        assert on_console.put("/api/rules/access", json=wider).status_code == 401
        for who in ("jamie@nyctr.demo", "admin@nyctr.demo"):
            token = on_portal.post("/api/auth/login", json={"email": who, "password": "nyctr-demo"}).json()
            headers = {"X-CSRF-Token": token["csrf_token"], "Origin": portal_url}
            assert on_portal.put("/api/rules/access", headers=headers, json=wider).status_code == 403
            assert on_portal.get("/api/rules").status_code == 403
        token = on_console.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "nyctr-demo"})
        headers = {"X-CSRF-Token": token.json()["csrf_token"], "Origin": console_url}
        assert on_console.get("/api/rules").json()["access"]["ad_tracker"]["max_score"] == 25  # Nothing got in.
        assert on_console.put("/api/rules/access", headers=headers, json=wider).status_code == 200


OLD = {"enabled": True, "max_score": 40, "max_minutes": 120, "per_day": 7}
POSTGRES = os.environ.get("NYCTR_TEST_POSTGRES_URL", "")


@pytest.mark.parametrize("database", ["sqlite", pytest.param("postgresql", marks=pytest.mark.skipif(
    not POSTGRES, reason="set NYCTR_TEST_POSTGRES_URL to an empty PostgreSQL database to run this"))])
def test_a_rule_stored_before_tiers_reads_as_it_acted_and_a_broken_one_as_everything_off(tmp_path, database):
    """Advertising and tracker lists on with the old limits, everything else off, the new total at its default."""
    engine = make_engine(POSTGRES if database == "postgresql" else f"sqlite:///{tmp_path}/old.db")
    migrate(engine)
    cases = [
        (OLD, AccessRule(enabled=True, per_day=7, ad_tracker=AdTier(mode="on", max_score=40, max_minutes=120))),
        ({**OLD, "enabled": False}, AccessRule(enabled=False, per_day=7, ad_tracker=AdTier(
            mode="on", max_score=40, max_minutes=120))),
        ({"enabled": True, "max_score": 0, "max_minutes": 15, "per_day": 1}, AccessRule(
            enabled=True, per_day=1, ad_tracker=AdTier(mode="on", max_score=0, max_minutes=15),
            threat_feed=ThreatTier(max_minutes=15))),
        ({"enabled": True, "max_score": 60, "max_minutes": 240, "per_day": 20}, AccessRule(
            enabled=True, per_day=20, ad_tracker=AdTier(mode="on", max_score=60, max_minutes=240))),
        # No longer valid in either form: the safe default, as before.
        ({**OLD, "max_score": 61}, AccessRule()), ({**OLD, "per_day": 0}, AccessRule()),
        ({**OLD, "ad_tracker": {"mode": "on"}}, AccessRule()),
        ({"enabled": True, "threat_feed": {"mode": "on"}}, AccessRule()),
        ({"enabled": True, "ad_tracker": {"mode": "on"}, "intrusion": {"mode": "on"}}, AccessRule()),
        ({"enabled": True, "ad_tracker": {"mode": "on", "max_minutes": 15}}, AccessRule()),
        ({"enabled": "yes please", "max_score": [25]}, AccessRule()),
    ]
    try:
        with session_factory(engine)() as db:
            for stored, expected in cases:
                db.execute(delete(Setting).where(Setting.key == "access_rule"))
                db.add(Setting(key="access_rule", value=stored))
                db.commit()
                db.expire_all()
                read = policy.get_rule(db, "access_rule")
                assert read == expected, stored
                assert (read.daily_total, read.threat_feed.mode) == (10, "off")
            assert not AccessRule().enabled and AccessRule().ad_tracker.mode == "off"
            policy.put_rule(db, "access_rule", cases[0][1], "someone")  # Stored again, it is in the new form.
            db.commit()
            db.expire_all()
            assert db.get(Setting, "access_rule").value["ad_tracker"]["max_score"] == 40
            assert policy.get_rule(db, "access_rule") == cases[0][1]
    finally:
        with session_factory(engine)() as db:
            db.execute(delete(Setting).where(Setting.key == "access_rule"))
            db.commit()
        engine.dispose()


def test_after_the_upgrade_the_same_requests_open_and_the_same_wait(client, app):
    """An older stored rule opens the privacy-list block it opened before, for its own minutes, and nothing else."""
    with app.state.session_factory() as db:
        db.get(Setting, "access_rule").value = {"enabled": True, "max_score": 25, "max_minutes": 45, "per_day": 4}
        db.commit()
    member = signin(client, member=True)
    opened = client.post("/api/requests", headers=member, json=GALLERY).json()
    assert (opened["status"], opened["duration_minutes"]) == ("auto_approved", 45)
    for block in ("block-verify", "block-tablet", "block-print"):  # Newly registered, a deny entry, an unsaid list.
        waits = client.post("/api/requests", headers=member, json={**GALLERY, "block_id": block}).json()
        assert waits["status"] == "pending"
    signin(client)
    assert client.get("/api/rules").json()["access"] == {
        "enabled": True, "per_day": 4, "daily_total": 10,
        "ad_tracker": {"mode": "on", "max_score": 25, "max_minutes": 45},
        "threat_feed": {"mode": "off", "max_minutes": 30, "min_registered_days": 180}}


def test_a_request_is_told_which_new_check_left_it_to_a_person(client, app):
    """The tier switched off, the day's total for everyone, and a block not tied to a device."""
    def request(block="block-gallery"):
        headers = signin(client, member=True)
        return client.post("/api/requests", headers=headers, json={**GALLERY, "block_id": block}).json()

    put_rule(client, signin(client), ad_tracker={"mode": "off"})
    off = request()
    assert off["status"] == "pending" and off["decision_note"] \
        == "Automatic access is switched off for advertising and tracker lists, so a person decides."
    put_rule(client, signin(client), daily_total=1)  # One automatic opening is already seeded today.
    full = request("block-fonts")
    assert full["status"] == "pending" and full["decision_note"] \
        == "Nyctr has reached today's limit of 1 automatic openings for everyone, so a person decides."
    with app.state.session_factory() as db:
        event = db.scalar(select(Audit).where(Audit.action == "access.rule_checked", Audit.target_id == full["id"]))
        assert event.details["checks"] == [*([name, "passed"] for name in ORDER[:-1]), ["daily_total", "failed"]]
        assert event.details["outcome"] == "waits" and "minutes" not in event.details
        one = db.get(Observation, "block-gallery")
        db.add(Observation(id="block-inferred", **{name: getattr(one, name) for name in (
            "integration_id", "device_id", "device_name", "domain", "source", "reason", "reason_codes",
            "observed_at", "expires_at", "evidence_kind", "risk_explanation")}, attribution="inferred"))
        db.commit()
    # Only an administrator can ask about a block that is not assigned; the rule does not open it for them either.
    admin = put_rule(client, signin(client)) or signin(client)
    loose = client.post("/api/requests", headers=admin, json={**GALLERY, "block_id": "block-inferred"}).json()
    assert loose["status"] == "pending" and loose["decision_note"] \
        == "Nyctr cannot be sure which device this block belongs to, so a person decides."


def test_record_only_leaves_the_request_to_a_person_and_changes_nothing_at_the_source(tmp_path, monkeypatch):
    """Shadow: the record says the rule would have opened it, with every check, and nothing is sent or opened."""
    source = Source(monkeypatch)
    with started(tmp_path) as (app, client, member, admin):
        put_rule(client, admin["headers"], ad_tracker={"mode": "shadow"})
        row = client.post("/api/requests", headers=live_signin(client, LIVE_MEMBER), json=ask("one")).json()
        assert (row["status"], row["decided_by"]) == ("pending", None) and row["decision_note"] == (
            "The access rule would have opened this for 60 minutes. It is set to record only, so a person decides.")
        assert source.calls == [] and source.listed == []
        with app.state.session_factory() as db:
            assert db.scalars(select(Lease)).all() == []
            assert held(db) == []
            event = db.scalar(select(Audit).where(Audit.action == "access.rule_checked", Audit.target_id == row["id"]))
            assert event.actor_id is None and event.details["checks"] == [[name, "passed"] for name in ORDER]
            assert (event.details["outcome"], event.details["tier"], event.details["minutes"]) \
                == ("would_open", "ad_tracker", 60)
            assert event.details["limits"] == {"per_day": 4, "daily_total": 10, "mode": "shadow", "max_score": 25,
                                               "max_minutes": 60}
        # A person still decides it, and that does change the source.
        assert client.post(f"/api/requests/{row['id']}/review", headers=live_signin(client),
                           json={"decision": "approved", "note": "Fine", "minutes": 30}).status_code == 200
        assert source.listed == [DOMAIN]


def test_two_requests_of_one_person_at_one_instant_cannot_both_pass_the_daily_total(tmp_path, monkeypatch):
    """Both count the day before either has opened. The second waits its turn and counts again."""
    source = Source(monkeypatch, hold=(2, "after"))  # The first has sent its add and has no answer yet.
    monkeypatch.setattr(access, "OPENING_WAITS", 3600.0)  # However busy the machine, the second gets its turn.
    waiting, claim = asyncio.Event(), access._claim

    def watched(db, name):
        got = claim(db, name)
        if got is None and name.startswith("ending:auto:"):
            waiting.set()  # The second passed the rule on the first count and now waits for the person's turn.
        return got

    async def scenario(app, member):
        async with console(app, member) as sam:
            first = asyncio.create_task(sam.post("/api/requests", json=ask("one")))
            await asyncio.wait_for(source.reached.wait(), 300)
            second = asyncio.create_task(sam.post("/api/requests", json=ask("two")))
            await asyncio.wait_for(waiting.wait(), 300)
            source.go.set()
            rows = [(await task).json() for task in (first, second)]
        assert [row["status"] for row in rows] == ["auto_approved", "pending"]
        assert rows[1]["decision_note"] \
            == "Nyctr has reached today's limit of 1 automatic openings for everyone, so a person decides."

    with started(tmp_path) as (app, client, member, admin):
        put_rule(client, admin["headers"], daily_total=1)
        monkeypatch.setattr(access, "_claim", watched)
        asyncio.run(scenario(app, member))
        with app.state.session_factory() as db:
            assert [lease.status for lease in db.scalars(select(Lease))] == ["active"]


def test_two_people_at_one_instant_cannot_both_pass_the_daily_total(tmp_path, monkeypatch):
    """The turn is one person's, so two people both pass the count. The one stored second is counted again
    with the rule's row locked: it is not stored, and the entry it added stays on record to be removed."""
    source = Source(monkeypatch, hold=(2, "after"))
    robin = ("robin@example.net", "a third secure password")

    async def scenario(app, sam, other):
        async with console(app, sam) as first_person, console(app, other) as second_person:
            first = asyncio.create_task(first_person.post("/api/requests", json=ask("one")))
            await asyncio.wait_for(source.reached.wait(), 300)  # Sam's add is sent; nothing of it is stored yet.
            second = (await second_person.post("/api/requests", json=ask("robin"))).json()
            source.go.set()
            return (await first).json(), second

    with started(tmp_path) as (app, client, member, admin):
        put_rule(client, admin["headers"], daily_total=1)
        with app.state.session_factory() as db:
            one, laptop = db.get(Observation, "dns:block:one"), db.get(Resource, "unifi:client:laptop")
            db.add(User(id="robin", email=robin[0], name="Robin", role="member", password_hash=hash_password(robin[1])))
            db.flush()
            db.add(Resource(id="unifi:client:phone", name="Robin's phone", owner_id="robin", source_id="phone", **{
                name: getattr(laptop, name) for name in ("integration_id", "kind", "provider", "site_id",
                                                         "observed_at", "evidence_kind", "classification")}))
            db.flush()
            db.add(DeviceGrant(device_id="unifi:client:phone", user_id="robin",
                               valid_from=one.observed_at - timedelta(days=1)))
            db.add(Observation(id="dns:block:robin", device_id="unifi:client:phone", domain="fonts.example", **{
                name: getattr(one, name) for name in (
                    "integration_id", "device_name", "source", "reason", "reason_codes", "observed_at",
                    "expires_at", "evidence_kind", "attribution", "risk_explanation")}))
            db.commit()
        client.cookies.clear()
        other = {"headers": live_signin(client, robin), "cookies": dict(client.cookies)}
        late, stored = asyncio.run(scenario(app, member, other))
        assert stored["status"] == "auto_approved" and late["status"] == "pending"
        assert late["decision_note"] \
            == "Nyctr has reached today's limit of 1 automatic openings for everyone, so a person decides."
        with app.state.session_factory() as db:
            leases = {lease.domain: (lease.status, lease.owned) for lease in db.scalars(select(Lease))}
            assert leases == {"fonts.example": ("active", True), DOMAIN: ("unconfirmed", True)}
            assert held(db) == []
