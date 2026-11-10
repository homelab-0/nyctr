"""The rule-based assessment: explainable, and unknown stays unknown."""

import pytest

from nyctr import risk


def test_privacy_list_block_scores_low_and_says_why():
    """A privacy-list reason is low risk and the factor names the kind of list, not a verdict of safety."""
    result = risk.assess("click.shootproof.com", "HaGeZi Multi PRO++", ["blocklist:hagezi-multi-pro-plusplus"], "nextdns")
    assert result.score == 16 and result.band == "low" and result.category == risk.PRIVACY
    assert "privacy" in result.factors[0]["label"].lower()


@pytest.mark.parametrize("reason,codes,category,minimum", [
    ("Threat Intelligence Feeds", ["threat-intelligence-feeds"], risk.SECURITY, 90),
    ("Newly Registered Domains", ["nrd"], risk.SECURITY, 61),
    ("Denylist", ["denylist"], risk.POLICY, 61),
    ("Parental Control: streaming", [], risk.POLICY, 31),
])
def test_security_and_policy_reasons_are_never_low(reason, codes, category, minimum):
    """Security feeds and deliberate rules must not land in the band the access rule can open."""
    result = risk.assess("example.net", reason, codes, "nextdns")
    assert result.category == category and result.score >= minimum and result.band != "low"


def test_unrecognised_or_missing_reason_is_unknown_not_low():
    """No recognised evidence yields no score at all."""
    for reason in ("", "IoT outbound policy", "Upstream DNS query lacks device identity"):
        result = risk.assess("telemetry.example", reason, [], "nextdns")
        assert result.score is None and result.band == "unknown" and result.category == risk.UNKNOWN
        assert result.factors[0]["points"] is None
    assert risk.band(None) == "unknown"


def test_the_most_serious_reason_wins_and_name_shape_adds():
    """Several reasons take the highest base; look-alike and random-looking names add explained points."""
    mixed = risk.assess("example.net", "HaGeZi Multi PRO++; Threat Intelligence Feeds", [], "nextdns")
    assert mixed.category == risk.SECURITY and mixed.score >= 90
    plain = risk.assess("example.net", "", ["blocklist:x"], "nextdns").score
    lookalike = risk.assess("xn--pple-43d.example", "", ["blocklist:x"], "nextdns")
    random_name = risk.assess("a8f3k2j9x7q1m5z0c4v6.example", "", ["blocklist:x"], "nextdns")
    assert lookalike.score == plain + 20 and random_name.score == plain + 12
    assert all(0 <= r.score <= 100 for r in (mixed, lookalike, random_name))


def test_each_source_explains_its_own_reasons():
    """The same word means different things at different sources, so the source's integration decides.

    NextDNS names its lists, so a blocklist reason is a privacy list. Pi-hole
    does not say what a subscribed list is for, so its blocks stay unknown
    instead of borrowing a low score.
    """
    assert risk.assess("ads.example", "", ["blocklist:x"], "nextdns").band == "low"
    gravity = risk.assess("ads.example", "On a subscribed blocklist", ["gravity"], "pihole")
    assert gravity.score is None and gravity.band == "unknown"
    assert "does not say" in gravity.factors[0]["label"]
    denied = risk.assess("games.example", "Blocked by name on the deny list", ["denylist"], "pihole")
    assert denied.category == risk.POLICY and denied.band == "high"


def test_a_source_without_a_classifier_gets_only_the_generic_table():
    """An unknown or silent source is scored from a few plain words, and a bare 'blocklist' is not one of them."""
    assert risk.assess("x.example", "Malware feed", [], "something_new").category == risk.SECURITY
    assert risk.assess("x.example", "Vendor blocklist", [], "something_new").score is None
    assert risk.assess("x.example", "Vendor blocklist", [], None).score is None


def test_a_privacy_score_never_hides_a_reason_nyctr_does_not_recognise():
    """A block with a privacy list and an unrecognised reason identifier is unknown, not low.

    Opening the address would lift every reason at once, so the one score that
    can open things without a person must account for all of them.
    """
    mixed = risk.assess("shop.example", "HaGeZi Multi PRO++; Something new",
                        ["blocklist:hagezi-multi-pro-plusplus", "newfeature:xyz"], "nextdns")
    assert mixed.score is None and mixed.band == "unknown"
    assert "does not recognise" in mixed.factors[0]["label"]
    # A free-form list name beside recognised identifiers is fine: identifiers decide.
    named = risk.assess("shop.example", "HaGeZi Multi PRO++", ["blocklist:hagezi-multi-pro-plusplus"], "nextdns")
    assert named.band == "low"
    # Without identifiers, the names decide.
    assert risk.assess("shop.example", "Tracker blocklist; Something new", [], "nextdns").score is None
    assert risk.assess("shop.example", "Tracker blocklist", [], "nextdns").band == "low"
    # The same rule holds for a source with no classifier of its own.
    assert risk.assess("shop.example", "", ["tracker list", "something new"], "something_else").score is None
    # A recognised security reason still wins and is still scored, whatever sits beside it.
    threat = risk.assess("shop.example", "", ["blocklist:x", "threat-intelligence-feeds", "newfeature:xyz"], "nextdns")
    assert threat.category == risk.SECURITY and threat.band == "high"
