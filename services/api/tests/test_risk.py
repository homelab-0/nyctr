"""The rule-based assessment: explainable, and unknown stays unknown."""

import pytest

from nyctr import risk


def test_privacy_list_block_scores_low_and_says_why():
    """A privacy-list reason is low risk and the factor names the kind of list, not a verdict of safety."""
    result = risk.assess("click.shootproof.com", "HaGeZi Multi PRO++", ["blocklist:hagezi-multi-pro-plusplus"])
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
    result = risk.assess("example.net", reason, codes)
    assert result.category == category and result.score >= minimum and result.band != "low"


def test_unrecognised_or_missing_reason_is_unknown_not_low():
    """No recognised evidence yields no score at all."""
    for reason in ("", "IoT outbound policy", "Upstream DNS query lacks device identity"):
        result = risk.assess("telemetry.example", reason, [])
        assert result.score is None and result.band == "unknown" and result.category == risk.UNKNOWN
        assert result.factors[0]["points"] is None
    assert risk.band(None) == "unknown"


def test_the_most_serious_reason_wins_and_name_shape_adds():
    """Several reasons take the highest base; look-alike and random-looking names add explained points."""
    mixed = risk.assess("example.net", "HaGeZi Multi PRO++; Threat Intelligence Feeds", [])
    assert mixed.category == risk.SECURITY and mixed.score >= 90
    plain = risk.assess("example.net", "", ["blocklist:x"]).score
    lookalike = risk.assess("xn--pple-43d.example", "", ["blocklist:x"])
    random_name = risk.assess("a8f3k2j9x7q1m5z0c4v6.example", "", ["blocklist:x"])
    assert lookalike.score == plain + 20 and random_name.score == plain + 12
    assert all(0 <= r.score <= 100 for r in (mixed, lookalike, random_name))
