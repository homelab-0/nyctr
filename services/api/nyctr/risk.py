"""Explainable, rule-based risk assessment of a blocked domain.

The score is computed only from evidence Nyctr holds: the provider's reason for
the block and the shape of the name. It is not a reputation lookup. When the
reason is missing or unrecognised the score is None, which callers must treat as
"unknown" and never as low risk.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

LOW_MAX = 30
MEDIUM_MAX = 60

# (category, base score, plain-language factor). Matched against provider reason
# identifiers and names in order; the first match per reason wins.
_REASONS: tuple[tuple[re.Pattern[str], str, int, str], ...] = tuple(
    (re.compile(pattern, re.I), category, score, text) for pattern, category, score, text in (
        (r"threat|safe.?browsing|malware|phish|cryptojack|rebind|homograph|typosquat|\bdga\b|csam",
         "security", 92, "A security feed lists this address as a threat"),
        (r"\bnrd\b|newly.registered", "security", 72, "The address was registered very recently"),
        (r"\bddns\b|dynamic.dns", "security", 58, "It uses a dynamic address service, common for short-lived sites"),
        (r"parked|parking", "security", 52, "The address is parked and has no real site behind it"),
        (r"denylist|deny.list", "policy", 65, "An administrator blocked this address by name"),
        (r"parental|category|service:|safe.?search|bypass", "policy", 60, "A household rule blocks this kind of site"),
        (r"disguised", "privacy_list", 24, "It is a tracker hidden behind another site's name"),
        (r"^native|native.tracking", "privacy_list", 14, "It is device telemetry blocked by a tracking list"),
        (r"^blocklist:|blocklist|privacy list|ad.?block|tracker|tracking", "privacy_list", 16,
         "A privacy and ad-blocking list covers it, not a security feed"),
    )
)

SECURITY = "security"
PRIVACY = "privacy_list"
POLICY = "policy"
UNKNOWN = "unknown"


@dataclass
class Assessment:
    """The result shown to the requester and stored with the request."""
    score: int | None
    category: str
    factors: list[dict] = field(default_factory=list)

    @property
    def band(self) -> str:
        """Translate the number into the word used across the product."""
        return band(self.score)

    def as_dict(self) -> dict:
        """Serialize for API responses without inventing a value for unknown risk."""
        return {"score": self.score, "band": self.band, "category": self.category, "factors": self.factors}


def band(score: int | None) -> str:
    """Name the band for a score; a missing score is 'unknown', never 'low'."""
    if score is None:
        return "unknown"
    return "low" if score <= LOW_MAX else "medium" if score <= MEDIUM_MAX else "high"


def _entropy(label: str) -> float:
    """Shannon entropy per character, a rough signal for machine-generated names."""
    counts = Counter(label)
    return -sum(n / len(label) * math.log2(n / len(label)) for n in counts.values())


def _name_factors(domain: str) -> list[dict]:
    """Add small, explained adjustments from the shape of the name itself."""
    factors = []
    labels = domain.lower().split(".")
    if any(label.startswith("xn--") for label in labels):
        factors.append({"label": "The name uses look-alike characters from another alphabet", "points": 20})
    longest = max(labels[:-1] or labels, key=len)
    digits = sum(c.isdigit() for c in longest)
    if len(longest) >= 16 and (_entropy(longest) > 3.6 or digits >= len(longest) // 3):
        factors.append({"label": "Part of the name looks randomly generated", "points": 12})
    if len(labels) >= 6:
        factors.append({"label": "The address is unusually deep", "points": 6})
    return factors


def assess(domain: str, reason: str = "", reason_codes: list[str] | None = None) -> Assessment:
    """Score a blocked domain from its block reason and name.

    Each provider reason is matched by identifier and by name. The highest
    matching base score sets the category; name-shape factors add to it. No
    recognised reason returns an unknown assessment with an explanatory factor.

    A privacy-list score is the only one that can open an address without a
    person, so it must cover every reason the block carries. If the provider
    gave reason identifiers and one of them is not recognised, the result is
    unknown: opening the address would also lift whatever that reason was.
    Identifiers decide when present because reason names are free-form list
    names; names decide only when there are no identifiers.
    """
    codes = [code for code in (reason_codes or []) if isinstance(code, str)]
    names = [part.strip() for part in reason.split(";") if part.strip()]
    best: tuple[int, str, str] | None = None
    recognised: set[str] = set()
    for text in codes + names:
        for pattern, category, score, label in _REASONS:
            if pattern.search(text):
                recognised.add(text)
                if best is None or score > best[0]:
                    best = (score, category, label)
                break
    if best is not None and best[1] == PRIVACY and any(text not in recognised for text in codes or names):
        return Assessment(None, UNKNOWN, [{
            "label": "A privacy list blocked this, and so did something Nyctr does not recognise, "
                     "so it cannot score it", "points": None}])
    if best is None:
        return Assessment(None, UNKNOWN, [{
            "label": "Nyctr does not recognise the reason this was blocked, so it cannot score it", "points": None}])
    score, category, label = best
    factors = [{"label": label, "points": score}] + _name_factors(domain)
    total = max(0, min(100, sum(f["points"] for f in factors)))
    return Assessment(total, category, factors)


def member_summary(assessment: Assessment) -> str:
    """One calm sentence a non-technical person can read about why this was blocked."""
    if assessment.score is None:
        return "Nyctr could not tell why this was blocked, so a person will look at it."
    lead = assessment.factors[0]["label"]
    return lead[0].upper() + lead[1:] + "."
