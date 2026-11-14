"""Explainable, rule-based risk assessment of a blocked domain.

The score is computed only from evidence Nyctr holds: the reason the source gave
for the block, explained by that source's integration, and the shape of the name. It is not a reputation lookup. When the
reason is missing or unrecognised the score is None, which callers must treat as
"unknown" and never as low risk.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache

LOW_MAX = 30
MEDIUM_MAX = 60

# Generic reasons, used only for a source that does not explain its own. Each integration
# that knows its provider's reasons classifies them itself (see integrations/registry.py).
# (pattern, category, base score, plain-language factor); the first match per reason wins.
_REASONS: tuple[tuple[re.Pattern[str], str, int, str], ...] = tuple(
    (re.compile(pattern, re.I), category, score, text) for pattern, category, score, text in (
        (r"threat|malware|phish|cryptojack|botnet|ransomware", "security", 92,
         "A security feed lists this address as a threat"),
        (r"newly.registered", "security", 72, "The address was registered very recently"),
        (r"denylist|deny.list", "policy", 65, "An administrator blocked this address by name"),
        (r"parental|category|safe.?search", "policy", 60,
         "A content rule set by an administrator blocks this kind of site"),
        (r"ad.?block|advert|tracker|tracking|privacy list", "privacy_list", 16,
         "A privacy and ad-blocking list covers it, not a security feed"),
    )
)


def _generic(text: str) -> tuple[str, int, str] | None:
    """Explain a reason from a source that has no classifier of its own."""
    for pattern, category, score, label in _REASONS:
        if pattern.search(text):
            return category, score, label
    return None


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
    if len(longest) >= 16 and (_entropy(longest) > 3.6
                               or sum(c.isdigit() for c in longest) >= len(longest) // 3):
        factors.append({"label": "Part of the name looks randomly generated", "points": 12})
    if len(labels) >= 6:
        factors.append({"label": "The address is unusually deep", "points": 6})
    return factors


@lru_cache(maxsize=4096)
def _reasoned(source: str | None, reason: str, codes: tuple[str, ...]) -> tuple[int | None, str, str]:
    """Score the reasons a source gave, apart from the name: (base score, category, plain-language label).

    A source repeats a few reasons over thousands of lookups, so each distinct set is
    explained once. A base score of None means unknown, and the label says why.
    """
    from .integrations import registry

    provider = registry.find(source)
    explain = provider.classify if provider and provider.classify else _generic
    names = [part.strip() for part in reason.split(";") if part.strip()]
    best: tuple[int, str, str] | None = None
    cannot_tell: str | None = None
    scored: set[str] = set()
    for text in [*codes, *names]:
        found = explain(text)
        if found is None:
            continue
        category, score, label = found
        if score is None:
            cannot_tell = cannot_tell or label
            continue
        scored.add(text)
        if best is None or score > best[0]:
            best = (score, category, label)
    # A privacy-list score is the only one that can open an address without a person, so it
    # must cover every reason on the block: opening the address lifts all of them at once.
    # Identifiers decide when the source gave any, because names are free-form list names.
    if best is not None and best[1] == PRIVACY and any(text not in scored for text in codes or names):
        return None, UNKNOWN, (cannot_tell or "A privacy list blocked this, and so did something Nyctr does not "
                                              "recognise, so it cannot score it")
    if best is None:
        return None, UNKNOWN, (cannot_tell
                               or "Nyctr does not recognise the reason this was blocked, so it cannot score it")
    return best


def assess(domain: str, reason: str = "", reason_codes: list[str] | None = None,
           source: str | None = None) -> Assessment:
    """Score a blocked domain from its block reason and name.

    `source` is the kind of integration that reported the block. Its own
    classifier explains each reason, by identifier and by name; a source
    without one falls back to a short generic table. The highest base score
    sets the category and name-shape factors add to it. No recognised reason,
    or a source that says it cannot tell, returns an unknown assessment. So
    does a privacy-list score beside a reason that could not be explained.
    """
    score, category, label = _reasoned(
        source, reason, tuple(code for code in (reason_codes or []) if isinstance(code, str)))
    if score is None:
        return Assessment(None, UNKNOWN, [{"label": label, "points": None}])
    factors = [{"label": label, "points": score}] + _name_factors(domain)
    total = max(0, min(100, sum(f["points"] for f in factors)))
    return Assessment(total, category, factors)


def member_summary(assessment: Assessment) -> str:
    """One calm sentence a non-technical person can read about why this was blocked."""
    if assessment.score is None:
        return "Nyctr could not tell how risky this is, so a person will look at it."
    lead = assessment.factors[0]["label"]
    return lead[0].upper() + lead[1:] + "."
