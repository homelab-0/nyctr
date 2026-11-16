"""Administrator-written rules. These, not a model, decide what Nyctr does on its own.

Both rules are off until an administrator turns them on. Reads always return a
complete, validated rule so callers never act on a partial setting.

Whether the access rule may open one request is decided by `may_open`, a pure
function of the rule and of plain facts the caller gathered. It reads no
database, calls nothing and holds no model: its refusals can be run in full.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .layers import Descriptor
from .models import Setting, User, utcnow


class AdTier(BaseModel):
    """Blocks by lists of advertising or tracking addresses, and by nothing else."""
    model_config = ConfigDict(extra="forbid")
    # `shadow` opens nothing: the request waits for a person and its record says the rule would have opened it.
    mode: Literal["off", "shadow", "on"] = "off"
    max_score: int = Field(default=25, ge=0, le=60)
    max_minutes: int = Field(default=60, ge=15, le=240)


class ThreatTier(BaseModel):
    """Blocks by a feed of addresses reported as threats. Its conditions are kept and shown; it stays off.

    This tier opens nothing without an analysis of the address. None exists yet, so no other mode validates.
    """
    model_config = ConfigDict(extra="forbid")
    mode: Literal["off"] = "off"
    max_minutes: int = Field(default=30, ge=15, le=240)
    min_registered_days: int = Field(default=180, ge=30, le=3650)


class AccessRule(BaseModel):
    """When a member's request may be opened without waiting for a person.

    Only the two tiers named here can ever be automatic. Every other tier has no field at all, so a
    rule that tries to switch one on does not validate.
    """
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    per_day: int = Field(default=4, ge=1, le=20)  # Automatic openings a day for each person.
    daily_total: int = Field(default=10, ge=1, le=100)  # And for everyone together.
    ad_tracker: AdTier = Field(default_factory=AdTier)
    threat_feed: ThreatTier = Field(default_factory=ThreatTier)

    @model_validator(mode="after")
    def _threat_is_never_longer(self):
        if self.threat_feed.max_minutes > self.ad_tracker.max_minutes:
            raise ValueError("A threat-feed block cannot be opened for longer than an advertising or tracker block")
        return self


class _FlatRule(BaseModel):
    """The access rule as it was stored up to 0.1.0-alpha.5."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    max_score: int = Field(default=25, ge=0, le=60)
    max_minutes: int = Field(default=60, ge=15, le=240)
    per_day: int = Field(default=4, ge=1, le=20)


def _accounts(db: Session) -> int:
    """Active accounts. Each of them could be opened for, up to the old limit for one person."""
    return db.scalar(select(func.count()).select_from(User).where(User.active.is_(True))) or 0


def _from_flat(value: dict, accounts: int) -> AccessRule:
    """Read an older stored rule: advertising and tracker lists on with its limits, everything else off.

    That rule opened privacy-list blocks and nothing else, and it had no daily total. The total it is
    read with is its limit for one person, for every active account, and never outside 1 to 100, which
    is all a rule may name. A rule written now still starts at 10.
    """
    old = _FlatRule(**value)
    total = min(100, max(1, old.per_day * accounts))
    return AccessRule(enabled=old.enabled, per_day=old.per_day, daily_total=total,
                      ad_tracker=AdTier(mode="on", max_score=old.max_score, max_minutes=old.max_minutes),
                      threat_feed=ThreatTier(max_minutes=min(ThreatTier().max_minutes, old.max_minutes)))


# The tiers, mildest first. A block with several reasons takes the strictest tier of all of them.
AUTOMATIC = ("ad_tracker", "threat_feed")
NEVER = ("category", "deny_entry", "firewall_policy", "intrusion", "unknown")
TIERS = AUTOMATIC + NEVER
# The fixed table for a reason at a DNS layer: (kind, origin) -> tier. An origin of None stands for any.
_DNS_TIERS = {("list", "third_party"): "ad_tracker", ("list", "vendor"): "ad_tracker",
              ("feed", "third_party"): "threat_feed", ("feed", "vendor"): "threat_feed",
              ("category", None): "category", ("deny_entry", None): "deny_entry"}
VERDICTS = ("justified", "not_justified", "cannot_tell")
RISKS = ("low", "medium", "high", "unknown")
# How a block is tied to the device that asked. Only these count without the member's own statement.
MATCHES = ("flow_named", "assignment", "link")


def tier_of(policy: Descriptor) -> str:
    """Place one reason in its tier. Whatever the table does not name is `unknown`, which never opens."""
    if policy.layer == "intrusion" or policy.kind == "signature":
        return "intrusion"
    if policy.layer == "firewall" or policy.kind in ("policy", "region"):
        return "firewall_policy"
    if policy.layer not in ("dns_gateway", "dns_upstream"):
        return "unknown"
    return _DNS_TIERS.get((policy.kind, policy.origin)) or _DNS_TIERS.get((policy.kind, None), "unknown")


def block_tier(policies: tuple[Descriptor, ...]) -> str:
    """The strictest tier among a block's reasons, and `unknown` for a block that states none."""
    return max((tier_of(policy) for policy in policies), key=TIERS.index, default="unknown")


@dataclass(frozen=True)
class AnalysisInput:
    """All that reaches the rule from an analysis of the address: whether there is one, and two fixed words."""
    present: bool = False
    verdict: str = "cannot_tell"
    risk: str = "unknown"


@dataclass(frozen=True)
class Facts:
    """What the rule is asked about, as plain values the caller gathered."""
    policies: tuple[Descriptor, ...]  # Every reason at every layer that blocks the address.
    can_open: bool  # Nyctr can open the address at every one of those layers,
    changes_on: bool  # and changes are switched on for each of them.
    match: str  # How the block is tied to the device (see MATCHES).
    score: int | None
    name_shape: bool  # The shape of the name itself added to the score.
    registered_days: int | None  # How long ago the address was registered. None: not known.
    declined: bool  # An administrator said no to this address before.
    opened_today: int  # Openings by the rule in the last day, for this person,
    opened_today_all: int  # and for everyone.
    asked_minutes: int
    analysis: AnalysisInput = AnalysisInput()


@dataclass(frozen=True)
class Decision:
    """What the rule says about one request, and every check it ran, in order, with its result."""
    allow: bool
    would: bool  # Every check passed, but the tier only records: a person still decides.
    tier: str
    minutes: int  # The longest the tier would give this request. Never read from the analysis.
    failed: str | None  # The check that stopped it.
    checks: tuple[tuple[str, str], ...]


def may_open(rule: AccessRule, facts: Facts) -> Decision:
    """Say whether the rule lets Nyctr open this block by itself. The first check that fails ends it.

    The order is fixed. A tier that can never be automatic is refused before the analysis is looked
    at, so nothing an analysis says can open one. Outside the threat tier an analysis can only stop
    an opening. The minutes come from the request and the tier's limit alone.
    """
    tier = block_tier(facts.policies)
    limits = getattr(rule, tier) if tier in AUTOMATIC else None
    minutes = min(facts.asked_minutes, limits.max_minutes) if limits else 0
    said = facts.analysis

    def conditions() -> bool:
        if tier == "threat_feed":  # The score cannot be the condition here: a threat reason scores above any limit.
            return not facts.name_shape and facts.registered_days is not None \
                and facts.registered_days >= limits.min_registered_days
        return facts.score is not None and facts.score <= limits.max_score

    def analysis() -> bool:
        if tier == "threat_feed":  # Required: there, and saying the block looks unjustified and the risk low.
            return said.present and said.verdict == "not_justified" and said.risk == "low"
        return not said.present or (said.verdict in ("not_justified", "cannot_tell") and said.risk in ("low", "unknown"))

    steps = (
        ("rule_on", lambda: rule.enabled),
        ("tier", lambda: tier in AUTOMATIC),
        ("mode", lambda: limits.mode in ("shadow", "on")),
        ("can_open", lambda: facts.can_open),
        ("changes_on", lambda: facts.changes_on),
        ("match", lambda: facts.match in MATCHES),
        ("conditions", conditions),
        ("declined", lambda: not facts.declined),
        ("analysis", analysis),
        ("per_day", lambda: facts.opened_today < rule.per_day),
        ("daily_total", lambda: facts.opened_today_all < rule.daily_total),
    )
    checks: list[tuple[str, str]] = []
    for name, passes in steps:
        if passes() is not True:
            return Decision(False, False, tier, minutes, name, (*checks, (name, "failed")))
        checks.append((name, "passed"))
    return Decision(limits.mode == "on", limits.mode == "shadow", tier, minutes, None, tuple(checks))


class GuestRule(BaseModel):
    """When a guest device is cut off without waiting for a person."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    hits: int = Field(default=3, ge=1, le=50)
    minutes: int = Field(default=5, ge=1, le=120)


RULES = {"access_rule": AccessRule, "guest_rule": GuestRule}
# How to read a rule stored in an older form, by key.
OLDER = {"access_rule": _from_flat}


def get_rule(db: Session, key: str):
    """Load a rule, falling back to its safe default if it was never written or no longer validates."""
    model = RULES[key]
    row = db.get(Setting, key)
    if row is None:
        return model()
    try:
        return model(**row.value)
    except ValueError:
        pass
    try:
        return OLDER[key](row.value, _accounts(db)) if key in OLDER else model()
    except (ValueError, TypeError):
        return model()


def put_rule(db: Session, key: str, value: BaseModel, actor: str) -> None:
    """Store a validated rule and who wrote it. The caller audits and commits."""
    row = db.get(Setting, key)
    if row is None:
        row = Setting(key=key)
        db.add(row)
    row.value = value.model_dump()
    row.updated_at = utcnow()
    row.updated_by = actor


def get_list(db: Session, key: str) -> list[str]:
    """Read a small administrator-maintained list such as dismissed suggestions."""
    row = db.get(Setting, key)
    items = row.value.get("items", []) if row else []
    return [x for x in items if isinstance(x, str)]


def put_list(db: Session, key: str, items: list[str], actor: str) -> None:
    """Replace a small administrator-maintained list. The caller audits and commits."""
    row = db.get(Setting, key)
    if row is None:
        row = Setting(key=key)
        db.add(row)
    row.value = {"items": sorted(set(items))[:500]}
    row.updated_at = utcnow()
    row.updated_by = actor
