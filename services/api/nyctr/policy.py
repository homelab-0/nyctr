"""Administrator-written rules. These, not a model, decide what Nyctr does on its own.

Both rules are off until an administrator turns them on. Reads always return a
complete, validated rule so callers never act on a partial setting.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .models import Setting, utcnow


class AccessRule(BaseModel):
    """When a member's request may be opened without waiting for a person."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    max_score: int = Field(default=25, ge=0, le=60)
    max_minutes: int = Field(default=60, ge=15, le=240)
    per_day: int = Field(default=4, ge=1, le=20)


class GuestRule(BaseModel):
    """When a guest device is cut off without waiting for a person."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    hits: int = Field(default=3, ge=1, le=50)
    minutes: int = Field(default=5, ge=1, le=120)


RULES = {"access_rule": AccessRule, "guest_rule": GuestRule}


def get_rule(db: Session, key: str):
    """Load a rule, falling back to its safe default if it was never written or no longer validates."""
    model = RULES[key]
    row = db.get(Setting, key)
    if row is None:
        return model()
    try:
        return model(**row.value)
    except ValueError:
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
