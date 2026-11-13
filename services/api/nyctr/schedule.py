"""The collection schedule, set by an administrator.

One schedule covers every source. The saved value lives in the `settings` table,
so every running copy of Nyctr reads the same one at each upkeep pass. The time
of the last scheduled run is kept there too: the next run is worked out from it,
not from when a process started, and only one copy can claim a run.

A source that fails a scheduled run for a reason that may pass is tried again
after 1, 2 and 4 minutes, never at or past the next run. Each pending retry is
one row in the same table, keyed by the source, whose time is when it is due;
a copy claims it by moving that time forward in one conditional write, exactly
as a run is claimed, so no schema change is needed.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import Settings
from .models import Setting, utc, utcnow

# Minutes an administrator can pick, from five minutes to a day.
CHOICES = (5, 15, 30, 60, 180, 360, 720, 1440)
DEFAULT_MINUTES = 15
KEY = "collection_schedule"
RUN_KEY = "collection_run"
RETRY_PREFIX = "collection_retry:"
# Seconds before the first, second and third retry of a failed scheduled collection.
RETRY_DELAYS = (60, 120, 240)
# How long a claimed retry is held before another copy may take it, if the claimant stopped.
RETRY_HOLD = timedelta(minutes=5)


class Schedule(BaseModel):
    """Whether Nyctr collects on its own, and how often."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool
    minutes: Literal[5, 15, 30, 60, 180, 360, 720, 1440]


def in_force(db: Session, settings: Settings) -> dict:
    """Return the schedule that applies now and where it came from.

    A value an administrator saved wins. Before one is saved, a deployment
    interval above zero is the starting value, and without one a live
    installation collects every 15 minutes. Demo mode never collects.
    """
    if settings.mode == "demo":
        return {"enabled": False, "interval_seconds": DEFAULT_MINUTES * 60, "source": "demo"}
    row = db.get(Setting, KEY)
    if row is not None:
        try:
            saved = Schedule(**row.value)
            return {"enabled": saved.enabled, "interval_seconds": saved.minutes * 60, "source": "console"}
        except ValueError:
            pass  # An unreadable saved value falls back to the starting value below.
    if settings.collect_interval_seconds > 0:
        return {"enabled": True, "interval_seconds": settings.collect_interval_seconds, "source": "deployment"}
    return {"enabled": True, "interval_seconds": DEFAULT_MINUTES * 60, "source": "default"}


def next_run(db: Session, schedule: dict, now: datetime | None = None) -> datetime | None:
    """Say when the next scheduled collection is due, or None when the schedule is off.

    Counted from the last scheduled run on record. With none on record the
    first run is due at the next upkeep pass.
    """
    if not schedule["enabled"]:
        return None
    last = db.get(Setting, RUN_KEY)
    if last is None:
        return now or utcnow()
    return utc(last.updated_at) + timedelta(seconds=schedule["interval_seconds"])


def claim_run(db: Session, schedule: dict, now: datetime | None = None) -> bool:
    """Take the scheduled run that is due, so that exactly one copy of Nyctr performs it.

    The record of the last run moves forward in one conditional write; a second
    copy asking at the same moment changes no row and is told no. Commits.
    """
    if not schedule["enabled"]:
        return False
    now = now or utcnow()
    if db.get(Setting, RUN_KEY) is None:
        db.add(Setting(key=RUN_KEY, value={}, updated_at=now))
        try:
            db.commit()
        except IntegrityError:  # Another copy recorded the first run a moment earlier.
            db.rollback()
            return False
        return True
    due_before = now - timedelta(seconds=schedule["interval_seconds"])
    claimed = db.execute(update(Setting).where(Setting.key == RUN_KEY, Setting.updated_at <= due_before)
                         .values(updated_at=now).execution_options(synchronize_session=False))
    if claimed.rowcount == 1:
        # The new run covers every source, so retries left from the last one end here.
        db.execute(delete(Setting).where(Setting.key.startswith(RETRY_PREFIX)))
    db.commit()
    return claimed.rowcount == 1


def _retry_key(integration_id: str) -> str:
    """Name the settings row of one source's pending retry; hashed so any source id fits the key."""
    return RETRY_PREFIX + sha256(integration_id.encode()).hexdigest()[:40]


def plan_retry(db: Session, schedule: dict, integration_id: str, failed: int, now: datetime,
               wait: int | None = None) -> datetime | None:
    """Stage the retry after failed attempt `failed` (0 is the scheduled run) and return when it is due.

    A rate limit's own wait is honoured when longer than the usual delay. With
    the three retries spent, or no time left before the next run, nothing is
    staged and None is returned. The caller commits.
    """
    due = now + timedelta(seconds=max(RETRY_DELAYS[failed], wait or 0)) if failed < len(RETRY_DELAYS) else None
    return _stage(db, schedule, integration_id, failed + 1, due, now)


def defer_retry(db: Session, schedule: dict, integration_id: str, attempt: int, now: datetime) -> datetime | None:
    """Put a claimed retry back a minute later without using it up, because the source was busy."""
    return _stage(db, schedule, integration_id, attempt, now + timedelta(seconds=RETRY_DELAYS[0]), now)


def _stage(db: Session, schedule: dict, integration_id: str, attempt: int, due: datetime | None,
           now: datetime) -> datetime | None:
    """Record retry `attempt` as due at `due`, or remove it when it would not come before the next run."""
    upcoming = next_run(db, schedule, now)
    row = db.get(Setting, _retry_key(integration_id))
    if due is None or upcoming is None or due >= upcoming:
        if row is not None:
            db.delete(row)
        return None
    value = {"integration_id": integration_id, "attempt": attempt}
    if row is None:
        db.add(Setting(key=_retry_key(integration_id), value=value, updated_at=due))
    else:
        row.value, row.updated_at = value, due
    return due


def drop_retry(db: Session, integration_id: str) -> None:
    """Forget a source's pending retry. The caller commits."""
    db.execute(delete(Setting).where(Setting.key == _retry_key(integration_id)))


def claim_retries(db: Session, schedule: dict, now: datetime | None = None) -> list[tuple[str, int]]:
    """Take every retry that is due, each by one conditional write, and return (source, attempt) pairs.

    A second copy asking at the same moment finds the time already moved
    forward and gets nothing. A claimant that stops leaves the retry to be taken
    again after RETRY_HOLD, or to the next run. Commits.
    """
    if not schedule["enabled"]:
        return []
    now = now or utcnow()
    due = db.execute(select(Setting.key, Setting.value).where(Setting.key.startswith(RETRY_PREFIX),
                                                              Setting.updated_at <= now)).all()
    taken = []
    for key, value in due:
        claimed = db.execute(update(Setting).where(Setting.key == key, Setting.updated_at <= now)
                             .values(updated_at=now + RETRY_HOLD).execution_options(synchronize_session=False))
        db.commit()
        if claimed.rowcount == 1:
            taken.append((value["integration_id"], int(value["attempt"])))
    return taken
