"""The collection schedule, set by an administrator.

One schedule covers every source. The saved value lives in the `settings` table,
so every running copy of Nyctr reads the same one at each upkeep pass. The time
of the last scheduled run is kept there too: the next run is worked out from it,
not from when a process started, and only one copy can claim a run.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import Settings
from .models import Setting, utc, utcnow

# Minutes an administrator can pick, from five minutes to a day.
CHOICES = (5, 15, 30, 60, 180, 360, 720, 1440)
DEFAULT_MINUTES = 15
KEY = "collection_schedule"
RUN_KEY = "collection_run"


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
    db.commit()
    return claimed.rowcount == 1
