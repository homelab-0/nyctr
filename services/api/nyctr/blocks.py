"""One bounded page of blocked lookups, with counts over everything the caller may see.

Which lookups a caller may inspect is decided in the database query, before a
page is cut and before anything is counted. No total, count or page boundary is
ever worked out over a lookup the caller may not see.
"""

from __future__ import annotations

import json
from datetime import datetime
from functools import lru_cache

from fastapi import HTTPException
from sqlalchemy import Text, and_, cast, exists, func, or_, select, true
from sqlalchemy.orm import Session

from . import risk
from .deps import device_permitted, observation_json
from .models import DeviceGrant, Observation, Resource, utc, utcnow

# A stored lookup is about 650 bytes as JSON, so 200 rows stay near 130 KB and are a
# table a browser draws at once; most of a day's lookups are never scrolled to.
PAGE = 200
BANDS = ("high", "medium", "low", "unknown")


def visible(db: Session, user) -> list:
    """Return the query conditions for the fresh lookups this caller may inspect.

    Administrators may inspect every fresh lookup. A member may inspect a lookup
    only when it is assigned to a device they may use now and a grant of theirs
    covered that device when the lookup happened: the same rule as
    `deps.observation_permitted`, stated as conditions so it applies before paging.
    """
    fresh = [Observation.expires_at > utcnow()]
    if user.role == "admin":
        return fresh
    granted = select(DeviceGrant.device_id).where(DeviceGrant.user_id == user.id)
    devices = [row.id for row in db.scalars(select(Resource).where(Resource.id.in_(granted)))
               if device_permitted(db, row, user)]
    at_the_time = exists().where(
        DeviceGrant.device_id == Observation.device_id, DeviceGrant.user_id == user.id,
        DeviceGrant.valid_from <= Observation.observed_at,
        or_(DeviceGrant.valid_until.is_(None), DeviceGrant.valid_until > Observation.observed_at))
    return [*fresh, Observation.attribution == "assigned", Observation.device_id.in_(devices), at_the_time]


@lru_cache(maxsize=4096)
def _codes(stored: str | None) -> list | None:
    """Read one lookup's stored reason identifiers. A source repeats a few sets over thousands of lookups."""
    return json.loads(stored) if stored else None


def _cursor(value: str) -> tuple[datetime, str]:
    """Read the place a previous page ended: the time and identifier of its last lookup."""
    when, _, id_ = value.partition("~")
    try:
        return utc(datetime.fromisoformat(when)), id_
    except ValueError:
        raise HTTPException(422, "That place in the list is not valid. Load the list again.") from None


def page(db: Session, user, band: str | None = None, text: str = "", before: str | None = None) -> dict:
    """Return the most recent lookups the caller may see, one page at a time, newest first.

    `band` and `text` narrow the rows; `before` is the `next` value of the page
    above and asks for older rows. Rows are ordered by time and then identifier,
    and an older page holds only rows strictly before that place, so a lookup
    stored between two requests is neither skipped nor shown twice.

    `total`, `oldest_at`, `newest_at` and `counts` describe every lookup the
    caller may see, whatever the filter; `matching` is how many pass the filter.
    """
    allowed = visible(db, user)
    needle = text.strip().lower()
    # Whether a row lies before the place the page above ended is worked out by the database.
    older = true()
    if before:
        when, last = _cursor(before)
        older = or_(Observation.observed_at < when, and_(Observation.observed_at == when, Observation.id < last))
    # Read as plain rows: every stored lookup the caller may see is looked at once to be counted.
    rows = db.connection().execute(
        select(Observation.id, Observation.domain, Observation.reason, cast(Observation.reason_codes, Text),
               Observation.source, Observation.attribution, Observation.device_name, older.label("older"))
        .where(*allowed).order_by(Observation.observed_at.desc(), Observation.id.desc())).all()
    oldest, newest = db.execute(select(func.min(Observation.observed_at), func.max(Observation.observed_at))
                                .where(*allowed)).one()
    bands = dict.fromkeys(BANDS, 0)
    sources: dict[str, dict[str, int]] = {}
    matching, unnamed, wanted, more = 0, 0, [], False
    for id_, domain, reason, codes, source, attribution, device_name, is_older in rows:
        scored = risk.assess(domain, reason, _codes(codes), source).band
        bands[scored] += 1
        by_source = sources.setdefault(source, {"total": 0, "unnamed": 0})
        by_source["total"] += 1
        if attribution == "unattributed":
            by_source["unnamed"] += 1
            unnamed += 1
        if (band and scored != band) or (needle and needle not in domain.lower()
                                         and needle not in device_name.lower() and needle not in reason.lower()):
            continue
        matching += 1
        if not is_older:
            continue
        if len(wanted) < PAGE:
            wanted.append(id_)
        else:
            more = True
    found = {row.id: row for row in db.scalars(select(Observation).where(Observation.id.in_(wanted)))}
    listed = [found[id_] for id_ in wanted if id_ in found]
    return {
        "rows": [observation_json(row) for row in listed],
        "next": f"{utc(listed[-1].observed_at).isoformat()}~{listed[-1].id}" if more and listed else None,
        "page_size": PAGE,
        "total": len(rows),
        "matching": matching,
        "oldest_at": oldest and utc(oldest),
        "newest_at": newest and utc(newest),
        "counts": {"band": bands, "source": sources, "named": len(rows) - unnamed, "unnamed": unnamed},
    }
