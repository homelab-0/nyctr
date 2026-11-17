"""Shared request dependencies, authorization checks and serializers.

Kept apart from route modules so each feature router can use the same
authentication and member-visibility boundary as the core API.
"""

from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, Request
from sqlalchemy import and_, exists, or_, select
from sqlalchemy.orm import Session

from .models import DeviceGrant, DevicePresence, Observation, Resource, User, utc, utcnow
from .security import authenticate
from .sites import seen_as


def columns(instance, fields):
    """Select explicitly exposed ORM fields and normalize datetime values to UTC."""
    return {key: utc(value) if isinstance(value := getattr(instance, key), datetime) else value
            for key in fields.split()}


def resource_json(row):
    """Serialize inventory evidence and ownership fields for the authorized resource view."""
    return columns(row, "id name kind provider source_id site_id observed_at evidence_kind classification owner_id attributes")


def relationship_json(row):
    """Serialize a typed graph relationship together with its provenance metadata."""
    return columns(row, "id source target kind provider evidence_kind observed_at attributes")


def finding_json(row):
    """Serialize a finding with its supporting evidence and linked graph identifiers."""
    return columns(row, "id title severity summary resource_ids relationship_ids evidence status")


def integration_json(row):
    """Expose connector configuration and secret-variable name, never the resolved credential.

    `provider_name`, `status_note` and `provides` come from the integration's
    declared contract so the console never has to know a vendor by name.
    """
    from .integrations import registry

    data = columns(row, "id provider name status last_sync last_error config secret_ref capabilities")
    provider = registry.find(row.provider)
    data["provider_name"] = provider.name if provider else row.provider
    data["letter"] = provider.letter if provider else row.provider[:1].upper()
    data["tone"] = provider.tone if provider else "grey"
    data["maturity"] = provider.status if provider else "unknown"
    data["provides"] = [c for c in registry.CAPABILITIES if provider and c in provider.provides]
    return data


def observation_json(row):
    """Serialize an authorized block event with Nyctr's rule-based assessment.

    The score comes from `risk.assess` on the stored reason. An unrecognised
    reason yields a null score and the band "unknown", never a low score.
    """
    from . import risk

    data = columns(row, "id device_id device_name domain source reason observed_at expires_at evidence_kind "
                        "attribution reason_codes")
    assessment = risk.assess(row.domain, row.reason, row.reason_codes, row.source)
    data.update(risk_score=assessment.score, risk_band=assessment.band, risk_category=assessment.category,
                risk_factors=assessment.factors, risk_explanation=risk.member_summary(assessment))
    return data


def request_json(row):
    """Serialize the retained event snapshot, assessment and decision of an authorized access request."""
    return columns(row, "id block_id domain device_name requester_id reason duration_minutes status created_at "
                        "review_note risk_score risk_category risk_factors decided_by decision_note integration_id")


def get_db(request: Request):
    """Yield one request-scoped database session and close it after dependency cleanup."""
    with request.app.state.session_factory() as db:
        yield db


def identity(request: Request, db: Session = Depends(get_db)):
    """Resolve the current session and enforce mutation CSRF through the shared auth boundary.

    On the portal address the account is returned with member rights, so every
    permission check downstream, including `admin`, treats it as a member.
    """
    user, session = authenticate(request, db)
    return seen_as(request, user), session


def admin(auth=Depends(identity)):
    """Require the current authenticated user to have the administrator role, otherwise return 403."""
    if auth[0].role != "admin":
        raise HTTPException(403, "Administrator access required")
    return auth[0]


def grant_at(db, device: str, user_id: str, when):
    """Check a user-device grant at a timestamp using inclusive start and exclusive end bounds."""
    return db.scalar(select(DeviceGrant.id).where(
        DeviceGrant.device_id == device, DeviceGrant.user_id == user_id,
        DeviceGrant.valid_from <= when,
        or_(DeviceGrant.valid_until.is_(None), DeviceGrant.valid_until > when)).limit(1)) is not None


# A sign-in tie stops showing its device this long after the last sign-in from it.
TIE_DAYS = 30


def live_ties(now=None) -> list:
    """Conditions for the sign-in ties in force: made, not ended, signed in from within `TIE_DAYS`."""
    return [DevicePresence.kind == "tie", DevicePresence.ended_at.is_(None),
            DevicePresence.last_at > (now or utcnow()) - timedelta(days=TIE_DAYS)]


def _assigned(db, resource, user, when) -> bool:
    """An administrator's assignment: personal or shared, the current owner if personal, a grant at that time."""
    return (resource.classification in {"personal", "shared"}
            and (resource.classification != "personal" or resource.owner_id == user.id)
            and grant_at(db, resource.id, user.id, when))


def _tie_allowed(resource, user) -> bool:
    """A tie never shows infrastructure, or a personal device that belongs to someone else."""
    return (resource.kind == "client" and resource.classification != "infrastructure"
            and (resource.classification != "personal" or resource.owner_id == user.id))


def _tied(db, resource, user, when) -> bool:
    """A sign-in tie of this person on this device, in force now, whose reach covers that time."""
    return _tie_allowed(resource, user) and db.scalar(select(DevicePresence.id).where(
        *live_ties(), DevicePresence.device_id == resource.id, DevicePresence.user_id == user.id,
        DevicePresence.reach_from <= when).limit(1)) is not None


def device_assigned(db, resource, user) -> bool:
    """Say whether an administrator's assignment, not a sign-in tie, lets this member see the device now."""
    return resource is not None and _assigned(db, resource, user, utcnow())


def statement_current(db, row) -> bool:
    """Whether a statement may still be opened for the member and device it stored.

    An event request is left to the path that filed it. A statement needs the
    device id from when it was filed, and that member must still be allowed to
    use the device by an assignment or a live tie. A sign-in session is not
    that permission. A missing device cannot prove it.
    """
    if getattr(row, "basis", None) != "statement":
        return True
    if not row.device_id or not row.requester_id:
        return False
    user = db.get(User, row.requester_id)
    device = db.get(Resource, row.device_id)
    return user is not None and device_permitted(db, device, user)


def device_permitted(db, resource, user, when=None):
    """Let a member see a device by an administrator's assignment or by their own sign-in tie.

    An assignment needs personal/shared classification, current personal
    ownership and a time-valid grant; the optional timestamp selects grant
    history, and the current owner remains authoritative so reassignment
    cannot expose a former owner event. A tie reaches back a set time before
    its first sign-in, on the assumption that the person who signed in was the
    one using the device then, and shows nothing once it is ended.
    """
    when = when or utcnow()
    return resource is not None and (_assigned(db, resource, user, when) or _tied(db, resource, user, when))


def observation_permitted(db, row, user):
    """Authorize an event for admins or for members with verified historical and current device access.

    Unattributed events and infrastructure devices never become member-visible.
    Access now and access when the event happened must rest on the same thing:
    an assignment for both, or a tie for both. Freshness is enforced separately
    by the inbox and request endpoints.
    """
    if user.role == "admin":
        return True
    resource = db.get(Resource, row.device_id) if row.device_id else None
    if resource is None or row.attribution != "assigned":
        return False
    now, then = utcnow(), utc(row.observed_at)
    return (_assigned(db, resource, user, now) and _assigned(db, resource, user, then)
            or _tied(db, resource, user, now) and _tied(db, resource, user, then))


def observations_permitted(db, user) -> list:
    """The member rule of `observation_permitted` as query conditions, so a list applies it before paging."""
    now = utcnow()
    granted = select(DeviceGrant.device_id).where(DeviceGrant.user_id == user.id)
    assigned = [row.id for row in db.scalars(select(Resource).where(Resource.id.in_(granted)))
                if _assigned(db, row, user, now)]
    at_the_time = exists().where(
        DeviceGrant.device_id == Observation.device_id, DeviceGrant.user_id == user.id,
        DeviceGrant.valid_from <= Observation.observed_at,
        or_(DeviceGrant.valid_until.is_(None), DeviceGrant.valid_until > Observation.observed_at))
    ties = [tie for tie in db.scalars(select(DevicePresence).where(*live_ties(now), DevicePresence.user_id == user.id))
            if (device := db.get(Resource, tie.device_id)) is not None and _tie_allowed(device, user)]
    by_tie = [and_(Observation.device_id == tie.device_id, Observation.observed_at >= tie.reach_from)
              for tie in ties]
    return [Observation.attribution == "assigned",
            or_(and_(Observation.device_id.in_(assigned), at_the_time), *by_tie)]
