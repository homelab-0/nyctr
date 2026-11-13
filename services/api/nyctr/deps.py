"""Shared request dependencies, authorization checks and serializers.

Kept apart from route modules so each feature router can use the same
authentication and member-visibility boundary as the core API.
"""

from datetime import datetime

from fastapi import Depends, HTTPException, Request
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from .models import Audit, DeviceGrant, Integration, Resource, utc, utcnow
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


def last_test(db: Session, integration: Integration) -> Audit | None:
    """Return the newest record that settles whether a source is tested: a stored collection,
    or a later edit of its address or secret name, after which it is untested again."""
    history = select(Audit).where(Audit.action.in_(("integration.collected", "integration.updated")),
                                  Audit.target_id == integration.id).order_by(Audit.created_at.desc())
    return next((record for record in db.scalars(history)
                 if record.action == "integration.collected" or record.details.get("retest") is True), None)


def predates_change(db: Session, integration: Integration) -> bool:
    """Say whether what is stored was collected before the address or secret name last changed.

    Only a stored collection clears this; a failed one leaves the old data and the mark.
    """
    last = last_test(db, integration) if integration.last_sync else None
    return last is not None and last.action == "integration.updated"


def source_for_people(db: Session, integration_id: str, *, adding: bool) -> None:
    """Hold a source's row until the caller commits, and refuse to tie people to data it has outgrown.

    Editing a source counts its assignments and label links under this same row
    lock, so the edit and a new assignment or link run one after the other. One
    that comes second finds the source changed and not yet collected again: its
    devices are still the old network's, and an assignment or link made now would
    carry over to whatever the new address reports. Removing one is always allowed.
    """
    db.execute(update(Integration).where(Integration.id == integration_id)
               .values(name=Integration.name).execution_options(synchronize_session=False))
    source = db.get(Integration, integration_id, populate_existing=True)
    if adding and source is not None and predates_change(db, source):
        raise HTTPException(409, f"{source.name} was changed and has not been collected since, so this device "
                                 "was read before the change. Collect that source again first.")


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


def device_permitted(db, resource, user, when=None):
    """Require personal/shared classification, current personal ownership, and a time-valid grant.

    The optional timestamp selects grant history; the current resource owner
    remains authoritative so reassignment cannot expose a former owner event.
    """
    return (resource is not None and resource.classification in {"personal", "shared"}
            and (resource.classification != "personal" or resource.owner_id == user.id)
            and grant_at(db, resource.id, user.id, when or utcnow()))


def observation_permitted(db, row, user):
    """Authorize an event for admins or for members with verified historical and current device access.

    Unattributed events and infrastructure devices never become member-visible.
    Freshness is enforced separately by the inbox and request endpoints.
    """
    if user.role == "admin":
        return True
    resource = db.get(Resource, row.device_id) if row.device_id else None
    return (row.attribution == "assigned" and device_permitted(db, resource, user)
            and device_permitted(db, resource, user, utc(row.observed_at)))
