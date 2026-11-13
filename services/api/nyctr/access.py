"""Access decisions and the leases that carry them out.

A request is always assessed and the assessment is stored and shown. Nyctr opens
access on its own only when the administrator-written access rule allows it; a
score alone never does. Every exception Nyctr is responsible for is a durable
lease that records what actually happened at the provider and is closed again by
reconciliation, including after a restart.
"""

from __future__ import annotations

import os
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import risk, schedule
from .collection import SECRET_REF
from .config import Settings
from .deps import admin, columns, device_permitted, get_db, identity, observation_permitted
from .integrations import registry
from .models import AccessRequest, DeviceLink, Integration, Lease, Observation, Resource, User, utc, utcnow
from .policy import AccessRule, GuestRule, get_list, get_rule, put_list, put_rule
from .security import audit

router = APIRouter(prefix="/api")


def lease_json(row: Lease, names: dict[str, str] | None = None) -> dict:
    """Serialize a lease with the provider outcome kept separate from the decision."""
    data = columns(row, "id request_id integration_id domain device_name requester_id kind status ended_reason "
                        "execution owned scope decided_by risk_score created_at expires_at ended_at last_error")
    if names is not None:
        data["requester_name"] = names.get(row.requester_id or "", "")
        data["decided_by_name"] = "The access rule" if row.decided_by == "rule" else names.get(row.decided_by, "")
    return data


def _secret(integration: Integration) -> str | None:
    """Resolve the connector secret by its restricted reference, or None when it is not configured."""
    if not SECRET_REF.fullmatch(integration.secret_ref or ""):
        return None
    return os.environ.get(integration.secret_ref) or None


def _scope(integration: Integration | None) -> str:
    """State who a DNS exception really affects: the whole profile, not one person."""
    if integration is None:
        return "Not connected to a DNS source"
    return f"Everyone using {integration.name}"


def _opener(integration: Integration | None):
    """Return the source's integration contract if it can open a blocked address, else None."""
    provider = registry.find(integration.provider) if integration else None
    return provider if provider and "dns.exceptions" in provider.provides else None


def feature_mode(db: Session, settings: Settings, capability: str) -> str:
    """Say how a feature would act right now across the connected sources that offer it.

    `none` means no connected source offers the capability at all, which is a
    different answer from a source that offers it but may not be changed.
    """
    modes = {settings.write_mode(row.provider) for row in db.scalars(select(Integration))
             if registry.provides(row.provider, capability)}
    return next((mode for mode in ("simulated", "enabled", "disabled") if mode in modes), "none")


async def open_lease(db: Session, settings: Settings, *, integration: Integration | None, domain: str,
                     device_name: str, requester_id: str | None, request_id: str | None,
                     minutes: int | None, decided_by: str, risk_score: int | None) -> Lease:
    """Create a lease and carry it out according to the provider's write mode.

    The source of the block decides what is possible: only an integration that
    declares it can open addresses is ever asked to. Demo simulates. With
    changes allowed the exception is added and verified first; a provider
    failure raises and no lease is stored. Otherwise the lease is stored as not
    applied, so the administrator sees exactly what still has to be done by hand.
    """
    from .integrations import IntegrationError

    opener = _opener(integration)
    if integration is None:
        mode = "simulated" if settings.mode == "demo" else "disabled"
    else:
        mode = settings.write_mode(integration.provider) if opener else "disabled"
    execution, owned = "not_applied", False
    if mode == "simulated":
        execution, owned = "simulated", True
    elif mode == "enabled":
        key = _secret(integration)
        if not key:
            raise IntegrationError(f"The secret for {integration.name} is not configured on the server.",
                                   category="secret")
        shared = db.scalar(select(Lease.id).where(
            Lease.status == "active", Lease.domain == domain, Lease.integration_id == integration.id,
            Lease.execution == "applied", Lease.owned.is_(True)).limit(1))
        result = await opener.allow_domain(integration.config, key, domain, allowed=True)
        execution, owned = "applied", bool(result["owned"] or shared)
    now = utcnow()
    lease = Lease(request_id=request_id, integration_id=integration.id if integration else None, domain=domain,
                  device_name=device_name, requester_id=requester_id,
                  kind="temporary" if minutes else "permanent", execution=execution, owned=owned,
                  scope=_scope(integration), decided_by=decided_by, risk_score=risk_score, created_at=now,
                  expires_at=now + timedelta(minutes=minutes) if minutes else None)
    db.add(lease)
    db.flush()
    audit(db, None if decided_by == "rule" else decided_by, "access.opened", lease.id, domain=domain,
          execution=execution, owned=owned, minutes=minutes, decided_by=decided_by)
    return lease


async def end_lease(db: Session, settings: Settings, lease: Lease, reason: str, actor: str | None = None) -> bool:
    """Close a lease, removing the provider entry only if Nyctr created it and nothing else needs it.

    Returns False and keeps the lease active with a visible error when the
    provider could not be changed, so it is retried instead of silently left open.
    """
    from .integrations import IntegrationError

    if lease.status != "active":
        return True
    if lease.execution == "applied" and lease.owned:
        others = db.scalar(select(func.count()).select_from(Lease).where(
            Lease.status == "active", Lease.id != lease.id, Lease.domain == lease.domain,
            Lease.integration_id == lease.integration_id, Lease.execution == "applied"))
        if not others:
            integration = db.get(Integration, lease.integration_id) if lease.integration_id else None
            key = _secret(integration) if integration else None
            opener = _opener(integration)
            try:
                if not integration or not key or not opener:
                    raise IntegrationError("The source's secret is not configured on the server.")
                await opener.disallow_domain(integration.config, key, lease.domain,
                                             allowed=settings.write_mode(integration.provider) == "enabled")
            except IntegrationError as error:
                lease.last_error = str(error)
                audit(db, actor, "access.close_failed", lease.id, domain=lease.domain)
                return False
    lease.status, lease.ended_reason, lease.ended_at, lease.last_error = "ended", reason, utcnow(), None
    audit(db, actor, "access.closed", lease.id, domain=lease.domain, reason=reason, execution=lease.execution)
    return True


async def reconcile(db: Session, settings: Settings) -> int:
    """Close every lease whose time is up. Safe to call repeatedly and after a restart."""
    due = list(db.scalars(select(Lease).where(Lease.status == "active", Lease.expires_at.is_not(None),
                                              Lease.expires_at <= utcnow())))
    closed = 0
    for lease in due:
        closed += await end_lease(db, settings, lease, "expired")
        db.commit()
    return closed


def _auto_opens_today(db: Session, user_id: str) -> int:
    """Count leases the rule opened for this person in the last 24 hours."""
    return db.scalar(select(func.count()).select_from(Lease).where(
        Lease.requester_id == user_id, Lease.decided_by == "rule",
        Lease.created_at > utcnow() - timedelta(hours=24))) or 0


async def decide(db: Session, settings: Settings, row: AccessRequest, observation: Observation) -> None:
    """Assess a new request, store the assessment, and open access only if the written rule allows.

    Fails closed: an unknown score, a security or content-rule block, a domain
    an administrator denied before, a source whose integration cannot open
    addresses or a disabled write path all leave the request waiting for a
    person, with the reason recorded.
    """
    from .integrations import IntegrationError

    assessment = risk.assess(observation.domain, observation.reason, observation.reason_codes, observation.source)
    row.risk_score, row.risk_category, row.risk_factors = assessment.score, assessment.category, assessment.factors
    row.integration_id = observation.integration_id
    rule: AccessRule = get_rule(db, "access_rule")
    integration = db.get(Integration, observation.integration_id)
    why = None
    if not rule.enabled:
        why = "Automatic access is switched off, so a person decides."
    elif assessment.score is None:
        why = "Nyctr could not score this address, so a person decides."
    elif assessment.category != risk.PRIVACY:
        why = "This was blocked for safety or by an administrator's rule, so a person decides."
    elif assessment.score > rule.max_score:
        why = f"The score is above the automatic limit of {rule.max_score}, so a person decides."
    elif not integration:
        why = "This block did not come from a connected source, so a person decides."
    elif not _opener(integration):
        why = f"Nyctr cannot open addresses at {integration.name}, so a person decides."
    elif settings.write_mode(integration.provider) == "disabled":
        why = f"Nyctr is not allowed to change {integration.name}, so a person decides."
    elif db.scalar(select(AccessRequest.id).where(AccessRequest.domain == observation.domain,
                                                  AccessRequest.status == "denied").limit(1)):
        why = "An administrator said no to this address before, so a person decides."
    elif _auto_opens_today(db, row.requester_id) >= rule.per_day:
        why = f"You have reached today's limit of {rule.per_day} automatic openings, so a person decides."
    if why is None:
        minutes = min(row.duration_minutes, rule.max_minutes)
        try:
            await open_lease(db, settings, integration=integration, domain=row.domain,
                             device_name=row.device_name, requester_id=row.requester_id, request_id=row.id,
                             minutes=minutes, decided_by="rule", risk_score=assessment.score)
            row.status, row.decided_by, row.duration_minutes = "auto_approved", "rule", minutes
            row.decision_note = f"Opened for {minutes} minutes by the access rule."
            return
        except IntegrationError:
            why = f"Nyctr could not change {integration.name} just now, so a person decides."
    row.decision_note = why


def suggestions(db: Session) -> list[dict]:
    """List addresses the rule keeps opening, as candidates for a permanent exception.

    Nothing here is applied; an administrator must choose to make one permanent.
    """
    dismissed = set(get_list(db, "dismissed_suggestions"))
    permanent = set(db.scalars(select(Lease.domain).where(Lease.kind == "permanent", Lease.status == "active")))
    names = {u.id: u.name for u in db.scalars(select(User))}
    grouped: dict[str, dict] = {}
    for lease in db.scalars(select(Lease).where(Lease.decided_by == "rule").order_by(Lease.created_at.desc())):
        if lease.domain in dismissed or lease.domain in permanent:
            continue
        item = grouped.setdefault(lease.domain, {
            "domain": lease.domain, "times": 0, "people": set(), "last_at": utc(lease.created_at),
            "risk_score": lease.risk_score, "integration_id": lease.integration_id, "scope": lease.scope})
        item["times"] += 1
        if lease.requester_id:
            item["people"].add(names.get(lease.requester_id, "Someone"))
    return [{**item, "people": sorted(item["people"])} for item in grouped.values()]


class InputModel(BaseModel):
    """Reject unexpected fields and trim text."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class DomainInput(InputModel):
    """One domain name supplied by a signed-in person."""
    domain: str = Field(min_length=3, max_length=253, pattern=r"^[A-Za-z0-9._-]+$")


class SuggestionInput(DomainInput):
    """An administrator's choice about a suggested permanent exception."""
    action: Literal["make_permanent", "dismiss"]


def _names(db: Session) -> dict[str, str]:
    """Map user identifiers to display names for administrator views."""
    return {u.id: u.name for u in db.scalars(select(User))}


@router.get("/leases")
async def leases(request: Request, auth=Depends(identity), db: Session = Depends(get_db)):
    """List leases: everything recent for administrators, only their own for members."""
    await reconcile(db, request.app.state.settings)
    query = select(Lease).order_by(Lease.created_at.desc()).limit(300)
    if auth[0].role != "admin":
        query = query.where(Lease.requester_id == auth[0].id)
        return [lease_json(row) for row in db.scalars(query)]
    names = _names(db)
    return [lease_json(row, names) for row in db.scalars(query)]


@router.post("/leases/{lease_id}/end")
async def end(lease_id: str, request: Request, user=Depends(admin), db: Session = Depends(get_db)):
    """Close an active lease now. Reports honestly if the provider entry could not be removed."""
    lease = db.get(Lease, lease_id)
    if not lease:
        raise HTTPException(404, "Lease not found")
    if lease.status != "active":
        raise HTTPException(409, "This access has already ended")
    done = await end_lease(db, request.app.state.settings, lease, "revoked", user.id)
    db.commit()
    if not done:
        raise HTTPException(502, "Nyctr could not remove the entry at the provider. It is still open and will be retried.")
    return lease_json(lease, _names(db))


@router.get("/suggestions")
def list_suggestions(_user=Depends(admin), db: Session = Depends(get_db)):
    """Return addresses that could become permanent exceptions. Nothing is applied by reading."""
    return suggestions(db)


@router.post("/suggestions")
async def act_on_suggestion(body: SuggestionInput, request: Request, user=Depends(admin),
                            db: Session = Depends(get_db)):
    """Make a suggested address permanent or dismiss the suggestion, as the administrator chose."""
    from .integrations import IntegrationError

    domain = body.domain.lower()
    item = next((x for x in suggestions(db) if x["domain"] == domain), None)
    if not item:
        raise HTTPException(404, "Suggestion not found")
    if body.action == "dismiss":
        put_list(db, "dismissed_suggestions", get_list(db, "dismissed_suggestions") + [domain], user.id)
        audit(db, user.id, "suggestion.dismissed", domain)
        db.commit()
        return {"ok": True}
    integration = db.get(Integration, item["integration_id"]) if item["integration_id"] else None
    try:
        lease = await open_lease(db, request.app.state.settings, integration=integration, domain=domain,
                                 device_name="", requester_id=None, request_id=None, minutes=None,
                                 decided_by=user.id, risk_score=item["risk_score"])
    except IntegrationError as error:
        db.rollback()
        raise HTTPException(502, str(error)) from None
    db.commit()
    return lease_json(lease, _names(db))


@router.get("/rules")
def rules(request: Request, _user=Depends(admin), db: Session = Depends(get_db)):
    """Return both written rules and how Nyctr may act for each feature that changes a source.

    `writes` is keyed by feature, never by vendor: `access` is opening blocked
    addresses and `guests` is letting guest devices on or off. `sources` lists
    every connected source with what it adds and how Nyctr may change it.
    """
    settings: Settings = request.app.state.settings
    sources = []
    for row in db.scalars(select(Integration).order_by(Integration.name)):
        provider = registry.find(row.provider)
        sources.append({"id": row.id, "name": row.name, "provider": row.provider,
                        "provider_name": provider.name if provider else row.provider,
                        "changes": provider.changes if provider else [],
                        "write_mode": settings.write_mode(row.provider) if provider and provider.changes
                        else "none"})
    return {"access": get_rule(db, "access_rule").model_dump(), "guest": get_rule(db, "guest_rule").model_dump(),
            "writes": {"access": feature_mode(db, settings, "dns.exceptions"),
                       "guests": feature_mode(db, settings, "guest.control")},
            "sources": sources}


def _schedule_json(db: Session, settings: Settings) -> dict:
    """Describe the schedule in force, the intervals on offer and when the next collection is due."""
    now = schedule.in_force(db, settings)
    return {**now, "choices": list(schedule.CHOICES), "next_at": schedule.next_run(db, now)}


@router.get("/collection")
def collection_schedule(request: Request, auth=Depends(identity), db: Session = Depends(get_db)):
    """Tell any signed-in person whether Nyctr collects on its own, how often, and when next.

    Screens use it so that nothing promises a collection that will not happen.
    A member gets only those three facts. Where the value came from and the
    intervals on offer are for administrators.
    """
    full = _schedule_json(db, request.app.state.settings)
    if auth[0].role == "admin":
        return full
    return {key: full[key] for key in ("enabled", "interval_seconds", "next_at")}


@router.put("/collection")
def put_collection_schedule(body: schedule.Schedule, request: Request, user=Depends(admin),
                            db: Session = Depends(get_db)):
    """Turn scheduled collection on or off and set its interval. Audited with the old and new value.

    Turning it on lets the written guest rule and lock-out act at every
    scheduled collection, so only an administrator can change it.
    """
    settings: Settings = request.app.state.settings
    if settings.mode == "demo":
        raise HTTPException(409, "Live collection is disabled in demo mode")
    old = schedule.in_force(db, settings)
    put_rule(db, schedule.KEY, body, user.id)
    audit(db, user.id, "collection.schedule_changed", schedule.KEY, old=old,
          new={"enabled": body.enabled, "interval_seconds": body.minutes * 60})
    db.commit()
    return _schedule_json(db, settings)


@router.put("/rules/access")
def put_access_rule(body: AccessRule, user=Depends(admin), db: Session = Depends(get_db)):
    """Replace the access rule. Only an administrator can widen what Nyctr does on its own."""
    put_rule(db, "access_rule", body, user.id)
    audit(db, user.id, "rule.access_changed", "access_rule", **body.model_dump())
    db.commit()
    return body.model_dump()


@router.put("/rules/guest")
def put_guest_rule(body: GuestRule, user=Depends(admin), db: Session = Depends(get_db)):
    """Replace the guest cut-off rule."""
    put_rule(db, "guest_rule", body, user.id)
    audit(db, user.id, "rule.guest_changed", "guest_rule", **body.model_dump())
    db.commit()
    return body.model_dump()


class LinkInput(InputModel):
    """Link a DNS-provider device label to an inventory device, or clear the link."""
    source_id: str = Field(min_length=1, max_length=255)
    device_id: str | None = Field(default=None, max_length=255)


def _is_label(row: Resource) -> bool:
    """A client reported by a source that sees DNS lookups but holds no device inventory.

    Such a client is only a name the DNS source attached to a lookup. It becomes
    useful once an administrator links it to a device from an inventory source.
    """
    return row.kind == "client" and registry.provides(row.provider, "dns.blocks") \
        and not registry.provides(row.provider, "inventory")


@router.get("/device-links")
def device_links(_user=Depends(admin), db: Session = Depends(get_db)):
    """List device labels reported by DNS sources with their link and a same-name suggestion.

    A suggestion is only a hint. Nothing is linked until an administrator says so.
    """
    clients = list(db.scalars(select(Resource).where(Resource.kind == "client").order_by(Resource.name)))
    links = {link.source_id: link for link in db.scalars(select(DeviceLink))}
    inventory = [c for c in clients if not _is_label(c)]
    result = []
    for label in (c for c in clients if _is_label(c)):
        simple = "".join(ch for ch in label.name.casefold() if ch.isalnum())
        same = [c for c in inventory if "".join(ch for ch in c.name.casefold() if ch.isalnum()) == simple]
        link = links.get(label.id)
        result.append({"source_id": label.id, "name": label.name, "model": label.attributes.get("model"),
                       "integration_id": label.integration_id, "device_id": link.device_id if link else None,
                       "linked_at": utc(link.created_at) if link else None,
                       "suggested_device_id": same[0].id if len(same) == 1 else None})
    return result


@router.put("/device-links")
def put_device_link(body: LinkInput, user=Depends(admin), db: Session = Depends(get_db)):
    """Create, replace or clear a link. A link applies only to lookups observed after it is made."""
    label = db.get(Resource, body.source_id)
    if not label or not _is_label(label):
        raise HTTPException(404, "DNS device label not found")
    existing = db.get(DeviceLink, body.source_id)
    if existing:
        db.delete(existing)
        db.flush()
    if body.device_id:
        device = db.get(Resource, body.device_id)
        if not device or device.kind != "client" or _is_label(device):
            raise HTTPException(422, "Choose a device from your network inventory")
        db.add(DeviceLink(source_id=body.source_id, device_id=device.id, created_by=user.id))
    audit(db, user.id, "device.link_changed", body.source_id, device_id=body.device_id)
    db.commit()
    return {"ok": True}


@router.get("/me/device")
def this_device(request: Request, auth=Depends(identity), db: Session = Depends(get_db)):
    """Recognise the device this browser is on, only among devices the caller is allowed to see.

    The connecting address is matched to inventory. An address alone never
    grants anything: the device must already be assigned to the caller.
    """
    user = auth[0]
    settings: Settings = request.app.state.settings
    address = request.client.host if request.client else ""
    rows = [r for r in db.scalars(select(Resource).where(Resource.kind == "client").order_by(Resource.name))
            if device_permitted(db, r, user)]
    match = next((r for r in rows if address and address == r.attributes.get("ip")), None)
    simulated = False
    if match is None and settings.mode == "demo":
        # Demo has no real network. Pretend the browser is on the member's own device.
        match = next((r for r in rows if r.classification == "personal"), None)
        simulated = match is not None
    return {"device_id": match.id if match else None, "name": match.name if match else None,
            "simulated": simulated}


@router.post("/blocks/find")
def find_blocks(body: DomainInput, auth=Depends(identity), db: Session = Depends(get_db)):
    """Find fresh blocks of a typed address among events the caller may already see."""
    wanted = body.domain.lower().strip(".")
    rows = db.scalars(select(Observation).where(Observation.expires_at > utcnow())
                      .order_by(Observation.observed_at.desc()))
    from .deps import observation_json

    return [observation_json(r) for r in rows
            if (r.domain == wanted or r.domain.endswith("." + wanted) or wanted.endswith("." + r.domain))
            and observation_permitted(db, r, auth[0])][:20]
