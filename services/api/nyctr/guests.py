"""Guest Wi-Fi: passes, who is on, what they did, and cutting a device off.

Everything Nyctr knows about a guest comes from two places: the network source
that runs the guest Wi-Fi (the device, its access point, its authorisation and
data use) and blocked DNS lookups tied to it. Connection attempts and port scans
are not visible through either, and this module never pretends otherwise.

Nothing here names a vendor. A guest device is any client a source reports with
guest access, and every action goes through whatever that source's integration
declares it can do (`guest.passes`, `guest.control`).

The automatic cut-off is a counted, administrator-written rule. No model score
can trigger it.

Design boundary (docs/guest-wifi.md): the network source serves the Wi-Fi
sign-in page. Nyctr never serves a page to a guest device and nothing on the
guest network needs to reach Nyctr. Nyctr works from the management side only:
it issues passes, lets a waiting device on, and reads who is connected.
"""

from __future__ import annotations

import os
import secrets
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import risk
from .collection import SECRET_REF, parsed_date
from .config import Settings
from .deps import admin, columns, get_db
from .integrations import registry
from .models import GuestAction, GuestPass, Integration, Observation, Resource, Sighting, User, utc, utcnow
from .policy import GuestRule, get_rule
from .security import audit

router = APIRouter(prefix="/api")
EFFECTIVE = ("applied", "simulated")

# Suggested wording for the terms box of the network's own sign-in page. Nyctr does not
# set it, so the console offers it for the administrator to paste.
NOTICE = ("This guest Wi-Fi is monitored for security. The network owner can see which device "
          "you connect with, which access point you use, how much data you use and which "
          "addresses were blocked. A device that repeatedly looks up addresses on a threat list "
          "may be disconnected automatically.")


def guest_devices(db: Session) -> list[Resource]:
    """Return inventory clients a source reports as being on guest access."""
    return [row for row in db.scalars(select(Resource).where(Resource.kind == "client").order_by(Resource.name))
            if is_guest(row)]


def is_guest(row: Resource) -> bool:
    """A client is a guest when its source reported guest-access state for it."""
    return row.kind == "client" and isinstance(row.attributes.get("guest"), dict)


def _grant(device: Resource) -> dict:
    """Return the device's guest-access record in the neutral shape adapters write."""
    grant = device.attributes.get("guest")
    return grant if isinstance(grant, dict) else {}


def _set_grant(device: Resource, **changes) -> None:
    """Record what Nyctr just did to a device's access until the next collection reads the real state."""
    device.attributes = {**device.attributes, "guest": {**_grant(device), **changes}}


def _actions(db: Session, device_id: str) -> list[GuestAction]:
    """Load a device's actions, newest first."""
    return list(db.scalars(select(GuestAction).where(GuestAction.device_id == device_id)
                           .order_by(GuestAction.created_at.desc())))


def state_of(device: Resource, actions: list[GuestAction]) -> str:
    """Name the device's current state from what was actually carried out, not what was intended."""
    latest = next((a for a in actions if a.execution in EFFECTIVE), None)
    if latest and latest.action == "lock":
        return "locked"
    if latest and latest.action == "cut":
        return "cut"
    if device.attributes.get("missing_from_latest_snapshot"):
        return "offline"
    return "online" if _grant(device).get("authorized") else "waiting"


def _lookups(db: Session, device_id: str) -> list[tuple[Observation, risk.Assessment]]:
    """Return fresh blocked lookups tied to the device with their assessments, newest first."""
    rows = db.scalars(select(Observation).where(Observation.device_id == device_id,
                                                Observation.expires_at > utcnow())
                      .order_by(Observation.observed_at.desc()))
    return [(row, risk.assess(row.domain, row.reason, row.reason_codes, row.source)) for row in rows]


def _is_threat(assessment: risk.Assessment) -> bool:
    """A lookup counts toward the cut-off only when a security reason scored it high."""
    return assessment.category == risk.SECURITY and (assessment.score or 0) > risk.MEDIUM_MAX


def device_risk(lookups: list[tuple[Observation, risk.Assessment]]) -> dict:
    """Score a guest device from counted lookups. No attributed lookups means unknown, not safe."""
    if not lookups:
        return {"score": None, "band": "unknown", "factors": [{
            "label": "No blocked lookups are tied to this device. That does not prove it is safe.",
            "points": None}]}
    threats = sum(_is_threat(a) for _, a in lookups)
    other = len(lookups) - threats
    factors = []
    if threats:
        factors.append({"label": f"{threats} lookup{'s' if threats != 1 else ''} of addresses on a threat list",
                        "points": min(90, 30 * threats)})
    if other:
        factors.append({"label": f"{other} ordinary blocked lookup{'s' if other != 1 else ''} (ads, trackers)",
                        "points": min(15, other)})
    score = min(100, sum(f["points"] for f in factors))
    return {"score": score, "band": risk.band(score), "factors": factors}


def _pass_for(device: Resource, passes: list[GuestPass]) -> GuestPass | None:
    """Infer which pass a device used from timing. Sources do not link them, so this is a guess."""
    grant = _grant(device)
    if grant.get("method") not in (None, "pass") or not grant.get("authorized_at"):
        return None
    try:
        joined = parsed_date(grant["authorized_at"])
    except (ValueError, TypeError):
        return None
    near = [p for p in passes if p.activated_at and abs((utc(p.activated_at) - joined).total_seconds()) <= 90]
    return near[0] if len(near) == 1 else None


def pass_json(row: GuestPass, names: dict[str, str]) -> dict:
    """Serialize a pass for administrators, including its code."""
    data = columns(row, "id integration_id code name minutes guest_limit data_limit_mb guest_count issued_by "
                        "execution created_at activated_at expires_at ended_at")
    data["issued_by_name"] = names.get(row.issued_by or "", "")
    now = utcnow()
    data["state"] = ("ended" if row.ended_at or (row.expires_at and utc(row.expires_at) <= now)
                     else "in_use" if row.activated_at else "unused")
    return data


def guest_json(db: Session, device: Resource, passes: list[GuestPass]) -> dict:
    """Assemble everything Nyctr knows about one guest device, with evidence kinds kept apart."""
    attrs = device.attributes
    actions = _actions(db, device.id)
    lookups = _lookups(db, device.id)
    uplink = None
    if attrs.get("uplink"):
        uplink = db.scalar(select(Resource).where(Resource.integration_id == device.integration_id,
                                                  Resource.source_id == attrs["uplink"]).limit(1))
    used = _pass_for(device, passes)
    timeline = []
    grant = _grant(device)
    source = registry.name_of(device.provider)
    joined_by = {"pass": "pass", "console": "administrator"}.get(grant.get("method"))
    if grant.get("authorized_at") and joined_by != "administrator":
        timeline.append({"at": grant["authorized_at"], "kind": "joined",
                         "text": f"Joined with {'pass ' + used.name if used else 'a pass'}",
                         "evidence": "observed"})
    names = {r.source_id: r.name for r in db.scalars(select(Resource).where(
        Resource.integration_id == device.integration_id,
        Resource.kind.in_(("access_point", "switch", "gateway"))))}
    for index, seen in enumerate(db.scalars(select(Sighting).where(Sighting.device_id == device.id)
                                            .order_by(Sighting.first_seen))):
        timeline.append({"at": utc(seen.first_seen).isoformat(), "kind": "moved", "evidence": "observed",
                         "text": ("Seen on " if index == 0 else "Moved to ")
                         + names.get(seen.uplink_id or "", "an unknown access point")})
    for row, assessment in lookups[:40]:
        timeline.append({"at": utc(row.observed_at).isoformat(), "evidence": row.attribution,
                         "kind": "threat" if _is_threat(assessment) else "blocked",
                         "text": f"Looked up {row.domain}", "detail": row.reason})
    for action in actions:
        who = "The cut-off rule" if action.actor == "rule" else "An administrator"
        verb = {"cut": "cut this device off", "lock": "locked this device out",
                "restore": "let this device back on", "admit": "let this device on"}[action.action]
        outcome = {"applied": "", "simulated": " (simulated)", "not_applied": f" but Nyctr may not change {source}",
                   "failed": f" but {source} refused"}[action.execution]
        timeline.append({"at": utc(action.created_at).isoformat(), "kind": action.action, "evidence": "observed",
                         "text": f"{who} {verb}{outcome}", "detail": action.reason})
    timeline.sort(key=lambda item: item["at"], reverse=True)
    return {
        "id": device.id, "name": device.name, "integration_id": device.integration_id,
        "source": source,
        "mac": attrs.get("mac"), "ip": attrs.get("ip"), "connected_at": attrs.get("connected_at"),
        "access_point": {"id": uplink.id, "name": uplink.name} if uplink else None,
        "authorized": bool(grant.get("authorized")),
        "authorization": {key: grant.get(key) for key in ("method", "authorized_at", "expires_at", "bytes",
                                                           "seconds", "data_limit_mb")}
        if grant.get("authorized_at") else None,
        "state": state_of(device, actions), "observed_at": utc(device.observed_at),
        "pass": {"id": used.id, "name": used.name, "evidence": "inferred"} if used else None,
        # How the device got on: a pass typed into the network's sign-in page, or let on from here.
        "joined_by": joined_by,
        "risk": device_risk(lookups),
        "lookups": {"blocked": len(lookups), "threat": sum(_is_threat(a) for _, a in lookups)},
        "timeline": timeline[:60],
    }


def _target(db: Session, device_or_integration) -> tuple[Integration, str, str | None]:
    """Resolve the source, the scope (site) an action applies to and the server-side secret."""
    if isinstance(device_or_integration, Resource):
        integration = db.get(Integration, device_or_integration.integration_id)
        site = db.get(Resource, device_or_integration.site_id) if device_or_integration.site_id else None
    else:
        integration = device_or_integration
        sites = list(db.scalars(select(Resource).where(Resource.integration_id == integration.id,
                                                       Resource.kind == "site")))
        provider = registry.find(integration.provider)
        wanted = provider.scope(integration.config) if provider and provider.scope else None
        site = next((s for s in sites if s.source_id == wanted), sites[0] if len(sites) == 1 else None)
    if integration is None or site is None:
        raise HTTPException(409, "Nyctr cannot tell which site this belongs to. Collect the source first, "
                                 "or set a site on it.")
    key = os.environ.get(integration.secret_ref) if SECRET_REF.fullmatch(integration.secret_ref or "") else None
    return integration, site.source_id, key


def _mode(settings: Settings, provider_id: str, capability: str) -> str:
    """How a guest action on this kind of source is carried out; `disabled` when it cannot do it at all."""
    return settings.write_mode(provider_id) if registry.provides(provider_id, capability) else "disabled"


def _read_only(name: str) -> str:
    """The one sentence shown whenever an operator has not allowed changes to a source."""
    return f"Nyctr is read-only for {name}. An operator must allow changes to it first."


async def apply_action(db: Session, settings: Settings, device: Resource, action: str, actor: str,
                       reason: str, minutes: int | None = None) -> GuestAction:
    """Carry out one guest action in the current write mode and record exactly what happened.

    `admit` authorises a waiting device for a stated time from the management
    side, which ties the grant to that exact device without any page being
    served to it. The device's own source carries the action out.
    """
    from .integrations import IntegrationError

    provider = registry.find(device.provider)
    mode = _mode(settings, device.provider, "guest.control")
    record = GuestAction(device_id=device.id, action=action, actor=actor, reason=reason[:500])
    allow = action in {"restore", "admit"}

    def granted(length: int | None) -> dict:
        """Describe the authorisation Nyctr just made, until the next collection reads the real one."""
        now = utcnow()
        return {"method": "console", "authorized_at": now.isoformat(),
                "expires_at": (now + timedelta(minutes=length or 60)).isoformat()}

    if mode == "simulated":
        record.execution = "simulated"
        _set_grant(device, authorized=allow, **(granted(minutes) if action == "admit" else {}))
    elif mode == "enabled" and not allow and _grant(device).get("authorized") is False:
        # Already without access at the last collection: nothing to send, and a source
        # may reject removing access from a guest that holds none.
        record.execution = "applied"
    elif mode == "enabled":
        try:
            integration, site, key = _target(db, device)
            if not key:
                raise IntegrationError(f"The secret for {integration.name} is not configured on the server.")
            if action == "restore":
                try:
                    left = (parsed_date(_grant(device)["expires_at"]) - utcnow()).total_seconds() / 60
                except (KeyError, ValueError, TypeError, AttributeError):
                    left = 60
                minutes = int(max(15, min(left, 1440)))
            await provider.guest_access(integration.config, key, site, device.source_id, allow,
                                        minutes=minutes, allowed=True)
            record.execution = "applied"
            _set_grant(device, authorized=allow, **(granted(minutes) if action == "admit" else {}))
        except (IntegrationError, HTTPException) as error:
            record.execution = "failed"
            record.error = str(error.detail if isinstance(error, HTTPException) else error)[:300]
    else:
        record.execution = "not_applied"
    db.add(record)
    db.flush()
    audit(db, None if actor == "rule" else actor, f"guest.{action}", device.id, execution=record.execution,
          by_rule=actor == "rule", reason=reason[:200])
    return record


def evaluate_rule(db: Session, settings: Settings) -> list[tuple[str, str]]:
    """Return (device, reason) for each online guest the written rule says to cut off now.

    Counts threat-list lookups inside the rule's window. A device is not
    reported again for lookups it was already cut off for.
    """
    rule: GuestRule = get_rule(db, "guest_rule")
    if not rule.enabled:
        return []
    since = utcnow() - timedelta(minutes=rule.minutes)
    due = []
    for device in guest_devices(db):
        actions = _actions(db, device.id)
        if state_of(device, actions) != "online":
            continue
        hits = [row for row, assessment in _lookups(db, device.id)
                if _is_threat(assessment) and utc(row.observed_at) >= since]
        last_rule = next((a for a in actions if a.actor == "rule"), None)
        if last_rule:
            hits = [row for row in hits if utc(row.observed_at) > utc(last_rule.created_at)]
        if len(hits) >= rule.hits:
            due.append((device.id, f"{len(hits)} lookups of threat-listed addresses in {rule.minutes} minutes"))
    return due


async def enforce(db: Session, settings: Settings, due: list[tuple[str, str]]) -> int:
    """Cut off devices the rule named and re-cut locked devices that were let back on elsewhere."""
    count = 0
    for device_id, reason in due:
        device = db.get(Resource, device_id)
        if device:
            await apply_action(db, settings, device, "cut", "rule", reason)
            count += 1
    for device in guest_devices(db):
        if state_of(device, _actions(db, device.id)) == "locked" and _grant(device).get("authorized"):
            await apply_action(db, settings, device, "lock", "rule", "Locked device was authorised again")
            count += 1
    from .analysis import refresh_findings

    refresh_findings(db)
    db.commit()
    return count


class InputModel(BaseModel):
    """Reject unexpected fields and trim text."""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class PassInput(InputModel):
    """A new guest pass: who it is for, how long, and how many devices."""
    name: str = Field(min_length=1, max_length=120)
    minutes: int = Field(ge=30, le=10080)
    guest_limit: int = Field(default=1, ge=1, le=20)
    data_limit_mb: int | None = Field(default=None, ge=100, le=1048576)
    integration_id: str | None = Field(default=None, max_length=128)


class ActionInput(InputModel):
    """An administrator's action on one guest device."""
    device_id: str = Field(min_length=1, max_length=255)
    action: Literal["cut", "restore", "lock", "admit"]
    reason: str = Field(default="", max_length=500)
    minutes: int | None = Field(default=None, ge=30, le=10080)


class DeviceInput(InputModel):
    """Identify one guest device."""
    device_id: str = Field(min_length=1, max_length=255)


def _sources(db: Session, capability: str = "guest.devices") -> list[Integration]:
    """Connected sources whose integration offers a guest capability, in name order."""
    return [row for row in db.scalars(select(Integration).order_by(Integration.name))
            if registry.provides(row.provider, capability)]


def portal(db: Session, settings: Settings) -> dict:
    """Describe how guests sign in: always on the network's own page, never through Nyctr.

    Lists each Wi-Fi name a source reported with whether it sits behind that
    source's sign-in page, so an administrator can see the guest network really
    is gated.
    """
    networks = {r.source_id: r.name for r in db.scalars(select(Resource).where(Resource.kind == "network"))}
    wifi = []
    for site in db.scalars(select(Resource).where(Resource.kind == "site")):
        for row in site.attributes.get("wifi") or []:
            if isinstance(row, dict):
                wifi.append({"name": row.get("name"), "enabled": bool(row.get("enabled")),
                             "captive_portal": bool(row.get("captive_portal")),
                             "network": networks.get(row.get("network_id") or "")})
    served = sorted({registry.name_of(row.provider) for row in _sources(db)})
    return {"served_by": served, "nyctr_in_guest_path": False, "wifi": wifi, "notice": NOTICE,
            "nudge": bool(settings.nudge_token) and settings.mode == "live"}


def overview(db: Session, settings: Settings) -> dict:
    """Return passes, guest devices, the written rule and what Nyctr can and cannot see."""
    names = {u.id: u.name for u in db.scalars(select(User))}
    passes = list(db.scalars(select(GuestPass).order_by(GuestPass.created_at.desc()).limit(200)))
    sources = [{"id": i.id, "name": i.name, "provider_name": registry.name_of(i.provider),
                "passes": _mode(settings, i.provider, "guest.passes"),
                "control": _mode(settings, i.provider, "guest.control")} for i in _sources(db)]
    modes = {source["control"] for source in sources}
    return {
        # One answer for the page: how a cut-off or admit would be carried out right now.
        "writes": next((m for m in ("simulated", "enabled", "disabled") if m in modes),
                       "simulated" if settings.mode == "demo" else "disabled"),
        "rule": get_rule(db, "guest_rule").model_dump(),
        "portal": portal(db, settings),
        "sources": sources, "passes": [pass_json(p, names) for p in passes],
        "devices": [guest_json(db, d, passes) for d in guest_devices(db)],
        "not_collected": ["Connection attempts and port scans (no connected source reports them)",
                          "Devices that have already left (only connected clients are listed)"],
    }


@router.get("/guests")
def guests(request: Request, _user=Depends(admin), db: Session = Depends(get_db)):
    """Administrator view of guest Wi-Fi."""
    return overview(db, request.app.state.settings)


@router.post("/guests/passes", status_code=201)
async def issue_pass(body: PassInput, request: Request, user=Depends(admin), db: Session = Depends(get_db)):
    """Issue one guest pass at a source that offers passes. Refuses with a clear reason when it may not."""
    from .integrations import IntegrationError

    settings: Settings = request.app.state.settings
    candidates = [row for row in _sources(db, "guest.passes")
                  if not body.integration_id or row.id == body.integration_id]
    if not candidates:
        raise HTTPException(409, "Connect a source that offers guest passes before issuing one.")
    integration = candidates[0]
    provider = registry.get(integration.provider)
    mode = settings.write_mode(integration.provider)
    if mode == "disabled":
        raise HTTPException(409, _read_only(integration.name))
    row = GuestPass(integration_id=integration.id, name=body.name, minutes=body.minutes,
                    guest_limit=body.guest_limit, data_limit_mb=body.data_limit_mb, issued_by=user.id, code="")
    if mode == "simulated":
        digits = "".join(secrets.choice("0123456789") for _ in range(10))
        row.code, row.execution = f"{digits[:5]}-{digits[5:]}", "simulated"
    else:
        integration, site, key = _target(db, integration)
        if not key:
            raise HTTPException(409, f"The secret for {integration.name} is not configured on the server.")
        try:
            issued = await provider.issue_pass(integration.config, key, site, name=body.name,
                                               minutes=body.minutes, guest_limit=body.guest_limit,
                                               data_limit_mb=body.data_limit_mb, allowed=True)
        except IntegrationError as error:
            raise HTTPException(502, str(error)) from None
        row.voucher_id, row.code, row.execution = issued["id"], issued["code"][:64], "applied"
    db.add(row)
    db.flush()
    audit(db, user.id, "guest.pass_issued", row.id, minutes=body.minutes, guest_limit=body.guest_limit,
          execution=row.execution)
    db.commit()
    return pass_json(row, {user.id: user.name})


@router.post("/guests/passes/{pass_id}/end")
async def end_pass(pass_id: str, request: Request, user=Depends(admin), db: Session = Depends(get_db)):
    """End a pass so it cannot be used again. Devices already on it stay until they are cut off."""
    from .integrations import IntegrationError

    settings: Settings = request.app.state.settings
    row = db.get(GuestPass, pass_id)
    if not row:
        raise HTTPException(404, "Pass not found")
    if row.ended_at:
        raise HTTPException(409, "This pass has already ended")
    if row.execution == "applied":
        integration = db.get(Integration, row.integration_id)
        provider = registry.find(integration.provider) if integration else None
        if not integration or not provider or not provider.end_pass \
                or settings.write_mode(integration.provider) != "enabled":
            name = integration.name if integration else "the source"
            raise HTTPException(409, f"Nyctr is read-only for {name}. End this pass there instead.")
        integration, site, key = _target(db, integration)
        try:
            if not key or not row.voucher_id:
                raise IntegrationError(f"The secret for {integration.name} is not configured on the server.")
            await provider.end_pass(integration.config, key, site, row.voucher_id, allowed=True)
        except IntegrationError as error:
            raise HTTPException(502, str(error)) from None
    row.ended_at = utcnow()
    audit(db, user.id, "guest.pass_ended", row.id, execution=row.execution)
    db.commit()
    return pass_json(row, {u.id: u.name for u in db.scalars(select(User))})


@router.post("/guests/actions")
async def act(body: ActionInput, request: Request, user=Depends(admin), db: Session = Depends(get_db)):
    """Cut off, restore or lock out one guest device, and return its updated record."""
    settings: Settings = request.app.state.settings
    device = db.get(Resource, body.device_id)
    if not device or not is_guest(device):
        raise HTTPException(404, "Guest device not found")
    if _mode(settings, device.provider, "guest.control") == "disabled":
        raise HTTPException(409, _read_only(registry.name_of(device.provider)))
    if body.action == "admit" and state_of(device, _actions(db, device.id)) != "waiting":
        raise HTTPException(409, "Only a device that is connected and waiting can be let on from here.")
    record = await apply_action(db, settings, device, body.action, user.id, body.reason,
                                body.minutes or 240 if body.action == "admit" else None)
    from .analysis import refresh_findings

    refresh_findings(db)
    db.commit()
    if record.execution == "failed":
        raise HTTPException(502, record.error or "The source refused the change.")
    passes = list(db.scalars(select(GuestPass)))
    return guest_json(db, device, passes)


@router.post("/demo/guest-activity")
async def demo_activity(body: DeviceInput, request: Request, user=Depends(admin), db: Session = Depends(get_db)):
    """Demo only: add three synthetic threat-list lookups for a guest device, then apply the rule."""
    settings: Settings = request.app.state.settings
    if settings.mode != "demo":
        raise HTTPException(404, "API endpoint not found")
    device = db.get(Resource, body.device_id)
    if not device or not is_guest(device):
        raise HTTPException(404, "Guest device not found")
    reason, codes = "Threat Intelligence Feeds", ["threat-intelligence-feeds"]
    # Attach the synthetic lookups to a DNS source whose integration reads this reason as a threat.
    integration = next((row for row in db.scalars(select(Integration).order_by(Integration.name))
                        if registry.provides(row.provider, "dns.blocks")
                        and _is_threat(risk.assess("demo.example", reason, codes, row.provider))), None)
    if integration is None:
        raise HTTPException(409, "The demo has no DNS source to attach lookups to.")
    now = utcnow()
    for index in range(3):
        stamp = now - timedelta(seconds=20 * index)
        db.add(Observation(
            id=f"demo-threat-{secrets.token_hex(6)}", integration_id=integration.id, device_id=device.id,
            device_name=device.name, domain=f"cdn{index + 1}.update-check.example",
            source=integration.provider, reason=reason, reason_codes=codes, observed_at=stamp,
            expires_at=stamp + timedelta(hours=24), evidence_kind="observed", attribution="inferred",
            risk_score=None, risk_explanation="Synthetic demo event."))
    audit(db, user.id, "demo.guest_activity", device.id)
    db.flush()
    await enforce(db, settings, evaluate_rule(db, settings))
    return overview(db, settings)
