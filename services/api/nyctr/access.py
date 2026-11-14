"""Access decisions and the leases that carry them out.

A request is always assessed and the assessment is stored and shown. Nyctr opens
access on its own only when the administrator-written access rule allows it; a
score alone never does. Every exception Nyctr is responsible for is a durable
lease that records what actually happened at the provider and is closed again by
reconciliation, including after a restart.
"""

from __future__ import annotations

import asyncio
import os
import secrets
from datetime import timedelta
from hashlib import sha256
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import risk, schedule
from .collection import SECRET_REF
from .config import Settings
from .deps import admin, columns, device_permitted, get_db, identity, observation_permitted
from .integrations import IntegrationError, registry
from .models import (
    AccessRequest,
    Audit,
    DeviceLink,
    Integration,
    Lease,
    Observation,
    Resource,
    Setting,
    User,
    utc,
    utcnow,
)
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


def where_it_reads(integration: Integration) -> tuple[dict, str]:
    """What says where a source reads: its settings other than numbers, and its secret name.

    A number (how many hours of lookups, say) changes what is read, not where, so it never moves a source.
    """
    provider = registry.find(integration.provider)
    numbers = {field.key for field in provider.fields if field.kind == "number"} if provider else set()
    return {key: value for key, value in (integration.config or {}).items() if key not in numbers}, \
        integration.secret_ref


class NotCollected(IntegrationError):
    """Nyctr was asked to change a source it has never collected from."""


def require_collected(integration: Integration) -> None:
    """Refuse, before any provider call, a change at a source Nyctr has never collected from.

    Where a source reads can change only until its first stored collection (`last_sync`), and nothing
    clears `last_sync`. So once this passes, the source cannot move while the call is in flight; only a
    removal can still happen, which the check after the call handles. No lock is held: none is needed.
    """
    if integration.last_sync is None:
        raise NotCollected(f"Nyctr has not collected from {integration.name} yet, so it changes nothing there. "
                           "Collect from it first, then try again.", category="configuration")


def source_held(db: Session, integration_id: str) -> bool:
    """Lock the source row until this transaction ends, and say whether it still exists.

    Taken only after a provider call returns, never across one. A removal then either waits for this
    transaction, and sees what Nyctr now has at the source, or has already happened and is seen here.
    """
    return db.execute(update(Integration).where(Integration.id == integration_id).values(name=Integration.name)
                      .execution_options(synchronize_session=False)).rowcount == 1


def source_unchanged(db: Session, integration: Integration, place: tuple[dict, str]) -> bool:
    """After a provider call returns, say whether the source still exists and reads where the call wrote.

    When it does, its row stays locked until the caller commits. When it does not, the transaction is
    rolled back before returning, so no lock is held during the undo call that follows.

    A move is a defence only: every change first passes `require_collected`, and a source that has
    collected cannot move, so in practice only a removal makes this answer False.
    """
    if source_held(db, integration.id):
        db.refresh(integration)
        if where_it_reads(integration) == place:
            return True
    db.rollback()
    return False


class SourceGone(IntegrationError):
    """The source was removed or moved while Nyctr was changing it. `record` writes what was done about it."""

    def __init__(self, message: str, record):
        super().__init__(message, category="configuration")
        self.record = record


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
                     minutes: int | None, decided_by: str, risk_score: int | None,
                     claim: Claim | None = None) -> Lease:
    """Create a lease and carry it out according to the provider's write mode.

    The source of the block decides what is possible: only an integration that
    declares it can open addresses is ever asked to. Demo simulates. With
    changes allowed the exception is added and verified first; a provider
    failure raises and no lease is stored. Otherwise the lease is stored as not
    applied, so the administrator sees exactly what still has to be done by hand.

    Before the source is read or changed the entry's claim is held (`hold_entry`), the same one an
    ending takes, so openings and endings of one address at one source go one at a time. The claim
    is given back in the transaction that stores the lease, or at once if the opening fails. Taking
    it commits the session: a caller with something unsaved takes it earlier and passes it in.

    With the claim comes a record of the attempt (see `hold_entry`). A stored lease replaces it. An
    opening that fails once the add may have been sent keeps it, tries the removal once before it
    raises, and leaves the rest to the upkeep tick: the caller is still told nothing was opened.
    """
    opener = _opener(integration)
    if integration is None:
        mode = "simulated" if settings.mode == "demo" else "disabled"
    else:
        mode = settings.write_mode(integration.provider) if opener else "disabled"
    execution, owned, sent, added = "not_applied", False, False, None
    if mode == "simulated":
        execution, owned = "simulated", True
    elif mode == "enabled":
        try:
            claim = claim or await hold_entry(db, settings, integration, domain)
            key = _secret(integration)
            shared = db.scalar(select(Lease.id).where(
                Lease.status == "active", Lease.domain == domain, Lease.integration_id == integration.id,
                Lease.execution == "applied", Lease.owned.is_(True)).limit(1))
            # Read before the call: if the source goes meanwhile, its row can no longer be loaded.
            config, place, about = dict(integration.config), where_it_reads(integration), \
                (integration.name, integration.id, _scope(integration))
            sent = True
            result = await opener.allow_domain(integration.config, key, domain, allowed=True)
            execution, owned, added = "applied", bool(result["owned"] or shared), bool(result["owned"])
            claim.added = added
            if not source_unchanged(db, integration, place):
                await _take_back(opener, about, config, key, domain, owned=bool(result["owned"] and not shared),
                                 decided_by=decided_by, requester_id=requester_id, request_id=request_id,
                                 minutes=minutes, risk_score=risk_score)
            # Given back in the transaction that stores the lease, so the next attempt counts it. If another
            # attempt took the claim over meanwhile, what this one saw may no longer be true: it stores nothing.
            if not _give_back(db, claim):
                raise TakenOver(f"Nyctr took too long to open {domain} at {about[0]}, and another change to it "
                                "went ahead. Nothing was opened.", category="configuration")
        except BaseException as error:  # Failed, refused or stopped: no lease, and the claim goes back now.
            if claim:
                db.rollback()
                await _not_confirmed(db, settings, claim, error, sent, added)
            raise
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
    if claim:
        db.execute(delete(Lease).where(Lease.id == claim.record))  # The stored lease replaces the record.
    return lease


async def _not_confirmed(db: Session, settings: Settings, claim: Claim, error: BaseException, sent: bool,
                         added: bool | None) -> None:
    """Deal with the record of an opening that did not end in a stored lease, and give the claim back.

    The record goes when nothing of Nyctr's can be at the source: nothing was sent, the add itself
    answered that the entry was already there, or the source went and the take-back dealt with it.
    Otherwise it stays. Where the source could not say whether the address was there before, a person
    has to look, and Nyctr removes nothing. Where it could, the record is due at once and the removal
    is tried here once (not while Nyctr is being stopped); after that the upkeep tick goes on trying.
    """
    record = db.get(Lease, claim.record) if claim.record else None
    if record is not None and record.status != "unconfirmed":  # Settled by whoever took the claim over.
        record = claim.record = None
    # The add's own answer wins over what was read first. An add that failed says whether it was sent
    # after its own read found the address absent: the entry may then be there, and if it is, it is Nyctr's.
    sent_absent = added if added is not None else getattr(error, "add_sent", None)
    ours = sent_absent or (sent_absent is None and claim.said is False)
    if not sent or added is False or isinstance(error, SourceGone) or (claim.said is not None and not ours) \
            or (record is None and not ours):
        return release_entry(db, claim)
    if not _mine(db, claim):
        # Whatever way the opening came out (returned, failed, cut off, stopped): its claim is no longer its
        # own, so it stood still past the hold and others changed the address meanwhile. Its entry may have been
        # removed, and one now there may be a person's. Not known, so Nyctr never acts on it: a person checks.
        db.execute(delete(Lease).where(Lease.id == claim.record))
        record = _record(db, claim, None)
    elif ours and not (record and record.owned):  # First read as already there, and the add then added it.
        db.execute(delete(Lease).where(Lease.id == claim.record))
        record = _record(db, claim, False)
    claim.record = None  # Kept.
    audit(db, None, "access.open_unconfirmed", record.id, domain=record.domain, execution="failed",
          removes=record.owned)
    if record.owned:
        record.expires_at = utcnow()
    release_entry(db, claim)
    if record.owned and isinstance(error, Exception):
        try:
            await end_lease(db, settings, record, "not_confirmed")
            db.commit()
        except BeingEnded:
            pass  # Someone took the claim in between; the tick settles it after them.


async def _take_back(opener, about: tuple[str, str, str], config: dict, key: str, domain: str, *,
                     owned: bool, **lease) -> None:
    """Undo an exception added at a source that was removed or moved during the call, at the place the call used.

    Called with no transaction open. Only an entry Nyctr itself added is taken out. Raises SourceGone. Its
    record says what happened; an undo that failed is kept as an open exception with its error, so it stays
    listed under Open now and is never shown as done.
    """
    (name, iid, scope), undone = about, True
    if owned:
        try:
            await opener.disallow_domain(config, key, domain, allowed=True)
        except IntegrationError:
            undone = False
    went = f"{name} was removed or now reads from somewhere else while Nyctr was opening {domain} there"
    if not owned:
        message = f"{went}. The exception was there before Nyctr's, so Nyctr left it as it was. Nothing was opened."
    elif undone:
        message = f"{went}, so Nyctr took that exception back out. Nothing was opened."
    else:
        message = (f"{went}, and Nyctr could not take it back out. Remove the exception for {domain} at that "
                   "source by hand.")
    actor = None if lease["decided_by"] == "rule" else lease["decided_by"]

    def record(db: Session) -> None:
        target = None
        if not undone:
            now, minutes = utcnow(), lease["minutes"]
            row = Lease(integration_id=iid, domain=domain, execution="applied", owned=True,
                        kind="temporary" if minutes else "permanent", scope=scope, last_error=message,
                        decided_by=lease["decided_by"], requester_id=lease["requester_id"],
                        request_id=lease["request_id"], risk_score=lease["risk_score"], created_at=now,
                        expires_at=now + timedelta(minutes=minutes) if minutes else None)
            db.add(row)
            db.flush()
            target = row.id
        audit(db, actor, "access.open_undone", target, domain=domain, source=name,
              execution="not_applied" if not owned else "applied" if undone else "failed")
    raise SourceGone(message, record)


def source_removed(db: Session, lease: Lease) -> bool:
    """Say whether the source this exception was opened at has since been removed from Nyctr."""
    return bool(lease.integration_id) and db.get(Integration, lease.integration_id) is None


# How long a claim on a source entry is held if the copy that took it was killed mid-call. Longer than an
# opening and its undo can take: each is one change with its own time limit (`actions.CHANGE_SECONDS`).
ENDING_HOLD = timedelta(minutes=5)
# How long an opening waits for an ending or another opening of the same address before it is refused.
OPENING_WAITS = 10.0


class BeingEnded(Exception):
    """Another attempt is changing this exception's entry at the source right now; this one did nothing."""


class EntryBusy(IntegrationError):
    """An opening waited for another change to the same address at the same source and was refused."""


class TakenOver(EntryBusy):
    """An opening came back from the source to find its claim taken over: it stores nothing as its own."""


class Claim(str):
    """The key of a claim on a source entry, with the mark of the one attempt that holds it and,
    for an opening, the id of its record."""
    mark: str
    record: str | None = None
    about: tuple = ()  # Source id, address, scope and source name, for the record.
    added: bool = False  # What the add itself answered, once it has: it added the entry.
    said: bool | None = None  # What the source said before the add: already there, not there, or no such read.


def _claim_entry(db: Session, lease: Lease) -> Claim | None:
    """Take the one claim on a source entry before it is read or changed there, or None while another holds it.

    The claim is a row in the settings table named after the source and the address, written by one
    insert that a second attempt cannot repeat, and committed here so that no lock is held during the
    provider call. Every opening and ending of that address at that source shares it, so they go one
    at a time. A claim left by a copy that was killed can be taken over after ENDING_HOLD; the row
    carries the mark of the attempt that holds it, so only that attempt can give it back.
    """
    return _claim(db, "ending:" + sha256(f"{lease.integration_id}\n{lease.domain}".encode()).hexdigest()[:40])


def _claim(db: Session, name: str) -> Claim | None:
    """Take the claim of that name as `_claim_entry` describes, or None while another attempt holds it."""
    key = Claim(name)
    key.mark, now = secrets.token_hex(8), utcnow()
    taken = db.execute(update(Setting).where(Setting.key == str(key), Setting.updated_at <= now - ENDING_HOLD)
                       .values(updated_at=now, updated_by=key.mark)
                       .execution_options(synchronize_session=False)).rowcount
    try:
        if not taken:
            db.execute(insert(Setting).values(key=str(key), value={}, updated_at=now, updated_by=key.mark))
        db.commit()
    except IntegrityError:
        db.rollback()
        return None
    return key


def _give_back(db: Session, claim: Claim) -> bool:
    """Delete a claim in the caller's transaction. False if another attempt took it over: it is theirs now."""
    return db.execute(delete(Setting).where(Setting.key == str(claim), Setting.updated_by == claim.mark)
                      .execution_options(synchronize_session=False)).rowcount == 1


def _mine(db: Session, claim: Claim) -> bool:
    """Lock the claim's row until the caller commits, and say whether it is still this attempt's own.

    The one check every way out of an opening goes through before it writes that an entry is Nyctr's.
    """
    return db.scalar(select(Setting.updated_by).where(Setting.key == str(claim)).with_for_update()) == claim.mark


def release_entry(db: Session, claim: Claim | None, unstored: bool = False) -> None:
    """Give a claim back at once, when what it was taken for will not happen, with its record. Commits.

    `unstored`: the source accepted the opening and storing the exception then failed. What the add
    itself answered decides: if it added the entry, the record is kept as Nyctr's own and made due, so
    the tick removes it; if the address was already there, the record goes and nothing is removed.
    """
    if claim and unstored and claim.added:
        db.execute(delete(Lease).where(Lease.id == claim.record))
        record = _record(db, claim, False if _mine(db, claim) else None)  # Taken over meanwhile: not known.
        record.expires_at, claim.record = utcnow() if record.owned else None, None
    if claim:
        db.execute(delete(Lease).where(Lease.id == claim.record))
        _give_back(db, claim)
        db.commit()


# A lease is open while its status is one of these. `unconfirmed` is the record of an opening that has
# not ended in a stored exception: it is never access, only something Nyctr may still have to remove.
OPEN = ("active", "unconfirmed")
# What an administrator reads beside such a record: where Nyctr knows the entry would be its own, and
# where the source could not say whether the address was there before.
NOT_CONFIRMED = ("Nyctr tried to open {domain} at {name} and has not confirmed it. It may be open there. "
                 "Unless the opening completes, Nyctr removes it.")
NOT_KNOWN = ("Nyctr tried to open {domain} at {name} and has not confirmed it. It may be open there. Nyctr cannot "
             "tell whether it put it there, so it removes nothing. Check at {name}, then end this here.")
THERE = ("Nyctr tried to open {domain} at {name} and has not confirmed it. The address was already allowed there "
         "before, so Nyctr removes nothing.")
REVIEWING = "This request is being approved. If that does not finish, it can be decided again within five minutes."
# What the person who asked reads after an approval that failed: nothing about the source or the reason.
NOT_OPENED = "This was not opened. Whoever runs Nyctr has been told."


def _record(db: Session, claim: Claim, said: bool | None) -> Lease:
    """Put an opening attempt on record with what the source said before the add (see `hold_entry`)."""
    (iid, domain, scope, name), now = claim.about, utcnow()
    words = NOT_KNOWN if said is None else THERE if said else NOT_CONFIRMED
    record = Lease(integration_id=iid, domain=domain, status="unconfirmed", owned=said is False, scope=scope,
                   decided_by="", created_at=now, expires_at=None if said is None else now + ENDING_HOLD,
                   last_error=words.format(domain=domain, name=name))
    db.add(record)
    db.flush()
    claim.record = record.id
    return record


def hold_review(db: Session, request_id: str) -> Claim | None:
    """Take the claim on one request that every decision on it holds, or None while another decision has it.

    An approval holds it across its call to the source, with nothing unsaved, so a second decision is
    answered at once (`REVIEWING`) and never waits on the request's row. Always taken before the
    entry's claim. One left by a copy that was killed can be taken over after ENDING_HOLD.
    """
    return _claim(db, f"review:{request_id}")


def end_review(db: Session, gate: Claim, note: str | None = None) -> None:
    """Give a request's claim back when its decision was not stored, with a note on why it still waits. Commits."""
    _give_back(db, gate)
    if note:
        db.execute(update(AccessRequest).where(AccessRequest.id == str(gate)[7:], AccessRequest.status == "pending")
                   .values(decision_note=note))
    db.commit()


def clear_stale_reviews(db: Session) -> None:
    """Clear claims on requests left by a copy killed mid-decision (a person's or the rule's), and say so."""
    for gate in db.scalars(select(Setting).where(Setting.key.startswith("review:"),
                                                 Setting.updated_at <= utcnow() - ENDING_HOLD)).all():
        # By key and mark: a claim another copy took over in this instant is theirs and stays.
        if db.execute(delete(Setting).where(Setting.key == gate.key, Setting.updated_by == gate.updated_by)
                      .execution_options(synchronize_session=False)).rowcount:
            db.execute(update(AccessRequest).where(AccessRequest.id == gate.key[7:], AccessRequest.status == "pending")
                       .values(decision_note="Nyctr was stopped while this was being decided. Nothing was opened."))
    db.commit()


async def hold_entry(db: Session, settings: Settings, integration: Integration | None, domain: str) -> Claim | None:
    """Take the claim an opening needs, waiting a short while for whoever holds it. None if nothing is sent.

    An opening that arrives during an ending or another opening of the same address waits, because
    nobody tries an opening again on a person's behalf and the other change is usually done within a
    second. After OPENING_WAITS it is refused in plain words (EntryBusy) and nothing was sent.
    Commits the session at each try, so the caller must hold nothing unsaved.

    With the claim held, and before any add, the source is asked whether the address is already
    allowed there, and the attempt goes on record with the answer: a lease with status `unconfirmed`,
    due when the claim could be taken over. If the address was not there the record is `owned`, so
    that after a failure or a kill Nyctr knows there may be an entry of its own to remove. If it was
    already there the record is not `owned` and Nyctr removes nothing, unless the add itself later
    finds the address gone and adds it. A source that offers no such read gets a record that is not
    `owned` and never due: Nyctr removes nothing there and a person checks. An earlier record for the
    same address is settled before the claim is taken, or the opening is refused.
    A source never collected from, or without its secret, is refused before any of this, and one
    removed from Nyctr during the wait is refused as removed.
    """
    opener = _opener(integration)
    if not integration or not opener or settings.write_mode(integration.provider) != "enabled":
        return None
    require_collected(integration)
    key = _secret(integration)
    if not key:
        raise IntegrationError(f"The secret for {integration.name} is not configured on the server.",
                               category="secret")
    entry, name, waited = Lease(integration_id=integration.id, domain=domain), integration.name, 0.0
    while True:
        while (claim := _claim_entry(db, entry)) is None:
            if waited >= OPENING_WAITS:
                raise EntryBusy(f"Nyctr is already changing {domain} at {name}. Nothing was opened. Try again in a "
                                "moment.", category="configuration")
            await asyncio.sleep(0.25)
            waited += 0.25
        # With the claim held, a record still there is no opening in flight: it is left over. Settle it first.
        if db.get(Integration, entry.integration_id) is None:  # A wait reads the source again: it may be gone.
            release_entry(db, claim)
            raise SourceGone(f"{name} was removed from Nyctr while it was waiting to open {domain} there. "
                             "Nothing was opened.", lambda db: None)
        earlier = db.scalars(select(Lease).where(
            Lease.status == "unconfirmed", Lease.integration_id == entry.integration_id, Lease.domain == domain,
            Lease.owned.is_(True))).first()
        if earlier is None:
            break
        release_entry(db, claim)
        try:
            settled = await end_lease(db, settings, earlier, "not_confirmed")
            db.commit()
        except BeingEnded:
            settled = False
        if not settled:
            raise EntryBusy(f"Nyctr is still removing an earlier attempt to open {domain} at {name}. Nothing was "
                            "opened. Try again in a moment.", category="configuration")
    listed, there = getattr(opener, "domain_listed", None), None
    if listed:
        try:
            there = await listed(integration.config, key, domain)
        except BaseException:  # Nothing was sent, so nothing is kept.
            release_entry(db, claim)
            raise
    claim.about, claim.said = (integration.id, domain, _scope(integration), name), bool(there) if listed else None
    _record(db, claim, claim.said)
    db.commit()
    return claim


def still_open(db: Session, lease_id: str) -> bool:
    """Lock the exception's row until the caller commits, and say whether the database still has it open."""
    with db.no_autoflush:  # What is stored, not what this session is about to write.
        return db.scalar(select(Lease.status).where(Lease.id == lease_id).with_for_update()) in OPEN


def _ours(lease: Lease) -> bool:
    """Whether an entry at the source would be Nyctr's to remove: an exception it applied, or an opening on record."""
    return lease.owned and (lease.execution == "applied" or lease.status == "unconfirmed")


async def end_lease(db: Session, settings: Settings, lease: Lease, reason: str, actor: str | None = None) -> bool:
    """Close a lease, removing the provider entry only if Nyctr created it and nothing else needs it.

    Returns False and keeps the lease active with a visible error when the
    provider could not be changed, so it is retried instead of silently left open.
    An entry Nyctr added at a source since removed cannot be reached at all: it is
    neither called nor retried, and its message is kept until a person marks it
    as removed by hand.

    Every ending comes through here, and an exception is ended once. Before an entry of Nyctr's is
    removed its claim is taken (and committed; callers hold nothing unsaved): a second attempt while
    the first, or an opening of the same address, is in flight raises BeingEnded, having sent and
    recorded nothing. With the claim held the exception is read again, and before the ending is
    recorded its row is locked and read once more; an attempt that finds it already ended sends and
    records nothing and returns True. The claim is given back in the transaction the caller commits,
    and only by the attempt that holds it: one whose claim was taken over meanwhile records nothing
    and raises BeingEnded. No lock is held during the call.

    The record of an opening that was not confirmed (status `unconfirmed`) is settled here too. Its
    entry is removed if the source has it; its words stay on it while a try fails; its ending says
    what the source did (`applied`: removed, `not_applied`: nothing was removed). It is not access, so
    it never keeps a real exception's entry in place. If a real exception uses the address, the
    entry is left to that exception, which from then on carries it as Nyctr's own.
    """
    from .integrations import IntegrationError

    db.refresh(lease)  # What is stored now, not what the caller read: the duty to remove may have been passed on.
    if lease.status not in OPEN:
        return True
    unconfirmed = lease.status == "unconfirmed"
    if _ours(lease) and source_removed(db, lease):
        lease.last_error = lease.last_error or (
            f"The source was removed, so Nyctr cannot reach it. Remove the exception for {lease.domain} there "
            "by hand.")
        return False
    claim = failure = removed = None
    # What ending did at the source, for the record: only an entry Nyctr added is ever removed.
    removal = "not_owned" if lease.execution == "applied" else None
    if _ours(lease):
        removal = "kept_for_another"
        claim = _claim_entry(db, lease)
        if claim is None:
            raise BeingEnded
        db.refresh(lease)
        using = (Lease.status == "active", Lease.id != lease.id, Lease.domain == lease.domain,
                 Lease.integration_id == lease.integration_id, Lease.execution == "applied")
        # Nyctr added this entry: whoever still uses it carries the duty to remove it from here on. Only an
        # exception that is still open has a duty to pass on. The update is also the count, so an exception
        # another copy is ending at this moment is either marked first or not counted.
        others = lease.status in OPEN and db.execute(
            update(Lease).where(*using).values(owned=True).execution_options(synchronize_session=False)).rowcount
        if lease.status in OPEN and not others:
            db.commit()  # Nothing was marked: end the transaction, so no write lock is held during the call.
            integration = db.get(Integration, lease.integration_id) if lease.integration_id else None
            key = _secret(integration) if integration else None
            opener = _opener(integration)
            try:
                if not integration or not key or not opener:
                    raise IntegrationError("The source's secret is not configured on the server.")
                sent = await opener.disallow_domain(integration.config, key, lease.domain,
                                                    allowed=settings.write_mode(integration.provider) == "enabled")
                removed = (sent or {}).get("removed")
                removal = "removed" if removed else "already_gone"
            except IntegrationError as error:
                failure = str(error)
            except BaseException:  # Stopped mid-call: give the claim back so the next start can end it.
                db.rollback()
                release_entry(db, claim)
                raise
    if claim and not _give_back(db, claim):
        db.rollback()  # Taken over while the call was going: whoever holds it now records what happens.
        raise BeingEnded
    if failure:
        lease.last_error = lease.last_error if unconfirmed else failure
        audit(db, actor, "access.close_failed", lease.id, domain=lease.domain)
        return False
    if not still_open(db, lease.id):
        db.refresh(lease)
        return True
    if claim is None:  # Its row is locked now. If the duty was passed to it meanwhile, end it as Nyctr's own.
        db.refresh(lease)
        if _ours(lease):
            return await end_lease(db, settings, lease, reason, actor)
    reason, outcome = ("not_confirmed", "applied" if removed else "not_applied") if unconfirmed else \
        (reason, lease.execution)
    lease.status, lease.ended_reason, lease.ended_at, lease.last_error = "ended", reason, utcnow(), None
    audit(db, actor, "access.closed", lease.id, domain=lease.domain, reason=reason, execution=outcome,
          **({"removal": removal} if removal else {}))
    return True


async def reconcile(db: Session, settings: Settings) -> int:
    """Close every lease whose time is up. Safe to call repeatedly and after a restart."""
    due = list(db.scalars(select(Lease).where(Lease.status.in_(OPEN), Lease.expires_at.is_not(None),
                                              Lease.expires_at <= utcnow())))
    closed = 0
    for lease in due:
        try:
            closed += await end_lease(db, settings, lease, "expired")
        except BeingEnded:
            continue  # In flight elsewhere, which records it; it is listed as open until then.
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
    limit = f"You have reached today's limit of {rule.per_day} automatic openings, so a person decides."
    if why is None and _auto_opens_today(db, row.requester_id) >= rule.per_day:
        why = limit
    if why is None:
        minutes, name, turn, waited = min(row.duration_minutes, rule.max_minutes), integration.name, None, 0.0
        db.commit()  # The assessment is stored now: the opening takes a claim, and may undo what is unsaved.
        # The rule's decision holds the request's claim like any other, so a person's decision on a request
        # that is already listed as waiting is never overwritten. If a person has it, the rule leaves it to them.
        gate = hold_review(db, row.id)
        db.refresh(row)
        if gate is None or row.status != "pending":
            return end_review(db, gate) if gate else None
        try:
            # One automatic opening at a time for each person, so the day's count is right when it is read.
            while (turn := _claim(db, "ending:auto:" + sha256(row.requester_id.encode()).hexdigest()[:40])) is None \
                    and waited < OPENING_WAITS:
                await asyncio.sleep(0.25)
                waited += 0.25
            integration = db.get(Integration, row.integration_id)
            if turn is None:
                why = "Nyctr was still opening your earlier requests, so a person decides this one."
            elif integration is None:
                why = f"{name} was removed from Nyctr while this request waited, so a person decides."
            elif _auto_opens_today(db, row.requester_id) >= rule.per_day:
                why = limit
            else:
                claim = await hold_entry(db, settings, integration, row.domain)
                await open_lease(db, settings, integration=integration, domain=row.domain,
                                 device_name=row.device_name, requester_id=row.requester_id, request_id=row.id,
                                 minutes=minutes, decided_by="rule", risk_score=assessment.score, claim=claim)
                # Compare and swap, as in the review route: a copy that does not know the request's claim may
                # have decided meanwhile. Then nothing is stored, and what was added stays on record to be removed.
                if db.execute(update(AccessRequest).where(AccessRequest.id == row.id, AccessRequest.status == "pending")
                              .values(status="auto_approved", decided_by="rule", duration_minutes=minutes,
                                      decision_note=f"Opened for {minutes} minutes by the access rule.")).rowcount != 1:
                    db.rollback()
                    return release_entry(db, claim, unstored=True)
                _give_back(db, turn)  # With the commit that stores the lease, so the next one counts it.
                _give_back(db, gate)
                turn = gate = None
                return db.refresh(row)
        except SourceGone as error:
            error.record(db)
            why = f"{error} A person decides."
        except NotCollected as error:
            why = f"{error} A person decides."
        except IntegrationError:
            why = f"Nyctr could not change {name} just now, so a person decides."
        finally:
            release_entry(db, turn)
            if gate:
                end_review(db, gate)
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
        # What went wrong at a source is written for an administrator: a member is given none of it.
        return [{**lease_json(row), "last_error": None} for row in db.scalars(query)]
    names, known = _names(db), set(db.scalars(select(Integration.id)))
    rows = list(db.scalars(query))
    # What each ending did at the source is kept in its audit record, not on the exception.
    removal = {event.target_id: event.details.get("removal") for event in db.scalars(select(Audit).where(
        Audit.action == "access.closed", Audit.target_id.in_([row.id for row in rows if row.status == "ended"])))}
    return [{**lease_json(row, names), "source_removed": bool(row.integration_id) and row.integration_id not in known,
             "removal": removal.get(row.id)} for row in rows]


class EndInput(BaseModel):
    """`by_hand`: the administrator removed the entry at a since-removed source themselves."""
    model_config = ConfigDict(extra="forbid")
    by_hand: bool = False


@router.post("/leases/{lease_id}/end")
async def end(lease_id: str, request: Request, body: EndInput | None = None, user=Depends(admin),
              db: Session = Depends(get_db)):
    """Close an active lease now. Reports honestly if the provider entry could not be removed.

    Nyctr cannot reach an exception it added at a source since removed. An administrator who removed
    it there marks it so (`by_hand`); that ends it here, says so in its record and sends nothing.
    """
    lease = db.get(Lease, lease_id)
    if not lease:
        raise HTTPException(404, "Lease not found")
    if lease.status not in OPEN:
        raise HTTPException(409, "This access has already ended")
    # A record at a source that could not say whether the entry is Nyctr's: once the source is gone, a person ends it.
    mine = _ours(lease) or lease.status == "unconfirmed"
    gone, by_hand = mine and source_removed(db, lease), bool(body and body.by_hand)
    if by_hand and not gone:
        raise HTTPException(409, "Nyctr can still reach this source, so end the exception here instead.")
    if gone and not by_hand:
        raise HTTPException(409, f"{lease.last_error or 'Its source was removed.'} Then mark it as removed by hand.")
    if gone and not still_open(db, lease.id):
        raise HTTPException(409, "This access has already ended")
    if gone:
        lease.status, lease.ended_reason, lease.ended_at, lease.last_error = "ended", "removed_by_hand", utcnow(), None
        audit(db, user.id, "access.closed", lease.id, domain=lease.domain, reason="removed_by_hand",
              execution="applied")
        db.commit()
        return lease_json(lease, _names(db))
    try:
        done = await end_lease(db, request.app.state.settings, lease, "revoked", user.id)
    except BeingEnded:
        raise HTTPException(409, "Nyctr is already ending this exception. Look again in a moment.") from None
    db.commit()
    if not done:
        raise HTTPException(502, "Nyctr could not remove the entry at the source. It is still open and will be retried.")
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
        if isinstance(error, SourceGone):
            error.record(db)
            db.commit()
            raise HTTPException(409, str(error)) from None
        raise HTTPException(409 if isinstance(error, NotCollected) else 502, str(error)) from None
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
                        else "none", "collected": row.last_sync is not None})
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
    try:
        db.commit()
    except IntegrityError:
        # The device went (its source was removed) after it was read: nothing is stored.
        db.rollback()
        raise HTTPException(404, "That device is no longer in your inventory, so nothing was linked") from None
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
