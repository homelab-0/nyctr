"""Persisted identity, evidence, requests, and audit records.

Provider data lives in namespaced resources. Device grants carry validity periods;
observation visibility snapshots never substitute for checking today's permission.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def uid() -> str:
    """Generate a random UUID string for application-owned records."""
    return str(uuid4())


def utcnow() -> datetime:
    """Return the current timezone-aware UTC timestamp for persistence and expiry checks."""
    return datetime.now(UTC)


def utc(value: datetime) -> datetime:
    """Normalize timestamps to UTC, interpreting timezone-naive database values as UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    """Declarative base shared by the versioned Nyctr database schema."""
    pass


class SchemaVersion(Base):
    """Record which explicit schema migration has been applied to the database."""
    __tablename__ = "schema_versions"
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Workspace(Base):
    """Bind the database to demo or live mode so sample identities cannot become live accounts."""
    __tablename__ = "workspace"
    id: Mapped[str] = mapped_column(String(20), primary_key=True, default="default")
    mode: Mapped[str] = mapped_column(String(10))


class User(Base):
    """Store a local or issuer-and-subject identity with its current authorization role."""
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(320), index=True)
    name: Mapped[str] = mapped_column(String(160))
    role: Mapped[str] = mapped_column(String(20), default="member")
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    oidc_issuer: Mapped[str | None] = mapped_column(Text, nullable=True)
    oidc_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    __table_args__ = (UniqueConstraint("oidc_issuer", "oidc_subject"),)


class LoginSession(Base):
    """Store a revocable session-token hash, CSRF secret, user binding, and absolute expiry."""
    __tablename__ = "login_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class LoginAttempt(Base):
    """Maintain an atomic account or peer login quota until its fixed window resets."""
    __tablename__ = "login_attempts"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    reset_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OIDCFlow(Base):
    """Bind a short-lived sign-in flow to browser state, nonce, and PKCE verifier."""
    __tablename__ = "oidc_flows"
    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    binding_hash: Mapped[str] = mapped_column(String(64))
    nonce: Mapped[str] = mapped_column(String(128))
    code_verifier: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Integration(Base):
    """Persist connector configuration and collection state without storing its credential."""
    __tablename__ = "integrations"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    provider: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(32), default="configured")
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sync_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Which start of Nyctr holds the collection, and when it last showed it was still in that start.
    sync_holder: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sync_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    secret_ref: Mapped[str] = mapped_column(String(160), default="")
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)


class Resource(Base):
    """Represent integration-namespaced inventory and its evidence, classification, and owner."""
    __tablename__ = "resources"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    integration_id: Mapped[str] = mapped_column(ForeignKey("integrations.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(40), index=True)
    provider: Mapped[str] = mapped_column(String(40))
    source_id: Mapped[str] = mapped_column(String(255))
    site_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    evidence_kind: Mapped[str] = mapped_column(String(20))
    classification: Mapped[str] = mapped_column(String(32), default="unassigned")
    owner_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Relationship(Base):
    """Store a typed evidence-bearing relationship without implying successful reachability."""
    __tablename__ = "relationships"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    integration_id: Mapped[str] = mapped_column(ForeignKey("integrations.id"), index=True)
    source: Mapped[str] = mapped_column(String(255), index=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    kind: Mapped[str] = mapped_column(String(40))
    provider: Mapped[str] = mapped_column(String(40))
    evidence_kind: Mapped[str] = mapped_column(String(20))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class DeviceGrant(Base):
    """Authorize a user for a device over a half-open time interval.

    A null end time represents a current grant; historical grants support
    event-time authorization without backdating a new assignment.
    """
    __tablename__ = "device_grants"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    device_id: Mapped[str] = mapped_column(ForeignKey("resources.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DevicePresence(Base):
    """A signed-in person was on a device at a time: a tie, or a conflict where no tie was made.

    Never an assignment: it changes no device's owner or classification. A tie lets
    its person see that one device from `reach_from` on, until it is ended or 30
    days pass after `last_at`. `basis` says whether the gateway was read (`live`)
    or the stored inventory stood in (`stored`); `session` marks the sign-in that
    last confirmed it. The device is named, not referenced, so a device that
    leaves the inventory leaves a tie that shows nothing.
    """
    __tablename__ = "device_presence"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(16), default="tie")
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(String(255), index=True)
    address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    basis: Mapped[str] = mapped_column(String(16), default="live")
    first_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    reach_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    session: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Observation(Base):
    """Retain a block event until inbox expiry, with explicit attribution and unknown risk support."""
    __tablename__ = "observations"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    integration_id: Mapped[str] = mapped_column(ForeignKey("integrations.id"), index=True)
    device_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_name: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(40))
    reason: Mapped[str] = mapped_column(Text)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    evidence_kind: Mapped[str] = mapped_column(String(20))
    attribution: Mapped[str] = mapped_column(String(40))
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_explanation: Mapped[str] = mapped_column(Text)
    # Schema 2: provider reason identifiers and the provider-reported device label's resource.
    reason_codes: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    source_device_id: Mapped[str | None] = mapped_column(String(255), nullable=True)


class Finding(Base):
    """Store a reviewable issue linked to resources, relationships, and supporting evidence."""
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20))
    summary: Mapped[str] = mapped_column(Text)
    resource_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    relationship_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="open")


class AccessRequest(Base):
    """Retain a user request and event snapshot independently of observation cleanup.

    The user/event uniqueness constraint makes repeat submissions idempotent.
    Review status records an internal decision and never authorizes execution.
    """
    __tablename__ = "access_requests"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    block_id: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str] = mapped_column(String(255))
    device_name: Mapped[str] = mapped_column(String(255))
    requester_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    reason: Mapped[str] = mapped_column(Text)
    duration_minutes: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Schema 2: the assessment that was shown to the requester and who decided.
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    risk_factors: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    integration_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Schema 8: the stored analysis, and the claim of the job that is writing it. A restart finishes that job once.
    analysis_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    analysis_holder: Mapped[str | None] = mapped_column(String(64), nullable=True)
    analysis_claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # One request per member/event preserves idempotence even under concurrent POSTs.
    __table_args__ = (UniqueConstraint("requester_id", "block_id"),)


class Audit(Base):
    """Record an application action and sanitized metadata for administrator review."""
    __tablename__ = "audit"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action: Mapped[str] = mapped_column(String(80))
    target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Setting(Base):
    """Hold one administrator-written rule as validated JSON with its last editor."""
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(60), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[str | None] = mapped_column(String(128), nullable=True)


class Lease(Base):
    """Record one DNS exception Nyctr is responsible for, from decision to verified end.

    `execution` states what happened at the provider: simulated (demo), applied,
    not_applied (provider writes are off) or failed. `owned` is false when the
    entry already existed, so ending the lease never removes someone else's rule.
    """
    __tablename__ = "leases"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    integration_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    device_name: Mapped[str] = mapped_column(String(255), default="")
    requester_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(20), default="temporary")
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    ended_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    execution: Mapped[str] = mapped_column(String(20), default="not_applied")
    owned: Mapped[bool] = mapped_column(Boolean, default=False)
    scope: Mapped[str] = mapped_column(Text, default="")
    decided_by: Mapped[str] = mapped_column(String(128), default="rule")
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class DeviceLink(Base):
    """An administrator's statement that a DNS-provider device label is one inventory device.

    The link applies only to events observed after it was made; it never
    backdates visibility of earlier lookups.
    """
    __tablename__ = "device_links"
    source_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("resources.id"), index=True)
    created_by: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GuestPass(Base):
    """A guest Wi-Fi pass known to Nyctr. `voucher_id` is the pass's identifier at its source. Codes are administrator-only."""
    __tablename__ = "guest_passes"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    integration_id: Mapped[str] = mapped_column(String(128), index=True)
    voucher_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    code: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(160))
    minutes: Mapped[int] = mapped_column(Integer)
    guest_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    data_limit_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    guest_count: Mapped[int] = mapped_column(Integer, default=0)
    issued_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    execution: Mapped[str] = mapped_column(String(20), default="applied")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class GuestAction(Base):
    """One cut-off, restore, lock or unlock of a guest device, by a person or the written rule."""
    __tablename__ = "guest_actions"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    device_id: Mapped[str] = mapped_column(String(255), index=True)
    action: Mapped[str] = mapped_column(String(20))
    actor: Mapped[str] = mapped_column(String(128))
    reason: Mapped[str] = mapped_column(Text, default="")
    execution: Mapped[str] = mapped_column(String(20), default="not_applied")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class Sighting(Base):
    """Where a client was attached during consecutive collections; Nyctr's own movement history."""
    __tablename__ = "sightings"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    device_id: Mapped[str] = mapped_column(String(255), index=True)
    uplink_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Insight(Base):
    """Cache one generated explanation of a finding, bound to the evidence it was written from."""
    __tablename__ = "insights"
    finding_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    evidence_hash: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(20))
    model: Mapped[str] = mapped_column(String(160), default="")
    body: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FactCache(Base):
    """One looked-up fact about a name, kept so the next day is the soonest it is asked again.

    `value` holds `{"value", "reason"}`. The registry list itself is stored here too,
    under an empty domain, because it is not a fact about one name.
    """
    __tablename__ = "fact_cache"
    domain: Mapped[str] = mapped_column(String(253), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32), primary_key=True)
    value: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    state: Mapped[str] = mapped_column(String(20))
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OwnLookup(Base):
    """A name this installation resolved or asked a registry about.

    Kept so a later match can ignore Nyctr's own questions. Nothing reads it yet.
    """
    __tablename__ = "own_lookups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(253))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Analysis(Base):
    """One stored judgement of a blocked name.

    `facts` is the object sent to the model. The model's raw reply is not stored.
    `model_state` is ok, cannot_tell, missing, failed, invalid or timed_out.
    `cannot_tell` keeps that verdict and stores no risk. A rule is told an answer
    is present only when the state is ok and the verdict is justified or
    not_justified. A missing or undecided answer cannot be read as a low one.
    """
    __tablename__ = "analyses"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    block_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    domain: Mapped[str] = mapped_column(String(253))
    facts: Mapped[dict[str, Any]] = mapped_column(JSON)
    rule_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    model_name: Mapped[str] = mapped_column(String(200), default="")
    verdict: Mapped[str | None] = mapped_column(String(20), nullable=True)
    risk: Mapped[str | None] = mapped_column(String(20), nullable=True)
    reasons: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    uncertainty: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_state: Mapped[str] = mapped_column(String(20))
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_version: Mapped[str] = mapped_column(String(16))
    duration_ms: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Notice(Base):
    """One outbound notice, written in the same transaction as the thing it reports.

    The background tick sends a row when it is due. `payload` is the JSON body.
    `state` is due, sending, sent or gave_up.
    """
    __tablename__ = "notices"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(32))
    subject: Mapped[str] = mapped_column(String(128), default="")
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    state: Mapped[str] = mapped_column(String(20), default="due")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_try_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    claimed_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    __table_args__ = (
        Index("ix_notices_due", "state", "next_try_at"),
        UniqueConstraint("kind", "subject", name="uq_notices_kind_subject"),
    )


Index("ix_device_grant_validity", DeviceGrant.device_id, DeviceGrant.user_id, DeviceGrant.valid_from)
Index("ix_own_lookups_name_at", OwnLookup.name, OwnLookup.at)
