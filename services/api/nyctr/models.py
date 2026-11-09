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
    return str(uuid4())


def utcnow() -> datetime:
    return datetime.now(UTC)


def utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    pass


class SchemaVersion(Base):
    __tablename__ = "schema_versions"
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Workspace(Base):
    __tablename__ = "workspace"
    id: Mapped[str] = mapped_column(String(20), primary_key=True, default="default")
    mode: Mapped[str] = mapped_column(String(10))


class User(Base):
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
    __tablename__ = "login_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    csrf_token: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    reset_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class OIDCFlow(Base):
    __tablename__ = "oidc_flows"
    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    binding_hash: Mapped[str] = mapped_column(String(64))
    nonce: Mapped[str] = mapped_column(String(128))
    code_verifier: Mapped[str] = mapped_column(String(128))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class Integration(Base):
    __tablename__ = "integrations"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    provider: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(32), default="configured")
    last_sync: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sync_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    secret_ref: Mapped[str] = mapped_column(String(160), default="")
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)


class Resource(Base):
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
    __tablename__ = "device_grants"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    device_id: Mapped[str] = mapped_column(ForeignKey("resources.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Observation(Base):
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


class Finding(Base):
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
    # One request per member/event preserves idempotence even under concurrent POSTs.
    __table_args__ = (UniqueConstraint("requester_id", "block_id"),)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[str] = mapped_column(String(128), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action: Mapped[str] = mapped_column(String(80))
    target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


Index("ix_device_grant_validity", DeviceGrant.device_id, DeviceGrant.user_id, DeviceGrant.valid_from)
