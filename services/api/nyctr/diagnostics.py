"""Read-only connector diagnostics that expose evidence, never source payloads or secrets."""

from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime
from time import perf_counter
from typing import Literal

from pydantic import BaseModel

from . import integrations
from .integrations import registry
from .integrations.core import (
    IntegrationError,
    ProbeEvidence,
    capture_probe,
    describe_gaps,
    patience,
    utc_now,
)

DIAGNOSTICS_TIMEOUT_SECONDS = 90
# Someone is waiting on a connection test. Where a source's request limit is in use, the test
# waits this long in total for a turn and then says so, instead of holding the request open.
DIAGNOSTICS_WAIT_SECONDS = 20

CheckStatus = Literal["passed", "failed", "unknown", "unavailable"]
ErrorCategory = Literal[
    "configuration", "secret", "transport", "tls", "authentication",
    "provider_contract", "rate_limit", "timeout", "internal", "not_checked",
]


class DiagnosticCheck(BaseModel):
    """Describe one verified, failed, or still-unknown stage using application-owned text."""
    id: str
    label: str
    status: CheckStatus
    category: ErrorCategory
    summary: str
    guidance: str | None = None


class DiagnosticCapability(BaseModel):
    """Separate an adapter's implementation from evidence obtained in this particular probe."""
    id: str
    label: str
    implementation: Literal["implemented", "not_implemented"]
    verification: Literal["verified", "unavailable", "unknown"]
    summary: str


class EvidenceGap(BaseModel):
    """Explain a fixed product or source limitation without reflecting provider-controlled text."""
    id: str
    title: str
    summary: str


class SnapshotCounts(BaseModel):
    """Count normalized in-memory records only after a complete bounded collection succeeds."""
    resources: int
    relationships: int
    observations: int


class DiagnosticReport(BaseModel):
    """Return an ephemeral diagnostic result; no inventory or collection-health state is imported."""
    integration_id: str
    provider: str
    checked_at: datetime
    duration_ms: int
    outcome: Literal["verified", "partial", "failed"]
    summary: str
    read_only: Literal[True] = True
    checks: list[DiagnosticCheck]
    capabilities: list[DiagnosticCapability]
    evidence_gaps: list[EvidenceGap]
    snapshot_counts: SnapshotCounts | None


_CHECK_LABELS = {
    "configuration": "Saved configuration",
    "secret": "Server credential",
    "connectivity": "Provider connectivity",
    "tls": "HTTPS certificate validation",
    "authentication": "Provider authentication and read access",
    "provider_contract": "Supported response contract",
}

_FAILURES = {
    "configuration": (
        "The saved configuration does not meet the supported connector requirements.",
        "Check the provider, identifier, HTTPS integration path, and server hostname allowlist.",
    ),
    "secret": (
        "A valid server-side credential reference and value are not available.",
        "Configure the referenced NYCTR_CONNECTOR_SECRET_ variable in the deployment secret store.",
    ),
    "transport": (
        "The provider exchange could not be completed securely.",
        "Check the provider address, network reachability, and certificate trust. No individual cause was established.",
    ),
    "tls": (
        "Certificate validation or the configured connector trust bundle failed.",
        "Use a certificate valid for the configured hostname and a trusted CA bundle. Keep TLS verification enabled.",
    ),
    "authentication": (
        "The provider rejected the credential or its permissions for a requested read.",
        "Check the API key, the selected site or profile, and the provider's read permissions.",
    ),
    "provider_contract": (
        "The provider response could not be normalized within the adapter's supported contract and limits.",
        "Check the supported provider API version and scope. Missing, malformed, redirected, or oversized data is not accepted.",
    ),
    "rate_limit": (
        "The source's request limit was reached or is in use, so a requested read was not made.",
        "Try again shortly. If it keeps happening, narrow what this source reads or collect from it less often.",
    ),
    "timeout": (
        "The bounded provider check reached its deadline before completion.",
        "Check provider availability and narrow the site scope or DNS log lookback before retrying.",
    ),
    "internal": (
        "The diagnostic could not complete because of an unexpected internal failure.",
        "Retry once, then report the failed stage and application version without credentials or provider payloads.",
    ),
}

# A rate limit where every request in the count was this test's own. Trying again cannot help.
_OWN_LIMIT = (
    "This test sent as many requests as the source allows in a minute and still needed more, so it stopped.",
    "Trying again will not help: the test would stop at the same place. "
    "Collect from this source instead. A collection may wait longer for its turn.",
)


def _set_check(checks, id_, status, category, summary, guidance=None):
    """Replace one fixed report stage with sanitized application-owned diagnostic text."""
    checks[id_] = DiagnosticCheck(id=id_, label=_CHECK_LABELS[id_], status=status,
                                  category=category, summary=summary, guidance=guidance)


def _failed_check(checks, id_, category, text=None):
    """Render a known failure category without exposing the underlying exception message.

    `text` is other fixed wording for the same category, as a summary and what to do.
    """
    summary, guidance = text or _FAILURES[category]
    _set_check(checks, id_, "failed", category, summary, guidance)


def _capabilities(provider: str, evidence: ProbeEvidence) -> list[DiagnosticCapability]:
    """List supported reads separately from runtime verification and unavailable product features.

    The reads, their labels and the features a source cannot support all come
    from the integration's own declaration.
    """
    definition = registry.find(provider)
    result = []
    for capability, label in (definition.reads if definition else ()):
        verification = "unknown"
        summary = "Implemented by the adapter; not verified by this diagnostic."
        if capability in evidence.unavailable_capabilities:
            verification = "unavailable"
            summary = "The provider explicitly reports that DNS logging is disabled for this profile."
        elif capability in evidence.verified_capabilities:
            verification = "verified"
            summary = "The corresponding source data passed the implemented parser within the checked scope."
        result.append(DiagnosticCapability(id=capability, label=label, implementation="implemented",
                                           verification=verification, summary=summary))
    limitations = [("device_identity:verify", "Automatic user attribution",
                    "Source device labels and addresses do not establish event-time user ownership.")]
    limitations.extend(definition.limitations if definition else ())
    for capability, label, summary in limitations:
        result.append(DiagnosticCapability(id=capability, label=label, implementation="not_implemented",
                                          verification="unavailable", summary=summary))
    return result


def _gaps(provider: str, evidence: ProbeEvidence, counts: SnapshotCounts | None) -> list[EvidenceGap]:
    """Keep identity, event coverage, and incomplete source fields explicit even after successful reads.

    Standing gaps and the text for recorded gap codes belong to the integration.
    The log-coverage gaps apply to any source that reports blocked lookups.
    """
    definition = registry.find(provider)
    entries = list(definition.gaps) if definition else []
    if definition and "dns.blocks" in definition.provides:
        if "blocked_dns_logs:read" in evidence.unavailable_capabilities:
            entries.append(("logging_disabled", "DNS logging is disabled at the source",
                            "The profile reports logging disabled. Zero returned observations must not be interpreted as an absence of blocks."))
        elif "blocked_dns_logs:read" not in evidence.verified_capabilities:
            entries.append(("log_coverage_unknown", "Blocked-query coverage is unverified",
                            "This diagnostic did not complete a verified read of recent blocked queries."))
        elif counts is not None and counts.observations == 0:
            entries.append(("no_recent_events", "No recent blocks were returned",
                            "The bounded log query returned no normalized block events. This does not prove that no connection was blocked."))
    entries.extend(describe_gaps(definition.gap_notes if definition else {},
                                 {gap: evidence.gap_causes.get(gap) for gap in evidence.gaps}))
    return [EvidenceGap(id=id_, title=title, summary=summary) for id_, title, summary in entries]


async def diagnose_integration(provider: str, integration_id: str, config: dict,
                               secret_ref: str) -> DiagnosticReport:
    """Probe a saved connector without persisting its in-memory snapshot or reflecting provider data.

    Authorization and mutual exclusion belong to the API caller. A context-local
    recorder distinguishes implemented capabilities from reads actually parsed.
    Configuration and secret failures make no provider requests; all network work
    uses the existing verified, GET-only adapter and a bounded overall deadline.
    """
    started = perf_counter()
    checked_at = utc_now()
    checks = {}
    for id_ in _CHECK_LABELS:
        _set_check(checks, id_, "unknown", "not_checked", "This stage was not verified by the diagnostic.")
    valid_config = None
    try:
        valid_config = integrations.validate_config(provider, config)
        _set_check(checks, "configuration", "passed", "configuration",
                   "The saved configuration meets the adapter's supported format and destination restrictions.")
    except (IntegrationError, ValueError, TypeError):
        _failed_check(checks, "configuration", "configuration")
    api_key = None
    if isinstance(secret_ref, str) and re.fullmatch(r"NYCTR_CONNECTOR_SECRET_[A-Z0-9_]{1,100}", secret_ref):
        api_key = os.environ.get(secret_ref)
    if api_key and api_key.strip() and not any(c in api_key for c in "\r\n"):
        _set_check(checks, "secret", "passed", "secret",
                   "A server-side credential value is available. Provider acceptance is checked separately.")
    else:
        api_key = None
        _failed_check(checks, "secret", "secret")
    error_category = None
    spent_here = False
    counts = None
    with capture_probe() as evidence:
        if valid_config is not None and api_key is not None:
            try:
                with patience(DIAGNOSTICS_WAIT_SECONDS):
                    snapshot = await asyncio.wait_for(
                        integrations.collect(provider, integration_id, valid_config, api_key),
                        timeout=DIAGNOSTICS_TIMEOUT_SECONDS,
                    )
                counts = SnapshotCounts(resources=len(snapshot.resources), relationships=len(snapshot.relationships),
                                        observations=len(snapshot.blocks))
            except TimeoutError:
                error_category = "timeout"
            except IntegrationError as exc:
                error_category = exc.category if exc.category in _FAILURES else "internal"
                spent_here = exc.category == "rate_limit" and exc.limit_spent_here
            except Exception:
                error_category = "internal"
    if evidence.responses_received:
        _set_check(checks, "connectivity", "passed", "transport",
                   "At least one provider response was received. DNS resolution and routing were not tested separately.")
        _set_check(checks, "tls", "passed", "tls",
                   "An HTTPS response was received through the certificate-verifying connector client.")
    if evidence.verified_capabilities:
        _set_check(checks, "authentication", "passed", "authentication",
                   "At least one supported read accepted the credential. This verifies only the checked read scope.")
    if counts is not None:
        _set_check(checks, "provider_contract", "passed", "provider_contract",
                   "The bounded snapshot passed the implemented parsers. Capability coverage is reported separately.")
    if error_category:
        stage = {
            "configuration": "configuration", "secret": "secret", "tls": "tls",
            "authentication": "authentication",
        }.get(error_category, "provider_contract")
        if error_category in {"transport", "timeout"} and not evidence.responses_received:
            stage = "connectivity"
        _failed_check(checks, stage, error_category, _OWN_LIMIT if spent_here else None)
    capabilities = _capabilities(provider, evidence)
    implemented = [item for item in capabilities if item.implementation == "implemented"]
    if not evidence.verified_capabilities:
        outcome = "failed"
        summary = "No supported provider read was verified. Review the checks before collecting data."
    elif error_category or evidence.gaps or any(item.verification != "verified" for item in implemented):
        outcome = "partial"
        summary = "Some supported reads were verified, but source coverage is incomplete or a later check failed."
    else:
        outcome = "verified"
        summary = "The supported reads were verified within this diagnostic's bounded scope. Review the remaining evidence gaps."
    return DiagnosticReport(
        integration_id=integration_id, provider=provider, checked_at=checked_at,
        duration_ms=max(0, int((perf_counter() - started) * 1000)), outcome=outcome, summary=summary,
        checks=list(checks.values()), capabilities=capabilities, evidence_gaps=_gaps(provider, evidence, counts),
        snapshot_counts=counts,
    )
