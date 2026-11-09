import type {
  Integration,
  IntegrationDiagnosticCapability,
  IntegrationDiagnosticCheck,
  IntegrationDiagnosticsReport,
} from '../types';

const MAX_REPORT_ITEMS = 32;
const categories = [
  'configuration',
  'secret',
  'transport',
  'tls',
  'authentication',
  'provider_contract',
  'rate_limit',
  'timeout',
  'internal',
  'not_checked',
];

/** Excludes null, arrays, and primitives before a diagnostic field is inspected. */
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Bounds human-readable report text without interpreting source content as HTML or instructions. */
function text(value: unknown, limit: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit;
}

/** Accepts only explicit contract states; an unfamiliar value must never become verified. */
function oneOf(value: unknown, allowed: readonly string[]): boolean {
  return typeof value === 'string' && allowed.includes(value);
}

/** Restricts examined-record counts and timing to representable nonnegative integers. */
function count(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/** Requires bounded check descriptions, known outcomes, and optional guidance before rendering. */
function check(value: unknown): value is IntegrationDiagnosticCheck {
  return (
    record(value) &&
    text(value.id, 128) &&
    text(value.label, 200) &&
    oneOf(value.status, ['passed', 'failed', 'unknown', 'unavailable']) &&
    oneOf(value.category, categories) &&
    text(value.summary, 4000) &&
    (value.guidance === null || text(value.guidance, 4000))
  );
}

/** Validates static implementation and runtime verification as separate capability fields. */
function capability(value: unknown): value is IntegrationDiagnosticCapability {
  return (
    record(value) &&
    text(value.id, 128) &&
    text(value.label, 200) &&
    oneOf(value.implementation, ['implemented', 'not_implemented']) &&
    oneOf(value.verification, ['verified', 'unavailable', 'unknown']) &&
    text(value.summary, 4000)
  );
}

/** Retains only complete evidence-gap descriptions suitable for the bounded report view. */
function gap(value: unknown): value is IntegrationDiagnosticsReport['evidence_gaps'][number] {
  return (
    record(value) && text(value.id, 128) && text(value.title, 200) && text(value.summary, 4000)
  );
}

/** Bounds report sections and requires unique identifiers so rows cannot silently replace each other. */
function items<T extends { id: string }>(
  value: unknown,
  valid: (item: unknown) => item is T,
  minimum = 0,
): value is T[] {
  if (
    !Array.isArray(value) ||
    value.length < minimum ||
    value.length > MAX_REPORT_ITEMS ||
    !value.every(valid)
  )
    return false;
  return new Set(value.map((item) => item.id)).size === value.length;
}

/**
 * Accepts only a complete, bounded report for the connection the administrator requested.
 * HTTP success alone does not establish a valid result: malformed, cross-connection,
 * or write-capable responses must become a visible error before reaching the renderer.
 */
export function isDiagnosticReport(
  value: unknown,
  integration: Pick<Integration, 'id' | 'provider'>,
): value is IntegrationDiagnosticsReport {
  if (
    !record(value) ||
    !text(value.integration_id, 255) ||
    !text(value.provider, 64) ||
    value.integration_id !== integration.id ||
    value.provider !== integration.provider ||
    value.read_only !== true ||
    !oneOf(value.outcome, ['verified', 'partial', 'failed']) ||
    !text(value.summary, 4000) ||
    !text(value.checked_at, 64) ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(
      value.checked_at,
    ) ||
    !Number.isFinite(Date.parse(value.checked_at)) ||
    !count(value.duration_ms) ||
    !items(value.checks, check, 1) ||
    !items(value.capabilities, capability, 1) ||
    !items(value.evidence_gaps, gap)
  )
    return false;
  const totals = value.snapshot_counts;
  return (
    totals === null ||
    (record(totals) &&
      count(totals.resources) &&
      count(totals.relationships) &&
      count(totals.observations))
  );
}
