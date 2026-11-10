export type Role = 'admin' | 'member';
export type Mode = 'demo' | 'live';
export type EvidenceKind = 'observed' | 'configured' | 'inferred';
export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  csrf_token: string;
  mode: Mode;
}
export interface AuthConfig {
  mode: Mode;
  local_enabled: boolean;
  oidc_enabled: boolean;
}
export interface Resource {
  id: string;
  name: string;
  kind: string;
  provider: string;
  source_id: string;
  site_id: string | null;
  observed_at: string;
  evidence_kind: EvidenceKind;
  classification: string;
  owner_id: string | null;
  attributes: Record<string, unknown>;
}
export interface Relationship {
  id: string;
  source: string;
  target: string;
  kind: string;
  provider: string;
  evidence_kind: EvidenceKind;
  observed_at: string;
  attributes: Record<string, unknown>;
}
export interface Graph {
  nodes: Resource[];
  edges: Relationship[];
}
export interface Finding {
  id: string;
  title: string;
  severity: string;
  summary: string;
  resource_ids: string[];
  relationship_ids: string[];
  evidence: string[];
  status: string;
}
export interface Integration {
  id: string;
  provider: string;
  name: string;
  status: string;
  last_sync: string | null;
  last_error: string | null;
  config: Record<string, unknown>;
  secret_ref: string;
  capabilities: string[];
}
/** One bounded connection check; a passed check is not a network posture assessment. */
export interface IntegrationDiagnosticCheck {
  id: string;
  label: string;
  status: 'passed' | 'failed' | 'unknown' | 'unavailable';
  category: string;
  summary: string;
  guidance: string | null;
}
/** Separates adapter implementation from evidence actually verified by this diagnostic run. */
export interface IntegrationDiagnosticCapability {
  id: string;
  label: string;
  implementation: 'implemented' | 'not_implemented';
  verification: 'verified' | 'unavailable' | 'unknown';
  summary: string;
}
/** Sanitized, transient results of an explicit administrator probe; no snapshot is imported. */
export interface IntegrationDiagnosticsReport {
  integration_id: string;
  provider: string;
  checked_at: string;
  duration_ms: number;
  outcome: 'verified' | 'partial' | 'failed';
  summary: string;
  read_only: true;
  checks: IntegrationDiagnosticCheck[];
  capabilities: IntegrationDiagnosticCapability[];
  evidence_gaps: { id: string; title: string; summary: string }[];
  snapshot_counts: { resources: number; relationships: number; observations: number } | null;
}
export interface Block {
  id: string;
  device_id: string | null;
  device_name: string;
  domain: string;
  source: string;
  reason: string;
  observed_at: string;
  expires_at: string;
  evidence_kind: EvidenceKind;
  attribution: string;
  risk_score: number | null;
  risk_explanation: string;
  risk_band: RiskBand;
  risk_category: string;
  risk_factors: RiskFactor[];
  reason_codes: string[] | null;
}
export type RiskBand = 'low' | 'medium' | 'high' | 'unknown';
/** One explained contribution to a score. Null points mean the score is unknown. */
export interface RiskFactor {
  label: string;
  points: number | null;
}
export interface AccessRequest {
  id: string;
  block_id: string;
  domain: string;
  device_name: string;
  requester_id: string;
  reason: string;
  duration_minutes: number;
  status: string;
  created_at: string;
  review_note: string | null;
  risk_score: number | null;
  risk_category: string | null;
  risk_factors: RiskFactor[] | null;
  decided_by: string | null;
  decision_note: string | null;
}
/** What happened at the provider for a decision. Only `applied` means the provider was changed. */
export type Execution = 'simulated' | 'applied' | 'not_applied' | 'failed';
export interface Lease {
  id: string;
  request_id: string | null;
  integration_id: string | null;
  domain: string;
  device_name: string;
  requester_id: string | null;
  requester_name?: string;
  decided_by_name?: string;
  kind: 'temporary' | 'permanent';
  status: 'active' | 'ended';
  ended_reason: string | null;
  execution: Execution;
  owned: boolean;
  scope: string;
  decided_by: string;
  risk_score: number | null;
  created_at: string;
  expires_at: string | null;
  ended_at: string | null;
  last_error: string | null;
}
export interface Suggestion {
  domain: string;
  times: number;
  people: string[];
  last_at: string;
  risk_score: number | null;
  integration_id: string | null;
  scope: string;
}
export type WriteMode = 'simulated' | 'enabled' | 'disabled';
export interface AccessRule {
  enabled: boolean;
  max_score: number;
  max_minutes: number;
  per_day: number;
}
export interface GuestRule {
  enabled: boolean;
  hits: number;
  minutes: number;
}
export interface Rules {
  access: AccessRule;
  guest: GuestRule;
  writes: { nextdns: WriteMode; unifi_network: WriteMode };
  collect_interval_seconds: number;
}
export interface GuestPass {
  id: string;
  integration_id: string;
  code: string;
  name: string;
  minutes: number;
  guest_limit: number | null;
  data_limit_mb: number | null;
  guest_count: number;
  issued_by: string | null;
  issued_by_name: string;
  execution: Execution;
  created_at: string;
  activated_at: string | null;
  expires_at: string | null;
  ended_at: string | null;
  state: 'unused' | 'in_use' | 'ended';
}
export interface TimelineItem {
  at: string;
  kind: string;
  text: string;
  detail?: string;
  evidence: string;
}
export interface GuestDevice {
  id: string;
  name: string;
  integration_id: string;
  mac: string | null;
  ip: string | null;
  connected_at: string | null;
  access_point: { id: string; name: string } | null;
  authorized: boolean;
  authorization: {
    authorizationMethod?: string;
    authorizedAt?: string;
    expiresAt?: string;
    usage?: { bytes?: number; durationSec?: number };
  } | null;
  state: 'online' | 'waiting' | 'cut' | 'locked' | 'offline';
  observed_at: string;
  pass: { id: string; name: string; evidence: string } | null;
  /** How the device got on: a pass typed into UniFi's sign-in page, or let on from the console. */
  joined_by: 'pass' | 'administrator' | null;
  risk: { score: number | null; band: RiskBand; factors: RiskFactor[] };
  lookups: { blocked: number; threat: number };
  timeline: TimelineItem[];
}
/** How guests sign in. UniFi always serves the page; Nyctr is never in the guest's path. */
export interface GuestPortal {
  served_by: 'unifi';
  nyctr_in_guest_path: false;
  wifi: { name: string; enabled: boolean; captive_portal: boolean; network: string | null }[];
  notice: string;
  nudge: boolean;
}
export interface GuestOverview {
  writes: WriteMode;
  rule: GuestRule;
  portal: GuestPortal;
  sources: { id: string; name: string }[];
  passes: GuestPass[];
  devices: GuestDevice[];
  not_collected: string[];
}
export interface AttentionItem {
  kind: 'guest' | 'lease' | 'request' | 'finding' | 'source' | 'suggestion';
  id: string;
  severity: 'high' | 'medium' | 'low';
  title: string;
  detail: string;
  at: string | null;
}
export interface AssistantReference {
  ref: string;
  kind: string;
  id: string;
  label: string;
}
export interface AssistantAnswer {
  answer: string;
  references: AssistantReference[];
  provider: 'model' | 'sample';
  model: string;
}
export interface AssistantConfig {
  provider: 'model' | 'sample' | 'off';
  model: string;
}
export interface Insight {
  take: string;
  reasoning: string[];
  next_steps: string[];
  confidence: 'low' | 'medium' | 'high';
  provider: 'model' | 'sample';
  model: string;
  created_at: string;
}
export interface Person {
  id: string;
  name: string;
  email: string;
  role: Role;
  active: boolean;
}
export interface DeviceLabel {
  source_id: string;
  name: string;
  model: string | null;
  integration_id: string;
  device_id: string | null;
  linked_at: string | null;
  suggested_device_id: string | null;
}
export interface ThisDevice {
  device_id: string | null;
  name: string | null;
  simulated: boolean;
}
export interface AuditEvent {
  id: string;
  created_at: string;
  actor_id: string;
  action: string;
  target_id: string;
  details: Record<string, unknown>;
}
export interface Overview {
  resource_count: number;
  relationship_count: number;
  finding_count: number;
  recent_block_count: number;
  integration_count: number;
  mode: Mode;
}
