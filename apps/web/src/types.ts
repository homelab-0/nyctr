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
  /** Set for an administrator on the member portal address: where the console is. */
  console_url?: string | null;
}
export interface AuthConfig {
  mode: Mode;
  local_enabled: boolean;
  oidc_enabled: boolean;
  /** Which address this page was opened on. Absent on servers that only have one. */
  site?: 'console' | 'portal';
  /** The member portal's address when it is separate from the console. */
  portal_url?: string | null;
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
  /** Display name of the kind of integration, from the server's catalog. */
  provider_name?: string;
  maturity?: string;
  /** Feature capabilities this source adds to Nyctr, by id. */
  provides?: string[];
  /** What the last stored collection could not read, in the integration's own words. */
  gaps?: { id: string; title: string; summary: string }[];
}
/** One thing Nyctr can do once a source that offers it is connected. */
export interface Capability {
  id: string;
  name: string;
  /** True when using it changes the source, so an operator must allow it first. */
  changes_provider: boolean;
}
/** One kind of integration this server ships, as declared by the integration itself. */
export interface CatalogProvider {
  id: string;
  name: string;
  summary: string;
  letter: string;
  tone: string;
  /** The source's own logo as an image `data:` address; empty when it declared none. */
  logo?: string;
  status: string;
  secret_hint: string;
  fields: {
    key: string;
    label: string;
    hint: string;
    placeholder: string;
    kind: string;
    required: boolean;
  }[];
  provides: Capability[];
  reads: { id: string; label: string }[];
  changes: string[];
  write_mode: WriteMode | 'none';
}
export interface Catalog {
  capabilities: Capability[];
  providers: CatalogProvider[];
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
  /** The connected source whose block this request is about. */
  integration_id?: string | null;
  /** That source's name, kept after it is removed. Sent to administrators only. */
  source_name?: string | null;
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
  /** Its source was removed, so Nyctr cannot reach the entry; an administrator removes it by hand. */
  source_removed?: boolean;
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
export type FeatureMode = WriteMode | 'none';
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
  /** How each feature that changes a source would act now. `none`: no connected source offers it. */
  writes: { access: FeatureMode; guests: FeatureMode };
  /** Every connected source with what Nyctr could change there and whether it may. */
  sources: {
    id: string;
    name: string;
    provider: string;
    provider_name: string;
    changes: string[];
    write_mode: FeatureMode;
  }[];
}
/** What any signed-in person may know about the schedule: on or off, how often, and when next. */
export interface ScheduleSummary {
  enabled: boolean;
  interval_seconds: number;
  next_at: string | null;
}
/** The one collection schedule for every source, as an administrator sees it. */
export interface CollectionSchedule extends ScheduleSummary {
  /** Where the value came from: saved in the Console, a deployment value, the product default, or demo. */
  source: 'console' | 'deployment' | 'default' | 'demo';
  /** Minutes an administrator may pick. */
  choices: number[];
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
  /** The name of the kind of source that reported this device. */
  source: string;
  authorization: {
    method: 'pass' | 'console' | 'other' | null;
    authorized_at: string | null;
    expires_at: string | null;
    bytes: number | null;
    seconds: number | null;
    data_limit_mb: number | null;
  } | null;
  state: 'online' | 'waiting' | 'cut' | 'locked' | 'offline';
  observed_at: string;
  pass: { id: string; name: string; evidence: string } | null;
  /** How the device got on: a pass typed into the network's sign-in page, or let on from the console. */
  joined_by: 'pass' | 'administrator' | null;
  risk: { score: number | null; band: RiskBand; factors: RiskFactor[] };
  lookups: { blocked: number; threat: number };
  timeline: TimelineItem[];
}
/** How guests sign in. The network source always serves the page; Nyctr is never in the guest's path. */
export interface GuestPortal {
  /** Names of the kinds of source that run guest Wi-Fi here. Empty when none is connected. */
  served_by: string[];
  nyctr_in_guest_path: false;
  wifi: { name: string; enabled: boolean; captive_portal: boolean; network: string | null }[];
  notice: string;
  nudge: boolean;
}
export interface GuestOverview {
  writes: WriteMode;
  rule: GuestRule;
  portal: GuestPortal;
  sources: {
    id: string;
    name: string;
    provider_name: string;
    passes: WriteMode;
    control: WriteMode;
  }[];
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
  /** Stored inventory per kind, so each count can be named. */
  kind_counts: Record<string, number>;
  relationship_count: number;
  finding_count: number;
  recent_block_count: number;
  /** The oldest and newest stored blocked lookup: the span the count actually covers. */
  oldest_block_at: string | null;
  newest_block_at: string | null;
  integration_count: number;
  mode: Mode;
}
