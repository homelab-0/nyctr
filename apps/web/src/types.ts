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
