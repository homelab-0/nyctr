import type { EvidenceKind, Relationship, Resource } from '../types';

/** Builds a fabricated resource with the same required evidence fields as an API snapshot. */
export function resource(id: string, kind = 'client', name = id): Resource {
  return {
    id,
    name,
    kind,
    provider: 'test-provider',
    source_id: id,
    site_id: null,
    observed_at: '2026-01-01T00:00:00Z',
    evidence_kind: 'configured',
    classification: 'unassigned',
    owner_id: null,
    attributes: {},
  };
}

/** Builds directional source evidence; the layout may explore it in either direction. */
export function relationship(
  id: string,
  source: string,
  target: string,
  evidence_kind: EvidenceKind = 'configured',
): Relationship {
  return {
    id,
    source,
    target,
    kind: 'belongs_to',
    provider: 'test-provider',
    evidence_kind,
    observed_at: '2026-01-01T00:00:00Z',
    attributes: {},
  };
}
