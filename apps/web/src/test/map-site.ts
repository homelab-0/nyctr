import type { Graph, Relationship, Resource } from '../types';

const at = '2026-11-13T00:00:00Z';
export const thing = (id: string, kind: string, name = id, provider = 'example'): Resource => ({
  id,
  name,
  kind,
  provider,
  source_id: id,
  site_id: null,
  observed_at: at,
  evidence_kind: 'observed',
  classification: 'unassigned',
  owner_id: null,
  attributes: {},
});
export const link = (source: string, target: string, kind: string): Relationship => ({
  id: `${source}-${kind}-${target}`,
  source,
  target,
  kind,
  provider: 'example',
  evidence_kind: 'configured',
  observed_at: at,
  attributes: {},
});

/**
 * A fabricated site the size of a real one: 10 networks, 13 pieces of equipment (a gateway,
 * 4 switches, 8 access points), 67 devices (7 on no network) and 190 rules (40 for one
 * network each, 150 between two networks).
 */
export function bigSite(): Graph {
  const nodes: Resource[] = [thing('gw', 'gateway', 'Gateway')];
  const edges: Relationship[] = [];
  for (let n = 0; n < 10; n += 1) {
    nodes.push({ ...thing(`net${n}`, 'network', `Network ${n}`), attributes: { vlan: 10 + n } });
  }
  for (let i = 0; i < 12; i += 1) {
    nodes.push(thing(`eq${i}`, i < 4 ? 'switch' : 'access_point', `Equipment ${i}`));
    edges.push(link(`eq${i}`, 'gw', 'connects_to'));
  }
  for (let i = 0; i < 67; i += 1) {
    nodes.push(thing(`dev${i}`, 'client', `Device ${i}`));
    // Half the placed devices crowd one network; the rest are spread over the others.
    if (i < 60) edges.push(link(`dev${i}`, `net${i < 30 ? 0 : i % 10}`, 'member_of'));
  }
  for (let i = 0; i < 190; i += 1) {
    nodes.push(thing(`rule${i}`, 'policy', `Rule ${i}`));
    edges.push(link(`rule${i}`, `net${i % 10}`, 'applies_to'));
    if (i >= 40) edges.push(link(`rule${i}`, `net${(i + 1) % 10}`, 'applies_to'));
  }
  return { nodes, edges };
}
