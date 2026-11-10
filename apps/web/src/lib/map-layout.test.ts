import { describe, expect, it } from 'vitest';
import { SHARED, assignLanes, layoutMap } from './map-layout';
import type { Graph, Relationship, Resource } from '../types';

const node = (
  id: string,
  kind: string,
  provider: string,
  attributes: Record<string, unknown> = {},
): Resource => ({
  id,
  name: id,
  kind,
  provider,
  source_id: id,
  site_id: null,
  observed_at: '2026-11-10T00:00:00Z',
  evidence_kind: 'observed',
  classification: 'unassigned',
  owner_id: null,
  attributes,
});
const edge = (
  source: string,
  target: string,
  kind: string,
  evidence: Relationship['evidence_kind'] = 'configured',
): Relationship => ({
  id: `${source}-${kind}-${target}`,
  source,
  target,
  kind,
  provider: evidence === 'inferred' ? 'nyctr' : 'unifi_network',
  evidence_kind: evidence,
  observed_at: '2026-11-10T00:00:00Z',
  attributes: evidence === 'inferred' ? { basis: 'Network card tagged VLAN 66' } : {},
});

const graph: Graph = {
  nodes: [
    node('site', 'site', 'unifi_network'),
    node('gw', 'gateway', 'unifi_network'),
    node('guest', 'network', 'unifi_network', { vlan: 80 }),
    node('lan', 'network', 'unifi_network', { vlan: 65 }),
    node('servers', 'network', 'unifi_network', { vlan: 66 }),
    node('laptop', 'client', 'unifi_network'),
    node('nic', 'client', 'unifi_network'),
    node('pve', 'host', 'proxmox'),
    node('vmbr0', 'bridge', 'proxmox'),
    node('vm', 'workload', 'proxmox'),
    node('stray', 'workload', 'proxmox'),
    node('example.com', 'domain', 'nextdns'),
  ],
  edges: [
    edge('site', 'gw', 'contains'),
    edge('laptop', 'lan', 'member_of'),
    edge('nic', 'servers', 'member_of'),
    edge('pve', 'nic', 'same_device', 'inferred'),
    edge('vmbr0', 'pve', 'hosted_by'),
    edge('vm', 'servers', 'member_of', 'inferred'),
    edge('vm', 'vmbr0', 'connects_to'),
    edge('stray', 'pve', 'hosted_by', 'observed'),
    edge('gw', 'laptop', 'connects_to', 'observed'),
  ],
};

describe('map layout', () => {
  it('orders network lanes by VLAN after the shared lane', () => {
    const layout = layoutMap(graph);
    expect(layout.lanes.map((lane) => lane.id)).toEqual([SHARED, 'lan', 'servers', 'guest']);
    expect(layout.lanes.map((lane) => lane.sub).slice(1)).toEqual([
      'VLAN 65',
      'VLAN 66',
      'VLAN 80',
    ]);
  });

  it('places hosts, bridges and workloads by the links the API returned, including inferred ones', () => {
    const lanes = assignLanes(graph);
    expect(lanes.get('vm')).toBe('servers');
    expect(lanes.get('pve')).toBe('servers');
    expect(lanes.get('vmbr0')).toBe('servers');
    expect(lanes.get('stray')).toBe('servers');
    expect(lanes.get('gw')).toBeUndefined();
    const layout = layoutMap(graph);
    const placed = Object.fromEntries(layout.nodes.map((item) => [item.id, item]));
    expect(placed.gw.lane).toBe(SHARED);
    expect(placed.vm.band).toBe('work');
    expect(placed.pve.band).toBe('hyp');
    expect(placed.vm.y).toBeGreaterThan(placed.pve.y);
  });

  it('never draws sites, domains or containment, and keeps each link evidence kind', () => {
    const layout = layoutMap(graph);
    expect(
      layout.nodes.find((item) => item.id === 'site' || item.id === 'example.com'),
    ).toBeUndefined();
    expect(layout.edges.some((item) => item.kind === 'contains' || item.kind === 'member_of')).toBe(
      false,
    );
    expect(layout.edges.find((item) => item.kind === 'same_device')?.evidence).toBe('inferred');
    expect(layout.edges.find((item) => item.source === 'gw')?.evidence).toBe('observed');
    expect(layout.edges.every((item) => item.path.startsWith('M'))).toBe(true);
  });

  it('narrows to one source while keeping the network lanes for orientation', () => {
    const layout = layoutMap(graph, 'proxmox');
    expect(new Set(layout.nodes.map((item) => item.provider))).toEqual(
      new Set(['proxmox', 'unifi_network']),
    );
    expect(
      layout.nodes
        .filter((item) => item.provider === 'unifi_network')
        .every((item) => item.kind === 'network'),
    ).toBe(true);
    expect(layout.lanes).toHaveLength(4);
  });

  it('collapses a crowded cell into a counted stand-in instead of growing without limit', () => {
    const many: Graph = {
      nodes: [
        node('lan', 'network', 'unifi_network', { vlan: 1 }),
        ...Array.from({ length: 40 }, (_, i) => node(`c${i}`, 'client', 'unifi_network')),
      ],
      edges: Array.from({ length: 40 }, (_, i) => edge(`c${i}`, 'lan', 'member_of')),
    };
    const layout = layoutMap(many, 'all', 6);
    const devices = layout.nodes.filter((item) => item.band === 'dev');
    expect(devices).toHaveLength(6);
    expect(devices.at(-1)).toMatchObject({ kind: 'more', more: 35, name: '35 more' });
  });
});
