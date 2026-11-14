import { describe, expect, it } from 'vitest';
import { SHARED, UNPLACED, assignLanes, layoutMap } from './map-layout';
import { bigSite } from '../test/map-site';
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
  attributes: evidence === 'inferred' ? { basis: 'Network card tagged VLAN 20' } : {},
});

const graph: Graph = {
  nodes: [
    node('site', 'site', 'unifi_network'),
    node('gw', 'gateway', 'unifi_network'),
    node('guest', 'network', 'unifi_network', { vlan: 40 }),
    node('lan', 'network', 'unifi_network', { vlan: 10 }),
    node('servers', 'network', 'unifi_network', { vlan: 20 }),
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
      'VLAN 10',
      'VLAN 20',
      'VLAN 40',
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

  it('puts a device on the network a link places it on, and one with no network in its own column', () => {
    const site: Graph = {
      nodes: [
        node('gw', 'gateway', 'unifi_network'),
        node('sw', 'switch', 'unifi_network'),
        node('lan', 'network', 'unifi_network', { vlan: 10 }),
        node('tv', 'client', 'unifi_network', { ip: '192.0.2.20' }),
        node('roamer', 'client', 'unifi_network'),
      ],
      edges: [
        edge('tv', 'lan', 'member_of', 'inferred'),
        edge('lan', 'gw', 'managed_by', 'inferred'),
        edge('sw', 'gw', 'connects_to', 'observed'),
      ],
    };
    const layout = layoutMap(site);
    const placed = Object.fromEntries(layout.nodes.map((item) => [item.id, item]));
    expect(placed.tv.lane).toBe('lan');
    expect(placed.roamer.lane).toBe(UNPLACED);
    expect(placed.gw).toMatchObject({ lane: SHARED, band: 'net' });
    expect(placed.sw.lane).toBe(SHARED);
    expect(layout.lanes.at(-1)).toMatchObject({ id: UNPLACED, name: 'Network not reported' });
    expect(layout.lanes.at(-1)!.x).toBeGreaterThan(layout.lanes[1].x);
    expect(layout.edges.find((item) => item.kind === 'managed_by')?.evidence).toBe('inferred');
    expect(layout.edges.find((item) => item.source === 'sw')?.evidence).toBe('observed');
    // The column appears only when a device needs it.
    expect(layoutMap(graph).lanes.some((lane) => lane.id === UNPLACED)).toBe(false);
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
    const box = devices.at(-1)!;
    expect(box).toMatchObject({ kind: 'more', name: '35 more devices on lan' });
    // By name with 2 before 10: c0 to c4 are drawn, and the box holds the rest in that order.
    expect(devices.slice(0, 5).map((item) => item.id)).toEqual(['c0', 'c1', 'c2', 'c3', 'c4']);
    expect(box.held!.map((item) => item.id).slice(0, 3)).toEqual(['c5', 'c6', 'c7']);
    expect(box.held).toHaveLength(35);
    expect(layout.holder.get('c39')).toBe(box.id);
    expect(layout.holder.has('c0')).toBe(false);
  });

  it('always draws gateways and networks, says where a box is, and never boxes one item', () => {
    const rules = (count: number) =>
      Array.from({ length: count }, (_, i) => node(`r${i}`, 'policy', 'unifi_network'));
    const gateways = Array.from({ length: 8 }, (_, i) => node(`gw${i}`, 'gateway', 'x'));
    const crowded = layoutMap({ nodes: [...rules(20), ...gateways], edges: [] }, 'all', 6);
    const cell = crowded.nodes.filter((item) => item.band === 'net');
    expect(cell.slice(0, 8).every((item) => item.kind === 'gateway')).toBe(true);
    expect(cell.at(-1)!.name).toBe('20 more rules not tied to one network');
    expect(crowded.bands.find((band) => band.id === 'net')!.h).toBeGreaterThan(9 * 44);
    // Six gateways and one rule: a box for the one rule would take the room the rule needs.
    const seven = layoutMap({ nodes: [...gateways.slice(0, 6), ...rules(1)], edges: [] }, 'all', 6);
    expect(seven.nodes.map((item) => item.kind)).toEqual([...Array(6).fill('gateway'), 'policy']);
    const loose = layoutMap(
      { nodes: Array.from({ length: 9 }, (_, i) => node(`d${i}`, 'client', 'x')), edges: [] },
      'all',
      6,
    );
    expect(loose.nodes.at(-1)!.name).toBe('4 more devices with no network reported');
  });

  it('keeps every item of a site of real size on a card or in exactly one box', () => {
    const site = bigSite();
    const started = performance.now();
    const layout = layoutMap(site);
    const took = performance.now() - started;
    const cards = layout.nodes.filter((item) => !item.held);
    const boxed = layout.nodes.flatMap((item) => item.held || []);
    expect(site.nodes).toHaveLength(280);
    expect([...cards, ...boxed].map((item) => item.id).sort()).toEqual(
      site.nodes.map((item) => item.id).sort(),
    );
    expect(boxed.every((item) => layout.holder.has(item.id))).toBe(true);
    expect(cards.some((item) => item.id === 'gw')).toBe(true);
    // The drawing stays small however much there is: at most six places in a square.
    expect(cards.length).toBeLessThan(110);
    expect(took).toBeLessThan(250);
  });
});
