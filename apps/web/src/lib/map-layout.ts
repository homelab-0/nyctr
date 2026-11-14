import type { EvidenceKind, Graph, Relationship, Resource } from '../types';

/**
 * Lays the network out as a grid: one column per network (VLAN), one row per layer.
 * Position therefore answers "which network, which layer" before any line is read.
 * The layout is deterministic and never invents a link: lane placement follows
 * member_of, hosted_by and same_device relationships that the API returned,
 * including ones it marked inferred.
 */

/** `all`, or the id of one kind of source to narrow the map to. */
export type MapView = string;

export const BANDS = [
  { id: 'dns', name: 'DNS', kinds: ['dns_profile'] },
  { id: 'net', name: 'Networks and firewall', kinds: ['gateway', 'network', 'policy'] },
  { id: 'wifi', name: 'Switching and Wi-Fi', kinds: ['switch', 'access_point'] },
  { id: 'dev', name: 'Devices', kinds: ['client'] },
  { id: 'hyp', name: 'Hypervisor', kinds: ['host', 'bridge'] },
  { id: 'work', name: 'Workloads', kinds: ['workload'] },
] as const;

const NODE_W = 172;
const NODE_H = 44;
const GAP = 10;
const LANE_W = NODE_W + 28;
const LABEL_W = 132;
const HEAD_H = 54;
const BAND_PAD = 16;
/** Kinds left off the map: sites are the whole picture, and domains would bury it. */
const HIDDEN = new Set(['site', 'domain']);
/** Relationships the grid already expresses, or that would only add noise. */
const UNDRAWN = new Set(['contains', 'member_of', 'blocked_dns_query']);
export const SHARED = '__shared__';
/** Devices no source places on a network. Never the same as belonging to the whole site. */
export const UNPLACED = '__unplaced__';

export interface MapNode {
  id: string;
  name: string;
  kind: string;
  provider: string;
  evidence: EvidenceKind;
  lane: string;
  band: string;
  x: number;
  y: number;
  w: number;
  h: number;
  /** Set on a stand-in node that represents this many nodes not drawn. */
  more?: number;
  resource?: Resource;
}
export interface MapEdge {
  id: string;
  source: string;
  target: string;
  kind: string;
  evidence: EvidenceKind;
  provider: string;
  path: string;
  basis?: string;
}
export interface MapLane {
  id: string;
  name: string;
  sub: string;
  x: number;
  w: number;
}
export interface MapBand {
  id: string;
  name: string;
  y: number;
  h: number;
}
export interface MapLayout {
  width: number;
  height: number;
  lanes: MapLane[];
  bands: MapBand[];
  nodes: MapNode[];
  edges: MapEdge[];
}

const vlanOf = (network: Resource) => {
  const value = network.attributes.vlan;
  return typeof value === 'number' ? value : null;
};

/** Finds each resource's network lane by following the relationships the API returned. */
export function assignLanes(graph: Graph): Map<string, string> {
  const byId = new Map(graph.nodes.map((node) => [node.id, node]));
  const out = new Map<string, Relationship[]>();
  const into = new Map<string, Relationship[]>();
  for (const edge of graph.edges) {
    out.set(edge.source, [...(out.get(edge.source) || []), edge]);
    into.set(edge.target, [...(into.get(edge.target) || []), edge]);
  }
  const lanes = new Map<string, string>();
  const network = (id: string | undefined) =>
    id && byId.get(id)?.kind === 'network' ? id : undefined;
  for (const node of graph.nodes) {
    if (node.kind === 'network') lanes.set(node.id, node.id);
  }
  // Direct membership, stated by a source or inferred from a VLAN tag.
  for (const node of graph.nodes) {
    const member = (out.get(node.id) || []).find(
      (edge) => edge.kind === 'member_of' && network(edge.target),
    );
    if (member) lanes.set(node.id, member.target);
  }
  // A rule that governs exactly one network sits in that network's lane.
  for (const node of graph.nodes) {
    if (node.kind !== 'policy' || lanes.has(node.id)) continue;
    const networks = new Set(
      [...(into.get(node.id) || []), ...(out.get(node.id) || [])]
        .map((edge) => network(edge.source === node.id ? edge.target : edge.source))
        .filter(Boolean) as string[],
    );
    if (networks.size === 1) lanes.set(node.id, [...networks][0]);
  }
  // Hosts take the lane of the inventory device they were matched to; bridges and
  // unplaced workloads follow their host. Two passes settle host -> bridge -> workload.
  for (let pass = 0; pass < 2; pass += 1) {
    for (const node of graph.nodes) {
      if (lanes.has(node.id)) continue;
      const follow = (out.get(node.id) || []).find(
        (edge) =>
          (edge.kind === 'same_device' || edge.kind === 'hosted_by') && lanes.has(edge.target),
      );
      if (follow) lanes.set(node.id, lanes.get(follow.target)!);
    }
  }
  return lanes;
}

/** Whether the map draws a node at all, so a count beside the map counts only what is on it. */
export const drawn = (node: Resource) =>
  !HIDDEN.has(node.kind) &&
  BANDS.some((band) => (band.kinds as readonly string[]).includes(node.kind));

/** Computes positions for every visible node and a path for every drawn relationship. */
export function layoutMap(graph: Graph, view: MapView = 'all', perCell = 6): MapLayout {
  const laneOf = assignLanes(graph);
  const networks = graph.nodes
    .filter((node) => node.kind === 'network')
    .sort((a, b) => (vlanOf(a) ?? 1e9) - (vlanOf(b) ?? 1e9) || a.name.localeCompare(b.name));
  const shown = graph.nodes.filter(
    (node) => drawn(node) && (view === 'all' || node.provider === view || node.kind === 'network'),
  );
  const lanes: MapLane[] = [
    { id: SHARED, name: 'Whole site', sub: 'Not tied to one network', x: LABEL_W, w: LANE_W },
    ...networks.map((node, index) => ({
      id: node.id,
      name: node.name,
      sub: vlanOf(node) === null ? 'No VLAN number' : `VLAN ${vlanOf(node)}`,
      x: LABEL_W + (index + 1) * LANE_W,
      w: LANE_W,
    })),
  ];
  // A device with no network is unknown, not site-wide: it gets its own last column.
  const homeOf = (node: Resource) =>
    laneOf.get(node.id) ?? (node.kind === 'client' ? UNPLACED : SHARED);
  if (shown.some((node) => homeOf(node) === UNPLACED))
    lanes.push({
      id: UNPLACED,
      name: 'Network not reported',
      sub: 'No source says which network',
      x: LABEL_W + lanes.length * LANE_W,
      w: LANE_W,
    });
  const laneX = new Map(lanes.map((lane) => [lane.id, lane.x]));
  const cells = new Map<string, Resource[]>();
  for (const node of shown) {
    const band = BANDS.find((item) => (item.kinds as readonly string[]).includes(node.kind))!;
    const lane = homeOf(node);
    const key = `${band.id}|${laneX.has(lane) ? lane : SHARED}`;
    cells.set(key, [...(cells.get(key) || []), node]);
  }
  const nodes: MapNode[] = [];
  const bands: MapBand[] = [];
  let y = HEAD_H;
  for (const band of BANDS) {
    let tallest = 1;
    for (const lane of lanes) {
      const items = (cells.get(`${band.id}|${lane.id}`) || []).sort(
        (a, b) =>
          Number(b.kind === 'network' || b.kind === 'gateway') -
            Number(a.kind === 'network' || a.kind === 'gateway') || a.name.localeCompare(b.name),
      );
      const drawn = items.length > perCell ? items.slice(0, perCell - 1) : items;
      drawn.forEach((item, index) => {
        nodes.push({
          id: item.id,
          name: item.name,
          kind: item.kind,
          provider: item.provider,
          evidence: item.evidence_kind,
          lane: lane.id,
          band: band.id,
          x: lane.x + (LANE_W - NODE_W) / 2,
          y: y + BAND_PAD + index * (NODE_H + GAP),
          w: NODE_W,
          h: NODE_H,
          resource: item,
        });
      });
      if (items.length > drawn.length) {
        nodes.push({
          id: `more:${band.id}:${lane.id}`,
          name: `${items.length - drawn.length} more`,
          kind: 'more',
          provider: '',
          evidence: 'observed',
          lane: lane.id,
          band: band.id,
          x: lane.x + (LANE_W - NODE_W) / 2,
          y: y + BAND_PAD + drawn.length * (NODE_H + GAP),
          w: NODE_W,
          h: NODE_H,
          more: items.length - drawn.length,
        });
      }
      tallest = Math.max(tallest, Math.min(items.length, perCell));
    }
    const height = BAND_PAD * 2 + tallest * NODE_H + (tallest - 1) * GAP;
    bands.push({ id: band.id, name: band.name, y, h: height });
    y += height;
  }
  const placed = new Map(nodes.map((node) => [node.id, node]));
  const edges: MapEdge[] = [];
  for (const edge of graph.edges) {
    if (UNDRAWN.has(edge.kind)) continue;
    const a = placed.get(edge.source);
    const b = placed.get(edge.target);
    if (!a || !b) continue;
    edges.push({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      kind: edge.kind,
      evidence: edge.evidence_kind,
      provider: edge.provider,
      basis: typeof edge.attributes.basis === 'string' ? edge.attributes.basis : undefined,
      path: route(a, b),
    });
  }
  return {
    width: LABEL_W + lanes.length * LANE_W + 16,
    height: y + 12,
    lanes,
    bands,
    nodes,
    edges,
  };
}

/** Draws a smooth path between two nodes, leaving from the sides that face each other. */
function route(a: MapNode, b: MapNode) {
  const ax = a.x + a.w / 2;
  const bx = b.x + b.w / 2;
  if (Math.abs(a.y - b.y) < 1) {
    // Same row: connect facing edges with a shallow arc so the line clears the nodes.
    const [left, right] = ax < bx ? [a, b] : [b, a];
    const x1 = left.x + left.w;
    const x2 = right.x;
    const y1 = left.y + left.h / 2;
    return `M${x1},${y1} C${x1 + 18},${y1 - 16} ${x2 - 18},${y1 - 16} ${x2},${y1}`;
  }
  const [top, bottom] = a.y < b.y ? [a, b] : [b, a];
  const x1 = top.x + top.w / 2;
  const y1 = top.y + top.h;
  const x2 = bottom.x + bottom.w / 2;
  const y2 = bottom.y;
  if (Math.abs(x1 - x2) < 1 && y2 - y1 > NODE_H) {
    // Same column with nodes in between: bow out to the side of the lane.
    const bend = top.x + top.w + 12;
    return `M${top.x + top.w},${top.y + top.h / 2} C${bend + 10},${top.y + top.h / 2} ${bend + 10},${bottom.y + bottom.h / 2} ${bottom.x + bottom.w},${bottom.y + bottom.h / 2}`;
  }
  const mid = (y1 + y2) / 2;
  return `M${x1},${y1} C${x1},${mid} ${x2},${mid} ${x2},${y2}`;
}
