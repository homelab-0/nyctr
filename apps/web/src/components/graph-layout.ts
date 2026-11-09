import type { Graph, Resource } from '../types';

/** Lookup data shared by layout and rendering for a single immutable graph snapshot. */
export interface GraphIndex {
  nodeIds: Set<string>;
  neighbors: Map<string, string[]>;
}

const kindRanks: Record<string, number> = {
  site: 0,
  gateway: 1,
  switch: 2,
  access_point: 3,
  network: 3,
  host: 4,
  client: 4,
  workload: 5,
  policy: 5,
  dns_profile: 5,
  domain: 6,
};

/**
 * Indexes relationship neighborhoods in source order for undirected exploration.
 * Missing endpoints remain traversable for layout compatibility, but nodeIds lets
 * the renderer exclude edges whose endpoint resources were not supplied.
 * This index describes adjacency, not packet direction or proven reachability.
 */
export function indexGraph(graph: Graph): GraphIndex {
  const nodeIds = new Set(graph.nodes.map((resource) => resource.id));
  const neighbors = new Map<string, string[]>();
  for (const edge of graph.edges) {
    const sourceNeighbors = neighbors.get(edge.source) ?? [];
    sourceNeighbors.push(edge.target);
    neighbors.set(edge.source, sourceNeighbors);
    if (edge.source !== edge.target) {
      const targetNeighbors = neighbors.get(edge.target) ?? [];
      targetNeighbors.push(edge.source);
      neighbors.set(edge.target, targetNeighbors);
    }
  }
  return { nodeIds, neighbors };
}

/**
 * Places resources in deterministic columns without changing the source snapshot.
 * A valid focus uses shortest undirected hop distance; disconnected resources use
 * kind ranks. Alphabetic rows, stable ties, and centered columns preserve the
 * explorer's visual ordering. Traversal is linear in vertices and relationships.
 */
export function layoutGraph(graph: Graph, focus?: string, index = indexGraph(graph)) {
  const ranks = new Map<string, number>();
  if (focus && index.nodeIds.has(focus)) {
    ranks.set(focus, 0);
    const queue = [focus];
    for (let cursor = 0; cursor < queue.length; cursor += 1) {
      const id = queue[cursor];
      for (const next of index.neighbors.get(id) ?? []) {
        if (next && !ranks.has(next)) {
          ranks.set(next, ranks.get(id)! + 1);
          queue.push(next);
        }
      }
    }
  }

  const groups = new Map<number, Resource[]>();
  for (const resource of graph.nodes) {
    const rank = ranks.get(resource.id) ?? kindRanks[resource.kind] ?? 4;
    const group = groups.get(rank) ?? [];
    group.push(resource);
    groups.set(rank, group);
  }

  const positions = new Map<string, { x: number; y: number }>();
  const columns = [...groups.keys()].sort((a, b) => a - b);
  const maxHeight = Math.max(1, ...[...groups.values()].map((items) => items.length));
  columns.forEach((rank, column) => {
    const items = groups.get(rank)!.sort((a, b) => a.name.localeCompare(b.name));
    items.forEach((resource, row) =>
      positions.set(resource.id, {
        x: column * 300,
        y: row * 128 + (maxHeight - items.length) * 64,
      }),
    );
  });
  return positions;
}
