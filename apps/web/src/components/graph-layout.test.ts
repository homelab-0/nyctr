import { describe, expect, it } from 'vitest';
import type { Graph } from '../types';
import { relationship, resource } from '../test/graph-fixtures';
import { indexGraph, layoutGraph } from './graph-layout';

/** Locks the existing coordinate/order contract while traversal changes to indexed neighborhoods. */
describe('relationship layout', () => {
  /** Equal names retain source order, unknown kinds share the fallback column, and inputs stay intact. */
  it('uses kind columns and stable alphabetic rows without mutating the source snapshot', () => {
    const graph: Graph = {
      nodes: [
        resource('destination', 'domain'),
        resource('zulu', 'client', 'Zulu'),
        resource('alpha-first', 'client', 'Alpha'),
        resource('alpha-second', 'unknown-kind', 'Alpha'),
        resource('gateway', 'gateway'),
      ],
      edges: [],
    };
    const original = structuredClone(graph);

    expect([...layoutGraph(graph)]).toEqual([
      ['gateway', { x: 0, y: 128 }],
      ['alpha-first', { x: 300, y: 0 }],
      ['alpha-second', { x: 300, y: 128 }],
      ['zulu', { x: 300, y: 256 }],
      ['destination', { x: 600, y: 128 }],
    ]);
    expect(layoutGraph(graph, 'missing-focus')).toEqual(layoutGraph(graph));
    expect(graph).toEqual(original);
  });

  /** Reverse links and shortcuts affect distance; duplicate/self edges must not add extra hops. */
  it('finds shortest undirected hops through cycles, parallel edges, and self loops', () => {
    const graph: Graph = {
      nodes: [
        resource('root'),
        resource('alpha'),
        resource('beta'),
        resource('child'),
        resource('isolated', 'network'),
      ],
      edges: [
        relationship('reverse', 'alpha', 'root'),
        relationship('chain', 'alpha', 'beta'),
        relationship('cycle-shortcut', 'beta', 'root'),
        relationship('self', 'beta', 'beta'),
        relationship('parallel', 'root', 'alpha'),
        relationship('reverse-child', 'child', 'beta'),
      ],
    };

    expect([...layoutGraph(graph, 'root')]).toEqual([
      ['root', { x: 0, y: 64 }],
      ['alpha', { x: 300, y: 0 }],
      ['beta', { x: 300, y: 128 }],
      ['child', { x: 600, y: 64 }],
      ['isolated', { x: 900, y: 64 }],
    ]);
    expect(indexGraph(graph).neighbors.get('beta')).toEqual(['alpha', 'root', 'beta', 'child']);
  });

  /** Layout can traverse supplied edges through a missing endpoint; the renderer still omits it. */
  it('retains layout traversal through absent endpoints without inventing visible resources', () => {
    const graph: Graph = {
      nodes: [resource('root'), resource('peer'), resource('next')],
      edges: [
        relationship('missing-source', 'uncollected', 'root'),
        relationship('missing-target', 'peer', 'uncollected'),
        relationship('visible', 'root', 'next'),
      ],
    };
    const index = indexGraph(graph);

    expect(index.nodeIds.has('uncollected')).toBe(false);
    expect([...layoutGraph(graph, 'root', index)]).toEqual([
      ['root', { x: 0, y: 0 }],
      ['next', { x: 300, y: 0 }],
      ['peer', { x: 600, y: 0 }],
    ]);
  });

  /** An absent focus cannot synthesize a node when no source inventory is available. */
  it('returns no positions for an empty snapshot', () => {
    expect(layoutGraph({ nodes: [], edges: [] }, 'absent')).toEqual(new Map());
  });
});
