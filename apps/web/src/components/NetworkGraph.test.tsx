import type { ReactNode } from 'react';
import { cleanup, render } from '@testing-library/react';
import { ReactFlow } from '@xyflow/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { relationship, resource } from '../test/graph-fixtures';
import type { Graph } from '../types';
import { NetworkGraph } from './NetworkGraph';

/** Replaces canvas machinery only; production memoization and evidence conversion still execute. */
vi.mock('@xyflow/react', () => ({
  ReactFlow: vi.fn(({ children }: { children?: ReactNode }) => <div>{children}</div>),
  Background: () => null,
  Controls: () => null,
  Handle: () => null,
  MiniMap: () => null,
  BackgroundVariant: { Dots: 'dots' },
  MarkerType: { ArrowClosed: 'arrowclosed' },
  Position: { Left: 'left', Right: 'right' },
}));

/** Reads the graph library boundary to verify rendering inputs without relying on DOM layout. */
function renderedGraph() {
  const props = vi.mocked(ReactFlow).mock.calls.at(-1)?.[0];
  if (!props) throw new Error('ReactFlow was not rendered');
  return props;
}

afterEach(cleanup);

/** Verifies the memoization and evidence semantics handed to the graph renderer. */
describe('NetworkGraph rendering contract', () => {
  /** Edge selection must not rebuild nodes; deliberate emphasis/selection changes must still apply. */
  it('keeps node identities stable when omitted emphasis and unrelated selection rerender', () => {
    const graph: Graph = {
      nodes: [resource('client'), resource('gateway', 'gateway')],
      edges: [relationship('attached', 'client', 'gateway')],
    };
    const { rerender } = render(<NetworkGraph graph={graph} />);
    const initialNodes = renderedGraph().nodes;

    rerender(<NetworkGraph graph={graph} selectedEdge="attached" />);
    expect(renderedGraph().nodes).toBe(initialNodes);

    rerender(<NetworkGraph graph={graph} selectedId="client" emphasizedIds={['gateway']} />);
    const updatedNodes = renderedGraph().nodes!;
    expect(updatedNodes.find((node) => node.id === 'client')?.selected).toBe(true);
    expect(updatedNodes.find((node) => node.id === 'gateway')?.data.emphasized).toBe(true);
    expect(updatedNodes.map((node) => node.position)).toEqual(
      initialNodes!.map((node) => node.position),
    );
  });

  /** Filtering incomplete edges must leave source direction and inferred-evidence styling intact. */
  it('omits dangling edges while preserving direction, order, evidence, and selection styling', () => {
    const graph: Graph = {
      nodes: [resource('client'), resource('gateway', 'gateway')],
      edges: [
        relationship('inferred', 'gateway', 'client', 'inferred'),
        relationship('missing-target', 'client', 'absent'),
        relationship('observed', 'client', 'gateway', 'observed'),
        relationship('missing-source', 'absent', 'gateway'),
      ],
    };
    render(<NetworkGraph graph={graph} selectedEdge="observed" />);
    const edges = renderedGraph().edges!;

    expect(edges.map((edge) => edge.id)).toEqual(['inferred', 'observed']);
    expect(edges[0]).toMatchObject({
      source: 'gateway',
      target: 'client',
      ariaLabel: 'belongs to, inferred evidence',
      style: { stroke: '#a88c5c', strokeDasharray: '5 5' },
    });
    expect(edges[1]).toMatchObject({
      source: 'client',
      target: 'gateway',
      selected: true,
      ariaLabel: 'belongs to, observed evidence',
      style: { stroke: '#8ebbff', strokeWidth: 2.5 },
    });
  });
});
