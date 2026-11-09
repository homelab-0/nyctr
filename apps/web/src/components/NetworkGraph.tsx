import { memo, useMemo } from 'react';
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type { Graph, Resource } from '../types';
import { label } from '../api';
import { kindIcon } from './ui';
import { indexGraph, layoutGraph } from './graph-layout';

type ResourceNodeData = { resource: Resource; emphasized: boolean; [key: string]: unknown };
type ResourceFlowNode = Node<ResourceNodeData, 'resource'>;
/** Keeps evidence provenance and missing-snapshot status visible on each selectable resource. */
const ResourceNode = memo(function ResourceNode({ data, selected }: NodeProps<ResourceFlowNode>) {
  const resource = data.resource;
  const Icon = kindIcon(resource.kind);
  const historical = resource.attributes.missing_from_latest_snapshot === true;
  return (
    <div
      className={`resource-node ${selected ? 'selected' : ''} ${data.emphasized ? 'emphasized' : ''} ${historical ? 'historical' : ''}`}
    >
      <Handle type="target" position={Position.Left} />
      <span className={`node-icon ${resource.kind}`}>
        <Icon size={21} strokeWidth={1.7} />
      </span>
      <div className="node-copy">
        <small>{label(resource.kind)}</small>
        <strong title={resource.name}>{resource.name}</strong>
        <span>
          {historical ? 'Historical · absent from latest snapshot' : label(resource.provider)}
        </span>
      </div>
      <i
        className={`evidence-dot ${resource.evidence_kind}`}
        title={`${label(resource.evidence_kind)} evidence`}
      />
      <Handle type="source" position={Position.Right} />
    </div>
  );
});
const nodeTypes = { resource: ResourceNode };
const EMPTY_EMPHASIZED_IDS: readonly string[] = [];

/**
 * Renders an evidence-aware graph with canvas panning, selection, and focus drill-down.
 * Selection updates do not recompute topology or layout. Missing endpoints are
 * omitted from rendering; inferred relationships retain their distinct styling.
 */
export function NetworkGraph({
  graph,
  selectedId,
  selectedEdge,
  onSelect,
  onSelectEdge,
  onFocus,
  focus,
  emphasizedIds = EMPTY_EMPHASIZED_IDS,
  compact = false,
}: {
  graph: Graph;
  selectedId?: string | null;
  selectedEdge?: string | null;
  onSelect?: (resource: Resource) => void;
  onSelectEdge?: (id: string) => void;
  onFocus?: (resource: Resource) => void;
  focus?: string;
  emphasizedIds?: readonly string[];
  compact?: boolean;
}) {
  const index = useMemo(() => indexGraph(graph), [graph]);
  const positions = useMemo(() => layoutGraph(graph, focus, index), [graph, focus, index]);
  const emphasized = useMemo(() => new Set(emphasizedIds), [emphasizedIds]);
  const nodes: ResourceFlowNode[] = useMemo(() => {
    return graph.nodes.map((resource) => ({
      id: resource.id,
      type: 'resource',
      position: positions.get(resource.id)!,
      data: { resource, emphasized: emphasized.has(resource.id) },
      selected: selectedId === resource.id,
      draggable: false,
      connectable: false,
      ariaLabel: `${resource.name}, ${label(resource.kind)}, ${label(resource.evidence_kind)} evidence`,
    }));
  }, [graph.nodes, positions, selectedId, emphasized]);
  const edges: Edge[] = useMemo(
    () =>
      graph.edges
        .filter((edge) => index.nodeIds.has(edge.source) && index.nodeIds.has(edge.target))
        .map((edge) => ({
          id: edge.id,
          source: edge.source,
          target: edge.target,
          type: 'smoothstep',
          label: edge.kind.replace(/_/g, ' '),
          selected: edge.id === selectedEdge,
          focusable: true,
          ariaLabel: `${edge.kind.replace(/_/g, ' ')}, ${edge.evidence_kind} evidence`,
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: edge.id === selectedEdge ? '#8ebbff' : '#4d719d',
            width: 15,
            height: 15,
          },
          style: {
            stroke:
              edge.id === selectedEdge
                ? '#8ebbff'
                : edge.evidence_kind === 'inferred'
                  ? '#a88c5c'
                  : '#456a99',
            strokeWidth: edge.id === selectedEdge ? 2.5 : 1.5,
            strokeDasharray: edge.evidence_kind === 'inferred' ? '5 5' : undefined,
          },
          labelStyle: { fill: '#b4c0cf', fontSize: 10 },
          labelBgStyle: { fill: '#14181d', fillOpacity: 0.96 },
          labelBgPadding: [7, 4],
          labelBgBorderRadius: 4,
        })),
    [graph.edges, index, selectedEdge],
  );
  return (
    <div
      className={`graph-stage ${compact ? 'compact' : ''}`}
      aria-label="Interactive network relationships"
    >
      <ReactFlow<ResourceFlowNode>
        key={`${focus || 'all'}-${graph.nodes.map((n) => n.id).join(',')}`}
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={(_, node) => onSelect?.(node.data.resource)}
        onNodeDoubleClick={(_, node) => onFocus?.(node.data.resource)}
        onEdgeClick={(_, edge) => onSelectEdge?.(edge.id)}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        panOnDrag
        selectionOnDrag={false}
        zoomOnDoubleClick={false}
        minZoom={0.2}
        maxZoom={1.7}
        fitView
        fitViewOptions={{ padding: compact ? 0.17 : 0.22, maxZoom: 1 }}
        colorMode="dark"
        proOptions={{ hideAttribution: false }}
      >
        <Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#303a47" />
        <Controls showInteractive={false} position="bottom-left" />
        {!compact && (
          <MiniMap
            pannable
            zoomable
            nodeColor="#3675bd"
            maskColor="#0c101acc"
            position="bottom-right"
          />
        )}
      </ReactFlow>
    </div>
  );
}
