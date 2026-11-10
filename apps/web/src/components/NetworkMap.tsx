import { useEffect, useMemo, useRef } from 'react';
import { BANDS, layoutMap, type MapView } from '../lib/map-layout';
import type { Graph } from '../types';
import { kindIcon, sourceOf } from './ui';

const short = (text: string, max = 20) => (text.length > max ? `${text.slice(0, max - 1)}…` : text);
const KIND: Record<string, string> = {
  access_point: 'Access point',
  dns_profile: 'DNS profile',
  client: 'Device',
  policy: 'Rule',
  workload: 'Workload',
  host: 'Host',
  bridge: 'Virtual switch',
  gateway: 'Gateway',
  switch: 'Switch',
  network: 'Network',
};

/**
 * Draws the network as a grid: a column per network, a row per layer. Colour names the
 * source, line style names the evidence, and a red mark shows where a finding or a cut-off
 * sits. Every node is a button, so the map works from the keyboard.
 */
export default function NetworkMap({
  graph,
  view,
  zoom,
  selected,
  onSelect,
  pinned,
}: {
  graph: Graph;
  view: MapView;
  zoom: number;
  selected: string | null;
  onSelect: (id: string | null) => void;
  pinned: Set<string>;
}) {
  const layout = useMemo(() => layoutMap(graph, view), [graph, view]);
  const scroller = useRef<HTMLDivElement>(null);
  const near = useMemo(() => {
    if (!selected) return null;
    const ids = new Set([selected]);
    for (const edge of layout.edges) {
      if (edge.source === selected) ids.add(edge.target);
      if (edge.target === selected) ids.add(edge.source);
    }
    return ids;
  }, [selected, layout]);
  useEffect(() => {
    const node = layout.nodes.find((item) => item.id === selected);
    const box = scroller.current;
    if (!node || !box?.scrollTo) return;
    box.scrollTo({
      left: Math.max(0, (node.x + node.w / 2) * zoom - box.clientWidth / 2),
      top: Math.max(0, (node.y + node.h / 2) * zoom - box.clientHeight / 2),
      behavior: 'smooth',
    });
  }, [selected, layout, zoom]);
  return (
    <div className="map-scroll" ref={scroller}>
      <svg
        className="map"
        width={layout.width * zoom}
        height={layout.height * zoom}
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        role="group"
        aria-label="Network map"
        onClick={() => onSelect(null)}
      >
        {layout.lanes.map((lane, index) => (
          <g key={lane.id}>
            <rect
              className={`lane ${index % 2 ? 'alt' : ''}`}
              x={lane.x}
              y={0}
              width={lane.w}
              height={layout.height}
            />
            <text className="lane-name" x={lane.x + 14} y={24}>
              {short(lane.name, 22)}
            </text>
            <text className="lane-sub" x={lane.x + 14} y={41}>
              {lane.sub}
            </text>
          </g>
        ))}
        {layout.bands.map((band) => (
          <g key={band.id}>
            <line className="band-line" x1={0} x2={layout.width} y1={band.y} y2={band.y} />
            <text className="band-name" x={14} y={band.y + 26}>
              {BANDS.find((item) => item.id === band.id)?.name}
            </text>
          </g>
        ))}
        {layout.edges.map((edge) => {
          const on = selected !== null && (edge.source === selected || edge.target === selected);
          return (
            <path
              key={edge.id}
              className={`edge ${edge.evidence} ${on ? 'on' : selected ? 'dim' : ''}`}
              d={edge.path}
            >
              <title>{`${edge.kind.replace(/_/g, ' ')} (${edge.evidence})${edge.basis ? `: ${edge.basis}` : ''}`}</title>
            </path>
          );
        })}
        {layout.nodes.map((node) => {
          const Icon = kindIcon(node.kind);
          const source = sourceOf(node.provider);
          const guest = node.resource?.attributes.guest as { authorized?: boolean } | undefined;
          const off = guest?.authorized === false;
          const dim = near !== null && !near.has(node.id);
          if (node.more)
            return (
              <g key={node.id} className="node more" transform={`translate(${node.x},${node.y})`}>
                <rect width={node.w} height={node.h} rx={9} />
                <text x={node.w / 2} y={27} textAnchor="middle">
                  {node.name}
                </text>
              </g>
            );
          return (
            <g
              key={node.id}
              className={`node ${source.tone} ${selected === node.id ? 'sel' : ''} ${dim ? 'dim' : ''} ${off ? 'off' : ''} ${node.evidence}`}
              transform={`translate(${node.x},${node.y})`}
              role="button"
              tabIndex={0}
              aria-pressed={selected === node.id}
              aria-label={`${node.name}, ${KIND[node.kind] || node.kind}, from ${source.name}${pinned.has(node.id) ? ', has a finding' : ''}`}
              onClick={(event) => {
                event.stopPropagation();
                onSelect(node.id);
              }}
              onKeyDown={(event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                  event.preventDefault();
                  onSelect(node.id);
                }
              }}
            >
              <rect className="box" width={node.w} height={node.h} rx={9} />
              <rect className="stripe" x={0} y={8} width={3} height={node.h - 16} rx={1.5} />
              <Icon x={13} y={14} size={16} strokeWidth={1.8} />
              <text className="name" x={37} y={19}>
                {short(node.name)}
              </text>
              <text className="sub" x={37} y={34}>
                {off ? 'Cut off' : KIND[node.kind] || node.kind}
              </text>
              {(pinned.has(node.id) || off) && (
                <circle className="pin" cx={node.w - 12} cy={12} r={4.5} />
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
}
