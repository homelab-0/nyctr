import { useEffect, useMemo, useRef, useState } from 'react';
import { X } from 'lucide-react';
import { BANDS, UNDRAWN, layoutMap, type MapView } from '../lib/map-layout';
import type { Graph, Resource } from '../types';
import { SourceTag, kindIcon, sourceOf } from './ui';

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
/** A device a guest sign-in was taken away from: shown as cut off wherever it appears. */
const cutOff = (resource?: Resource) =>
  (resource?.attributes.guest as { authorized?: boolean } | undefined)?.authorized === false;

/**
 * Draws the network as a grid: a column per network, a row per layer. Colour names the
 * source, line style names the evidence, and a red mark shows where a finding or a cut-off
 * sits. Every node is a button, so the map works from the keyboard.
 *
 * A cell draws only a few cards. The rest sit in a box that opens a list beside the map,
 * where each one is picked exactly like a card. Which list is open is kept only while this
 * screen is: it is not stored and not put in the address.
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
  const list = useRef<HTMLElement>(null);
  const [opened, setOpened] = useState<string | null>(null);
  // The box that holds the selection when it is not drawn as a card.
  const holder = selected ? layout.holder.get(selected) : undefined;
  // A selection that is not drawn opens the list that holds it, wherever it was picked. Done
  // while drawing, not after, so the list is in place before anything is scrolled into sight.
  const follow = holder ? `${holder} ${selected}` : null;
  const [followed, setFollowed] = useState<string | null>(null);
  if (follow !== followed) {
    setFollowed(follow);
    if (holder) setOpened(holder);
  }
  const open = layout.nodes.find((item) => item.id === opened && item.held);
  const near = useMemo(() => {
    // Something this view does not show dims nothing: there is nothing to set it against.
    if (!selected || !(holder || layout.nodes.some((item) => item.id === selected))) return null;
    const ids = new Set<string>();
    // An item in a box lights the box, so what the selection is linked to can still be found.
    const light = (id: string) => ids.add(id).add(layout.holder.get(id) ?? id);
    light(selected);
    for (const edge of graph.edges) {
      if (UNDRAWN.has(edge.kind)) continue;
      if (edge.source === selected) light(edge.target);
      if (edge.target === selected) light(edge.source);
    }
    return ids;
  }, [selected, holder, layout, graph]);
  // Opening a list moves the keyboard to it, and the selected row is kept in sight.
  useEffect(() => {
    list.current?.focus({ preventScroll: true });
  }, [open?.id]);
  useEffect(() => {
    list.current?.querySelector('[aria-pressed="true"]')?.scrollIntoView?.({ block: 'nearest' });
  }, [open?.id, selected]);
  const show = (box: string) => {
    // A selection held in another box would be left with its list shut, so it is cleared.
    if (holder && holder !== box) onSelect(null);
    setOpened(box);
  };
  const close = () => {
    scroller.current?.querySelector<SVGGElement>('[aria-expanded="true"]')?.focus();
    // Closing the list that shows the selection clears it: nothing stays selected unseen.
    if (holder === opened) onSelect(null);
    setOpened(null);
  };
  useEffect(() => {
    const node = layout.nodes.find((item) => item.id === (holder ?? selected));
    const box = scroller.current;
    if (!node || !box?.scrollTo) return;
    box.scrollTo({
      left: Math.max(0, (node.x + node.w / 2) * zoom - box.clientWidth / 2),
      top: Math.max(0, (node.y + node.h / 2) * zoom - box.clientHeight / 2),
      behavior: 'smooth',
    });
  }, [selected, holder, layout, zoom]);
  const act = (run: () => void) => ({
    role: 'button',
    tabIndex: 0,
    onClick: (event: React.MouseEvent) => {
      event.stopPropagation();
      run();
    },
    onKeyDown: (event: React.KeyboardEvent) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        run();
      }
    },
  });
  const map = (
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
              className={`edge ${edge.evidence} ${on ? 'on' : near ? 'dim' : ''}`}
              d={edge.path}
            >
              <title>{`${edge.kind.replace(/_/g, ' ')} (${edge.evidence})${edge.basis ? `: ${edge.basis}` : ''}`}</title>
            </path>
          );
        })}
        {layout.nodes.map((node) => {
          const Icon = kindIcon(node.kind);
          const source = sourceOf(node.provider);
          const off = cutOff(node.resource);
          const dim = near !== null && !near.has(node.id);
          if (node.held)
            return (
              <g
                key={node.id}
                className={`node more ${holder === node.id ? 'sel' : ''} ${dim ? 'dim' : ''}`}
                transform={`translate(${node.x},${node.y})`}
                aria-expanded={opened === node.id}
                aria-controls={opened === node.id ? 'map-list' : undefined}
                aria-label={node.name}
                {...act(() => (opened === node.id ? close() : show(node.id)))}
              >
                <rect className="box" width={node.w} height={node.h} rx={9} />
                <text className="name" x={node.w / 2} y={19} textAnchor="middle">
                  {node.held.length} more
                </text>
                <text className="sub" x={node.w / 2} y={34} textAnchor="middle">
                  {opened === node.id ? 'Hide the list' : 'Show them all'}
                </text>
              </g>
            );
          return (
            <g
              key={node.id}
              className={`node ${source.tone} ${selected === node.id ? 'sel' : ''} ${dim ? 'dim' : ''} ${off ? 'off' : ''} ${node.evidence}`}
              transform={`translate(${node.x},${node.y})`}
              aria-pressed={selected === node.id}
              aria-label={`${node.name}, ${KIND[node.kind] || node.kind}, from ${source.name}${pinned.has(node.id) ? ', has a finding' : ''}`}
              {...act(() => onSelect(node.id))}
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
  return (
    <>
      {map}
      {open && (
        <aside
          className="map-list"
          id="map-list"
          ref={list}
          tabIndex={-1}
          aria-label={open.name}
          onKeyDown={(event) => event.key === 'Escape' && close()}
        >
          <header>
            <div>
              <h2>{open.name}</h2>
              <p className="aside">
                Each square on the Map has room for a few cards: gateways and networks first, then
                by name. These are the ones that did not fit, in the same order.
              </p>
            </div>
            <button className="icon-button" aria-label="Close the list" onClick={close}>
              <X size={17} />
            </button>
          </header>
          <div className="rows boxed">
            {open.held!.map((item) => (
              <button
                className={`row ${selected === item.id ? 'on' : ''}`}
                key={item.id}
                aria-pressed={selected === item.id}
                onClick={() => onSelect(item.id)}
              >
                <SourceTag provider={item.provider} />
                <span>
                  <span className="t">{item.name}</span>
                  <span className="d">
                    {cutOff(item) ? 'Cut off' : KIND[item.kind] || item.kind}
                    {pinned.has(item.id) ? ', has a finding' : ''}
                  </span>
                </span>
                {(pinned.has(item.id) || cutOff(item)) && <i className="dot red" />}
              </button>
            ))}
          </div>
        </aside>
      )}
    </>
  );
}
