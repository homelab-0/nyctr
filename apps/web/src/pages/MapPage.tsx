import { useEffect, useMemo, useState } from 'react';
import { Minus, Plus, X } from 'lucide-react';
import { label, useApi } from '../api';
import NetworkMap from '../components/NetworkMap';
import {
  Empty,
  ErrorState,
  Evidence,
  KV,
  Loading,
  Seg,
  SourceTag,
  sourceOf,
} from '../components/ui';
import type { MapView } from '../lib/map-layout';
import type { Finding, Graph, Resource } from '../types';

/** Attributes worth showing in the inspector, with plain names. Everything else stays in Queries. */
const FACTS: [string, string][] = [
  ['ip', 'Address'],
  ['mac', 'Hardware address'],
  ['vlan', 'VLAN'],
  ['subnet', 'Subnet'],
  ['model', 'Model'],
  ['type', 'Type'],
  ['status', 'Status'],
  ['vmid', 'Workload ID'],
  ['node', 'Runs on'],
  ['cidr', 'Address'],
  ['action', 'Action'],
  ['port', 'Port'],
];

/**
 * Why a device is filed as what it is, when Nyctr worked that out instead of the source saying it.
 * The keys are the `kind_basis` values in the integration contract.
 */
const KIND_BASIS: Record<string, string> = {
  gateway_address:
    'Worked out by Nyctr: the source does not list this as a gateway, but its address is the gateway address of a network the source says its gateway runs.',
  outside_network_ranges:
    'Worked out by Nyctr: the source does not say which device is the gateway. This is the only equipment with an address outside every network range, the source reports nothing above it, and other equipment is attached to it.',
};

/** The sentence for a device whose kind is Nyctr's deduction, or nothing when the source named it. */
export function kindBasis(resource: Resource): string | undefined {
  const basis = resource.attributes.kind_basis;
  if (typeof basis !== 'string') return undefined;
  return (
    KIND_BASIS[basis] ?? 'Worked out by Nyctr: the source does not say what kind of device this is.'
  );
}

function facts(resource: Resource): [string, string][] {
  const rows: [string, string][] = [];
  for (const [key, name] of FACTS) {
    const value = resource.attributes[key];
    if (typeof value === 'string' || typeof value === 'number') rows.push([name, String(value)]);
  }
  const a = resource.attributes;
  if (resource.kind === 'workload')
    rows.push([
      'Firewall',
      a.firewall_enabled === false ? 'Off' : a.firewall_enabled === true ? 'On' : 'Unknown',
    ]);
  if (resource.kind === 'network' && Array.isArray(a.subnets) && a.subnets.length)
    rows.push(['Address range', a.subnets.join(', ')]);
  if (Array.isArray(a.nics))
    rows.push([
      'Network cards',
      (a.nics as { bridge?: string; vlan?: number | null; firewall?: boolean }[])
        .map(
          (nic) =>
            `${nic.bridge}${nic.vlan ? `, VLAN ${nic.vlan}` : ''}, firewall ${nic.firewall ? 'on' : 'off'}`,
        )
        .join('; '),
    ]);
  const guest = a.guest as { authorized?: boolean } | undefined;
  if (guest && typeof guest === 'object')
    rows.push(['Guest Wi-Fi', guest.authorized ? 'Has access' : 'No access']);
  return rows;
}

/**
 * The map and its inspector. Views narrow the map to one kind of source, built from whatever
 * sources reported something, so an administrator can start on the network side, pick a host,
 * and follow it into the source that runs it.
 */
export default function MapPage({ params }: { params: URLSearchParams }) {
  const graph = useApi<Graph>('/graph');
  const findings = useApi<Finding[]>('/findings');
  const [view, setView] = useState<MapView>('all');
  const [zoom, setZoom] = useState(1);
  const [selected, setSelected] = useState<string | null>(params.get('focus'));
  useEffect(() => {
    if (params.get('focus')) {
      setSelected(params.get('focus'));
      setView('all');
    }
  }, [params]);
  const open = useMemo(
    () => (findings.data || []).filter((item) => item.status === 'open'),
    [findings.data],
  );
  const pinned = useMemo(() => new Set(open.flatMap((item) => item.resource_ids)), [open]);
  if (graph.loading) return <Loading text="Drawing the map…" />;
  if (graph.error) return <ErrorState message={graph.error} retry={graph.reload} />;
  const data = graph.data!;
  if (data.nodes.length === 0)
    return (
      <Empty
        title="Nothing to draw yet"
        text="Connect a source and collect from it. The map fills in from what it reports."
        action={
          <a className="button primary" href="#/sources">
            Open sources
          </a>
        }
      />
    );
  const byId = new Map(data.nodes.map((node) => [node.id, node]));
  const node = selected ? byId.get(selected) : undefined;
  const links = node
    ? data.edges.filter(
        (edge) => edge.kind !== 'contains' && (edge.source === node.id || edge.target === node.id),
      )
    : [];
  const twin = links.find((edge) => edge.kind === 'same_device');
  const twinProvider =
    (twin && byId.get(twin.source === node?.id ? twin.target : twin.source)?.provider) || '';
  const count = (provider: string) =>
    data.nodes.filter((item) => item.provider === provider).length;
  // One view per kind of source that reported something, in a stable order.
  const kinds = [...new Set(data.nodes.map((item) => item.provider))]
    .filter((kind) => kind && kind !== 'demo')
    .sort((a, b) => sourceOf(a).name.localeCompare(sourceOf(b).name));
  return (
    <div className="page map-page">
      <div className="bar">
        <Seg
          label="Map view"
          value={view}
          onChange={setView}
          options={[
            { id: 'all', name: 'Everything' },
            ...kinds.map((kind) => ({ id: kind, name: sourceOf(kind).name, count: count(kind) })),
          ]}
        />
        <div className="legend">
          <Evidence kind="observed" />
          <Evidence kind="configured" />
          <Evidence kind="inferred" />
          <span className="evw">
            <i className="dot red" /> Finding or cut-off
          </span>
        </div>
        <div className="button-row">
          <button
            className="icon-button"
            aria-label="Zoom out"
            onClick={() => setZoom((z) => Math.max(0.5, +(z - 0.15).toFixed(2)))}
          >
            <Minus size={16} />
          </button>
          <span className="muted tiny" style={{ minWidth: 38, textAlign: 'center' }}>
            {Math.round(zoom * 100)}%
          </span>
          <button
            className="icon-button"
            aria-label="Zoom in"
            onClick={() => setZoom((z) => Math.min(1.6, +(z + 0.15).toFixed(2)))}
          >
            <Plus size={16} />
          </button>
        </div>
      </div>
      <div className="map-frame">
        <NetworkMap
          graph={data}
          view={view}
          zoom={zoom}
          selected={selected}
          onSelect={setSelected}
          pinned={pinned}
        />
        {node && (
          <aside className="inspector" aria-label={`About ${node.name}`}>
            <header>
              <div>
                <h2>{node.name}</h2>
                <span className="aside">
                  {node.kind === 'client' ? 'Device' : label(node.kind)}
                </span>
              </div>
              <button className="icon-button" aria-label="Close" onClick={() => setSelected(null)}>
                <X size={17} />
              </button>
            </header>
            <div className="stack">
              <div className="bar">
                <SourceTag provider={node.provider} named />
                <Evidence kind={node.evidence_kind} />
              </div>
              {open
                .filter((item) => item.resource_ids.includes(node.id))
                .map((item) => (
                  <a
                    className="note red"
                    key={item.id}
                    href={`#/findings?id=${encodeURIComponent(item.id)}`}
                  >
                    <div>
                      <b>{item.title}</b>
                    </div>
                  </a>
                ))}
              {kindBasis(node) && (
                <p className="aside">
                  <i className="ev inferred" /> {kindBasis(node)}
                </p>
              )}
              <KV
                items={[
                  ...facts(node),
                  ...(node.kind === 'client' && !links.some((edge) => edge.kind === 'member_of')
                    ? ([['Network', 'Not reported']] as [string, string][])
                    : []),
                ]}
              />
              {node.attributes.access_type === 'GUEST' && (
                <a
                  className="button secondary small"
                  href={`#/guests?id=${encodeURIComponent(node.id)}`}
                >
                  Open this guest
                </a>
              )}
              {twin && (
                <button
                  className="button secondary small"
                  onClick={() => {
                    const other = twin.source === node.id ? twin.target : twin.source;
                    setView(byId.get(other)?.provider || 'all');
                    setSelected(other);
                  }}
                >
                  Show it in {sourceOf(twinProvider).name}
                </button>
              )}
              {links.length > 0 && (
                <div>
                  <h3>Linked to</h3>
                  <div className="rows boxed">
                    {links.map((edge) => {
                      const other = byId.get(edge.source === node.id ? edge.target : edge.source);
                      if (!other) return null;
                      return (
                        <button className="row" key={edge.id} onClick={() => setSelected(other.id)}>
                          <i className={`ev ${edge.evidence_kind}`} />
                          <span>
                            <span className="t">{other.name}</span>
                            <span className="d">
                              {label(edge.kind)}
                              {typeof edge.attributes.basis === 'string'
                                ? `. ${edge.attributes.basis}`
                                : ''}
                            </span>
                          </span>
                          <SourceTag provider={other.provider} />
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
              <p className="aside">
                A link shows how things are connected or configured. It does not prove traffic can
                flow.
              </p>
            </div>
          </aside>
        )}
      </div>
    </div>
  );
}
