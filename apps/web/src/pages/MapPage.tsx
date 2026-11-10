import { useEffect, useMemo, useState } from 'react';
import { Minus, Plus, X } from 'lucide-react';
import { label, useApi } from '../api';
import NetworkMap from '../components/NetworkMap';
import { Empty, ErrorState, Evidence, KV, Loading, Seg, SourceTag } from '../components/ui';
import type { MapView } from '../lib/map-layout';
import type { Finding, Graph, Resource } from '../types';

/** Attributes worth showing in the inspector, with plain names. Everything else stays in Queries. */
const FACTS: [string, string][] = [
  ['ipAddress', 'Address'],
  ['macAddress', 'Hardware address'],
  ['vlanId', 'VLAN'],
  ['subnet', 'Subnet'],
  ['model', 'Model'],
  ['type', 'Type'],
  ['status', 'Status'],
  ['vmid', 'ID in Proxmox'],
  ['node', 'Runs on'],
  ['cidr', 'Address'],
  ['action', 'Action'],
  ['port', 'Port'],
];

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
  if (a.access_type === 'GUEST')
    rows.push(['Guest Wi-Fi', a.guest_authorized ? 'Has access' : 'No access']);
  return rows;
}

/**
 * The map and its inspector. Views narrow the map to one source so an administrator can
 * start on the UniFi side, pick a host, and follow it into Proxmox.
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
  const count = (provider: string) =>
    data.nodes.filter((item) => item.provider === provider).length;
  return (
    <div className="page map-page">
      <div className="bar">
        <Seg
          label="Map view"
          value={view}
          onChange={setView}
          options={[
            { id: 'all', name: 'Everything' },
            { id: 'unifi_network', name: 'UniFi side', count: count('unifi_network') },
            { id: 'proxmox', name: 'Proxmox side', count: count('proxmox') },
            { id: 'nextdns', name: 'DNS side', count: count('nextdns') },
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
              <KV items={facts(node)} />
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
                    setView(byId.get(other)?.provider === 'proxmox' ? 'proxmox' : 'unifi_network');
                    setSelected(other);
                  }}
                >
                  {node.provider === 'proxmox'
                    ? 'Show it on the UniFi side'
                    : 'Follow it into Proxmox'}
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
