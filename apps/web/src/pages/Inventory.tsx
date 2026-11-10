import { useMemo, useState } from 'react';
import { label, useApi } from '../api';
import {
  Empty,
  ErrorState,
  Evidence,
  Loading,
  Panel,
  SearchInput,
  Seg,
  SourceTag,
  kindIcon,
} from '../components/ui';
import { ago, useNow } from '../lib/format';
import type { Person, Resource } from '../types';

const GROUPS = {
  all: { name: 'Everything', kinds: null },
  devices: { name: 'Devices', kinds: ['client'] },
  gear: { name: 'Network gear', kinds: ['gateway', 'switch', 'access_point'] },
  networks: { name: 'Networks', kinds: ['network'] },
  compute: { name: 'Hosts and workloads', kinds: ['host', 'bridge', 'workload'] },
  rules: { name: 'Rules', kinds: ['policy', 'dns_profile'] },
} as const;
type Group = keyof typeof GROUPS;

/** A short, source-specific detail worth a column: an address, VLAN, model or firewall state. */
function detail(row: Resource) {
  const a = row.attributes;
  if (row.kind === 'network') return a.vlanId !== undefined ? `VLAN ${a.vlanId}` : '';
  if (row.kind === 'workload')
    return `${a.type || 'guest'} ${a.vmid ?? ''} · firewall ${a.firewall_enabled === false ? 'off' : a.firewall_enabled === true ? 'on' : 'unknown'}`;
  if (row.kind === 'client' && a.access_type === 'GUEST') return 'Guest Wi-Fi';
  return String(a.ipAddress || a.model || a.cidr || a.section || '');
}

/** Everything your sources reported, in one searchable list. Each row opens on the map. */
export default function Inventory({ params }: { params: URLSearchParams }) {
  const resources = useApi<Resource[]>('/resources');
  const people = useApi<Person[]>('/users');
  const [group, setGroup] = useState<Group>(
    (params.get('show') as Group) in GROUPS ? (params.get('show') as Group) : 'all',
  );
  const [text, setText] = useState('');
  const now = useNow(60000);
  const all = useMemo(
    () => (resources.data || []).filter((row) => row.kind !== 'domain' && row.kind !== 'site'),
    [resources.data],
  );
  const rows = useMemo(() => {
    const kinds = GROUPS[group].kinds as readonly string[] | null;
    const needle = text.trim().toLowerCase();
    return all.filter(
      (row) =>
        (!kinds || kinds.includes(row.kind)) &&
        (!needle ||
          row.name.toLowerCase().includes(needle) ||
          JSON.stringify(row.attributes).toLowerCase().includes(needle)),
    );
  }, [all, group, text]);
  const names = new Map((people.data || []).map((person) => [person.id, person.name]));
  if (resources.loading) return <Loading text="Loading inventory…" />;
  if (resources.error) return <ErrorState message={resources.error} retry={resources.reload} />;
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="display d2">Inventory</h1>
          <p className="lede">Everything your sources reported. Pick a row to see it on the map.</p>
        </div>
      </header>
      <div className="bar">
        <Seg
          label="Kind"
          value={group}
          onChange={setGroup}
          options={(Object.keys(GROUPS) as Group[]).map((id) => ({
            id,
            name: GROUPS[id].name,
            count: all.filter(
              (row) =>
                !GROUPS[id].kinds || (GROUPS[id].kinds as readonly string[]).includes(row.kind),
            ).length,
          }))}
        />
        <SearchInput value={text} onChange={setText} placeholder="Find by name, address or model" />
      </div>
      {rows.length === 0 ? (
        <Empty title="Nothing matches" text="Clear the search or pick another kind." />
      ) : (
        <Panel flush>
          <div className="tblwrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Kind</th>
                  <th>Source</th>
                  <th>Detail</th>
                  <th>Belongs to</th>
                  <th>Evidence</th>
                  <th>Seen</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => {
                  const Icon = kindIcon(row.kind);
                  const missing = Boolean(row.attributes.missing_from_latest_snapshot);
                  return (
                    <tr
                      key={row.id}
                      className="click"
                      onClick={() =>
                        (window.location.hash = `/map?focus=${encodeURIComponent(row.id)}`)
                      }
                    >
                      <th>
                        <a
                          className="srcn rowlink"
                          href={`#/map?focus=${encodeURIComponent(row.id)}`}
                        >
                          <Icon size={15} /> {row.name}
                        </a>
                      </th>
                      <td>{label(row.kind)}</td>
                      <td>
                        <SourceTag provider={row.provider} named />
                      </td>
                      <td className="muted">{detail(row)}</td>
                      <td>
                        {row.kind !== 'client'
                          ? ''
                          : row.classification === 'personal'
                            ? names.get(row.owner_id || '') || 'One person'
                            : label(row.classification)}
                      </td>
                      <td>
                        <Evidence kind={row.evidence_kind} plain />
                      </td>
                      <td className="nowrap muted">
                        {missing ? (
                          <span className="tag yellow">Missing from last collection</span>
                        ) : (
                          ago(row.observed_at, now)
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}
