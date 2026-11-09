import { useMemo, useState } from 'react';
import { ArrowRight, ExternalLink, Network, RefreshCw, Shield } from 'lucide-react';
import { dateTime, label, relativeTime, stringify, useApi } from '../api';
import type { Resource } from '../types';
import {
  Badge,
  Card,
  Empty,
  ErrorState,
  EvidenceBadge,
  Loading,
  Modal,
  PageHeader,
  SearchInput,
  kindIcon,
} from '../components/ui';

/**
 * Presents authorized inventory, configured policies, or a member's assigned devices.
 * Member data comes from the scoped devices endpoint, not a client-filtered full
 * inventory. Historical resources keep their missing-snapshot status visible.
 */
export default function Resources({
  member = false,
  policies = false,
}: {
  member?: boolean;
  policies?: boolean;
}) {
  const result = useApi<Resource[]>(member ? '/devices' : '/resources');
  const [search, setSearch] = useState('');
  const [kind, setKind] = useState('all');
  const [selected, setSelected] = useState<Resource | null>(null);
  /** Applies display filters only within the resource set already authorized by the API. */
  const data = useMemo(
    () =>
      (result.data || []).filter(
        (r) =>
          (!policies || r.kind === 'policy') &&
          (kind === 'all' || r.kind === kind) &&
          `${r.name} ${r.kind} ${r.provider} ${r.classification} ${JSON.stringify(r.attributes)}`
            .toLowerCase()
            .includes(search.toLowerCase()),
      ),
    [result.data, policies, kind, search],
  );
  const kinds = [...new Set(result.data?.map((r) => r.kind) || [])].sort();
  return (
    <>
      <PageHeader
        eyebrow={member ? 'Member portal' : 'Infrastructure'}
        title={member ? 'My devices' : policies ? 'Policies' : 'Infrastructure'}
        description={
          member
            ? 'Devices your administrator has associated with your account.'
            : policies
              ? 'Source policy configuration, with its provenance intact.'
              : 'The resources behind your network, collected into one consistent view.'
        }
        actions={
          <button className="button secondary" onClick={result.reload}>
            <RefreshCw size={15} />
            Refresh
          </button>
        }
      />
      <Card>
        <div className="table-toolbar">
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder={policies ? 'Search policies…' : 'Search resources…'}
          />
          {!policies && !member && (
            <select
              aria-label="Filter resource kind"
              value={kind}
              onChange={(e) => setKind(e.target.value)}
            >
              <option value="all">All resource types</option>
              {kinds.map((k) => (
                <option key={k} value={k}>
                  {label(k)}
                </option>
              ))}
            </select>
          )}
          <span className="tiny muted">
            {data.length} {policies ? 'policies' : 'resources'}
          </span>
        </div>
        {result.loading ? (
          <Loading />
        ) : result.error ? (
          <ErrorState message={result.error} retry={result.reload} />
        ) : !data.length ? (
          <Empty
            icon={policies ? Shield : Network}
            title={
              search
                ? 'No matching resources'
                : member
                  ? 'No devices assigned yet'
                  : 'No resources collected'
            }
            text={
              member
                ? 'Ask your administrator to associate your personal devices with your account.'
                : 'Try a different filter, or collect a source snapshot from Integrations.'
            }
          />
        ) : (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Resource</th>
                  <th>{member ? 'Classification' : 'Provider'}</th>
                  <th>Evidence</th>
                  <th>Collected</th>
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.map((resource) => {
                  const Icon = kindIcon(resource.kind);
                  return (
                    <tr key={resource.id}>
                      <td>
                        <button className="resource-cell" onClick={() => setSelected(resource)}>
                          <span className="icon-tile">
                            <Icon size={18} />
                          </span>
                          <span>
                            <strong>{resource.name}</strong>
                            <small>{label(resource.kind)}</small>
                            {resource.attributes.missing_from_latest_snapshot === true && (
                              <span className="historical-label">Missing from latest snapshot</span>
                            )}
                          </span>
                        </button>
                      </td>
                      <td>{label(member ? resource.classification : resource.provider)}</td>
                      <td>
                        <EvidenceBadge kind={resource.evidence_kind} />
                      </td>
                      <td title={dateTime(resource.observed_at)} className="muted">
                        {relativeTime(resource.observed_at)}
                      </td>
                      <td>
                        {!member ? (
                          <a
                            className="icon-button"
                            href={`#/explorer?focus=${encodeURIComponent(resource.id)}`}
                            aria-label={`Explore ${resource.name}`}
                          >
                            <ArrowRight size={17} />
                          </a>
                        ) : (
                          <Badge>{label(resource.classification)}</Badge>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {selected && (
        <Modal title={selected.name} onClose={() => setSelected(null)}>
          <div className="modal-body">
            <div className="button-row">
              <Badge>{label(selected.kind)}</Badge>
              <EvidenceBadge kind={selected.evidence_kind} />
              {selected.attributes.missing_from_latest_snapshot === true && (
                <Badge tone="amber">Historical · missing from latest snapshot</Badge>
              )}
            </div>
            <dl className="details-list">
              <div>
                <dt>Provider</dt>
                <dd>{label(selected.provider)}</dd>
              </div>
              <div>
                <dt>Classification</dt>
                <dd>{label(selected.classification)}</dd>
              </div>
              <div>
                <dt>Collected</dt>
                <dd>{dateTime(selected.observed_at)}</dd>
              </div>
              {Object.entries(selected.attributes).map(([key, value]) => (
                <div key={key}>
                  <dt>{label(key)}</dt>
                  <dd>{stringify(value)}</dd>
                </div>
              ))}
            </dl>
            {!member && (
              <a
                className="button primary full"
                href={`#/explorer?focus=${encodeURIComponent(selected.id)}`}
                onClick={() => setSelected(null)}
              >
                Explore relationships
                <ExternalLink size={15} />
              </a>
            )}
          </div>
        </Modal>
      )}
    </>
  );
}
