import { useState, type FormEvent } from 'react';
import {
  ArrowRight,
  Check,
  Database,
  Globe2,
  LockKeyhole,
  Network,
  Plus,
  RefreshCw,
  Server,
  Settings2,
  Workflow,
} from 'lucide-react';
import { label, post, relativeTime, useApi } from '../api';
import { useAuth } from '../auth';
import type { Integration } from '../types';
import {
  Badge,
  Card,
  Empty,
  ErrorState,
  Field,
  InlineError,
  Loading,
  Modal,
  Notice,
  PageHeader,
  Status,
  Success,
  type IconComponent,
} from '../components/ui';

const catalog: {
  id: string;
  name: string;
  icon: IconComponent;
  description: string;
  available: boolean;
}[] = [
  {
    id: 'unifi_network',
    name: 'UniFi Network',
    icon: Network,
    description: 'Devices, networks, clients, and firewall policy configuration.',
    available: true,
  },
  {
    id: 'nextdns',
    name: 'NextDNS',
    icon: Database,
    description: 'DNS profiles, configuration, and supported block observations.',
    available: true,
  },
  {
    id: 'unifi_fabric',
    name: 'UniFi Fabric',
    icon: Workflow,
    description: 'Site Manager discovery and Fabric capabilities, configured together.',
    available: false,
  },
  {
    id: 'proxmox',
    name: 'Proxmox VE',
    icon: Server,
    description: 'Hosts, guests, bridges, and hypervisor firewall configuration.',
    available: false,
  },
  {
    id: 'aws',
    name: 'AWS networking',
    icon: Globe2,
    description: 'VPCs, routes, security groups, and network access control lists.',
    available: false,
  },
  {
    id: 'azure',
    name: 'Azure networking',
    icon: Globe2,
    description: 'Virtual networks, security groups, routes, and policy context.',
    available: false,
  },
];

/**
 * Collects configuration for implemented read-only providers and a server secret reference.
 * The form never requests the provider key itself; the API validates endpoint and
 * credential-reference restrictions and rejects live connections in demo mode.
 */
function AddIntegration({
  provider,
  onClose,
  onSaved,
}: {
  provider: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { user } = useAuth();
  const [selected, setSelected] = useState(provider);
  const [name, setName] = useState('');
  const [secret, setSecret] = useState('');
  const [endpoint, setEndpoint] = useState('');
  const [site, setSite] = useState('');
  const [profile, setProfile] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const demo = user?.mode === 'demo';
  /** Persists connection metadata, leaving source collection to a separate explicit action. */
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setPending(true);
    const config =
      selected === 'nextdns'
        ? { profile_id: profile.trim(), lookback_hours: 24 }
        : { base_url: endpoint.trim(), ...(site.trim() ? { site_id: site.trim() } : {}) };
    try {
      await post('/integrations', {
        provider: selected,
        name: name.trim(),
        config,
        secret_ref: secret.trim(),
      });
      onSaved();
      onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPending(false);
    }
  };
  return (
    <Modal title="Connect a read-only source" onClose={onClose}>
      <form className="modal-body form-stack" onSubmit={submit}>
        {demo && (
          <Notice tone="amber">
            Live connections are disabled in the demo workspace. Deploy in live mode to configure a
            source.
          </Notice>
        )}
        <Field label="Provider">
          <select value={selected} onChange={(e) => setSelected(e.target.value)}>
            <option value="unifi_network">UniFi Network</option>
            <option value="nextdns">NextDNS</option>
          </select>
        </Field>
        <Field label="Connection name">
          <input
            required
            maxLength={100}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={selected === 'nextdns' ? 'Home DNS' : 'Primary network'}
          />
        </Field>
        {selected === 'unifi_network' ? (
          <>
            <Field
              label="Integration API base URL"
              hint="Use HTTPS. The server administrator must include this hostname in NYCTR_CONNECTOR_HOSTS."
            >
              <input
                required
                type="url"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="https://gateway.example/proxy/network/integration"
              />
            </Field>
            <Field
              label="Site ID (optional)"
              hint="Leave empty to collect supported sites returned by the API."
            >
              <input
                value={site}
                onChange={(e) => setSite(e.target.value)}
                placeholder="Provider site identifier"
              />
            </Field>
          </>
        ) : (
          <Field label="NextDNS profile ID">
            <input
              required
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              placeholder="abc123"
              pattern="[A-Za-z0-9]+"
            />
          </Field>
        )}
        <Field
          label="Credential environment reference"
          hint="The API key stays on the server. Enter the name of its environment variable, not the key itself."
        >
          <input
            required
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="NYCTR_CONNECTOR_SECRET_HOME_DNS"
            pattern="NYCTR_CONNECTOR_SECRET_[A-Z0-9_]+"
            className="mono"
          />
        </Field>
        <Notice>
          Nyctr uses read-only API operations. Connection setup records configuration; collect a
          snapshot after saving.
        </Notice>
        <InlineError message={error} />
        <div className="modal-actions">
          <button className="button secondary" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="button primary" disabled={pending || demo} type="submit">
            {pending ? 'Saving…' : 'Save connection'}
            <ArrowRight size={15} />
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Lists source health and capabilities while keeping planned providers distinct from live adapters. */
export default function Integrations() {
  const result = useApi<Integration[]>('/integrations');
  const [add, setAdd] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const { user } = useAuth();
  /**
   * Requests a read-only snapshot and reloads source health after success or failure.
   * Counts come from the server response; a failed collection is never displayed as success.
   */
  const sync = async (integration: Integration) => {
    setPending(integration.id);
    setError(null);
    setSuccess(null);
    try {
      const response = await post<{
        ok: boolean;
        resource_count: number;
        observation_count: number;
      }>(`/integrations/${encodeURIComponent(integration.id)}/sync`);
      setSuccess(
        `Snapshot collected: ${response.resource_count} resources and ${response.observation_count} observations.`,
      );
      result.reload();
    } catch (e) {
      setError((e as Error).message);
      result.reload();
    } finally {
      setPending(null);
    }
  };
  return (
    <>
      <PageHeader
        eyebrow="Manage workspace"
        title="Integrations"
        description="Connect your sources. Keep their capabilities, evidence, and health in view."
        actions={
          <button className="button primary" onClick={() => setAdd('unifi_network')}>
            <Plus size={16} />
            Add connection
          </button>
        }
      />
      <div className="collection-banner">
        <span className="icon-tile">
          <LockKeyhole size={20} />
        </span>
        <div>
          <strong>Read-only by design</strong>
          <p>
            Credentials stay on the server. Collection imports evidence; it cannot modify source
            policies.
          </p>
        </div>
        <Badge tone="blue">2 live adapters</Badge>
      </div>
      <InlineError message={error} />
      {success && <Success>{success}</Success>}
      <div className="section-heading">
        <h2>Configured connections</h2>
        <span className="tiny muted">{result.data?.length || 0} sources</span>
      </div>
      {result.loading ? (
        <Loading />
      ) : result.error ? (
        <ErrorState message={result.error} retry={result.reload} />
      ) : result.data?.length ? (
        <div className="integration-grid">
          {result.data.map((integration) => {
            const item = catalog.find((c) => c.id === integration.provider);
            const Icon = item?.icon || Database;
            return (
              <Card className="integration-card" key={integration.id}>
                <div className="integration-top">
                  <span className="icon-tile large">
                    <Icon size={24} />
                  </span>
                  <Status value={integration.status} />
                </div>
                <h3>{integration.name}</h3>
                <p>{item?.name || label(integration.provider)}</p>
                <div className="capabilities">
                  {integration.capabilities?.map((c) => (
                    <span key={c}>
                      <Check size={12} />
                      {label(c)}
                    </span>
                  ))}
                </div>
                <div className="integration-meta">
                  <span>Last collected</span>
                  <strong>{relativeTime(integration.last_sync)}</strong>
                </div>
                {integration.last_error && (
                  <div className="inline-error small-text">{integration.last_error}</div>
                )}
                <div className="integration-footer">
                  <span>
                    <LockKeyhole size={12} />
                    Read only
                  </span>
                  <button
                    className="button secondary small"
                    disabled={
                      pending !== null || user?.mode === 'demo' || integration.provider === 'demo'
                    }
                    onClick={() => void sync(integration)}
                    title={
                      user?.mode === 'demo'
                        ? 'Demo sources use seeded snapshots; live collection is disabled.'
                        : 'Read the current source configuration'
                    }
                  >
                    <RefreshCw size={14} className={pending === integration.id ? 'spin' : ''} />
                    {pending === integration.id ? 'Collecting…' : 'Collect snapshot'}
                  </button>
                </div>
              </Card>
            );
          })}
        </div>
      ) : (
        <Card>
          <Empty
            icon={Settings2}
            title="Connect your first source"
            text="Choose UniFi Network or NextDNS below to begin collecting supported evidence."
          />
        </Card>
      )}
      <div className="section-heading">
        <div>
          <h2>Integration catalog</h2>
          <p>One workspace, with provider-specific collection capabilities.</p>
        </div>
      </div>
      <div className="integration-grid catalog-grid">
        {catalog.map((item) => (
          <Card className="integration-card catalog-card" key={item.id}>
            <div className="integration-top">
              <span className="icon-tile">
                <item.icon size={21} />
              </span>
              <Badge tone={item.available ? 'blue' : ''}>
                {item.available ? 'Available' : 'Planned'}
              </Badge>
            </div>
            <h3>{item.name}</h3>
            <p>{item.description}</p>
            <div className="integration-footer">
              <span>
                {item.id === 'unifi_fabric'
                  ? 'Includes Site Manager'
                  : item.available
                    ? 'Read-only collector'
                    : 'Adapter not implemented'}
              </span>
              {item.available && (
                <button className="text-link" onClick={() => setAdd(item.id)}>
                  Set up
                  <ArrowRight size={14} />
                </button>
              )}
            </div>
          </Card>
        ))}
      </div>
      <Notice>
        UniFi firewall event export is a separate collection channel from the Network configuration
        API. Event ingestion and reliable cross-source device attribution are planned; API access
        alone does not provide every firewall block.
      </Notice>
      {add && (
        <AddIntegration
          provider={add}
          onClose={() => setAdd(null)}
          onSaved={() => {
            result.reload();
            setSuccess('Connection saved. Collect a snapshot to import its supported data.');
          }}
        />
      )}
    </>
  );
}
