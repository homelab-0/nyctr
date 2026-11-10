import { useState, type FormEvent } from 'react';
import {
  ArrowRight,
  Database,
  Globe2,
  Layers2,
  LockKeyhole,
  Network,
  Plus,
  RefreshCw,
  ScanLine,
  Server,
  Settings2,
  Workflow,
} from 'lucide-react';
import { label, post, relativeTime, useApi } from '../api';
import { useAuth } from '../auth';
import type { Integration, Rules } from '../types';
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
import {
  IntegrationDiagnostics,
  useIntegrationDiagnostics,
} from '../components/IntegrationDiagnostics';

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
    description:
      'Experimental. Nodes, bridges, guests, their network cards and the firewall on/off switches.',
    available: true,
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
        : selected === 'proxmox'
          ? { base_url: endpoint.trim() }
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
    <Modal title="Connect a source" onClose={onClose}>
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
            <option value="proxmox">Proxmox VE (experimental)</option>
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
        ) : selected === 'proxmox' ? (
          <Field
            label="Proxmox address"
            hint="Use HTTPS with a certificate the server trusts. The hostname must be in NYCTR_CONNECTOR_HOSTS. The secret is an API token in the form user@realm!name=value; give it a read-only role such as PVEAuditor."
          >
            <input
              required
              type="url"
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder="https://pve.example:8006"
            />
          </Field>
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
          Collection only reads. Saving records the connection; collect a snapshot afterwards.
          Whether Nyctr may change this source is a separate server setting.
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
export default function Integrations({ writes }: { writes?: Rules['writes'] } = {}) {
  const result = useApi<Integration[]>('/integrations');
  const allowed = [
    writes?.nextdns === 'enabled' && 'NextDNS',
    writes?.unifi_network === 'enabled' && 'UniFi',
  ].filter(Boolean);
  const [add, setAdd] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const { user } = useAuth();
  const admin = user?.role === 'admin';
  const demo = user?.mode === 'demo';
  const diagnostics = useIntegrationDiagnostics(admin && !demo);
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
        title="Sources"
        description="Where Nyctr reads from, what each one can tell it, and whether Nyctr may change it."
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
          <strong>
            {demo
              ? 'Demo: every change is simulated'
              : allowed.length
                ? `Nyctr may change ${allowed.join(' and ')}`
                : 'Read-only for every source'}
          </strong>
          <p>
            Collection never changes a source, and credentials stay on the server. Nyctr can add a
            NextDNS allowlist entry, issue UniFi guest passes and cut a guest off only when an
            operator names that source in NYCTR_PROVIDER_WRITES.
          </p>
        </div>
        <Badge tone="blue">3 adapters</Badge>
      </div>
      <InlineError message={error} />
      {success && <Success>{success}</Success>}
      {demo && (
        <Notice>
          Demo sources use seeded snapshots. Live connection diagnostics and collection are
          disabled; deploy in live mode to check a saved source.
        </Notice>
      )}
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
                <span className="integration-capability-label">
                  Adapter capabilities · not connection verification
                </span>
                <div className="capabilities">
                  {integration.capabilities?.map((c) => (
                    <span key={c}>
                      <Layers2 size={12} />
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
                    {demo
                      ? 'Changes simulated'
                      : writes?.[integration.provider as 'nextdns' | 'unifi_network'] === 'enabled'
                        ? 'Nyctr may change it'
                        : 'Read only'}
                  </span>
                </div>
                <div className="integration-actions">
                  {admin && (
                    <button
                      className="button secondary small"
                      disabled={
                        pending !== null ||
                        diagnostics.state?.pending === true ||
                        demo ||
                        !item?.available
                      }
                      onClick={() => void diagnostics.run(integration)}
                      title={
                        demo
                          ? 'Demo sources use seeded snapshots; live diagnostics are disabled.'
                          : !item?.available
                            ? 'Connection diagnostics are not implemented for this provider.'
                            : 'Verify supported reads without importing a snapshot'
                      }
                    >
                      <ScanLine size={14} />
                      Run diagnostics
                    </button>
                  )}
                  <button
                    className="button secondary small"
                    disabled={
                      pending !== null ||
                      diagnostics.state?.pending === true ||
                      demo ||
                      integration.provider === 'demo'
                    }
                    onClick={() => void sync(integration)}
                    title={
                      demo
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
            text="Choose UniFi Network, NextDNS or Proxmox VE below to begin collecting."
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
            setSuccess(
              'Connection saved. Run diagnostics to verify supported reads, then collect a snapshot to import evidence.',
            );
          }}
        />
      )}
      {diagnostics.state && (
        <IntegrationDiagnostics
          state={diagnostics.state}
          onClose={diagnostics.close}
          onRun={() => void diagnostics.run(diagnostics.state!.integration)}
        />
      )}
    </>
  );
}
