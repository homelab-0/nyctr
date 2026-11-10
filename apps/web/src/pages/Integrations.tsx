import { useState, type FormEvent } from 'react';
import {
  ArrowRight,
  Check,
  Layers2,
  LockKeyhole,
  Minus,
  Plus,
  RefreshCw,
  ScanLine,
  Settings2,
} from 'lucide-react';
import { label, post, relativeTime, useApi } from '../api';
import { useAuth } from '../auth';
import type { Catalog, CatalogProvider, Integration, Rules } from '../types';
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
  SourceTag,
  Status,
  Success,
} from '../components/ui';
import {
  IntegrationDiagnostics,
  useIntegrationDiagnostics,
} from '../components/IntegrationDiagnostics';

/**
 * Collects configuration for one integration and a server secret reference.
 * The fields come from the integration's own declaration, so a new integration gets a form
 * without any change here. The form never requests the provider key itself; the API validates
 * endpoint and credential-reference restrictions and rejects live connections in demo mode.
 */
function AddIntegration({
  providers,
  provider,
  onClose,
  onSaved,
}: {
  providers: CatalogProvider[];
  provider: string;
  onClose: () => void;
  onSaved: () => void;
}) {
  const { user } = useAuth();
  const [selected, setSelected] = useState(provider);
  const [name, setName] = useState('');
  const [secret, setSecret] = useState('');
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const demo = user?.mode === 'demo';
  const chosen = providers.find((item) => item.id === selected) || providers[0];
  /** Persists connection metadata, leaving source collection to a separate explicit action. */
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setPending(true);
    const config: Record<string, string | number> = {};
    for (const field of chosen.fields) {
      const value = (values[`${chosen.id}.${field.key}`] || '').trim();
      if (value) config[field.key] = field.kind === 'number' ? Number(value) : value;
    }
    try {
      await post('/integrations', {
        provider: chosen.id,
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
        <Field label="Integration" hint={chosen.summary}>
          <select value={chosen.id} onChange={(e) => setSelected(e.target.value)}>
            {providers.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
                {item.status === 'experimental' ? ' (experimental)' : ''}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Connection name">
          <input
            required
            maxLength={100}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Head office network"
          />
        </Field>
        {chosen.fields.map((field) => (
          <Field
            key={`${chosen.id}.${field.key}`}
            label={field.required ? field.label : `${field.label} (optional)`}
            hint={
              field.kind === 'url'
                ? `${field.hint} The server administrator must include this hostname in NYCTR_CONNECTOR_HOSTS.`
                : field.hint
            }
          >
            <input
              required={field.required}
              type={field.kind === 'url' ? 'url' : field.kind === 'number' ? 'number' : 'text'}
              value={values[`${chosen.id}.${field.key}`] || ''}
              onChange={(e) =>
                setValues({ ...values, [`${chosen.id}.${field.key}`]: e.target.value })
              }
              placeholder={field.placeholder}
            />
          </Field>
        ))}
        <Field
          label="Credential environment reference"
          hint={`${chosen.secret_hint} It stays on the server: enter the name of its environment variable, not the secret itself.`}
        >
          <input
            required
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="NYCTR_CONNECTOR_SECRET_HEAD_OFFICE"
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

/**
 * The table that carries the product idea: Nyctr's features down the side, integrations across
 * the top. A feature works when a connected source offers it. Nothing here is hard-coded per
 * vendor; rows and columns both come from the server's catalog.
 */
function CapabilityTable({ catalog, connected }: { catalog: Catalog; connected: Set<string> }) {
  return (
    <div className="table-scroll">
      <table className="capability-table">
        <thead>
          <tr>
            <th scope="col">What Nyctr can do</th>
            {catalog.providers.map((provider) => (
              <th scope="col" key={provider.id}>
                <SourceTag provider={provider.id} named />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {catalog.capabilities.map((capability) => {
            const live = catalog.providers.some(
              (provider) =>
                connected.has(provider.id) &&
                provider.provides.some((item) => item.id === capability.id),
            );
            return (
              <tr key={capability.id}>
                <th scope="row">
                  {capability.name}
                  <span className="d">
                    {live
                      ? 'Working: a connected source offers it'
                      : 'No connected source offers it'}
                    {capability.changes_provider ? '. Changes the source' : ''}
                  </span>
                </th>
                {catalog.providers.map((provider) => {
                  const offers = provider.provides.some((item) => item.id === capability.id);
                  return (
                    <td key={provider.id} className={offers ? 'yes' : 'no'}>
                      {offers ? (
                        <>
                          <Check size={15} aria-hidden="true" />
                          <span className="sr-only">Yes</span>
                        </>
                      ) : (
                        <>
                          <Minus size={15} aria-hidden="true" />
                          <span className="sr-only">No</span>
                        </>
                      )}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** Lists connected sources, what each integration adds to Nyctr, and whether Nyctr may change it. */
export default function Integrations({ sources = [] }: { sources?: Rules['sources'] } = {}) {
  const result = useApi<Integration[]>('/integrations');
  const fetched = useApi<Catalog>('/integrations/catalog');
  const catalog = fetched.data;
  const providers = catalog?.providers || [];
  const kind = (id: string) => providers.find((item) => item.id === id);
  const allowed = sources.filter((item) => item.write_mode === 'enabled').map((item) => item.name);
  const connected = new Set((result.data || []).map((item) => item.provider));
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
        description="Nyctr is the same product whatever you run. Each source you connect adds what its integration can read or change."
        actions={
          <button
            className="button primary"
            disabled={providers.length === 0}
            onClick={() => setAdd(providers[0].id)}
          >
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
            Collection never changes a source, and credentials stay on the server. Nyctr opens a
            blocked address, issues a guest pass or cuts a guest off only at a source whose
            integration offers it, and only when an operator names that integration in
            NYCTR_PROVIDER_WRITES.
          </p>
        </div>
        <Badge tone="blue">
          {providers.length} {providers.length === 1 ? 'integration' : 'integrations'}
        </Badge>
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
            const item = kind(integration.provider);
            const mode = sources.find((source) => source.id === integration.id)?.write_mode;
            return (
              <Card className="integration-card" key={integration.id}>
                <div className="integration-top">
                  <SourceTag provider={integration.provider} big />
                  <Status value={integration.status} />
                </div>
                <h3>{integration.name}</h3>
                <p>
                  {item?.name || integration.provider_name || label(integration.provider)}
                  {item?.status === 'experimental' ? ' · experimental' : ''}
                </p>
                <span className="integration-capability-label">Adds to Nyctr</span>
                <div className="capabilities">
                  {(item?.provides || []).map((capability) => (
                    <span key={capability.id}>
                      <Layers2 size={12} />
                      {capability.name}
                    </span>
                  ))}
                  {!item && <span>Unknown integration</span>}
                </div>
                <span className="integration-capability-label">
                  Reads · not connection verification
                </span>
                <div className="capabilities">
                  {integration.capabilities?.map((c) => (
                    <span key={c}>
                      {item?.reads.find((read) => read.id === c)?.label || label(c)}
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
                    {item && item.changes.length === 0
                      ? 'Nothing here for Nyctr to change'
                      : demo
                        ? 'Changes simulated'
                        : mode === 'enabled'
                          ? 'Nyctr may change it'
                          : 'Read only'}
                  </span>
                </div>
                <div className="integration-actions">
                  {admin && (
                    <button
                      className="button secondary small"
                      disabled={
                        pending !== null || diagnostics.state?.pending === true || demo || !item
                      }
                      onClick={() => void diagnostics.run(integration)}
                      title={
                        demo
                          ? 'Demo sources use seeded snapshots; live diagnostics are disabled.'
                          : !item
                            ? 'This release has no integration for this source.'
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
            text="Choose an integration below to begin collecting."
          />
        </Card>
      )}
      <div className="section-heading">
        <div>
          <h2>What each integration adds</h2>
          <p>
            Nyctr&apos;s features are the same for everyone. A feature works once a connected source
            offers it.
          </p>
        </div>
      </div>
      {catalog ? (
        <Card className="capability-card">
          <CapabilityTable catalog={catalog} connected={connected} />
        </Card>
      ) : fetched.error ? (
        <ErrorState message={fetched.error} retry={fetched.reload} />
      ) : (
        <Loading />
      )}
      <div className="section-heading">
        <div>
          <h2>Integrations in this release</h2>
          <p>Each one is a single module that declares what it reads and what it can change.</p>
        </div>
      </div>
      <div className="integration-grid catalog-grid">
        {providers.map((item) => (
          <Card className="integration-card catalog-card" key={item.id}>
            <div className="integration-top">
              <SourceTag provider={item.id} big />
              <Badge tone={item.status === 'stable' ? 'blue' : ''}>
                {item.status === 'stable' ? 'Available' : 'Experimental'}
              </Badge>
            </div>
            <h3>{item.name}</h3>
            <p>{item.summary}</p>
            <div className="integration-footer">
              <span>
                {item.changes.length
                  ? `Can change: ${item.changes.join(', ').toLowerCase()}`
                  : 'Reads only'}
              </span>
              <button className="text-link" onClick={() => setAdd(item.id)}>
                Set up
                <ArrowRight size={14} />
              </button>
            </div>
          </Card>
        ))}
      </div>
      <Notice>
        An integration reports only what its source exposes. Each connection&apos;s diagnostics list
        what was read and what that source cannot tell Nyctr.
      </Notice>
      {add && (
        <AddIntegration
          providers={providers}
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
