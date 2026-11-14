import { useEffect, useRef, useState, type FormEvent } from 'react';
import {
  ArrowRight,
  Check,
  Layers2,
  LockKeyhole,
  Minus,
  Pencil,
  Plus,
  RefreshCw,
  ScanLine,
  Settings2,
  Trash2,
} from 'lucide-react';
import { api, label, post, put, relativeTime, useApi } from '../api';
import { useAuth } from '../auth';
import { useNow } from '../lib/format';
import { nextCollection, useSchedule } from '../lib/schedule';
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

/** Shown wherever a collection stopped at its read limit, so it is never taken for a complete one. */
/** Shown on the edit form of a source that has collected; the server refuses with the same words. */
const FIXED_SOURCE =
  'This source has already collected, so where it reads can no longer change. To read from somewhere else, add a new source. Its name and numeric settings can still change.';

const PARTIAL_NOTE =
  "Only the most recent blocked lookups were read. Older ones in this source's time window were not.";

/**
 * Collects configuration for one integration and a server secret reference.
 * The fields come from the integration's own declaration, so a new integration gets a form
 * without any change here. The form never requests the provider key itself; the API validates
 * endpoint and credential-reference restrictions and rejects live connections in demo mode.
 * Given a saved source it becomes the edit form: the same fields filled in, with the kind of
 * source fixed. Only the name of the secret is shown; the secret itself never reaches the page.
 */
function AddIntegration({
  providers,
  provider,
  editing,
  onClose,
  onSaved,
  onPending,
}: {
  providers: CatalogProvider[];
  provider: string;
  editing?: Integration;
  onClose: () => void;
  onSaved: () => void;
  onPending?: (pending: boolean) => void;
}) {
  const { user } = useAuth();
  const [selected, setSelected] = useState(provider);
  const [name, setName] = useState(editing?.name || '');
  const [secret, setSecret] = useState(editing?.secret_ref || '');
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(
      Object.entries(editing?.config || {}).map(([key, value]) => [
        `${provider}.${key}`,
        String(value ?? ''),
      ]),
    ),
  );
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const demo = user?.mode === 'demo';
  const chosen = providers.find((item) => item.id === selected) || providers[0];
  // Once a source has collected, where it reads (every setting that is not a number, and the
  // secret name) is fixed; the server refuses a change with the same sentence.
  const fixed = Boolean(editing?.last_sync);
  // A save that finishes after this form was dismissed must not close whichever form is open now.
  const open = useRef(true);
  useEffect(() => {
    open.current = true;
    return () => {
      open.current = false;
    };
  }, []);
  /** Persists connection metadata, leaving source collection to a separate explicit action. */
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setPending(true);
    onPending?.(true);
    const config: Record<string, string | number> = {};
    for (const field of chosen.fields) {
      const value = (values[`${chosen.id}.${field.key}`] || '').trim();
      if (value) config[field.key] = field.kind === 'number' ? Number(value) : value;
    }
    try {
      const saved = { name: name.trim(), config, secret_ref: secret.trim() };
      if (editing) await put(`/integrations/${encodeURIComponent(editing.id)}`, saved);
      else await post('/integrations', { provider: chosen.id, ...saved });
      onSaved();
      if (open.current) onClose();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPending(false);
      onPending?.(false);
    }
  };
  return (
    <Modal title={editing ? 'Edit source' : 'Connect a source'} onClose={onClose}>
      <form className="modal-body form-stack" onSubmit={submit}>
        {demo && (
          <Notice tone="amber">
            Live connections are disabled in the demo workspace. Deploy in live mode to configure a
            source.
          </Notice>
        )}
        <Field
          label="Integration"
          hint={
            editing
              ? 'The kind of source cannot be changed. To use another kind, connect a new source.'
              : chosen.summary
          }
        >
          <select
            value={chosen.id}
            disabled={Boolean(editing)}
            onChange={(e) => setSelected(e.target.value)}
          >
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
              readOnly={fixed && field.kind !== 'number'}
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
            readOnly={fixed}
          />
        </Field>
        {fixed ? (
          <Notice tone="amber">{FIXED_SOURCE}</Notice>
        ) : (
          <Notice>
            {editing
              ? 'This source has not collected yet, so every field can still be corrected. A new address, setting or secret name means it must be tested again.'
              : 'Collection only reads. Saving records the connection; collect a snapshot afterwards. Whether Nyctr may change this source is a separate server setting.'}
          </Notice>
        )}
        <InlineError message={error} />
        <div className="modal-actions">
          <button className="button secondary" type="button" onClick={onClose}>
            Cancel
          </button>
          <button className="button primary" disabled={pending || demo} type="submit">
            {pending ? 'Saving…' : editing ? 'Save changes' : 'Save connection'}
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

/** What removing a source would delete and keep, counted by the server. */
interface RemovalPlan {
  name: string;
  remove: Record<string, number>;
  keep: Record<string, number>;
  refusal: string | null;
  notice: string | null;
}

const GOES: [string, string, string][] = [
  ['devices', 'device', 'devices'],
  ['networks', 'network', 'networks'],
  ['rules', 'rule', 'rules'],
  ['other_items', 'other item', 'other items'],
  ['lookups', 'blocked lookup', 'blocked lookups'],
  ['assignments', 'device assignment to a person', 'device assignments to people'],
  ['links', 'link from a DNS label', 'links from DNS labels'],
];
const STAYS: [string, string, string][] = [
  ['requests', 'request', 'requests'],
  ['exceptions', 'exception', 'exceptions'],
  ['passes', 'guest pass', 'guest passes'],
];
const counted = (counts: Record<string, number>, words: [string, string, string][]) =>
  words
    .filter(([key]) => counts[key] > 0)
    .map(([key, one, many]) => `${counts[key]} ${counts[key] === 1 ? one : many}`);

/**
 * Confirms removing a source: what goes and what stays, by count, and the source's name typed in.
 * Nothing is sent to the source; the server refuses while Nyctr still has something of its own there.
 */
function RemoveSource({
  integration,
  onClose,
  onRemoved,
}: {
  integration: Integration;
  onClose: () => void;
  onRemoved: () => void;
}) {
  const path = `/integrations/${encodeURIComponent(integration.id)}`;
  const plan = useApi<RemovalPlan>(`${path}/removal`);
  const [typed, setTyped] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    setPending(true);
    try {
      await api(path, { method: 'DELETE', body: JSON.stringify({ name: typed.trim() }) });
      onRemoved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPending(false);
    }
  };
  const goes = plan.data ? counted(plan.data.remove, GOES) : [];
  const stays = plan.data ? counted(plan.data.keep, STAYS) : [];
  return (
    <Modal title="Remove source" onClose={onClose}>
      <form className="modal-body form-stack" onSubmit={submit}>
        {plan.loading && <Loading text="Counting what this removes…" />}
        {plan.error && <ErrorState message={plan.error} retry={plan.reload} />}
        {plan.data && (
          <>
            <Notice tone="amber">
              Removing {plan.data.name} deletes everything Nyctr collected from it. Nothing at the
              source itself changes, and this cannot be undone. To read from it again, add it as a
              new source: it starts from nothing.
            </Notice>
            <p>
              <b>Goes:</b> {goes.length ? goes.join(', ') : 'nothing has been collected from it'}.
            </p>
            <p>
              <b>Stays:</b> {[...stays, 'the activity history'].join(', ')}, still naming{' '}
              {plan.data.name}.
            </p>
            {plan.data.notice && <p>{plan.data.notice}</p>}
            {plan.data.refusal ? (
              <InlineError message={plan.data.refusal} />
            ) : (
              <Field label={`Type ${plan.data.name} to confirm`}>
                <input
                  value={typed}
                  autoComplete="off"
                  onChange={(e) => setTyped(e.target.value)}
                />
              </Field>
            )}
          </>
        )}
        <InlineError message={error} />
        <div className="modal-actions">
          <button className="button secondary" type="button" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button danger"
            type="submit"
            disabled={
              pending || !plan.data || Boolean(plan.data.refusal) || typed.trim() !== plan.data.name
            }
          >
            {pending ? 'Removing…' : 'Remove source'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Lists connected sources, what each integration adds to Nyctr, and whether Nyctr may change it. */
export default function Integrations({ sources = [] }: { sources?: Rules['sources'] } = {}) {
  const result = useApi<Integration[]>('/integrations');
  const fetched = useApi<Catalog>('/integrations/catalog');
  const schedule = useSchedule();
  const now = useNow();
  const catalog = fetched.data;
  const providers = catalog?.providers || [];
  const kind = (id: string) => providers.find((item) => item.id === id);
  const allowed = sources.filter((item) => item.write_mode === 'enabled').map((item) => item.name);
  const connected = new Set((result.data || []).map((item) => item.provider));
  const { user } = useAuth();
  const [add, setAdd] = useState<string | null>(null);
  const [edit, setEdit] = useState<Integration | null>(null);
  const [removing, setRemoving] = useState<Integration | null>(null);
  // Where the keyboard goes when the removal dialog closes: its Remove button, or, once the
  // source and its card are gone, the Add connection button.
  const removeButton = useRef<HTMLButtonElement | null>(null);
  const addButton = useRef<HTMLButtonElement | null>(null);
  useEffect(() => {
    if (!removing) removeButton.current?.focus();
  }, [removing]);
  const editButton = useRef<HTMLButtonElement | null>(null);
  // Per source: 'pending' while an edit of it is being saved, then the list as it was when that
  // save succeeded. Its form would open on the values from before the save and could undo it, so
  // the source stays shut until a newer list has arrived. Every save starts a fresh read and
  // drops any older one, so the next list to arrive was read after the save.
  const [saving, setSaving] = useState<Record<string, 'pending' | Integration[] | null>>({});
  const listed = useRef(result.data);
  listed.current = result.data;
  const shut = (id: string) =>
    id in saving && (saving[id] === 'pending' || saving[id] === result.data);
  /** Puts the keyboard back on the card's Edit button once the edit form has closed. */
  useEffect(() => {
    if (!edit) editButton.current?.focus();
  }, [edit]);
  // A link from the Briefing names one source: `edit` opens its Edit form, `source` goes to its
  // card. Each link is followed once, so closing the form does not open it again.
  const followed = useRef('');
  const mayEdit = user?.role === 'admin' && user.mode !== 'demo';
  useEffect(() => {
    const hash = window.location.hash;
    if (!result.data || followed.current === hash) return;
    followed.current = hash;
    const wanted = new URLSearchParams(hash.split('?')[1] || '');
    const target = result.data.find(
      (item) => item.id === (wanted.get('edit') || wanted.get('source')),
    );
    if (!target) return;
    document.getElementById(`source-${target.id}`)?.focus();
    if (wanted.get('edit') && mayEdit) setEdit(target);
  }, [result.data, mayEdit]);
  const [pending, setPending] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
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
        partial?: boolean;
        gaps?: number;
      }>(`/integrations/${encodeURIComponent(integration.id)}/sync`);
      setSuccess(
        `Snapshot collected: ${response.resource_count} resources and ${response.observation_count} observations.` +
          (response.partial ? ` ${PARTIAL_NOTE}` : '') +
          (response.gaps
            ? ` ${response.gaps === 1 ? 'One thing' : `${response.gaps} things`} could not be read; the source's card says what.`
            : ''),
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
            ref={addButton}
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
                  {integration.status === 'connected' && integration.gaps?.length ? (
                    <Badge tone="amber">Connected, with gaps</Badge>
                  ) : (
                    <Status value={integration.status} />
                  )}
                </div>
                <h3 id={`source-${integration.id}`} tabIndex={-1}>
                  {integration.name}
                </h3>
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
                {schedule.data && (
                  <div className="integration-meta">
                    <span>Next collection</span>
                    <strong>{nextCollection(schedule.data, now)}</strong>
                  </div>
                )}
                {integration.status === 'partial' && <Notice tone="amber">{PARTIAL_NOTE}</Notice>}
                {integration.gaps?.length ? (
                  <Notice tone="amber">
                    <strong>The last collection could not read everything</strong>
                    <ul className="plain">
                      {integration.gaps.map((gap) => (
                        <li key={gap.id}>
                          <strong>{gap.title}.</strong> {gap.summary}
                        </li>
                      ))}
                    </ul>
                  </Notice>
                ) : null}
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
                      disabled={pending !== null || demo || !item}
                      aria-disabled={shut(integration.id)}
                      onClick={(event) => {
                        if (shut(integration.id)) return;
                        editButton.current = event.currentTarget;
                        setEdit(integration);
                      }}
                      title={
                        demo
                          ? 'Demo sources cannot be changed.'
                          : !item
                            ? 'This release has no integration for this source.'
                            : shut(integration.id)
                              ? 'Your last change to this source is still being saved.'
                              : 'Change this source'
                      }
                    >
                      <Pencil size={14} />
                      Edit
                    </button>
                  )}
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
                  {admin && (
                    <button
                      className="button secondary small"
                      disabled={pending !== null || demo}
                      onClick={(event) => {
                        removeButton.current = event.currentTarget;
                        setRemoving(integration);
                      }}
                      title={demo ? 'Demo sources cannot be removed.' : 'Remove this source'}
                    >
                      <Trash2 size={14} />
                      Remove
                    </button>
                  )}
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
      {edit && (
        <AddIntegration
          providers={providers}
          provider={edit.provider}
          editing={edit}
          onClose={() => setEdit(null)}
          onPending={(busy) =>
            setSaving(({ [edit.id]: was, ...rest }) =>
              busy
                ? { ...rest, [edit.id]: 'pending' }
                : was === 'pending'
                  ? rest
                  : { ...rest, [edit.id]: was },
            )
          }
          onSaved={() => {
            setSaving((all) => ({ ...all, [edit.id]: listed.current }));
            result.reload();
            setError(null);
            setSuccess('Changes saved.');
          }}
        />
      )}
      {removing && (
        <RemoveSource
          integration={removing}
          onClose={() => setRemoving(null)}
          onRemoved={() => {
            removeButton.current = addButton.current;
            setRemoving(null);
            result.reload();
            setError(null);
            setSuccess(`${removing.name} was removed.`);
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
