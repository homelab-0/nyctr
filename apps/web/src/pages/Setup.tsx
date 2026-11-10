import { useEffect, useState } from 'react';
import { put, useApi } from '../api';
import {
  ErrorState,
  InlineError,
  Loading,
  Panel,
  Seg,
  Stepper,
  Switch,
  kindIcon,
} from '../components/ui';
import { span, writeText } from '../lib/format';
import type {
  AccessRule,
  AssistantConfig,
  AuthConfig,
  DeviceLabel,
  Person,
  Resource,
  Rules,
  WriteMode,
} from '../types';

type Tab = 'rule' | 'people' | 'system';

/** The access rule as a sentence an administrator edits, with the bands it can and cannot reach. */
function RulePanel({ rules, reload }: { rules: Rules; reload: () => void }) {
  const [rule, setRule] = useState<AccessRule>(rules.access);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => setRule(rules.access), [rules.access]);
  /** Saves immediately so the sentence on screen is always the rule in force. */
  const save = async (next: AccessRule) => {
    setRule(next);
    setError(null);
    try {
      await put('/rules/access', next);
      reload();
    } catch (e) {
      setError((e as Error).message);
      setRule(rules.access);
    }
  };
  const writes = rules.writes.access;
  const openers = rules.sources.filter((source) => source.changes.length > 0);
  return (
    <Panel
      title="Access rule"
      hint="When Nyctr may open a blocked address without waiting for you."
    >
      <div className="stack">
        <p className="rule">
          Open a request on its own when the score is
          <Stepper
            label="highest score"
            min={0}
            max={60}
            step={5}
            value={rule.max_score}
            onChange={(max_score) => void save({ ...rule, max_score })}
          />
          or lower and a privacy list blocked it, for up to
          <Stepper
            label="minutes"
            min={15}
            max={240}
            step={15}
            value={rule.max_minutes}
            onChange={(max_minutes) => void save({ ...rule, max_minutes })}
          />
          minutes, at most
          <Stepper
            label="openings per day"
            min={1}
            max={20}
            value={rule.per_day}
            onChange={(per_day) => void save({ ...rule, per_day })}
          />
          times a day per person.
        </p>
        <div className="bandbar" aria-hidden="true">
          <i className="auto" style={{ width: `${rule.max_score}%` }} />
          <i className="person" style={{ width: `${100 - rule.max_score}%` }} />
        </div>
        <div className="bar aside">
          <span>0 to {rule.max_score}: Nyctr may open it</span>
          <span>{rule.max_score + 1} to 100, or no score: a person decides</span>
        </div>
        <div className="bar">
          <Switch
            label="Automatic access"
            checked={rule.enabled}
            onChange={(enabled) => void save({ ...rule, enabled })}
          />
          <span className="aside">
            Security blocks, content rules, addresses you said no to before and anything Nyctr
            cannot score always wait for a person.
          </span>
        </div>
        <InlineError message={error} />
        {writes === 'none' && (
          <div className="note yellow">
            <div>
              <b>
                No connected source can open a blocked address, so this rule has nothing to act on.
              </b>
              <p>
                Requests are still scored and shown. Connect a DNS source whose integration offers
                opening addresses; the Sources page lists what each one adds.
              </p>
            </div>
          </div>
        )}
        {writes === 'disabled' && (
          <div className="note yellow">
            <div>
              <b>Nyctr is read-only for your DNS source, so this rule cannot open anything yet.</b>
              <p>
                Requests are still scored and shown. To let the rule act, an operator names the
                source's integration ({openers.map((source) => source.provider).join(', ')}) in
                NYCTR_PROVIDER_WRITES on the server.
              </p>
            </div>
          </div>
        )}
        {writes === 'simulated' && (
          <p className="aside">
            Demo mode: the rule runs for real, and the change at the DNS source is simulated.
          </p>
        )}
      </div>
    </Panel>
  );
}

/** Who each device belongs to, and which inventory device a DNS label really is. */
function PeoplePanel() {
  const devices = useApi<Resource[]>('/devices');
  const people = useApi<Person[]>('/users');
  const labels = useApi<DeviceLabel[]>('/device-links');
  const [error, setError] = useState<string | null>(null);
  const run = async (action: () => Promise<unknown>) => {
    setError(null);
    try {
      await action();
      devices.reload();
      labels.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  };
  if (devices.loading || people.loading) return <Loading text="Loading devices…" />;
  if (devices.error) return <ErrorState message={devices.error} retry={devices.reload} />;
  // DNS labels are names a DNS source reported, not devices; guests are handled on their own page.
  const labelIds = new Set((labels.data || []).map((item) => item.source_id));
  const inventory = (devices.data || []).filter(
    (row) => !labelIds.has(row.id) && !row.attributes.guest,
  );
  const members = (people.data || []).filter((person) => person.active);
  const value = (row: Resource) =>
    row.classification === 'personal' ? `personal:${row.owner_id}` : row.classification;
  const assign = (row: Resource, choice: string) => {
    const [classification, owner] = choice.split(':');
    const body =
      classification === 'personal'
        ? { classification, user_ids: [owner] }
        : classification === 'shared'
          ? { classification, user_ids: members.map((person) => person.id) }
          : { classification, user_ids: [] };
    void run(() => put(`/devices/${encodeURIComponent(row.id)}/assignment`, body));
  };
  return (
    <div className="stack">
      <InlineError message={error} />
      <Panel
        title="Whose device is it"
        hint="A member only ever sees blocks from devices that are theirs or shared."
        flush
      >
        <div className="tblwrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Device</th>
                <th>Address</th>
                <th>Belongs to</th>
              </tr>
            </thead>
            <tbody>
              {inventory.map((row) => {
                const Icon = kindIcon(row.kind);
                return (
                  <tr key={row.id}>
                    <th>
                      <span className="srcn">
                        <Icon size={15} /> {row.name}
                      </span>
                    </th>
                    <td className="muted mono">{String(row.attributes.ip || '')}</td>
                    <td>
                      <select
                        aria-label={`Who ${row.name} belongs to`}
                        value={value(row)}
                        onChange={(e) => assign(row, e.target.value)}
                      >
                        <option value="unassigned">Nobody yet</option>
                        {members.map((person) => (
                          <option key={person.id} value={`personal:${person.id}`}>
                            {person.name}
                          </option>
                        ))}
                        <option value="shared">Shared by everyone</option>
                        <option value="infrastructure">Not a personal device</option>
                      </select>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>
      <Panel
        title="DNS device labels"
        hint="A DNS source reports a device name it was told. Say which inventory device each one is. A link only applies to lookups made after you set it."
        flush
      >
        {(labels.data || []).length === 0 ? (
          <p className="pad muted">Your DNS source has not reported any named devices.</p>
        ) : (
          <div className="tblwrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Label from DNS</th>
                  <th>Is this device</th>
                </tr>
              </thead>
              <tbody>
                {(labels.data || []).map((item) => (
                  <tr key={item.source_id}>
                    <th>
                      {item.name}
                      {item.model && <div className="muted tiny">{item.model}</div>}
                    </th>
                    <td>
                      <select
                        aria-label={`Device for ${item.name}`}
                        value={item.device_id || ''}
                        onChange={(e) =>
                          void run(() =>
                            put('/device-links', {
                              source_id: item.source_id,
                              device_id: e.target.value || null,
                            }),
                          )
                        }
                      >
                        <option value="">Not linked</option>
                        {inventory.map((row) => (
                          <option key={row.id} value={row.id}>
                            {row.name}
                            {item.suggested_device_id === row.id ? ' (same name)' : ''}
                          </option>
                        ))}
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}

/** What this installation is configured to do. All of it is set on the server, not here. */
function SystemPanel({ rules }: { rules: Rules }) {
  const auth = useApi<AuthConfig>('/auth/config');
  const assistant = useApi<AssistantConfig>('/assistant');
  const rows: [string, string, string][] = [
    ['Mode', auth.data?.mode === 'demo' ? 'Demo' : 'Live', 'NYCTR_MODE'],
    [
      'Sign-in',
      [
        auth.data?.oidc_enabled && 'Single sign-on',
        auth.data?.local_enabled && 'Email and password',
      ]
        .filter(Boolean)
        .join(' and ') || 'Unknown',
      'NYCTR_OIDC_ISSUER, NYCTR_LOCAL_LOGIN_ENABLED',
    ],
    ...rules.sources
      .filter((source) => source.write_mode !== 'none')
      .map((source): [string, string, string] => [
        `Changes to ${source.name}`,
        writeText(source.write_mode as WriteMode),
        'NYCTR_PROVIDER_WRITES',
      ]),
    [
      'Automatic collection',
      rules.collect_interval_seconds
        ? `Every ${span(Math.round(rules.collect_interval_seconds / 60))}`
        : 'Only when you press Collect',
      'NYCTR_COLLECT_INTERVAL_SECONDS',
    ],
    [
      'Assistant',
      assistant.data?.provider === 'model'
        ? `Model: ${assistant.data.model}`
        : assistant.data?.provider === 'sample'
          ? 'Sample answers (no model connected)'
          : 'Off (no model connected)',
      'NYCTR_AI_BASE_URL, NYCTR_AI_MODEL, NYCTR_AI_API_KEY',
    ],
  ];
  return (
    <Panel
      title="This installation"
      hint="These are set by whoever runs the server. They cannot be changed from the browser."
      flush
    >
      <div className="tblwrap">
        <table className="tbl">
          <thead>
            <tr>
              <th>Setting</th>
              <th>Now</th>
              <th>Set with</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([name, now, env]) => (
              <tr key={name}>
                <th>{name}</th>
                <td>{now}</td>
                <td className="muted mono">{env}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

/** Rules Nyctr acts on, who owns which device, and how the server is configured. */
export default function Setup({ params }: { params: URLSearchParams }) {
  const rules = useApi<Rules>('/rules');
  const [tab, setTab] = useState<Tab>((params.get('tab') as Tab) || 'rule');
  if (rules.loading && !rules.data) return <Loading text="Loading setup…" />;
  if (rules.error || !rules.data)
    return (
      <ErrorState message={rules.error || 'Setup could not be loaded.'} retry={rules.reload} />
    );
  return (
    <div className="page narrow">
      <header className="page-head">
        <div>
          <h1 className="display d2">Setup</h1>
          <p className="lede">What Nyctr may do on its own, and whose devices are whose.</p>
        </div>
        <Seg
          label="Setup section"
          value={tab}
          onChange={setTab}
          options={[
            { id: 'rule', name: 'Access rule' },
            { id: 'people', name: 'People and devices' },
            { id: 'system', name: 'This installation' },
          ]}
        />
      </header>
      {tab === 'rule' && <RulePanel rules={rules.data} reload={rules.reload} />}
      {tab === 'people' && <PeoplePanel />}
      {tab === 'system' && <SystemPanel rules={rules.data} />}
    </div>
  );
}
