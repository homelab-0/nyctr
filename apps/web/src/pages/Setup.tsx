import { useEffect, useRef, useState } from 'react';
import { ApiError, api, dateTime, put, useApi } from '../api';
import { ModelPanel } from '../components/ModelPanel';
import { NoticesPanel } from '../components/NoticesPanel';
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
import { isMissing, missingFor } from '../lib/counts';
import { span, useNow, writeText } from '../lib/format';
import { UNREACHABLE, nextCollection, useSchedule } from '../lib/schedule';
import type {
  AccessRule,
  AddressSeen,
  AuthConfig,
  CollectionSchedule,
  DeviceLabel,
  Person,
  Presence,
  PresenceRow,
  Resource,
  Rules,
  TierMode,
  WriteMode,
} from '../types';

type Tab = 'rule' | 'people' | 'system';

/** Kinds of block the rule never opens, each with why, in the order the card lists them. */
const ALWAYS_YOU: [string, string][] = [
  [
    'Kinds of site you chose to block',
    'A content category or safe search, or a newly registered, dynamic or parked address, is switched on at the source. That was a choice, so it stays yours.',
  ],
  ['Addresses on a deny list', 'Someone put this address on a deny list on purpose.'],
  [
    'Firewall rules',
    'A firewall rule or a blocked region stands in the way. Nyctr never opens the firewall by itself.',
  ],
  ['Intrusion prevention', 'The network recognised an attack pattern in the traffic.'],
  [
    'Anything Nyctr does not recognise',
    'When Nyctr cannot tell what blocked an address, it does not guess.',
  ],
];
const MODES: { id: TierMode; name: string }[] = [
  { id: 'off', name: 'Off' },
  { id: 'shadow', name: 'Record only' },
  { id: 'on', name: 'On' },
];
const MODE_MEANS: Record<TierMode, string> = {
  off: 'Off: these requests wait for you.',
  shadow:
    'Record only: Nyctr opens nothing. Each request waits for you, with a note saying the rule would have opened it.',
  on: 'On: Nyctr opens these by itself, within the limits written here.',
};

/** The access rule by kind of block: what may open by itself, within which limits, and what never does. */
function RulePanel({ rules, reload }: { rules: Rules; reload: () => void }) {
  const [rule, setRule] = useState<AccessRule>(rules.access);
  const [error, setError] = useState<string | null>(null);
  // The rule the next save sends. A change updates it at once, so a second change is built on
  // the first even before the page paints again.
  const latest = useRef(rules.access);
  // The last rule the server accepted. A failed save returns to this one. A success counts even
  // when its read-back is ignored because another save is still queued.
  const confirmed = useRef(rules.access);
  const tail = useRef(Promise.resolve());
  const pending = useRef(0);
  useEffect(() => {
    // A save that has not settled yet is newer than the rule just read back.
    if (pending.current > 0) return;
    latest.current = rules.access;
    confirmed.current = rules.access;
    setRule(rules.access);
  }, [rules.access]);
  /** Sends the whole rule, one save at a time, from the latest rule on the page. */
  const save = (apply: (current: AccessRule) => AccessRule) => {
    const next = apply(latest.current);
    latest.current = next;
    setRule(next);
    setError(null);
    pending.current += 1;
    const run = tail.current.then(async () => {
      const body = latest.current;
      try {
        await put('/rules/access', body);
        confirmed.current = body;
        reload();
      } catch (e) {
        setError((e as Error).message);
        if (latest.current === body) {
          latest.current = confirmed.current;
          setRule(confirmed.current);
        }
      } finally {
        pending.current -= 1;
      }
    });
    tail.current = run.then(
      () => undefined,
      () => undefined,
    );
  };
  const writes = rules.writes.access;
  const openers = rules.sources.filter((source) => source.changes.length > 0);
  const ads = rule.ad_tracker;
  const threats = rule.threat_feed;
  /** A threat-feed block is never open longer than an advertising one, so its limit follows down. */
  const saveAds = (change: Partial<AccessRule['ad_tracker']>) => {
    save((current) => {
      const next = { ...current.ad_tracker, ...change };
      const max_minutes = Math.min(current.threat_feed.max_minutes, next.max_minutes);
      return { ...current, ad_tracker: next, threat_feed: { ...current.threat_feed, max_minutes } };
    });
  };
  const saveThreats = (change: Partial<AccessRule['threat_feed']>) => {
    save((current) => {
      const next = { ...current.threat_feed, ...change };
      const max_minutes = Math.min(next.max_minutes, current.ad_tracker.max_minutes);
      return { ...current, threat_feed: { ...next, max_minutes } };
    });
  };
  return (
    <Panel
      title="Access rule"
      hint="When Nyctr may open a blocked address without waiting for you."
    >
      <div className="stack">
        <div className="bar">
          <Switch
            label="Automatic access"
            checked={rule.enabled}
            onChange={(enabled) => save((current) => ({ ...current, enabled }))}
          />
          <span className="aside">
            With this off, every request waits for you, whatever is set below.
          </span>
        </div>
        <div className="bar">
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
            <span>Open a site a member named</span>
            <Switch
              label="Open a site a member named"
              checked={rule.allow_statement === true}
              onChange={(allow_statement) => save((current) => ({ ...current, allow_statement }))}
            />
          </span>
          <span className="aside">
            With this off, a site someone on their own device names always waits for you. On, it
            follows the same rule as any other request.
          </span>
        </div>
        <p className="rule">
          Open at most
          <Stepper
            label="openings per day"
            min={1}
            max={20}
            value={rule.per_day}
            onChange={(per_day) => save((current) => ({ ...current, per_day }))}
          />
          requests a day for each person, and
          <Stepper
            label="openings per day for everyone"
            min={1}
            max={100}
            value={rule.daily_total}
            onChange={(daily_total) => save((current) => ({ ...current, daily_total }))}
          />
          a day for everyone together.
        </p>
        <h3>Can open by themselves</h3>
        <section className="tier" aria-label="Advertising and tracker lists">
          <div className="bar">
            <b>Advertising and tracker lists</b>
            <Seg
              label="Advertising and tracker lists"
              value={ads.mode}
              options={MODES}
              onChange={(mode) => saveAds({ mode })}
            />
          </div>
          <p className="rule">
            When a list of advert or tracker addresses is all that blocks it and the score is
            <Stepper
              label="highest score"
              min={0}
              max={60}
              step={5}
              value={ads.max_score}
              onChange={(max_score) => saveAds({ max_score })}
            />
            or lower, open it for up to
            <Stepper
              label="minutes"
              min={15}
              max={240}
              step={15}
              value={ads.max_minutes}
              onChange={(max_minutes) => saveAds({ max_minutes })}
            />
            minutes.
          </p>
          <div className="bandbar" aria-hidden="true">
            <i className="auto" style={{ width: `${ads.max_score}%` }} />
            <i className="person" style={{ width: `${100 - ads.max_score}%` }} />
          </div>
          <div className="bar aside">
            <span>0 to {ads.max_score}: Nyctr may open it</span>
            <span>{ads.max_score + 1} to 100, or no score: a person decides</span>
          </div>
          <div className="bar">
            <span>Require a check of the address</span>
            <Switch
              label="Require a check of the address"
              checked={ads.analysis_required}
              onChange={(analysis_required) => saveAds({ analysis_required })}
            />
          </div>
          <p className="aside">
            {ads.analysis_required
              ? 'Nyctr opens one of these only when the check says the block does not look justified ' +
                'and the risk looks low.'
              : 'A check can only stop an opening. It cannot open one by itself.'}{' '}
            {MODE_MEANS[ads.mode]} An address you said no to before always waits for you.
          </p>
        </section>
        <section className="tier" aria-label="Threat feeds">
          <div className="bar">
            <b>Threat feeds</b>
            <Seg
              label="Threat feeds"
              value={threats.mode}
              options={MODES}
              onChange={(mode) => saveThreats({ mode })}
            />
          </div>
          <p className="aside">
            A feed of addresses reported as dangerous blocked it. Nyctr opens one of these only when
            the check says the block does not look justified and the risk looks low, and these are
            also true:
          </p>
          <ul className="aside">
            <li>the name does not look machine-made or disguised</li>
            <li>the address was registered at least {threats.min_registered_days} days ago</li>
            <li>nobody said no to it before</li>
            <li>it is opened for {threats.max_minutes} minutes at most</li>
          </ul>
          <p className="aside">{MODE_MEANS[threats.mode]}</p>
        </section>
        <h3>Always come to you</h3>
        <div className="rows boxed">
          {ALWAYS_YOU.map(([kind, why]) => (
            <div className="row" key={kind}>
              <i className="dot" />
              <span>
                <span className="t">{kind}</span>
                <span className="d">{why}</span>
              </span>
              <span className="meta">Never automatic</span>
            </div>
          ))}
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

/** Where a person signed in from, for the line under a device. Empty when the record holds no address. */
const from = (item: PresenceRow) => (item.address ? ` from ${item.address}` : '');

/** Who each device belongs to, and which inventory device a DNS label really is. */
function PeoplePanel() {
  const devices = useApi<Resource[]>('/devices');
  const people = useApi<Person[]>('/users');
  const labels = useApi<DeviceLabel[]>('/device-links');
  const signIns = useApi<Presence>('/presence');
  const [error, setError] = useState<string | null>(null);
  const run = async (action: () => Promise<unknown>) => {
    setError(null);
    try {
      await action();
      devices.reload();
      labels.reload();
      signIns.reload();
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
      {signIns.error && (
        <p className="aside" role="alert">
          Nyctr could not read who signed in on which device, so the sign-ins under the devices
          below may be missing or out of date.{' '}
          <button className="linklike" onClick={signIns.reload}>
            Try again
          </button>
        </p>
      )}
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
                      </span>{' '}
                      {isMissing(row) && <span className="tag yellow">{missingFor(row)}</span>}
                      {(signIns.data?.items || [])
                        .filter((item) => item.device_id === row.id && !item.ended_at)
                        .map((item) => (
                          <div className="muted tiny" key={item.id}>
                            {item.kind === 'tie'
                              ? `${item.user_name} signed in on it${from(item)}, last on ${dateTime(item.last_at)}. `
                              : `${item.user_name} signed in on it${from(item)} on ${dateTime(item.last_at)} and was not tied to it, because it is someone else's.`}
                            {item.kind === 'tie' && (
                              <button
                                className="button quiet small"
                                aria-label={`End ${item.user_name}'s tie to ${row.name}`}
                                onClick={() =>
                                  void run(() =>
                                    api(`/presence/${encodeURIComponent(item.id)}`, {
                                      method: 'DELETE',
                                    }),
                                  )
                                }
                              >
                                End this tie
                              </button>
                            )}
                          </div>
                        ))}
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

/** How long the list waits after an arrow key before saving, so stepping through it is one change. */
const KEY_PAUSE_MS = 700;
/** Keys that move through a closed list one choice at a time. */
const STEP_KEYS = [
  'ArrowUp',
  'ArrowDown',
  'ArrowLeft',
  'ArrowRight',
  'Home',
  'End',
  'PageUp',
  'PageDown',
];

/**
 * The one collection schedule for every source. Saved on change, like the rules.
 * The controls are never disabled for a save: a disabled control drops keyboard focus to the
 * page. Input is ignored instead until the schedule in force is back on screen.
 */
function SchedulePanel() {
  const schedule = useSchedule();
  const now = useNow();
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  // A choice reached with the keyboard and not saved yet.
  const [picked, setPicked] = useState<number | null>(null);
  const busy = useRef(false);
  const byKey = useRef(false);
  const pause = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(pause.current), []);
  if (!schedule.data)
    return schedule.error ? (
      <ErrorState message={schedule.error} retry={() => void schedule.reload()} />
    ) : (
      <Loading text="Loading the schedule…" />
    );
  const { enabled, interval_seconds, source, choices } = schedule.data;
  const minutes = Math.round(interval_seconds / 60);
  const demo = source === 'demo';
  // A deployment value may sit between the choices; saving moves to the nearest one.
  const nearest = choices.reduce((a, b) => (Math.abs(b - minutes) < Math.abs(a - minutes) ? b : a));
  const save = async (next: Pick<CollectionSchedule, 'enabled'> & { minutes: number }) => {
    if (busy.current) return;
    busy.current = true;
    window.clearTimeout(pause.current);
    setError(null);
    setSaving(true);
    try {
      // The answer is the full schedule in force, so it goes on screen as it is.
      schedule.replace(await put<CollectionSchedule>('/collection', next));
    } catch (e) {
      // With no answer the save may still have landed, so read what is in force before going on.
      setError(
        e instanceof ApiError
          ? e.message
          : `${UNREACHABLE} Check the schedule shown here before you try again.`,
      );
      await schedule.reload();
    }
    setPicked(null);
    busy.current = false;
    setSaving(false);
  };
  /** Saves the choice the keyboard stopped on, if it is a change. */
  const commit = (value: number | null) => {
    window.clearTimeout(pause.current);
    byKey.current = false;
    if (value === null) return;
    if (value === minutes) setPicked(null);
    else void save({ enabled, minutes: value });
  };
  const pick = (value: number) => {
    if (busy.current) return;
    if (!byKey.current) return void save({ enabled, minutes: value });
    // Arrow keys change a closed list at every step. Wait for the keys to stop, or for focus
    // to leave, so that going from 15 minutes to 6 hours is saved and recorded once.
    setPicked(value);
    window.clearTimeout(pause.current);
    pause.current = window.setTimeout(() => commit(value), KEY_PAUSE_MS);
  };
  return (
    <Panel
      title="Collection schedule"
      hint="How often Nyctr reads every source on its own. A change applies within a minute."
    >
      <div className="stack">
        <div className="bar" aria-busy={saving}>
          <Switch
            label="Scheduled collection"
            checked={enabled}
            disabled={demo}
            onChange={(on) => void save({ enabled: on, minutes: picked ?? nearest })}
          />
          <select
            aria-label="How often to collect"
            aria-disabled={saving || undefined}
            value={picked ?? minutes}
            disabled={demo || !enabled}
            onKeyDown={(e) => {
              if (STEP_KEYS.includes(e.key)) byKey.current = true;
              else if (e.key === 'Enter') commit(picked);
            }}
            onPointerDown={() => (byKey.current = false)}
            onBlur={() => commit(picked)}
            onChange={(e) => pick(Number(e.target.value))}
          >
            {!choices.includes(minutes) && <option value={minutes}>Every {span(minutes)}</option>}
            {choices.map((choice) => (
              <option key={choice} value={choice}>
                Every {span(choice)}
              </option>
            ))}
          </select>
          <span className="aside">{nextCollection(schedule.data, now, 'Next collection ')}</span>
        </div>
        {schedule.error && (
          <InlineError
            message={`${schedule.error} Nyctr could not read the schedule again, so what is shown here may be out of date.`}
          />
        )}
        <InlineError message={error} />
        {source === 'default' && (
          <p className="aside">Nobody has changed this yet, so Nyctr collects every 15 minutes.</p>
        )}
        {source === 'deployment' && (
          <p className="aside">
            This starting value was set on the server with NYCTR_COLLECT_INTERVAL_SECONDS. What you
            save here replaces it.
          </p>
        )}
        {demo ? (
          <p className="aside">Demo mode uses sample data and never collects.</p>
        ) : (
          <p className="aside">
            The guest cut-off rule and lock-out act at every collection. With the schedule on, a
            rule you wrote can cut a guest off when nobody is at the console.
          </p>
        )}
      </div>
    </Panel>
  );
}

/** What this installation is configured to do. All of it is set on the server, not here. */
function SystemPanel({ rules }: { rules: Rules }) {
  const auth = useApi<AuthConfig>('/auth/config');
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

/** How Nyctr worked out the address, or why it has none, in words an operator can act on. */
export function addressText(seen: AddressSeen): string {
  const proxy = `The connection came from ${seen.peer}, which is on your list of proxies`;
  switch (seen.why) {
    case 'peer':
      return `The connection came straight from this address. It is not on your list of proxies, so nothing it said about another address was read. If one of your proxies sits at this address, add it to the list.`;
    case 'forwarded':
      return `${proxy}. Nyctr read address ${seen.entry} of the ${seen.entries} it passed on, counted from the right: the one your proxy wrote.`;
    case 'missing':
      return `${proxy}, but it passed no address on. Set the proxy to add the address it saw (X-Forwarded-For).`;
    case 'short':
      return `${proxy}, but it passed on ${seen.entries} and Nyctr is set to read number ${seen.proxy_hops} from the right. Lower the number of proxies Nyctr counts, or check that each proxy adds the address it saw.`;
    case 'unlisted':
      return `${proxy}, but ${seen.unlisted}, at position ${seen.entry} from the right of what it passed on, is not on the list. Nyctr is set to count ${seen.proxy_hops} proxies, and every one of them must be on the list. If ${seen.unlisted} is one of your proxies, add it. If it is your own device, you reached Nyctr without passing all of them, and Nyctr gives no address for that.`;
    case 'zone':
      return `The connection came from ${seen.peer}, an address that only works on one network link (the part after % names the link). Nyctr cannot match such an address to your list of proxies or to a device, so it gives none. Reach Nyctr, or have your proxy reach it, over an ordinary address.`;
    case 'hops':
      return `${proxy}, but Nyctr is set to count ${seen.proxy_hops} proxies. The number must be 1 or more.`;
    case 'malformed':
      return `${proxy}, but what it passed on at position ${seen.entry} from the right is not an address.`;
    default:
      return 'The server did not say where the connection came from.';
  }
}

/** The switch that lets a sign-in tie a person to the device they are on, beside the check it rests on. */
function RecognitionPanel() {
  const presence = useApi<Presence>('/presence');
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  // What the last save answered: the setting in force. It is shown until the setting has been read
  // again, so the switch never shows a value older than the one just saved.
  const [answered, setAnswered] = useState<Recognition | null>(null);
  const busy = useRef(false);
  useEffect(() => setAnswered(null), [presence.data]);
  const read = presence.data;
  const value =
    answered ??
    (read && read.enabled !== undefined
      ? { enabled: read.enabled, reach_back_hours: read.reach_back_hours ?? 2 }
      : null);
  if (!value) return <InlineError message={presence.error} />;
  // Only what was changed is sent. A value this page still shows can then never undo a change made
  // since, here or by another administrator. As with the schedule, input during a save is ignored
  // and nothing is disabled, so keyboard focus stays where it is.
  const save = async (change: Partial<Recognition>) => {
    if (busy.current) return;
    busy.current = true;
    setError(null);
    setSaving(true);
    try {
      setAnswered(await put<Recognition>('/presence', change));
    } catch (e) {
      // With no answer the save may still have landed: what is read next says what is in force.
      setError(
        e instanceof ApiError
          ? e.message
          : `${UNREACHABLE} Check what is shown here before you try again.`,
      );
    }
    presence.reload();
    busy.current = false;
    setSaving(false);
  };
  return (
    <Panel
      title="Recognise members' devices when they sign in"
      hint="A member who signs in on a device sees what was blocked on it, with nothing set up on the device."
    >
      <div className="stack" aria-busy={saving}>
        <div className="bar">
          <Switch
            label="Recognise members' devices when they sign in"
            checked={value.enabled}
            onChange={(enabled) => void save({ enabled })}
          />
          <span className="aside">
            Before you switch this on, check that the panel below shows the address of the device
            you are on now. If it shows a proxy's or a router's address, every member arrives from
            that one address and Nyctr cannot tell their devices apart.
          </span>
        </div>
        <div className="rule">
          A member sees what was blocked on that device from
          <Stepper
            label="hours before the first sign-in"
            min={0}
            max={24}
            value={value.reach_back_hours}
            onChange={(reach_back_hours) => void save({ reach_back_hours })}
          />
          hours before they first signed in on it.
        </div>
        <p className="aside">
          Nyctr takes it that the person signing in was the one using the device in those hours. A
          tie never changes whose a device is. It ends 30 days after the last sign-in from the
          device, or when the member or you end it; who signed in on which device is listed under
          People and devices. Switching this off ends every tie at once.
        </p>
        {presence.error && (
          <p className="aside" role="alert">
            Nyctr could not read this setting again, so what is shown here may be out of date.{' '}
            <button className="linklike" onClick={presence.reload}>
              Try again
            </button>
          </p>
        )}
        <InlineError message={error} />
      </div>
    </Panel>
  );
}

/** Whether signing in ties a person to a device, and how far back a new tie reaches. */
type Recognition = { enabled: boolean; reach_back_hours: number };

/** The operator's check that a proxy passes the right address on, before members rely on it. */
function AddressPanel() {
  const seen = useApi<AddressSeen>('/me/address');
  return (
    <Panel
      title="The address Nyctr sees for you"
      hint="Use this to check your proxy. It should be the address of the device you are on now."
    >
      {seen.error ? (
        <InlineError message={seen.error} />
      ) : !seen.data ? (
        <p className="aside">Checking…</p>
      ) : (
        <div className="stack">
          {seen.data.old_name && (
            <div className="note yellow" role="status">
              <div>
                <b>Your list of proxies is set under an old name.</b>
                <p>
                  It is read from <span className="mono">FORWARDED_ALLOW_IPS</span>. That name will
                  stop working in a later release. Set{' '}
                  <span className="mono">NYCTR_TRUSTED_PROXIES</span> to the same list and remove
                  the old name.
                </p>
              </div>
            </div>
          )}
          <p className="rule mono">{seen.data.address || 'Nyctr cannot tell your address'}</p>
          <p>{addressText(seen.data)}</p>
          <p className="aside">
            {!seen.data.address
              ? 'Sign-in attempts from every request like this one are counted together, and no device is recognised.'
              : seen.data.address_is_proxy
                ? 'This address is on your list of proxies. If it is one of your proxies and not your device, something in front of your proxy is hiding your address, or raise the number of proxies Nyctr counts.'
                : 'If this is a router or load balancer and not your device, something in front of your proxy is hiding your address.'}{' '}
            Set with <span className="mono">NYCTR_TRUSTED_PROXIES</span> (your proxies) and{' '}
            <span className="mono">NYCTR_PROXY_HOPS</span> (how many a request passes, now{' '}
            {seen.data.proxy_hops}).
          </p>
        </div>
      )}
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
      {tab === 'system' && (
        <div className="stack">
          <SchedulePanel />
          <ModelPanel />
          <NoticesPanel />
          <SystemPanel rules={rules.data} />
          <RecognitionPanel />
          <AddressPanel />
        </div>
      )}
    </div>
  );
}
