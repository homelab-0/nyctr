import { useEffect, useState, type FormEvent } from 'react';
import { Ban, Check, Copy, Lock, RotateCcw, Ticket } from 'lucide-react';
import { post, put, useApi } from '../api';
import { everyText, useSchedule } from '../lib/schedule';
import {
  Empty,
  ErrorState,
  Factors,
  InlineError,
  KV,
  Loading,
  Panel,
  Score,
  Stepper,
  Switch,
} from '../components/ui';
import { ago, bytes, clock, left, plural, someNames, span, useNow } from '../lib/format';
import { useAuth } from '../auth';
import type { GuestDevice, GuestOverview, GuestPass, GuestRule } from '../types';

const STATE: Record<GuestDevice['state'], { text: string; tone: string }> = {
  online: { text: 'Online', tone: 'green' },
  waiting: { text: 'On the sign-in page', tone: 'yellow' },
  cut: { text: 'Cut off', tone: 'red' },
  locked: { text: 'Locked out', tone: 'red' },
  offline: { text: 'Gone', tone: '' },
};
const LENGTHS = [60, 240, 480, 1440, 4320, 10080];

/** Copies a pass code, falling back silently where the clipboard is unavailable. */
function CopyCode({ code }: { code: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="code"
      title="Copy the code"
      onClick={() => {
        void navigator.clipboard?.writeText(code).then(
          () => setDone(true),
          () => setDone(false),
        );
      }}
    >
      <span className="mono">{code}</span>
      <Copy size={13} />
      {done && <span className="sr-only">Copied</span>}
    </button>
  );
}

/**
 * States the sign-in design where the administrator works: the network source serves the
 * page, Nyctr is not reachable from the guest network, and data comes back by Nyctr reading
 * that source. The source is named from what is connected, never assumed.
 */
function HowGuestsGetOn({
  portal,
  every,
}: {
  portal: GuestOverview['portal'];
  every: string | null;
}) {
  const [copied, setCopied] = useState(false);
  const gated = portal.wifi.filter((item) => item.captive_portal);
  const net = portal.served_by.join(' and ') || 'Your network system';
  return (
    <Panel title="How guests get on" hint={`${net} shows the sign-in page. Nyctr never does.`}>
      <div className="stack">
        <ol className="flow">
          <li>
            <b>The guest joins the guest Wi-Fi.</b> {net} holds the device and shows its own sign-in
            page.
          </li>
          <li>
            <b>They type a pass code</b> you issued here, or you let the waiting device on from this
            screen.
          </li>
          <li>
            <b>Nyctr reads {net}</b> to see who is on, where, and what was blocked.{' '}
            {portal.nudge
              ? 'The network also tells Nyctr to look straight away.'
              : every
                ? `It looks at each collection, ${every}.`
                : 'It looks when you collect from the source.'}
          </li>
        </ol>
        <div className="note green">
          <div>
            <b>Guests never need to reach Nyctr.</b>
            <p>
              Nothing on the guest network talks to this console, so block it from there in your
              firewall. The key that can cut devices off never sits behind a page guests can open.
            </p>
          </div>
        </div>
        <div>
          <h3>Wi-Fi names reported</h3>
          {portal.wifi.length === 0 ? (
            <p className="aside">
              Nyctr has none. It reads them when it collects from your network source.
            </p>
          ) : (
            <ul className="wifi">
              {portal.wifi.map((item) => (
                <li key={item.name}>
                  <span>
                    <span className="t">{item.name}</span>
                    {item.network && <span className="d"> on {item.network}</span>}
                  </span>
                  <span className={`tag ${item.captive_portal ? 'green' : ''}`}>
                    {item.captive_portal ? 'Sign-in page on' : 'No sign-in page'}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {portal.wifi.length > 0 && gated.length === 0 && (
            <p className="aside">
              No Wi-Fi name sits behind a sign-in page, so passes and the cut-off have nothing to
              act on. Turn on the guest sign-in page with passes for your guest Wi-Fi at the source.
            </p>
          )}
        </div>
        <div>
          <div className="bar">
            <h3>Notice for the sign-in page</h3>
            <button
              className="button quiet small"
              onClick={() => {
                void navigator.clipboard?.writeText(portal.notice).then(
                  () => setCopied(true),
                  () => setCopied(false),
                );
              }}
            >
              <Copy size={14} /> {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <p className="aside">
            Nyctr does not edit the sign-in page. Paste this into its terms box so guests know what
            is recorded.
          </p>
          <blockquote className="quote">{portal.notice}</blockquote>
        </div>
      </div>
    </Panel>
  );
}

/**
 * Guest Wi-Fi: issue passes, see who is on and what Nyctr can tell about them, and cut a device
 * off. The automatic cut-off is a counted rule written here; no model score can trigger it.
 */
export default function Guests({
  params,
  onChange,
}: {
  params: URLSearchParams;
  onChange: () => void;
}) {
  const { user } = useAuth();
  const guests = useApi<GuestOverview>('/guests');
  const [data, setData] = useState<GuestOverview | null>(null);
  const [selected, setSelected] = useState<string | null>(params.get('id'));
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ name: '', minutes: 240, guest_limit: 1 });
  const [issued, setIssued] = useState<GuestPass | null>(null);
  const [admitFor, setAdmitFor] = useState(240);
  const now = useNow();
  const every = everyText(useSchedule().data);
  useEffect(() => {
    if (guests.data) setData(guests.data);
  }, [guests.data]);
  useEffect(() => {
    if (params.get('id')) setSelected(params.get('id'));
  }, [params]);

  /** Runs one change and then shows the server's view; errors are shown, never swallowed. */
  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      const result = await action();
      if (result && typeof result === 'object' && 'devices' in result)
        setData(result as GuestOverview);
      else guests.reload();
      onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  if (!data && guests.loading) return <Loading text="Loading guest Wi-Fi…" />;
  if (guests.error && !data) return <ErrorState message={guests.error} retry={guests.reload} />;
  if (!data) return null;
  const readOnly = data.writes === 'disabled';
  const device = data.devices.find((item) => item.id === selected) || null;
  const issue = (event: FormEvent) => {
    event.preventDefault();
    void run(async () => {
      setIssued(await post<GuestPass>('/guests/passes', form));
      setForm({ ...form, name: '' });
    });
  };
  const saveRule = (rule: GuestRule) => void run(() => put('/rules/guest', rule));
  const act = (action: 'cut' | 'restore' | 'lock' | 'admit') =>
    device &&
    void run(() =>
      post('/guests/actions', {
        device_id: device.id,
        action,
        ...(action === 'admit' ? { minutes: admitFor } : {}),
      }),
    );
  const live = data.passes.filter((pass) => pass.state !== 'ended');
  // Only sources that have been read are named; the full list is on Sources.
  const readNames = data.sources
    .filter((item) => item.collected !== false)
    .map((item) => item.name);
  const source = someNames(data.sources.map((item) => item.name)) || 'your network source';
  // Why Nyctr cannot tell who is a guest here, when it cannot: said first, before passes or cut-offs,
  // and only from what the source reported. A source that reports guest devices is never called blind.
  const wifi = data.portal.wifi;
  const blind = data.devices.length
    ? null
    : !data.sources.length
      ? {
          title: 'No connected source can tell guests from other devices.',
          text: 'Nyctr does not know who is a guest here. Connect a network source that reports guest Wi-Fi to see them.',
        }
      : !wifi.length
        ? {
            title: `Nyctr has no Wi-Fi names and no guest devices from ${source}.`,
            text: 'So it does not know whether anyone is on the guest Wi-Fi.',
          }
        : !wifi.some((item) => item.captive_portal)
          ? {
              title: `No Wi-Fi name reported by ${source} uses a sign-in page, and Nyctr has no guest devices from ${source}.`,
              text: `So Nyctr cannot tell who is a guest here, and passes and the cut-off have nothing to act on. Turning on the guest sign-in page with passes at ${source} gives them something to act on.`,
            }
          : null;
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="display d2">Guests</h1>
          <p className="lede">
            {data.devices.length
              ? `${plural(data.devices.length, 'guest device')} seen, ${plural(live.length, 'pass', 'passes')} live.`
              : blind
                ? 'Nyctr cannot tell who is a guest here.'
                : 'No guest devices are connected.'}{' '}
            Guests sign in on the page your network shows. Nyctr stays out of their path
            {data.sources.length && !readNames.length ? (
              ' and has not read who is on yet: no source has been collected.'
            ) : (
              <>
                {' '}
                and reads who is on from{' '}
                <a href="#/sources" title={readNames.join(', ')}>
                  {someNames(readNames) || source}
                </a>
                .
              </>
            )}
          </p>
        </div>
      </header>
      {blind && (
        <div className="note yellow" role="status">
          <div>
            <b>{blind.title}</b>
            <p>{blind.text}</p>
          </div>
        </div>
      )}
      {readOnly && !!data.sources.length && (
        <div className="note yellow">
          <div>
            <b>Nyctr is read-only for {source}.</b>
            <p>
              You can watch guests here. Issuing passes and cutting devices off needs an operator to
              allow changes to it in NYCTR_PROVIDER_WRITES.
            </p>
          </div>
        </div>
      )}
      <InlineError message={error} />
      <div className="split">
        <div className="stack">
          <Panel title="Who is on" flush>
            {data.devices.length === 0 ? (
              <p className="pad muted">
                {blind
                  ? 'Not known. Nyctr cannot tell who is a guest here.'
                  : 'Nobody is on the guest Wi-Fi.'}
              </p>
            ) : (
              <div className="tblwrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Device</th>
                      <th>State</th>
                      <th>Risk</th>
                      <th>Where</th>
                      <th>Pass</th>
                      <th>Lookups blocked</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.devices.map((item) => (
                      <tr
                        key={item.id}
                        className={`click ${device?.id === item.id ? 'on' : ''}`}
                        onClick={() => setSelected(item.id)}
                      >
                        <th>
                          <button className="linklike" onClick={() => setSelected(item.id)}>
                            {item.name}
                          </button>
                        </th>
                        <td>
                          <span className={`tag ${STATE[item.state].tone}`}>
                            {STATE[item.state].text}
                          </span>
                        </td>
                        <td>
                          <Score value={item.risk.score} />
                        </td>
                        <td>{item.access_point?.name || 'Unknown'}</td>
                        <td>
                          {item.pass ? (
                            <span className="srcn">
                              <i className="ev inferred" />
                              {item.pass.name}
                            </span>
                          ) : (
                            <span className="muted">Not known</span>
                          )}
                        </td>
                        <td className="num">
                          {item.lookups.blocked}
                          {item.lookups.threat > 0 && (
                            <span className="tag red" style={{ marginLeft: 8 }}>
                              {item.lookups.threat} threat
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
          <Panel
            title="Automatic cut-off"
            hint={
              every
                ? `A rule you write. Nyctr applies it after each collection, ${every}.`
                : 'A rule you write. Nyctr applies it when a source is collected.'
            }
          >
            <div className="stack">
              <p className="rule">
                Cut a guest off after
                <Stepper
                  label="lookups"
                  min={1}
                  max={50}
                  value={data.rule.hits}
                  onChange={(hits) => saveRule({ ...data.rule, hits })}
                />
                lookups of threat-listed addresses within
                <Stepper
                  label="minutes"
                  min={1}
                  max={120}
                  value={data.rule.minutes}
                  onChange={(minutes) => saveRule({ ...data.rule, minutes })}
                />
                minutes.
              </p>
              <div className="bar">
                <Switch
                  label="Automatic cut-off"
                  checked={data.rule.enabled}
                  onChange={(enabled) => saveRule({ ...data.rule, enabled })}
                />
                <span className="aside">
                  {readOnly
                    ? 'While read-only, a match is reported as a finding and nothing is cut.'
                    : 'A cut-off device stays off until you let it back on.'}
                </span>
              </div>
              <div className="note hatch">
                <div>
                  <b>Not collected</b>
                  <ul className="plain">
                    {data.not_collected.map((line) => (
                      <li key={line}>{line}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </Panel>
          <Panel title="Passes" flush>
            {data.passes.length === 0 ? (
              <p className="pad muted">No passes yet.</p>
            ) : (
              <div className="tblwrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>For</th>
                      <th>Code</th>
                      <th>Length</th>
                      <th>State</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {data.passes.map((pass) => (
                      <tr key={pass.id}>
                        <th>{pass.name}</th>
                        <td>
                          {pass.state === 'ended' ? (
                            <span className="muted mono">{pass.code}</span>
                          ) : (
                            <CopyCode code={pass.code} />
                          )}
                        </td>
                        <td>
                          {span(pass.minutes)}
                          <div className="muted tiny">
                            {plural(pass.guest_limit || 1, 'device')}
                          </div>
                        </td>
                        <td>
                          {pass.state === 'unused'
                            ? 'Not used yet'
                            : pass.state === 'ended'
                              ? 'Ended'
                              : left(pass.expires_at, now) || 'In use'}
                        </td>
                        <td>
                          {pass.state !== 'ended' && (
                            <button
                              className="button quiet small"
                              disabled={busy || (readOnly && pass.execution === 'applied')}
                              onClick={() => void run(() => post(`/guests/passes/${pass.id}/end`))}
                            >
                              End
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </div>
        <div className="stack">
          {device ? (
            <Panel
              title={device.name}
              action={
                <span className={`tag ${STATE[device.state].tone}`}>
                  {STATE[device.state].text}
                </span>
              }
            >
              <div className="stack">
                <div className="bar">
                  <Score value={device.risk.score} big />
                  <div className="button-row">
                    {device.state === 'waiting' && (
                      <>
                        <select
                          className="os"
                          aria-label="Let it on for"
                          value={admitFor}
                          onChange={(e) => setAdmitFor(Number(e.target.value))}
                        >
                          {LENGTHS.map((value) => (
                            <option key={value} value={value}>
                              {span(value)}
                            </option>
                          ))}
                        </select>
                        <button
                          className="button primary small"
                          disabled={busy || readOnly}
                          onClick={() => act('admit')}
                        >
                          <Check size={15} /> Let it on
                        </button>
                      </>
                    )}
                    {device.state === 'online' || device.state === 'waiting' ? (
                      <button
                        className="button danger small"
                        disabled={busy || readOnly}
                        onClick={() => act('cut')}
                      >
                        <Ban size={15} /> Cut off
                      </button>
                    ) : (
                      <button
                        className="button secondary small"
                        disabled={busy || readOnly}
                        onClick={() => act('restore')}
                      >
                        <RotateCcw size={15} /> Let it back on
                      </button>
                    )}
                    {device.state !== 'locked' && (
                      <button
                        className="button secondary small"
                        disabled={busy || readOnly}
                        onClick={() => act('lock')}
                      >
                        <Lock size={15} /> Lock out
                      </button>
                    )}
                  </div>
                </div>
                <Factors items={device.risk.factors} />
                <KV
                  items={[
                    ['Access point', device.access_point?.name || 'Unknown'],
                    [
                      'Got on with',
                      device.joined_by === 'administrator'
                        ? 'Let on from this console'
                        : device.pass
                          ? `${device.pass.name} (matched by time)`
                          : device.state === 'waiting'
                            ? 'Nothing yet. It is on the sign-in page.'
                            : 'A pass, which one is not known',
                    ],
                    ['Data used', bytes(device.authorization?.bytes ?? undefined)],
                    [
                      'Pass ends',
                      device.authorization?.expires_at
                        ? left(device.authorization.expires_at, now) || 'Ended'
                        : 'Not known',
                    ],
                    ['Hardware address', <span className="mono">{device.mac || 'Unknown'}</span>],
                  ]}
                />
                {device.state === 'locked' && (
                  <p className="aside">
                    Locked out means Nyctr cuts this device off again each time it collects. A phone
                    can change its hardware address to get around that.
                  </p>
                )}
                <div>
                  <h3>What it did</h3>
                  <ol className="timeline">
                    {device.timeline.map((item, index) => (
                      <li key={index} className={item.kind}>
                        <time title={new Date(item.at).toLocaleString()}>{clock(item.at)}</time>
                        <div>
                          <span>{item.text}</span>
                          {item.detail && <span className="d">{item.detail}</span>}
                          {item.evidence === 'inferred' && (
                            <span className="d">
                              <i className="ev inferred" /> Tied to this device by its name, which
                              is a guess
                            </span>
                          )}
                        </div>
                      </li>
                    ))}
                  </ol>
                </div>
                {user?.mode === 'demo' && device.state === 'online' && (
                  <button
                    className="button quiet small"
                    disabled={busy}
                    onClick={() =>
                      void run(() =>
                        post<GuestOverview>('/demo/guest-activity', { device_id: device.id }),
                      )
                    }
                  >
                    Demo: make this device look up three threat sites
                  </button>
                )}
              </div>
            </Panel>
          ) : (
            data.devices.length > 0 && (
              <Empty title="Pick a device" text="Its timeline, risk and controls open here." />
            )
          )}
          <HowGuestsGetOn portal={data.portal} every={every} />
          <Panel title="New guest pass">
            <form className="form-stack" onSubmit={issue}>
              <label className="field">
                <span>Who is it for</span>
                <input
                  type="text"
                  required
                  maxLength={120}
                  value={form.name}
                  placeholder="Plumber, Saturday"
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </label>
              <div className="grid2">
                <label className="field">
                  <span>Works for</span>
                  <select
                    value={form.minutes}
                    onChange={(e) => setForm({ ...form, minutes: Number(e.target.value) })}
                  >
                    {LENGTHS.map((value) => (
                      <option key={value} value={value}>
                        {span(value)}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  <span>Devices</span>
                  <select
                    value={form.guest_limit}
                    onChange={(e) => setForm({ ...form, guest_limit: Number(e.target.value) })}
                  >
                    {[1, 2, 4, 8].map((value) => (
                      <option key={value} value={value}>
                        {value}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <button
                className="button primary"
                type="submit"
                disabled={busy || readOnly || !form.name.trim()}
              >
                <Ticket size={16} /> Issue pass
              </button>
              {issued && (
                <div className="note green">
                  <div>
                    <b>Pass for {issued.name}</b>
                    <p>
                      Give them this code: <CopyCode code={issued.code} />. They join the guest
                      Wi-Fi and type it into the sign-in page that appears.{' '}
                      {issued.execution === 'simulated'
                        ? 'Simulated: demo mode does not create it at the source.'
                        : `Created in ${source}.`}{' '}
                      Issued {ago(issued.created_at, now)}.
                    </p>
                  </div>
                </div>
              )}
            </form>
          </Panel>
        </div>
      </div>
    </div>
  );
}
