import { useEffect, useMemo, useState, type FormEvent } from 'react';
import {
  ArrowLeft,
  Check,
  Clock,
  Hourglass,
  Laptop,
  LogOut,
  Search,
  ShieldAlert,
  X,
} from 'lucide-react';
import { api, ApiError, post, useApi } from '../../api';
import { everyText, useScheduleSummary } from '../../lib/schedule';
import { useAuth } from '../../auth';
import {
  Brand,
  Empty,
  ErrorState,
  Factors,
  InlineError,
  Loading,
  RiskScale,
  Score,
  Seg,
} from '../../components/ui';
import { counted } from '../../lib/counts';
import { ago, detectOs, left, span, useNow, type DeviceOs } from '../../lib/format';
import type {
  AccessRequest,
  Block,
  BlockCoverage,
  BlockList,
  Lease,
  Resource,
  ThisDevice,
} from '../../types';

/** Steps to make a device forget that an address was blocked. Wording is deliberately non-technical. */
const RECONNECT: Record<DeviceOs, { name: string; steps: string[] }> = {
  mac: {
    name: 'Mac',
    steps: [
      'Quit your browser completely: press Command (⌘) and Q together. Closing the window is not enough.',
      'Open the browser again and go back to the page.',
      'Still blocked? Click the Wi-Fi icon at the top of the screen, turn Wi-Fi off, wait five seconds and turn it on.',
    ],
  },
  windows: {
    name: 'Windows PC',
    steps: [
      'Close every browser window.',
      'Open the browser again and go back to the page.',
      'Still blocked? Restart the PC. That clears what it remembered about the address.',
    ],
  },
  iphone: {
    name: 'iPhone or iPad',
    steps: [
      'Swipe up from the bottom of the screen and pause, then swipe the browser up and away to close it.',
      'Open the browser again and go back to the page.',
      'Still blocked? Turn Aeroplane Mode on for five seconds, then off.',
    ],
  },
  android: {
    name: 'Android',
    steps: [
      'Open your recent apps and swipe the browser away to close it.',
      'Open the browser again and go back to the page.',
      'Still blocked? Turn Aeroplane mode on for five seconds, then off.',
    ],
  },
  other: {
    name: 'Other device',
    steps: [
      'Close the browser or app completely, not just the tab.',
      'Open it again and go back to the page.',
      'Still blocked? Disconnect from the network and connect again, or restart the device.',
    ],
  },
};

const STATUS: Record<string, { text: string; tone: string }> = {
  pending: { text: 'Waiting for a person', tone: 'yellow' },
  auto_approved: { text: 'Opened', tone: 'green' },
  approved: { text: 'Approved', tone: 'green' },
  denied: { text: 'Not approved', tone: 'red' },
  reviewed: { text: 'Looked at', tone: '' },
};

function useMemberData() {
  // One page: the latest lookups this person may see. `beyond` is how many older ones are not on it.
  const list = useApi<BlockList>('/blocks');
  const blocks = {
    ...list,
    data: list.data ? list.data.rows : null,
    beyond: list.data ? list.data.total - list.data.rows.length : 0,
  };
  const requests = useApi<AccessRequest[]>('/requests');
  const leases = useApi<Lease[]>('/leases');
  const device = useApi<ThisDevice>('/me/device');
  const devices = useApi<Resource[]>('/devices');
  const coverage = useApi<BlockCoverage>('/blocks/coverage');
  return { blocks, requests, leases, device, devices, coverage };
}
type Data = ReturnType<typeof useMemberData>;

const ASK = 'Ask whoever runs Nyctr';

/**
 * Why Nyctr cannot show this person a blocked site, most basic reason first. Null means it could
 * have: an empty list then really is "nothing was blocked", not "nothing is known".
 */
function notKnown(data: Data): { title: string; text: string } | null {
  if (data.devices.data?.length === 0)
    return {
      title: 'No devices are assigned to you yet',
      text: `Nyctr shows blocked sites only for devices that are yours, and it does not know of any. ${ASK} to add your devices.`,
    };
  // Without the answer an empty list cannot be called clean, so the failure is said instead.
  if (data.coverage.error)
    return {
      title: 'Nyctr cannot tell right now whether anything was blocked',
      text: `It could not check whether blocked sites are being collected. Open this page again in a moment. ${ASK} if it keeps happening.`,
    };
  const cover = data.coverage.data;
  if (cover?.collected === 'failed')
    return {
      title: 'Blocked sites could not be collected',
      text: `Nyctr tried to read what was blocked and could not, so it does not know whether a site was blocked for you. ${ASK} to look into it.`,
    };
  if (cover?.collected === 'none')
    return {
      title: 'Blocked sites are not collected on this network',
      text: `Nothing connected to Nyctr reports blocked sites, so it cannot show any. ${ASK} if a page will not load.`,
    };
  if (cover && cover.collected !== 'yes')
    return {
      title: 'Blocked sites have not been collected yet',
      text: `Nyctr has not finished reading what was blocked on this network, so it does not know whether a site was blocked for you. ${ASK} when it will.`,
    };
  return null;
}

/** One row per address, newest first, so a page that retried ten times shows once. */
function latestPerDomain(blocks: Block[]) {
  const seen = new Set<string>();
  return blocks.filter((block) => {
    const key = `${block.device_id}|${block.domain}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function BlockRow({ block, request, now }: { block: Block; request?: AccessRequest; now: number }) {
  return (
    <a
      className="m-row"
      href={
        request
          ? `#/portal?request=${request.id}`
          : `#/portal?block=${encodeURIComponent(block.id)}`
      }
    >
      <span>
        <span className="dom">{block.domain}</span>
        <span className="d">
          {ago(block.observed_at, now)} on {block.device_name}
        </span>
      </span>
      {request ? (
        <span className={`tag ${STATUS[request.status]?.tone || ''}`}>
          {STATUS[request.status]?.text}
        </span>
      ) : (
        <span className="button secondary small">See why</span>
      )}
    </a>
  );
}

/** Home: blocks on the device in hand first, then the member's other devices, plus a search. */
function Home({ data }: { data: Data }) {
  const [text, setText] = useState('');
  const [found, setFound] = useState<Block[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const now = useNow();
  // How soon a new block can show up here. No wait is promised unless a schedule is on.
  const { user } = useAuth();
  const schedule = useScheduleSummary().data;
  const every = everyText(schedule);
  const comeBack = every
    ? `come back here in a while. Nyctr looks for new blocks ${every}.`
    : schedule && !schedule.enabled && user?.mode !== 'demo'
      ? 'ask whoever runs Nyctr to collect. New blocks show up here only after that.'
      : 'come back here later.';
  const here = data.device.data;
  const gap = notKnown(data);
  const noDevices = data.devices.data?.length === 0;
  // Some stored lookups are tied to nobody's device, so a block of theirs may be among those and
  // missing here. That is said whether or not this person's list is empty.
  // When this device is not recognised either, the sentence at the top says both, once.
  const said = !here?.name && !gap && !!data.coverage.data?.unassigned;
  const partly =
    data.coverage.data?.unassigned && !said
      ? `Some sites blocked on this network cannot be tied to a device, so one of yours may be missing here. ${ASK} if a page will not load.`
      : '';
  // Under a list, a failing or unfinished collection means a newer block may be missing. One
  // sentence carries that and the lookups tied to no device, so two notes never stack.
  const cover = data.coverage.data;
  const unread =
    cover?.collected === 'failed'
      ? 'Nyctr could not read what was blocked just now'
      : cover?.collected === 'none'
        ? 'Nyctr is not collecting what is blocked on this network'
        : cover && cover.collected !== 'yes'
          ? 'Nyctr has not finished reading what was blocked'
          : '';
  const missing = unread
    ? cover?.unassigned && !said
      ? `${unread}, and some sites blocked on this network cannot be tied to a device, so one of yours may be missing here. ${ASK} if a page will not load.`
      : `${unread}, so a newer block may be missing here. ${ASK} if a page will not load.`
    : gap
      ? ''
      : partly;
  const requestFor = useMemo(
    () => new Map((data.requests.data || []).map((row) => [row.block_id, row])),
    [data.requests.data],
  );
  // What an empty list means depends on these, so "nothing was blocked" is never shown before them.
  if (data.blocks.loading || data.devices.loading || data.coverage.loading)
    return <Loading text="Looking for blocked sites…" />;
  if (data.blocks.error)
    return <ErrorState message={data.blocks.error} retry={data.blocks.reload} />;
  const blocks = latestPerDomain(data.blocks.data || []);
  const mine = blocks.filter((block) => here?.device_id && block.device_id === here.device_id);
  const others = blocks.filter((block) => !here?.device_id || block.device_id !== here.device_id);
  /** Looks a typed address up among blocks this person is already allowed to see. */
  const find = async (event: FormEvent) => {
    event.preventDefault();
    const domain = text
      .trim()
      .replace(/^https?:\/\//i, '')
      .split('/')[0];
    if (domain.length < 3) return;
    setPending(true);
    setError(null);
    try {
      setFound(latestPerDomain(await post<Block[]>('/blocks/find', { domain })));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPending(false);
    }
  };
  return (
    <div className="m-col">
      <header className="stack tight">
        <h1 className="display d1">What got blocked?</h1>
        {gap && noDevices ? (
          <p className="lede">
            <b>{gap.title}.</b> {gap.text}
          </p>
        ) : here?.name ? (
          <p className="lede">
            <Laptop size={15} style={{ verticalAlign: '-2px' }} /> You're on <b>{here.name}</b>
            {here.simulated ? ' (demo: pretending this browser is that device).' : '.'}
          </p>
        ) : (
          <p className="lede">
            {/* One sentence when lookups tied to no device are also missing, so two notes never stack. */}
            {cover?.unassigned && !gap
              ? `Nyctr could not tell which of your devices this is, so it is showing all of them, and some sites blocked on this network cannot be tied to a device, so one of yours may be missing here. ${ASK} if a page will not load.`
              : 'Nyctr could not tell which of your devices this is, so it is showing all of them.'}
          </p>
        )}
      </header>
      <form className="m-find" onSubmit={find}>
        <Search size={18} />
        <input
          type="text"
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setFound(null);
          }}
          placeholder="Type the address that would not load, like example.com"
          aria-label="Address that was blocked"
          autoCapitalize="none"
          autoCorrect="off"
        />
        <button
          className="button primary"
          type="submit"
          disabled={pending || text.trim().length < 3}
        >
          Find it
        </button>
      </form>
      <InlineError message={error} />
      {found !== null &&
        (found.length ? (
          <section className="m-card">
            <h2>Found</h2>
            {found.map((block) => (
              <BlockRow key={block.id} block={block} request={requestFor.get(block.id)} now={now} />
            ))}
          </section>
        ) : (
          <Empty
            title={gap?.title || 'Nyctr has not seen that blocked on your devices'}
            text={
              gap?.text ||
              `Try opening the page once more on this device, then ${comeBack} Blocks from the last day show up here. ${partly}`.trim()
            }
          />
        ))}
      {mine.length > 0 && (
        <section className="m-card">
          <h2>Blocked on this device</h2>
          {mine.map((block) => (
            <BlockRow key={block.id} block={block} request={requestFor.get(block.id)} now={now} />
          ))}
        </section>
      )}
      {others.length > 0 && (
        <section className="m-card">
          <h2>{mine.length ? 'On your other devices' : 'Blocked on your devices'}</h2>
          {others.map((block) => (
            <BlockRow key={block.id} block={block} request={requestFor.get(block.id)} now={now} />
          ))}
        </section>
      )}
      {blocks.length > 0 && missing && <p className="aside">{missing}</p>}
      {data.blocks.beyond > 0 && (
        <p className="aside">
          These are the latest blocks on your devices. {counted(data.blocks.beyond, 'older one')}{' '}
          {data.blocks.beyond === 1 ? 'is' : 'are'} not listed here: to find one, type its address
          above.
        </p>
      )}
      {blocks.length === 0 && found === null && !noDevices && (
        <Empty
          // The heading hedges whenever lookups tied to no device exist, wherever the caveat is said.
          title={
            gap?.title ||
            (cover?.unassigned
              ? 'Nyctr has not seen anything blocked on your devices in the last day'
              : 'Nothing has been blocked on your devices in the last day')
          }
          text={
            gap?.text || `If a page will not load, open it again, then ${comeBack} ${partly}`.trim()
          }
        />
      )}
    </div>
  );
}

/** One block: why it was blocked, the score and what went into it, and the form to ask. */
function BlockDetail({ data, id }: { data: Data; id: string }) {
  const [reason, setReason] = useState('');
  const [minutes, setMinutes] = useState('60');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const now = useNow();
  const listed = (data.blocks.data || []).find((item) => item.id === id);
  // The list is only the latest page. One found by its address may be older than that, so a
  // block that is not on the page is asked for by itself; the server applies the same rights.
  const [older, setOlder] = useState<Block | 'gone' | 'failed' | null>(null);
  const [attempt, setAttempt] = useState(0);
  const waiting = data.blocks.loading;
  useEffect(() => {
    if (listed || waiting) return;
    const controller = new AbortController();
    setOlder(null);
    api<Block>(`/blocks/one?id=${encodeURIComponent(id)}`, { signal: controller.signal })
      .then((found) => setOlder(found))
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        setOlder(err instanceof ApiError && err.status === 404 ? 'gone' : 'failed');
      });
    return () => controller.abort();
  }, [id, listed, waiting, attempt]);
  if (waiting || (!listed && older === null)) return <Loading />;
  if (!listed && older === 'failed')
    return (
      <div className="m-col">
        <ErrorState
          message="This block could not be read just now."
          retry={() => setAttempt((value) => value + 1)}
        />
      </div>
    );
  const block = listed || (typeof older === 'object' ? older : null);
  if (!block)
    return (
      <div className="m-col">
        <Empty
          title="That block is no longer listed"
          text="Blocks stay for a day. Open the page again on your device and it will reappear."
          action={
            <a className="button primary" href="#/portal">
              Back to blocked sites
            </a>
          }
        />
      </div>
    );
  const risky = block.risk_band === 'high';
  /** Sends the request. The server scores it and applies the administrator's access rule. */
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      const row = await post<AccessRequest>('/requests', {
        block_id: block.id,
        reason: reason.trim(),
        duration_minutes: Number(minutes),
      });
      data.requests.reload();
      data.leases.reload();
      window.location.hash = `/portal?request=${row.id}`;
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPending(false);
    }
  };
  return (
    <div className="m-col">
      <a className="back" href="#/portal">
        <ArrowLeft size={16} /> Blocked sites
      </a>
      <header className="stack tight">
        <h1 className="display d2 dom">{block.domain}</h1>
        <p className="lede">
          Blocked {ago(block.observed_at, now)} on {block.device_name}.
        </p>
      </header>
      <section className="m-card pad">
        <div className="m-score">
          <Score value={block.risk_score} big />
          <div>
            <h2>
              {block.risk_band === 'unknown'
                ? 'Nyctr could not score this one'
                : `${block.risk_band[0].toUpperCase()}${block.risk_band.slice(1)} risk`}
            </h2>
            <p>{block.risk_explanation}</p>
          </div>
        </div>
        <RiskScale value={block.risk_score} />
        <h3>What that is based on</h3>
        <Factors items={block.risk_factors} />
      </section>
      {risky && (
        <div className="note red">
          <ShieldAlert size={17} />
          <div>
            <b>This one looks risky.</b>
            <p>You can still ask. It will not open by itself; an administrator will decide.</p>
          </div>
        </div>
      )}
      <form className="m-card pad form-stack" onSubmit={submit}>
        <h2>Ask to open it</h2>
        <label className="field">
          <span>What do you need it for?</span>
          <textarea
            rows={3}
            required
            minLength={5}
            maxLength={500}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="For example: I'm trying to see the wedding photos"
          />
        </label>
        <div className="field">
          <span>For how long?</span>
          <Seg
            label="How long"
            value={minutes}
            onChange={setMinutes}
            options={[30, 60, 120, 240].map((value) => ({ id: String(value), name: span(value) }))}
          />
        </div>
        <InlineError message={error} />
        <button
          className="button primary large full"
          type="submit"
          disabled={pending || reason.trim().length < 5}
        >
          {pending ? 'Checking…' : 'Ask to open it'}
        </button>
        <p className="aside">
          Nyctr checks the address straight away. Safe ones open in a few seconds.
        </p>
      </form>
    </div>
  );
}

/** The outcome of a request: open (with reconnect steps), waiting, or declined. Never vague. */
function Result({ data, id }: { data: Data; id: string }) {
  const [os, setOs] = useState<DeviceOs>(detectOs());
  const now = useNow(5000);
  if (data.requests.loading || data.leases.loading) return <Loading />;
  const row = (data.requests.data || []).find((item) => item.id === id);
  if (!row)
    return (
      <div className="m-col">
        <Empty
          title="That request could not be found"
          text=""
          action={
            <a className="button primary" href="#/portal">
              Back
            </a>
          }
        />
      </div>
    );
  const lease = (data.leases.data || []).find((item) => item.request_id === row.id);
  const open =
    lease?.status === 'active' && lease.execution !== 'not_applied' && lease.execution !== 'failed';
  const remaining = lease ? left(lease.expires_at, now) : null;
  return (
    <div className="m-col">
      <a className="back" href="#/portal">
        <ArrowLeft size={16} /> Blocked sites
      </a>
      {open ? (
        <>
          <header className="m-result ok">
            <span className="m-badge">
              <Check size={26} />
            </span>
            <h1 className="display d1">It's open.</h1>
            <p className="lede">
              <b className="dom">{row.domain}</b> works for the next{' '}
              {remaining ? remaining.replace(' left', '') : 'few minutes'}. It will close by itself
              after that.
            </p>
          </header>
          <section className="m-card pad">
            <div className="bar">
              <h2>
                One more step on {os === 'other' ? 'this device' : `your ${RECONNECT[os].name}`}
              </h2>
              <select
                className="os"
                aria-label="Which device are you on"
                value={os}
                onChange={(e) => setOs(e.target.value as DeviceOs)}
              >
                {(Object.keys(RECONNECT) as DeviceOs[]).map((key) => (
                  <option key={key} value={key}>
                    {RECONNECT[key].name}
                  </option>
                ))}
              </select>
            </div>
            <p className="aside">
              Your device remembers for a few minutes that the address was blocked. This makes it
              forget.
            </p>
            <ol className="m-steps">
              {RECONNECT[os].steps.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </section>
        </>
      ) : row.status === 'pending' ? (
        <header className="m-result wait">
          <span className="m-badge">
            <Hourglass size={24} />
          </span>
          <h1 className="display d1">A person needs to look at this.</h1>
          <p className="lede">
            {row.decision_note || 'It will not open by itself.'} You do not need to do anything
            else. The answer will show up here.
          </p>
        </header>
      ) : row.status === 'denied' ? (
        <header className="m-result no">
          <span className="m-badge">
            <X size={26} />
          </span>
          <h1 className="display d1">Not this time.</h1>
          <p className="lede">
            {row.review_note
              ? `The note says: “${row.review_note}”`
              : 'The request was not approved.'}
          </p>
        </header>
      ) : lease?.status === 'ended' ? (
        <header className="m-result">
          <span className="m-badge">
            <Clock size={24} />
          </span>
          <h1 className="display d1">The time ran out.</h1>
          <p className="lede">
            Access to {row.domain} has closed again. If you still need it, open the page and ask
            once more.
          </p>
        </header>
      ) : row.status === 'reviewed' ? (
        <header className="m-result">
          <span className="m-badge">
            <Clock size={24} />
          </span>
          <h1 className="display d1">Looked at, nothing changed.</h1>
          <p className="lede">
            {row.review_note
              ? `The note says: “${row.review_note}”`
              : 'Someone looked at this request and did not open the address.'}
          </p>
        </header>
      ) : (
        <header className="m-result wait">
          <span className="m-badge">
            <Hourglass size={24} />
          </span>
          <h1 className="display d1">Approved, but not switched on yet.</h1>
          <p className="lede">
            An administrator said yes and still has to turn it on. Check back in a little while.
          </p>
        </header>
      )}
      <section className="m-card pad">
        <div className="m-score">
          <Score value={row.risk_score} big />
          <div>
            <h2>What Nyctr found when it checked {row.domain}</h2>
            <p>
              {row.status === 'auto_approved'
                ? row.decision_note
                : 'This is the score the administrator will see too.'}
            </p>
          </div>
        </div>
        <RiskScale value={row.risk_score} />
        {row.risk_factors && <Factors items={row.risk_factors} />}
      </section>
    </div>
  );
}

function MyRequests({ data }: { data: Data }) {
  const now = useNow();
  // The reason stands only over an empty list of blocked sites. With one listed there is
  // something to ask about, whatever the collection is doing.
  const gap = data.blocks.data?.length === 0 ? notKnown(data) : null;
  if (data.requests.loading) return <Loading />;
  const rows = data.requests.data || [];
  const leaseFor = new Map((data.leases.data || []).map((lease) => [lease.request_id, lease]));
  return (
    <div className="m-col">
      <h1 className="display d2">My requests</h1>
      {rows.length === 0 ? (
        <Empty
          title="You have not asked for anything yet"
          text={
            gap
              ? `${gap.title}, so there is nothing to ask about yet. ${gap.text}`
              : 'When a page is blocked, find it under Blocked sites and ask to open it.'
          }
        />
      ) : (
        <section className="m-card">
          {rows.map((row) => {
            const lease = leaseFor.get(row.id);
            // A countdown reads as "it is open", so show one only when the change really happened.
            const active = lease?.status === 'active';
            const switchedOn =
              active && lease.execution !== 'not_applied' && lease.execution !== 'failed';
            const remaining = switchedOn ? left(lease.expires_at, now) : null;
            const waiting = active && !switchedOn;
            return (
              <a className="m-row" key={row.id} href={`#/portal?request=${row.id}`}>
                <span>
                  <span className="dom">{row.domain}</span>
                  <span className="d">
                    Asked {ago(row.created_at, now)} from {row.device_name}
                  </span>
                </span>
                <span
                  className={`tag ${remaining ? 'green' : waiting ? 'yellow' : lease?.status === 'ended' ? '' : STATUS[row.status]?.tone || ''}`}
                >
                  {remaining ||
                    (waiting
                      ? 'Approved, not on yet'
                      : lease?.status === 'ended'
                        ? 'Closed again'
                        : STATUS[row.status]?.text)}
                </span>
              </a>
            );
          })}
        </section>
      )}
    </div>
  );
}

function MyDevices({ data }: { data: Data }) {
  const devices = data.devices;
  if (devices.loading) return <Loading />;
  if (devices.error) return <ErrorState message={devices.error} retry={devices.reload} />;
  const gap = devices.data?.length === 0 ? notKnown(data) : null;
  if (gap)
    return (
      <div className="m-col">
        <h1 className="display d2">My devices</h1>
        <Empty title={gap.title} text={gap.text} icon={Laptop} />
      </div>
    );
  return (
    <div className="m-col">
      <h1 className="display d2">My devices</h1>
      <p className="lede">You see blocked sites only from these. {ASK} to add one.</p>
      <section className="m-card">
        {(devices.data || []).map((device) => (
          <div className="m-row" key={device.id}>
            <span>
              <span className="dom">{device.name}</span>
              <span className="d">
                {device.classification === 'shared' ? 'Shared device' : 'Yours'}
              </span>
            </span>
            {data.device.data?.device_id === device.id && (
              <span className="tag blue">This device</span>
            )}
          </div>
        ))}
      </section>
    </div>
  );
}

/**
 * The member portal. One calm column: what was blocked, why, and a single way to ask.
 * Members see only their own devices' blocks; the server enforces that, not this page.
 */
export default function Portal({ page, params }: { page: string; params: URLSearchParams }) {
  const { user, logout } = useAuth();
  const data = useMemberData();
  const [error, setError] = useState<string | null>(null);
  const block = params.get('block');
  const request = params.get('request');
  const section = page === 'requests' || page === 'devices' ? page : 'portal';
  useEffect(() => {
    document.title = 'Blocked sites · Nyctr';
    window.scrollTo?.(0, 0);
  }, [section, block, request]);
  if (!user) return null;
  return (
    <div className="member">
      <header className="m-top">
        <a href="#/portal" aria-label="Nyctr home">
          <Brand />
        </a>
        <nav aria-label="Portal">
          {[
            ['portal', 'Blocked sites'],
            ['requests', 'My requests'],
            ['devices', 'My devices'],
          ].map(([id, name]) => (
            <a key={id} href={`#/${id}`} aria-current={section === id ? 'page' : undefined}>
              {name}
            </a>
          ))}
        </nav>
        <span className="m-user">
          {user.console_url && (
            <a className="m-console" href={user.console_url}>
              Open the console
            </a>
          )}
          <span className="who">{user.name}</span>
          <button
            className="icon-button"
            title="Sign out"
            aria-label="Sign out"
            onClick={() => logout().catch((e: Error) => setError(e.message))}
          >
            <LogOut size={16} />
          </button>
        </span>
      </header>
      <main id="main-content">
        <InlineError message={error} />
        {section === 'requests' ? (
          <MyRequests data={data} />
        ) : section === 'devices' ? (
          <MyDevices data={data} />
        ) : request ? (
          <Result data={data} id={request} />
        ) : block ? (
          // Keyed by the block: what was read or typed for one never stands under another.
          <BlockDetail key={block} data={data} id={block} />
        ) : (
          <Home data={data} />
        )}
      </main>
    </div>
  );
}
