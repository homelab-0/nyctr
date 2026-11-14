import { useEffect, useMemo, useRef, useState } from 'react';
import { api, useApi } from '../api';
import {
  Empty,
  ErrorState,
  Evidence,
  Loading,
  Panel,
  Score,
  SearchInput,
  Seg,
  SourceTag,
} from '../components/ui';
import { counted, lookupSpan, number } from '../lib/counts';
import { failing, uncollected, whyEmpty } from '../lib/coverage';
import { ago, useNow } from '../lib/format';
import type { BlockList, Catalog, Integration, RiskBand } from '../types';

/**
 * The latest blocked lookups from every source, one page at a time, with the rule-based score and
 * how each was attributed. The server filters and counts over everything stored; this page draws
 * only the rows it was sent, so its counts and notes are never about the page alone.
 */
export default function Blocks() {
  const sources = useApi<Integration[]>('/integrations');
  const catalog = useApi<Catalog>('/integrations/catalog');
  const [text, setText] = useState('');
  const [needle, setNeedle] = useState('');
  const [band, setBand] = useState<'all' | RiskBand>('all');
  // The answer on screen and the filter it answers, which is not the one being asked for
  // while a new answer is on its way.
  const [list, setList] = useState<(BlockList & { asked: string }) | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [older, setOlder] = useState<'idle' | 'loading' | 'failed'>('idle');
  const [attempt, setAttempt] = useState(0);
  const now = useNow();
  // Typing asks the server once the person pauses, not on every letter.
  useEffect(() => {
    const timer = setTimeout(() => setNeedle(text.trim()), 250);
    return () => clearTimeout(timer);
  }, [text]);
  const query = useMemo(() => {
    const asked = new URLSearchParams();
    if (band !== 'all') asked.set('band', band);
    if (needle) asked.set('q', needle);
    return asked.toString();
  }, [band, needle]);
  const current = useRef(query);
  current.current = query;
  useEffect(() => {
    const controller = new AbortController();
    setOlder('idle');
    api<BlockList>(`/blocks${query && `?${query}`}`, { signal: controller.signal })
      .then((answer) => {
        if (controller.signal.aborted) return;
        setList({ ...answer, asked: query });
        setError(null);
      })
      .catch((err: Error) => {
        if (!controller.signal.aborted) setError(err.message || 'Unable to reach Nyctr.');
      });
    return () => controller.abort();
  }, [query, attempt]);
  /** Adds the next older page under the rows already drawn; the counts come fresh with it. */
  const showOlder = async () => {
    if (!list?.next) return;
    setOlder('loading');
    const asked = new URLSearchParams(query);
    asked.set('before', list.next);
    try {
      const answer = await api<BlockList>(`/blocks?${asked}`);
      // A filter chosen while this was on its way has its own first page; drop this one.
      if (current.current !== query) return;
      setList({ ...answer, asked: query, rows: [...list.rows, ...answer.rows] });
      setOlder('idle');
    } catch {
      if (current.current === query) setOlder('failed');
    }
  };
  // The span comes from the lookups actually stored, oldest and newest, never a fixed window.
  const span = lookupSpan(list?.total || 0, list?.oldest_at, list?.newest_at, now);
  const partial = (sources.data || []).filter((source) => source.status === 'partial');
  const dns = (sources.data || []).filter((source) => source.provides?.includes('dns.blocks'));
  const waiting = uncollected(dns);
  // A kind of source whose stored lookups all arrived without a device: said once, not on every row.
  const unnamed = useMemo(
    () =>
      new Map(
        Object.entries(list?.counts.source || {})
          .filter(([, kind]) => kind.total > 0 && kind.unnamed === kind.total)
          .map(([kind, { total }]) => [kind, total]),
      ),
    [list],
  );
  const stored = list?.total || 0;
  const rows = list?.rows || [];
  // What the line under the table says is about the rows drawn, so it follows the answer.
  const filtered = !!list?.asked;
  const reading = !!list && list.asked !== query && !error;
  if (error && !list)
    return <ErrorState message={error} retry={() => setAttempt((value) => value + 1)} />;
  if (!list) return <Loading text="Loading blocked lookups…" />;
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="display d2">Blocks</h1>
          <p className="lede">
            Lookups your DNS sources refused.{' '}
            {!stored && waiting.length
              ? waiting.some(failing)
                ? 'Blocked lookups could not be collected.'
                : 'Blocked lookups have not been collected yet.'
              : span}{' '}
            The score is rule-based from the block reason; no score means unknown, not safe.
          </p>
          {sources.error && (
            <div className="note yellow" role="alert">
              <span>
                <b>
                  Whether each source&rsquo;s last collection was complete could not be checked.
                </b>{' '}
                Some sources may have sent only their most recent blocked lookups.
              </span>
              <button className="button secondary small" onClick={sources.reload}>
                Try again
              </button>
            </div>
          )}
          {[...unnamed].map(([kind, count]) => {
            const named = dns.filter((source) => source.provider === kind).map((s) => s.name);
            const declared = catalog.data?.providers
              .find((provider) => provider.id === kind)
              ?.limits?.find((limit) => limit.id === 'upstream_identity');
            return (
              <div className="note yellow" key={kind}>
                <span>
                  <b>
                    {named.join(' and ') || 'A source'} does not say which device made a lookup.
                  </b>{' '}
                  None of its{' '}
                  {count === 1 ? 'one stored lookup' : `${number(count)} stored lookups`} can be
                  tied to a device, so nobody sees them on their own devices and nobody can ask to
                  open one from the portal. {declared?.summary}
                </span>
              </div>
            );
          })}
          {waiting.map((source) => (
            <div className="note yellow" key={source.id}>
              <span>
                {whyEmpty(source)},{' '}
                {source.last_sync
                  ? 'so anything it has blocked since its last collection that worked is missing here.'
                  : 'so none of its blocked lookups are listed here.'}
              </span>
            </div>
          ))}
          {partial.map((source) => (
            <div className="note yellow" key={source.id}>
              <span>
                <b>{source.name}</b>: only the most recent blocked lookups were read at its last
                collection, so older ones are missing.
              </span>
            </div>
          ))}
        </div>
      </header>
      <div className="bar">
        <Seg
          label="Risk band"
          value={band}
          onChange={setBand}
          options={[
            { id: 'all', name: 'All', count: stored },
            { id: 'high', name: 'High', count: list.counts.band.high },
            { id: 'medium', name: 'Medium', count: list.counts.band.medium },
            { id: 'low', name: 'Low', count: list.counts.band.low },
            { id: 'unknown', name: 'No score', count: list.counts.band.unknown },
          ]}
        />
        <SearchInput
          value={text}
          onChange={setText}
          placeholder="Find an address, device or reason"
        />
      </div>
      {error && (
        <div className="note yellow" role="alert">
          <span>
            <b>The list could not be read again.</b> What is below is from the last time it could.
          </span>
          <button className="button secondary small" onClick={() => setAttempt((v) => v + 1)}>
            Try again
          </button>
        </div>
      )}
      {rows.length === 0 ? (
        stored ? (
          <Empty title="No blocks match" text="Clear the filter to see every stored lookup." />
        ) : sources.data && !dns.length ? (
          <Empty
            title="No connected source reports blocked lookups"
            text="Connect a DNS source and collect from it to see what it refused."
          />
        ) : waiting.length ? (
          <Empty
            title={waiting.some(failing) ? 'Could not be collected' : 'Not collected yet'}
            text="Nothing is known about blocked lookups until a collection succeeds."
          />
        ) : (
          <Empty
            title="No blocked lookups are stored"
            text="The last collection brought none back. Lookups are kept for a day."
          />
        )
      ) : (
        <Panel flush>
          <div className="tblwrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Address</th>
                  <th>Score</th>
                  <th>Device</th>
                  <th>Why it was blocked</th>
                  <th>Tied to the device</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.id}>
                    <td className="nowrap muted">{ago(row.observed_at, now)}</td>
                    <th className="dom">{row.domain}</th>
                    <td>
                      <Score value={row.risk_score} />
                    </td>
                    <td>{row.device_name}</td>
                    <td>
                      <span className="srcn">
                        <SourceTag provider={row.source} />
                        {row.reason}
                      </span>
                    </td>
                    <td>
                      {unnamed.has(row.source) ? (
                        <span className="muted">The source does not say</span>
                      ) : (
                        <Evidence kind={row.attribution} />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
      {rows.length > 0 && (
        <div className="bar">
          <p className="aside" role="status">
            {rows.length < list.matching
              ? `Showing the latest ${number(rows.length)} of ${number(list.matching)}`
              : `Showing all ${number(list.matching)}`}
            {filtered
              ? ` that match, out of ${counted(stored, 'stored lookup')}.`
              : ` stored ${list.matching === 1 ? 'lookup' : 'lookups'}.`}
            {older === 'failed' && ' Older lookups could not be read.'}
            {reading && ' Reading…'}
          </p>
          {list.next && !reading && (
            <button
              className="button secondary small"
              onClick={showOlder}
              disabled={older === 'loading'}
            >
              {older === 'loading' ? 'Reading…' : older === 'failed' ? 'Try again' : 'Show older'}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
