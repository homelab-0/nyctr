import { useMemo, useState } from 'react';
import { useApi } from '../api';
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
import { lookupSpan } from '../lib/counts';
import { failing, uncollected, whyEmpty } from '../lib/coverage';
import { ago, useNow } from '../lib/format';
import type { Block, Catalog, Integration, RiskBand } from '../types';

/** Recent blocked lookups from every source, with the rule-based score and how each was attributed. */
export default function Blocks() {
  const blocks = useApi<Block[]>('/blocks');
  const sources = useApi<Integration[]>('/integrations');
  const catalog = useApi<Catalog>('/integrations/catalog');
  const [text, setText] = useState('');
  const [band, setBand] = useState<'all' | RiskBand>('all');
  const now = useNow();
  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return (blocks.data || []).filter(
      (row) =>
        (band === 'all' || row.risk_band === band) &&
        (!needle ||
          row.domain.includes(needle) ||
          row.device_name.toLowerCase().includes(needle) ||
          row.reason.toLowerCase().includes(needle)),
    );
  }, [blocks.data, text, band]);
  // The span comes from the lookups actually stored, oldest and newest, never a fixed window.
  const span = useMemo(() => {
    const times = (blocks.data || []).map((row) => row.observed_at).sort();
    return lookupSpan(times.length, times[0], times.at(-1), now);
  }, [blocks.data, now]);
  const partial = (sources.data || []).filter((source) => source.status === 'partial');
  const dns = (sources.data || []).filter((source) => source.provides?.includes('dns.blocks'));
  const waiting = uncollected(dns);
  // A kind of source whose stored lookups all arrived without a device: said once, not on every row.
  const unnamed = useMemo(() => {
    const found = new Map<string, number>();
    for (const row of blocks.data || []) found.set(row.source, (found.get(row.source) || 0) + 1);
    for (const row of blocks.data || [])
      if (row.attribution !== 'unattributed') found.delete(row.source);
    return found;
  }, [blocks.data]);
  const stored = blocks.data?.length || 0;
  const count = (value: RiskBand) =>
    (blocks.data || []).filter((row) => row.risk_band === value).length;
  if (blocks.loading) return <Loading text="Loading blocked lookups…" />;
  if (blocks.error) return <ErrorState message={blocks.error} retry={blocks.reload} />;
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
                  None of its {count === 1 ? 'one stored lookup' : `${count} stored lookups`} can be
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
            { id: 'all', name: 'All', count: blocks.data?.length || 0 },
            { id: 'high', name: 'High', count: count('high') },
            { id: 'medium', name: 'Medium', count: count('medium') },
            { id: 'low', name: 'Low', count: count('low') },
            { id: 'unknown', name: 'No score', count: count('unknown') },
          ]}
        />
        <SearchInput
          value={text}
          onChange={setText}
          placeholder="Find an address, device or reason"
        />
      </div>
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
    </div>
  );
}
