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
import { ago, useNow } from '../lib/format';
import type { Block, RiskBand } from '../types';

/** Recent blocked lookups from every source, with the rule-based score and how each was attributed. */
export default function Blocks() {
  const blocks = useApi<Block[]>('/blocks');
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
            Lookups your DNS source refused in the last day. The score is rule-based from the block
            reason; no score means unknown, not safe.
          </p>
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
        <Empty
          title="No blocks match"
          text="Clear the filter, or collect from your DNS source again."
        />
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
                      <Evidence kind={row.attribution} />
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
