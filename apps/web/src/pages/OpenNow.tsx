import { useState } from 'react';
import { post, useApi } from '../api';
import { Empty, ErrorState, InlineError, Loading, Panel, Score } from '../components/ui';
import { ago, executionText, left, plural, useNow } from '../lib/format';
import type { Lease, Suggestion } from '../types';

/**
 * Every exception Nyctr is responsible for: what is open, who decided, what happened at the
 * provider, and when it ends. Suggestions never apply themselves.
 */
export default function OpenNow({ onChange }: { onChange: () => void }) {
  const leases = useApi<Lease[]>('/leases');
  const suggestions = useApi<Suggestion[]>('/suggestions');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const now = useNow(5000);
  /** Runs one change, then reloads both lists so the screen reflects the server. */
  const run = async (key: string, action: () => Promise<unknown>) => {
    setBusy(key);
    setError(null);
    try {
      await action();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
      leases.reload();
      suggestions.reload();
      onChange();
    }
  };
  if (leases.loading) return <Loading text="Loading open access…" />;
  if (leases.error) return <ErrorState message={leases.error} retry={leases.reload} />;
  const all = leases.data || [];
  const active = all.filter((lease) => lease.status === 'active');
  const ended = all.filter((lease) => lease.status === 'ended').slice(0, 20);
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="display d2">Open now</h1>
          <p className="lede">
            {active.length
              ? `${plural(active.length, 'exception')} open. Temporary ones close themselves when their time is up.`
              : 'Nothing is open. Temporary access appears here while it lasts.'}
          </p>
        </div>
      </header>
      <InlineError message={error} />
      <Panel title="Open" flush>
        {active.length === 0 ? (
          <p className="pad muted">No exceptions are open.</p>
        ) : (
          <div className="tblwrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Score</th>
                  <th>For</th>
                  <th>Decided by</th>
                  <th>Ends</th>
                  <th>At the provider</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {active.map((lease) => {
                  const total = lease.expires_at
                    ? Date.parse(lease.expires_at) - Date.parse(lease.created_at)
                    : 0;
                  const remaining = lease.expires_at
                    ? Math.max(0, Date.parse(lease.expires_at) - now)
                    : 0;
                  return (
                    <tr key={lease.id}>
                      <th className="dom">{lease.domain}</th>
                      <td>
                        <Score value={lease.risk_score} />
                      </td>
                      <td>
                        {lease.requester_name || 'Everyone'}
                        <div className="muted tiny">{lease.scope}</div>
                      </td>
                      <td>{lease.decided_by_name || 'An administrator'}</td>
                      <td style={{ minWidth: 130 }}>
                        {lease.kind === 'permanent' ? (
                          'Never'
                        ) : (
                          <>
                            {left(lease.expires_at, now) || 'Closing'}
                            <div className="timebar" style={{ marginTop: 6 }}>
                              <i style={{ width: `${total ? (remaining / total) * 100 : 0}%` }} />
                            </div>
                          </>
                        )}
                      </td>
                      <td>
                        {lease.last_error ? (
                          <span className="tag red">Could not close</span>
                        ) : (
                          <span className="muted tiny">{executionText(lease.execution)}</span>
                        )}
                      </td>
                      <td>
                        <button
                          className="button secondary small"
                          disabled={busy === lease.id}
                          onClick={() => void run(lease.id, () => post(`/leases/${lease.id}/end`))}
                        >
                          End now
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <Panel
        title="Could be permanent"
        hint="Addresses the access rule keeps opening. Nothing changes unless you choose it."
        flush
      >
        {(suggestions.data || []).length === 0 ? (
          <p className="pad muted">No suggestions.</p>
        ) : (
          <div className="rows">
            {(suggestions.data || []).map((item) => (
              <div className="row" key={item.domain}>
                <Score value={item.risk_score} />
                <span>
                  <span className="t dom">{item.domain}</span>
                  <span className="d">
                    Opened {plural(item.times, 'time')} for {item.people.join(', ') || 'someone'},
                    last {ago(item.last_at, now)}. {item.scope}.
                  </span>
                </span>
                <span className="button-row">
                  <button
                    className="button secondary small"
                    disabled={busy === item.domain}
                    onClick={() =>
                      void run(item.domain, () =>
                        post('/suggestions', { domain: item.domain, action: 'make_permanent' }),
                      )
                    }
                  >
                    Make permanent
                  </button>
                  <button
                    className="button quiet small"
                    disabled={busy === item.domain}
                    onClick={() =>
                      void run(item.domain, () =>
                        post('/suggestions', { domain: item.domain, action: 'dismiss' }),
                      )
                    }
                  >
                    Dismiss
                  </button>
                </span>
              </div>
            ))}
          </div>
        )}
      </Panel>
      {ended.length > 0 ? (
        <Panel title="Recently closed" flush>
          <div className="rows">
            {ended.map((lease) => (
              <div className="row" key={lease.id}>
                <Score value={lease.risk_score} />
                <span>
                  <span className="t dom">{lease.domain}</span>
                  <span className="d">
                    {lease.ended_reason === 'revoked' ? 'Ended early' : 'Ran out'}{' '}
                    {ago(lease.ended_at, now)}
                    {lease.requester_name ? ` · ${lease.requester_name}` : ''}
                  </span>
                </span>
                <span className="muted tiny">{lease.decided_by_name}</span>
              </div>
            ))}
          </div>
        </Panel>
      ) : (
        active.length === 0 && (
          <Empty
            title="No history yet"
            text="Closed access will be listed here with who decided it."
          />
        )
      )}
    </div>
  );
}
