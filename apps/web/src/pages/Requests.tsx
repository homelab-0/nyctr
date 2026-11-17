import { useEffect, useRef, useState } from 'react';
import { Check, X } from 'lucide-react';
import { post, useApi } from '../api';
import {
  Empty,
  ErrorState,
  Factors,
  InlineError,
  KV,
  Loading,
  Panel,
  RiskScale,
  Score,
  Seg,
} from '../components/ui';
import { ago, atSource, span, useNow, writtenNote } from '../lib/format';
import { bringIntoView } from '../lib/links';
import { useRefreshWhile } from '../lib/refresh';
import type { AccessRequest, Lease, Person, Rules } from '../types';

const STATUS: Record<string, { text: string; tone: string }> = {
  analysing: { text: 'Checking', tone: '' },
  pending: { text: 'Waiting', tone: 'yellow' },
  auto_approved: { text: 'Opened by the rule', tone: 'green' },
  approved: { text: 'Approved', tone: 'green' },
  denied: { text: 'Said no', tone: 'red' },
  reviewed: { text: 'Reviewed, no change', tone: '' },
};

/**
 * Requests from members. Each shows the score the member saw, why the access rule did not
 * open it, and who a DNS exception would really affect before an administrator decides.
 */
export default function Requests({
  params,
  onChange,
}: {
  params: URLSearchParams;
  onChange: () => void;
}) {
  const requests = useApi<AccessRequest[]>('/requests');
  const people = useApi<Person[]>('/users');
  const rules = useApi<Rules>('/rules');
  const leases = useApi<Lease[]>('/leases');
  const [tab, setTab] = useState<'waiting' | 'decided'>('waiting');
  const [selected, setSelected] = useState<string | null>(params.get('id'));
  const [note, setNote] = useState('');
  const [minutes, setMinutes] = useState(60);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const now = useNow();
  const all = requests.data || [];
  const waiting = all
    .filter((row) => row.status === 'pending' || row.status === 'analysing')
    .sort((a, b) => (b.risk_score ?? 101) - (a.risk_score ?? 101));
  const decided = all.filter((row) => row.status !== 'pending' && row.status !== 'analysing');
  const list = tab === 'waiting' ? waiting : decided;
  const row = all.find((item) => item.id === selected) || list[0] || null;
  const names = new Map((people.data || []).map((person) => [person.id, person.name]));
  useEffect(() => {
    setNote('');
    setError(null);
    if (row) setMinutes(Math.min(240, Math.max(15, row.duration_minutes)));
  }, [row?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    const wanted = all.find((item) => item.id === params.get('id'));
    if (wanted) {
      setSelected(wanted.id);
      setTab(wanted.status === 'pending' || wanted.status === 'analysing' ? 'waiting' : 'decided');
    }
  }, [requests.data, params]); // eslint-disable-line react-hooks/exhaustive-deps

  // On a narrow screen the request's panel sits under the list: bring it into view when one is chosen.
  const panel = useRef<HTMLElement>(null);
  useEffect(() => {
    if (selected && row?.id === selected) bringIntoView(panel.current);
  }, [selected, row?.id]);
  // While a request is still being checked, read the list again so a finished check shows up
  // without a reload. Reading stops when none are left, and when this page is left.
  const checking = all.some((item) => item.status === 'analysing');
  useRefreshWhile(requests.data !== null && checking, () => requests.reload());

  /** Records the decision. Approval opens a lease; the server reports what really happened. */
  const decide = async (decision: 'approved' | 'denied') => {
    if (!row) return;
    setPending(true);
    setError(null);
    try {
      await post(`/requests/${row.id}/review`, {
        decision,
        // A note left empty stays empty: the decision is not repeated as if someone had written it.
        note: note.trim(),
        ...(decision === 'approved' ? { minutes } : {}),
      });
      requests.reload();
      leases.reload();
      onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPending(false);
    }
  };
  if (requests.loading) return <Loading text="Loading requests…" />;
  if (requests.error) return <ErrorState message={requests.error} retry={requests.reload} />;
  // The connected source this request's block came from, with whether Nyctr may open addresses there.
  const source = rules.data?.sources.find((item) => item.id === row?.integration_id);
  // What a decided request did at its source, from the exception's own record: the decision alone
  // never says whether anything was opened.
  const lease = (leases.data || []).find((item) => item.request_id === row?.id);
  const happened =
    !row || row.status === 'pending'
      ? ''
      : lease
        ? `${atSource(lease)}${lease.status === 'ended' ? ' It has ended since.' : ''}`
        : leases.error
          ? 'Nyctr could not read what happened at the source.'
          : leases.loading
            ? ''
            : row.status === 'denied' || row.status === 'reviewed'
              ? 'Nothing was changed at the source.'
              : 'Nyctr has no record of a change at the source.';
  const written = writtenNote(row?.review_note);
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="display d2">Requests</h1>
          <p className="lede">
            People asking for a blocked address. Anything the access rule could not open on its own
            waits here for you.
          </p>
        </div>
        <Seg
          label="Which requests"
          value={tab}
          onChange={(value) => {
            setTab(value);
            setSelected(null);
          }}
          options={[
            { id: 'waiting', name: 'Waiting', count: waiting.length },
            { id: 'decided', name: 'Decided', count: decided.length },
          ]}
        />
      </header>
      {list.length === 0 ? (
        <Empty
          title={tab === 'waiting' ? 'Nobody is waiting' : 'Nothing has been decided yet'}
          text={
            tab === 'waiting'
              ? 'New requests appear here when the access rule leaves the decision to you.'
              : 'Requests you or the access rule decide will be listed here.'
          }
        />
      ) : (
        <div className="split">
          <Panel flush>
            <div className="rows">
              {list.map((item) => (
                <button
                  className={`row ${row?.id === item.id ? 'on' : ''}`}
                  key={item.id}
                  onClick={() => setSelected(item.id)}
                >
                  <Score value={item.risk_score} />
                  <span>
                    <span className="t dom">{item.domain}</span>
                    <span className="d">
                      {names.get(item.requester_id) || 'Someone'} on {item.device_name},{' '}
                      {ago(item.created_at, now)}
                    </span>
                  </span>
                  <span className={`tag ${STATUS[item.status]?.tone || ''}`}>
                    {STATUS[item.status]?.text || item.status}
                  </span>
                </button>
              ))}
            </div>
          </Panel>
          {row && (
            <Panel
              title={<span className="dom">{row.domain}</span>}
              className="into-view"
              panelRef={panel}
            >
              <div className="stack">
                <div className="bar">
                  <Score value={row.risk_score} big />
                  <span className={`tag ${STATUS[row.status]?.tone || ''}`}>
                    {STATUS[row.status]?.text || row.status}
                  </span>
                </div>
                <RiskScale
                  value={row.risk_score}
                  limit={
                    rules.data?.access.enabled && rules.data.access.ad_tracker.mode === 'on'
                      ? rules.data.access.ad_tracker.max_score
                      : undefined
                  }
                />
                {row.risk_factors && <Factors items={row.risk_factors} />}
                {row.decision_note && <p className="aside">{row.decision_note}</p>}
                {row.status === 'analysing' && (
                  <p className="aside">Nyctr is still checking this request.</p>
                )}
                {row.analysis && (
                  <div>
                    <h3>Check of this address</h3>
                    <KV
                      items={[
                        ['Verdict', row.analysis.verdict || 'None'],
                        ['Risk', row.analysis.risk || 'None'],
                        ['Uncertainty', row.analysis.uncertainty || 'None'],
                      ]}
                    />
                    <ul className="aside">
                      {(row.analysis.facts?.facts || []).map((fact) => (
                        <li key={fact.id || fact.kind}>
                          {fact.kind}: {fact.state}
                        </li>
                      ))}
                    </ul>
                    {row.analysis.reasons.map((reason) => (
                      <p key={reason.fact}>{reason.text}</p>
                    ))}
                  </div>
                )}
                <KV
                  items={[
                    ['Who', names.get(row.requester_id) || 'Unknown'],
                    ['Device', row.device_name],
                    ...(row.source_name
                      ? ([['Source', row.source_name]] as [string, string][])
                      : []),
                    ['Their reason', row.reason],
                    ['Asked for', span(row.duration_minutes)],
                    ...(written ? ([['Your note', written]] as [string, string][]) : []),
                    ...(happened ? ([['At the source', happened]] as [string, string][]) : []),
                  ]}
                />
                {row.status === 'pending' && (
                  <>
                    <div className="note yellow">
                      <div>
                        <b>This opens it for everyone on the DNS profile.</b>
                        <p>
                          A DNS exception applies to everyone using{' '}
                          {source?.name || 'the DNS source'}, not to one person or device.
                        </p>
                      </div>
                    </div>
                    {(source?.write_mode === 'disabled' || source?.write_mode === 'none') && (
                      <div className="note">
                        <div>
                          <b>
                            {source.write_mode === 'none'
                              ? `Nyctr cannot open addresses at ${source.name}.`
                              : `Nyctr is read-only for ${source.name}.`}
                          </b>
                          <p>
                            Approving records your decision and the time window. You open the
                            address at the source yourself.
                          </p>
                        </div>
                      </div>
                    )}
                    <label className="field">
                      <span>Note for the record (optional)</span>
                      <textarea
                        rows={2}
                        value={note}
                        maxLength={500}
                        onChange={(e) => setNote(e.target.value)}
                      />
                    </label>
                    <label className="field">
                      <span>Open for</span>
                      <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
                        {[15, 30, 60, 120, 240].map((value) => (
                          <option key={value} value={value}>
                            {span(value)}
                          </option>
                        ))}
                      </select>
                    </label>
                    <InlineError message={error} />
                    <div className="button-row">
                      <button
                        className="button primary"
                        disabled={pending}
                        onClick={() => void decide('approved')}
                      >
                        <Check size={16} /> Approve
                      </button>
                      <button
                        className="button danger"
                        disabled={pending}
                        onClick={() => void decide('denied')}
                      >
                        <X size={16} /> Say no
                      </button>
                    </div>
                  </>
                )}
              </div>
            </Panel>
          )}
        </div>
      )}
    </div>
  );
}
