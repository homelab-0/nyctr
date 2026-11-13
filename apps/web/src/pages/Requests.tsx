import { useEffect, useState } from 'react';
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
import { ago, span, useNow } from '../lib/format';
import type { AccessRequest, Person, Rules } from '../types';

const STATUS: Record<string, { text: string; tone: string }> = {
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
  const [tab, setTab] = useState<'waiting' | 'decided'>('waiting');
  const [selected, setSelected] = useState<string | null>(params.get('id'));
  const [note, setNote] = useState('');
  const [minutes, setMinutes] = useState(60);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const now = useNow();
  const all = requests.data || [];
  const waiting = all
    .filter((row) => row.status === 'pending')
    .sort((a, b) => (b.risk_score ?? 101) - (a.risk_score ?? 101));
  const decided = all.filter((row) => row.status !== 'pending');
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
      setTab(wanted.status === 'pending' ? 'waiting' : 'decided');
    }
  }, [requests.data, params]); // eslint-disable-line react-hooks/exhaustive-deps

  /** Records the decision. Approval opens a lease; the server reports what really happened. */
  const decide = async (decision: 'approved' | 'denied') => {
    if (!row) return;
    setPending(true);
    setError(null);
    try {
      await post(`/requests/${row.id}/review`, {
        decision,
        note: note.trim() || (decision === 'approved' ? 'Approved' : 'Not approved'),
        ...(decision === 'approved' ? { minutes } : {}),
      });
      requests.reload();
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
            <Panel title={<span className="dom">{row.domain}</span>}>
              <div className="stack">
                <div className="bar">
                  <Score value={row.risk_score} big />
                  <span className={`tag ${STATUS[row.status]?.tone || ''}`}>
                    {STATUS[row.status]?.text || row.status}
                  </span>
                </div>
                <RiskScale
                  value={row.risk_score}
                  limit={rules.data?.access.enabled ? rules.data.access.max_score : undefined}
                />
                {row.risk_factors && <Factors items={row.risk_factors} />}
                {row.decision_note && <p className="aside">{row.decision_note}</p>}
                <KV
                  items={[
                    ['Who', names.get(row.requester_id) || 'Unknown'],
                    ['Device', row.device_name],
                    ...(row.source_name
                      ? ([['Source', row.source_name]] as [string, string][])
                      : []),
                    ['Their reason', row.reason],
                    ['Asked for', span(row.duration_minutes)],
                    ...(row.review_note
                      ? ([['Your note', row.review_note]] as [string, string][])
                      : []),
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
