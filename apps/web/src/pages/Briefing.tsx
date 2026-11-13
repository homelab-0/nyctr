import { useState, type FormEvent } from 'react';
import { ArrowRight, Sparkles } from 'lucide-react';
import { useApi } from '../api';
import { ErrorState, Loading, Panel, Score, SourceTag } from '../components/ui';
import { ago, left, plural, useNow, word } from '../lib/format';
import { askNyctr, hrefFor } from '../lib/links';
import { nextCollection, useSchedule } from '../lib/schedule';
import type { AttentionItem, Integration, Lease, Overview } from '../types';

const KIND: Record<AttentionItem['kind'], string> = {
  guest: 'Guest Wi-Fi',
  lease: 'Access',
  request: 'Request',
  finding: 'Finding',
  source: 'Source',
  suggestion: 'Suggestion',
};

/** What Nyctr cannot see today. Shown hatched so a quiet list is never read as "all clear". */
const NOT_COLLECTED = [
  'Firewall connection logs and port scans',
  'DNS lookups that were allowed',
  'Devices that have left the network',
  'Workload firewall rules (only the on/off switches are read)',
];

/**
 * The landing screen: what needs a person, ranked, then what is open and how fresh the sources are.
 * The ranking comes from fixed rules on the server; no model decides what appears here.
 */
export default function Briefing({
  attention,
  loading,
}: {
  attention: AttentionItem[];
  loading: boolean;
}) {
  const overview = useApi<Overview>('/overview');
  const leases = useApi<Lease[]>('/leases');
  const sources = useApi<Integration[]>('/integrations');
  const schedule = useSchedule();
  const [question, setQuestion] = useState('');
  const now = useNow();
  const urgent = attention.filter((item) => item.severity !== 'low');
  const open = (leases.data || []).filter((lease) => lease.status === 'active');
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (question.trim()) askNyctr(question);
    setQuestion('');
  };
  const headline = loading
    ? 'Checking what needs you.'
    : urgent.length
      ? `${word(urgent.length)} thing${urgent.length === 1 ? '' : 's'} need${urgent.length === 1 ? 's' : ''} you.`
      : 'Nothing needs you right now.';
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="display d1">{headline}</h1>
          <p className="lede">
            {overview.data
              ? `${plural(overview.data.resource_count, 'item')} inventoried from ${plural(overview.data.integration_count, 'source')}. ${plural(overview.data.recent_block_count, 'blocked lookup')} in the last day.`
              : 'Ranked by fixed rules from what your sources reported.'}
          </p>
        </div>
      </header>
      <form className="askbar" onSubmit={submit}>
        <Sparkles size={17} />
        <input
          type="text"
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          placeholder="Ask about your network, for example: who is on the guest Wi-Fi?"
          aria-label="Ask Nyctr a question"
        />
        <button className="button primary small" type="submit" disabled={!question.trim()}>
          Ask
        </button>
      </form>
      <div className="split">
        <Panel title="Needs you" hint="Most urgent first" flush>
          {loading ? (
            <Loading text="Ranking…" />
          ) : attention.length === 0 ? (
            <p className="pad muted">
              No cut-off guests, waiting requests, open findings or failing sources.
            </p>
          ) : (
            <div className="rows">
              {attention.map((item) => (
                <a
                  className="row"
                  key={`${item.kind}:${item.id}`}
                  href={hrefFor(item.kind, item.id)}
                >
                  <i className={`dot ${item.severity}`} />
                  <span>
                    <span className="t">{item.title}</span>
                    <span className="d">{item.detail}</span>
                  </span>
                  <span className="meta">
                    <span className="tag">{KIND[item.kind]}</span>
                    <ArrowRight size={15} />
                  </span>
                </a>
              ))}
            </div>
          )}
        </Panel>
        <div className="stack">
          <Panel
            title="Open right now"
            hint="Exceptions Nyctr is responsible for"
            action={
              <a className="button quiet small" href="#/access">
                All
              </a>
            }
            flush
          >
            {leases.error ? (
              <ErrorState message={leases.error} retry={leases.reload} />
            ) : open.length === 0 ? (
              <p className="pad muted">Nothing is open.</p>
            ) : (
              <div className="rows">
                {open.slice(0, 5).map((lease) => (
                  <a className="row" key={lease.id} href="#/access">
                    <Score value={lease.risk_score} />
                    <span>
                      <span className="t dom">{lease.domain}</span>
                      <span className="d">
                        {lease.kind === 'permanent'
                          ? 'Permanent'
                          : lease.last_error
                            ? 'Could not be closed'
                            : left(lease.expires_at, now) || 'Closing'}
                        {lease.requester_name ? ` · ${lease.requester_name}` : ''}
                      </span>
                    </span>
                    <span />
                  </a>
                ))}
              </div>
            )}
          </Panel>
          <Panel title="Sources" flush>
            <div className="rows">
              {(sources.data || []).map((source) => (
                <a className="row" key={source.id} href="#/sources">
                  <SourceTag provider={source.provider} />
                  <span>
                    <span className="t">{source.name}</span>
                    <span className="d">
                      {source.status === 'error'
                        ? source.last_error || 'Last collection failed'
                        : source.status === 'partial'
                          ? `Collected ${ago(source.last_sync, now)}. Only the most recent blocked lookups were read.`
                          : `Collected ${ago(source.last_sync, now)}`}
                    </span>
                    {schedule.data && (
                      <span className="d">
                        {nextCollection(schedule.data, now, 'Next collection ')}
                      </span>
                    )}
                  </span>
                  <i
                    className={`dot ${source.status === 'error' ? 'red' : source.status === 'partial' ? 'yellow' : source.last_sync ? 'green' : ''}`}
                    title={source.status === 'partial' ? 'Partly collected' : undefined}
                  />
                </a>
              ))}
              {sources.data?.length === 0 && <p className="pad muted">No sources connected yet.</p>}
            </div>
          </Panel>
          <div className="note hatch">
            <div>
              <b>Not collected</b>
              <ul className="plain">
                {NOT_COLLECTED.map((line) => (
                  <li key={line}>{line}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
