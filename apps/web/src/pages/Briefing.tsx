import { useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, Sparkles } from 'lucide-react';
import { useApi } from '../api';
import { ErrorState, Loading, Panel, Score, SourceTag } from '../components/ui';
import { counted, lookupSpan, namedCounts } from '../lib/counts';
import { ago, left, useNow, word } from '../lib/format';
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

/** One row under "Needs you": something the server ranked, or a source this screen read itself. */
type Need = Pick<AttentionItem, 'kind' | 'id' | 'severity' | 'title' | 'detail'> & { href: string };

/**
 * Sources whose last collection stored data but not all of it, each with one sentence and a way
 * to act. A read cut short opens the source's Edit form, where a shorter window is the cure; a
 * gap opens the source's card, which says what it means. A failed source is already listed.
 */
function sourceNeeds(sources: Integration[]): Need[] {
  const needs: Need[] = [];
  for (const source of sources) {
    const id = encodeURIComponent(source.id);
    if (source.status === 'partial')
      needs.push({
        kind: 'source',
        id: source.id,
        severity: 'medium',
        title: `${source.name} was only partly collected`,
        detail:
          'Only the most recent blocked lookups were read. Give it a shorter time window to read all of it.',
        href: `#/sources?edit=${id}`,
      });
    if (source.gaps?.length && source.status !== 'error')
      needs.push({
        kind: 'source',
        id: source.id,
        severity: 'medium',
        title: `${source.name} could not read everything`,
        detail: `${source.gaps.map((gap) => gap.title).join('. ')}.`,
        href: `#/sources?source=${id}`,
      });
  }
  return needs;
}

/** What the sources reported, each kind named with its own count, then the span of stored lookups. */
function briefingCounts(overview: Overview, now: number) {
  const named = namedCounts(overview.kind_counts || {});
  const sources = counted(overview.integration_count, 'source');
  const span = lookupSpan(
    overview.recent_block_count,
    overview.oldest_block_at,
    overview.newest_block_at,
    now,
  );
  return `${named ? `${named} from ${sources}.` : `Nothing inventoried yet from ${sources}.`} ${span}`;
}

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
  // A schedule read again means a collection was due, so "Collected ... ago" is read again too.
  const { reads } = schedule;
  const rereadSources = sources.reload;
  useEffect(() => {
    if (reads > 1) rereadSources();
  }, [reads, rereadSources]);
  const ranked: Need[] = attention.map((item) => ({ ...item, href: hrefFor(item.kind, item.id) }));
  const later = ranked.findIndex((item) => item.severity === 'low');
  // Sources that need a look sit with the other medium items, above suggestions.
  const needs = [...ranked];
  needs.splice(later < 0 ? ranked.length : later, 0, ...sourceNeeds(sources.data || []));
  const urgent = needs.filter((item) => item.severity !== 'low');
  // "Nothing needs you" is said only once the sources have answered too.
  const ranking = loading || (sources.loading && !sources.data);
  const open = (leases.data || []).filter((lease) => lease.status === 'active');
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (question.trim()) askNyctr(question);
    setQuestion('');
  };
  const headline = ranking
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
              ? briefingCounts(overview.data, now)
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
          {ranking ? (
            <Loading text="Ranking…" />
          ) : needs.length === 0 ? (
            <p className="pad muted">
              No cut-off guests, waiting requests, open findings, or sources that failed or could
              not read everything.
            </p>
          ) : (
            <div className="rows">
              {needs.map((item) => (
                <a className="row" key={`${item.kind}:${item.href}:${item.id}`} href={item.href}>
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
                          : source.gaps?.length
                            ? `Collected ${ago(source.last_sync, now)}. ${source.gaps.length === 1 ? 'One thing' : `${source.gaps.length} things`} could not be read.`
                            : `Collected ${ago(source.last_sync, now)}`}
                    </span>
                    {schedule.data && (
                      <span className="d">
                        {nextCollection(schedule.data, now, 'Next collection ')}
                      </span>
                    )}
                  </span>
                  <i
                    className={`dot ${source.status === 'error' ? 'red' : source.status === 'partial' || source.gaps?.length ? 'yellow' : source.last_sync ? 'green' : ''}`}
                    title={
                      source.status === 'partial'
                        ? 'Partly collected'
                        : source.gaps?.length && source.status !== 'error'
                          ? 'Collected with gaps'
                          : undefined
                    }
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
