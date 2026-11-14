import { useEffect, useState, type FormEvent } from 'react';
import { ArrowRight, Sparkles } from 'lucide-react';
import { useApi } from '../api';
import { ErrorState, Loading, Panel, Score, SourceTag } from '../components/ui';
import { counted, lookupSpan, namedCounts } from '../lib/counts';
import { uncollected, whyEmpty } from '../lib/coverage';
import { ago, left, useNow, word } from '../lib/format';
import { askNyctr, hrefFor } from '../lib/links';
import { nextCollection, useSchedule } from '../lib/schedule';
import type { AttentionItem, Catalog, FindingChecks, Integration, Lease, Overview } from '../types';

const KIND: Record<AttentionItem['kind'], string> = {
  guest: 'Guest Wi-Fi',
  lease: 'Access',
  request: 'Request',
  finding: 'Finding',
  source: 'Source',
  suggestion: 'Suggestion',
};

/**
 * What Nyctr cannot see here, built from the sources connected: one still to collect, what the last
 * collection could not read, and what each kind of source declares it never gives. Shown hatched so
 * a quiet list is never read as "all clear".
 */
function notCollected(sources: Integration[], catalog: Catalog | null) {
  return sources.flatMap((source) => {
    const declared = catalog?.providers.find((item) => item.id === source.provider)?.limits || [];
    return [
      ...(source.last_sync ? [] : [{ id: 'never', title: whyEmpty(source), summary: '' }]),
      ...[...(source.gaps || []), ...declared].map((gap) => ({
        ...gap,
        title: `${source.name}: ${gap.title}`,
      })),
    ].map((line) => ({ ...line, id: `${source.id}:${line.id}` }));
  });
}

/** Where a "Needs you" row leads. A source that stored only part names its Edit form or its card. */
function needHref(item: AttentionItem) {
  const id = encodeURIComponent(item.id);
  if (item.kind === 'source' && item.action === 'edit') return `#/sources?edit=${id}`;
  if (item.kind === 'source' && item.action === 'card') return `#/sources?source=${id}`;
  return hrefFor(item.kind, item.id);
}

/** What the sources reported, each kind named with its own count, then the span of stored lookups. */
function briefingCounts(overview: Overview, now: number, connected: Integration[] | null) {
  const named = namedCounts(overview.kind_counts || {});
  const sources = counted(overview.integration_count, 'source');
  // A count with no stored collection behind it is not a zero: it has not been collected.
  const waiting = uncollected(connected).length;
  const span =
    !overview.recent_block_count && uncollected(connected, 'dns.blocks').length
      ? 'Blocked lookups have not been collected yet.'
      : lookupSpan(
          overview.recent_block_count,
          overview.oldest_block_at,
          overview.newest_block_at,
          now,
        );
  const pending = waiting ? ` ${counted(waiting, 'source')} not collected yet.` : '';
  return `${named ? `${named} from ${sources}.` : waiting ? `Not collected yet from ${sources}.` : `Nothing inventoried yet from ${sources}.`}${named ? pending : ''} ${span}`;
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
  const catalog = useApi<Catalog>('/integrations/catalog');
  const cover = useApi<FindingChecks>('/findings/checks').data;
  const idle = cover?.checks.filter((check) => !check.active).length || 0;
  const missing = notCollected(sources.data || [], catalog.data);
  const [question, setQuestion] = useState('');
  const now = useNow();
  // A schedule read again means a collection was due, so "Collected ... ago" is read again too.
  const { reads } = schedule;
  const rereadSources = sources.reload;
  useEffect(() => {
    if (reads > 1) rereadSources();
  }, [reads, rereadSources]);
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
              ? briefingCounts(overview.data, now, sources.data)
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
              No cut-off guests, waiting requests, open findings, or sources that failed or could
              not read everything.
            </p>
          ) : (
            <div className="rows">
              {attention.map((item) => {
                const href = needHref(item);
                return (
                  <a className="row" key={`${item.kind}:${href}:${item.id}`} href={href}>
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
                );
              })}
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
                        : !source.last_sync
                          ? 'Not collected yet'
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
              {sources.data?.length === 0 ? (
                <p>No sources are connected, so nothing is collected yet.</p>
              ) : (
                <ul className="plain">
                  {missing.map((line) => (
                    <li key={line.id} title={line.summary}>
                      {line.title}
                    </li>
                  ))}
                </ul>
              )}
              {cover && (
                <p>
                  Findings come from {cover.checks.length} checks
                  {idle ? `, ${idle} with nothing to look at here` : ''}.
                  {cover.not_checked.length > 0 &&
                    ` Collected but not checked: ${cover.not_checked.join(', ')}.`}{' '}
                  <a href="#/findings">What is checked</a>
                </p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
