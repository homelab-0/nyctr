import { useMemo, useState } from 'react';
import { useApi } from '../api';
import { Empty, ErrorState, Loading, Panel, SearchInput } from '../components/ui';
import { counted } from '../lib/counts';
import { REMOVAL, clock } from '../lib/format';
import type { AuditEvent, Integration, Person } from '../types';

/** Every action the server writes has a sentence here or in ABOUT_A_SOURCE; a server test checks it. */
const WORDS: Record<string, string> = {
  'auth.login': 'Signed in',
  'auth.logout': 'Signed out',
  'auth.login_failed': 'Failed sign-in',
  'auth.sent_to_portal': 'Was sent to the member portal to sign in',
  'access.requested': 'Asked for access',
  'access.opened': 'Access opened',
  'access.open_undone': 'Access opened while its source was being removed or changed',
  'access.open_unconfirmed': 'Access could not be confirmed open',
  'access.closed': 'Access closed',
  'access.close_failed': 'Access could not be closed',
  'access.approved': 'Approved a request',
  'access.approve_failed': 'Approved a request, and nothing was opened',
  'access.denied': 'Said no to a request',
  'access.reviewed': 'Reviewed a request',
  'rule.access_changed': 'Changed the access rule',
  'rule.guest_changed': 'Changed the guest cut-off rule',
  'guest.pass_issued': 'Issued a guest pass',
  'guest.pass_ended': 'Ended a guest pass',
  'guest.pass_undone': 'A guest pass issued while its source was being removed or changed',
  'guest.admit': 'Let a waiting guest on',
  'guest.cut': 'Cut a guest off',
  'guest.restore': 'Let a guest back on',
  'guest.lock': 'Locked a guest out',
  'device.assignment_changed': 'Changed who a device belongs to',
  'device.link_changed': 'Linked a DNS device label',
  'collection.schedule_changed': 'Changed the collection schedule',
  'suggestion.dismissed': 'Dismissed a suggestion',
  'graph.queried': 'Ran a graph query',
  'assistant.asked': 'Asked the assistant',
  'assistant.insight': 'Asked for a finding insight',
  'demo.guest_activity': 'Simulated guest activity',
  'integration.nudged': 'Started a collection when the server was asked to',
};

/** Rows about one source, worded around its name. */
const ABOUT_A_SOURCE: Record<string, (name: string) => string> = {
  'integration.created': (name) => `Added the source ${name}`,
  'integration.collected': (name) => `Collected from ${name}`,
  'integration.collection_failed': (name) => `Could not collect from ${name}`,
  'integration.diagnosed': (name) => `Tested ${name}`,
  'integration.removed': (name) => `Removed the source ${name}`,
  'integration.updated': (name) => `Edited the source ${name}`,
  'integration.retries_stopped': (name) => `Stopped retrying ${name} and showed it as failed`,
};

/**
 * A change at a source that can fail, as what was attempted. A row reads as done only when its
 * record says applied; otherwise it says simulated, decided or tried, and the detail says why.
 */
const ATTEMPT: Record<string, string> = {
  'access.opened': 'open access',
  'access.closed': 'close access',
  'guest.pass_issued': 'issue a guest pass',
  'guest.pass_ended': 'end a guest pass',
  'guest.admit': 'let a waiting guest on',
  'guest.cut': 'cut a guest off',
  'guest.restore': 'let a guest back on',
  'guest.lock': 'lock a guest out',
};

/**
 * What a row says happened. A source is named as the audit record kept it, else by its current
 * name. It is called removed only when the source list loaded and does not hold it; while the
 * list is unavailable the row says "a source". Never an id.
 */
function what(event: AuditEvent, sources: Map<string, string> | null) {
  const about = ABOUT_A_SOURCE[event.action];
  // The record of an opening that was never confirmed is not access: settling it closed nothing.
  if (event.action === 'access.closed' && event.details?.reason === 'not_confirmed')
    return 'Settled an opening that was never confirmed';
  if (event.action === 'access.close_failed' && event.details?.record === true)
    return 'Could not settle an opening that was never confirmed';
  const tried = ATTEMPT[event.action];
  const did = event.details?.execution;
  if (tried && did !== 'applied')
    return did === 'simulated'
      ? `Simulated: ${tried}`
      : `${did === 'not_applied' ? 'Decided' : 'Tried'} to ${tried}`;
  if (!about) return WORDS[event.action] || 'Something this version of the page cannot describe';
  const kept = event.details?.name;
  return about(
    typeof kept === 'string' && kept
      ? kept
      : sources
        ? sources.get(event.target_id) || 'a source since removed'
        : 'a source',
  );
}

/**
 * Reasons the server records as a code; any other reason is a sentence a person or a rule wrote.
 * A server test checks every code has a sentence here.
 */
const REASONS: Record<string, string> = {
  expired: 'its time ran out',
  revoked: 'ended early by a person',
  removed_by_hand: 'removed at the source by hand, so nothing was sent',
  not_confirmed: 'the opening was never confirmed',
  schedule_off: 'scheduled collection was turned off',
  secret: 'its secret is no longer set on the server',
  secret_ref: 'the name of its secret on the server is not a valid one',
  missing: 'the source is no longer there',
};

/**
 * What an applied change left at the source, said per action and true however it got there: an
 * address already allowed, or a guest already without access, is recorded as applied with nothing
 * sent. An action not listed says nothing, so a change is never claimed that the record cannot show.
 */
const APPLIED: Record<string, string> = {
  'access.opened': 'allowed at the source',
  'access.approved': 'allowed at the source',
  'access.open_undone': 'taken back out at the source',
  // Said from what the ending recorded; a record from before that was kept says only this.
  'access.closed': 'this record does not say what was sent to the source',
  'guest.cut': 'without access at the source',
  'guest.lock': 'without access at the source',
  'guest.restore': 'let on at the source',
  'guest.admit': 'let on at the source',
  'guest.pass_issued': 'issued at the source',
  'guest.pass_ended': 'ended at the source',
  'guest.pass_undone': 'ended again at the source',
};
const LEFT_ALONE = 'already allowed at the source, left as it was';
/** A failure is any error: the source may have refused, not answered, or never been asked. */
const FAILED: Record<string, string> = {
  'access.open_unconfirmed': 'the source did not confirm it, so it may be open there',
  'access.open_undone': 'could not be taken back out, so remove it at the source by hand',
  'guest.pass_undone': 'could not be ended, so end it at the source by hand',
};

/** What happened at the source, kept apart from the decision; nothing reads as changed unless it was. */
function outcome(event: AuditEvent) {
  const d = event.details || {};
  if (event.action === 'access.close_failed')
    return d.record === true
      ? 'the source could not be reached, so it stays listed as not confirmed'
      : 'could not be removed at the source, so it is still open';
  if (d.execution === 'simulated') return 'simulated, nothing was sent to the source';
  if (d.execution === 'failed') return FAILED[event.action] || 'did not go through';
  // For an opening that was never confirmed, the record does say what closing it did at the source.
  if (event.action === 'access.closed' && d.reason === 'not_confirmed' && d.execution !== 'failed')
    return (
      REMOVAL[typeof d.removal === 'string' ? d.removal : ''] ||
      (d.execution === 'applied' ? REMOVAL.removed : REMOVAL.nothing_removed)
    );
  if (d.execution === 'not_applied')
    return event.action === 'access.open_undone' ? LEFT_ALONE : 'nothing changed at the source';
  if (d.execution !== 'applied') return undefined;
  if (event.action === 'access.closed' && typeof d.removal === 'string' && REMOVAL[d.removal])
    return REMOVAL[d.removal];
  return event.action === 'access.opened' && d.owned === false ? LEFT_ALONE : APPLIED[event.action];
}

/** Renders the few audit details worth reading, never raw provider text. */
function summary(event: AuditEvent) {
  const d = event.details || {};
  const parts: string[] = [];
  if (typeof d.domain === 'string') parts.push(d.domain);
  // An entry ended by hand was changed by a person at the source, not by Nyctr: the reason says so.
  const happened = d.reason === 'removed_by_hand' ? undefined : outcome(event);
  if (happened) parts.push(happened);
  if (d.by_rule === true || d.decided_by === 'rule') parts.push('by a written rule');
  if (typeof d.minutes === 'number') parts.push(`${d.minutes} min`);
  if (typeof d.resources === 'number') parts.push(counted(d.resources, 'item'));
  if (typeof d.observations === 'number') parts.push(counted(d.observations, 'blocked lookup'));
  if (d.partial === true) parts.push('most recent only');
  // Only the count: the codes are for the record, and the source's card says what each means.
  if (Array.isArray(d.gaps) && d.gaps.length)
    parts.push(`${counted(d.gaps.length, 'thing')} it could not read`);
  // Which settings changed stays in the record: their names there are not the form's labels.
  if (Array.isArray(d.fields)) parts.push(`${counted(d.fields.length, 'field')} changed`);
  const next = d.new as { enabled?: unknown; interval_seconds?: unknown } | undefined;
  if (next && typeof next.enabled === 'boolean')
    parts.push(
      next.enabled && typeof next.interval_seconds === 'number'
        ? `now every ${counted(Math.round(next.interval_seconds / 60), 'minute')}`
        : 'now turned off',
    );
  // That reason is already the row's own words (see `what`).
  if (typeof d.reason === 'string' && d.reason && d.reason !== 'not_confirmed')
    parts.push(REASONS[d.reason] || d.reason);
  // Why a collection failed, in the words the source's card uses, or why an approval opened nothing,
  // in the sentence the administrator was answered with; and when the next try is due.
  if (typeof d.why === 'string' && d.why) parts.push(d.why);
  if (typeof d.retry_at === 'string') parts.push(`next try at ${clock(d.retry_at)}`);
  return parts.join(' · ');
}

/** The audit trail: who did what, including what the written rules did on their own. */
export default function Activity() {
  const audit = useApi<AuditEvent[]>('/audit');
  const people = useApi<Person[]>('/users');
  const sources = useApi<Integration[]>('/integrations');
  const [text, setText] = useState('');
  const names = useMemo(
    () => new Map((people.data || []).map((p) => [p.id, p.name])),
    [people.data],
  );
  // Null while the list is loading or after it failed, so no source is wrongly called removed.
  const sourceNames = useMemo(
    () =>
      sources.data && !sources.error
        ? new Map(sources.data.map((source) => [source.id, source.name]))
        : null,
    [sources.data, sources.error],
  );
  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return (audit.data || []).filter((event) => {
      const line = `${what(event, sourceNames)} ${names.get(event.actor_id) || ''} ${summary(event)} ${event.target_id || ''}`;
      return !needle || line.toLowerCase().includes(needle);
    });
  }, [audit.data, text, names, sourceNames]);
  if (audit.loading) return <Loading text="Loading activity…" />;
  if (audit.error) return <ErrorState message={audit.error} retry={audit.reload} />;
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1 className="display d2">Activity</h1>
          <p className="lede">
            The last 500 recorded actions. Rows marked Nyctr have no signed-in person behind them: a
            written rule, the collection schedule, or a sign-in that failed.
          </p>
        </div>
        <SearchInput
          value={text}
          onChange={setText}
          placeholder="Find an action, person or address"
        />
      </header>
      {sources.error && (
        <div className="note yellow" role="alert">
          <span>
            <b>Source names could not be loaded.</b> Rows about a source say only &ldquo;a
            source&rdquo; until they load.
          </span>
          <button className="button secondary small" onClick={sources.reload}>
            Try again
          </button>
        </div>
      )}
      {rows.length === 0 ? (
        <Empty title="No activity matches" text="Clear the search to see everything." />
      ) : (
        <Panel flush>
          <div className="tblwrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Who</th>
                  <th>What</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((event) => (
                  <tr key={event.id}>
                    <td className="nowrap muted">{new Date(event.created_at).toLocaleString()}</td>
                    <td>
                      {event.actor_id ? (
                        names.get(event.actor_id) || 'Someone'
                      ) : (
                        <span className="tag">Nyctr</span>
                      )}
                    </td>
                    <th>{what(event, sourceNames)}</th>
                    <td className="muted">{summary(event)}</td>
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
