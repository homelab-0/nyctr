import { useMemo, useState } from 'react';
import { useApi } from '../api';
import { Empty, ErrorState, Loading, Panel, SearchInput } from '../components/ui';
import { counted } from '../lib/counts';
import type { AuditEvent, Integration, Person } from '../types';

const WORDS: Record<string, string> = {
  'auth.login': 'Signed in',
  'auth.logout': 'Signed out',
  'auth.login_failed': 'Failed sign-in',
  'access.requested': 'Asked for access',
  'access.opened': 'Access opened',
  'access.closed': 'Access closed',
  'access.close_failed': 'Access could not be closed',
  'access.approved': 'Approved a request',
  'access.denied': 'Said no to a request',
  'access.reviewed': 'Reviewed a request',
  'rule.access_changed': 'Changed the access rule',
  'rule.guest_changed': 'Changed the guest cut-off rule',
  'guest.pass_issued': 'Issued a guest pass',
  'guest.pass_ended': 'Ended a guest pass',
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
};

/** Rows about one source, worded around its name. */
const ABOUT_A_SOURCE: Record<string, (name: string) => string> = {
  'integration.created': (name) => `Added the source ${name}`,
  'integration.collected': (name) => `Collected from ${name}`,
  'integration.collection_failed': (name) => `Could not collect from ${name}`,
  'integration.diagnosed': (name) => `Tested ${name}`,
};

/**
 * What a row says happened. A source is named as the audit record kept it, else by its current
 * name. It is called removed only when the source list loaded and does not hold it; while the
 * list is unavailable the row says "a source". Never an id.
 */
function what(event: AuditEvent, sources: Map<string, string> | null) {
  const about = ABOUT_A_SOURCE[event.action];
  if (!about) return WORDS[event.action] || event.action;
  const kept = event.details?.name;
  return about(
    typeof kept === 'string' && kept
      ? kept
      : sources
        ? sources.get(event.target_id) || 'a source since removed'
        : 'a source',
  );
}

/** Renders the few audit details worth reading, never raw provider text. */
function summary(event: AuditEvent) {
  const d = event.details || {};
  const parts: string[] = [];
  if (typeof d.domain === 'string') parts.push(d.domain);
  if (typeof d.execution === 'string') parts.push(String(d.execution).replace('_', ' '));
  if (d.by_rule === true || d.decided_by === 'rule') parts.push('by a written rule');
  if (typeof d.minutes === 'number') parts.push(`${d.minutes} min`);
  if (typeof d.resources === 'number') parts.push(counted(d.resources, 'item'));
  if (typeof d.observations === 'number') parts.push(counted(d.observations, 'blocked lookup'));
  if (d.partial === true) parts.push('most recent only');
  if (typeof d.reason === 'string' && d.reason) parts.push(d.reason);
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
            The last 500 recorded actions. Rows with no person were done by Nyctr under a written
            rule.
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
