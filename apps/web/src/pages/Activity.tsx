import { useMemo, useState } from 'react';
import { useApi } from '../api';
import { Empty, ErrorState, Loading, Panel, SearchInput } from '../components/ui';
import type { AuditEvent, Person } from '../types';

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
  'integration.created': 'Added a source',
  'integration.collected': 'Collected from a source',
  'integration.collection_failed': 'Collection failed',
  'collection.schedule_changed': 'Changed the collection schedule',
  'integration.diagnosed': 'Tested a source',
  'suggestion.dismissed': 'Dismissed a suggestion',
  'graph.queried': 'Ran a graph query',
  'assistant.asked': 'Asked the assistant',
  'assistant.insight': 'Asked for a finding insight',
  'demo.guest_activity': 'Simulated guest activity',
};

/** Renders the few audit details worth reading, never raw provider text. */
function summary(event: AuditEvent) {
  const d = event.details || {};
  const parts: string[] = [];
  if (typeof d.domain === 'string') parts.push(d.domain);
  if (typeof d.execution === 'string') parts.push(String(d.execution).replace('_', ' '));
  if (d.by_rule === true || d.decided_by === 'rule') parts.push('by a written rule');
  if (typeof d.minutes === 'number') parts.push(`${d.minutes} min`);
  if (typeof d.resources === 'number') parts.push(`${d.resources} items`);
  if (typeof d.reason === 'string' && d.reason) parts.push(d.reason);
  return parts.join(' · ');
}

/** The audit trail: who did what, including what the written rules did on their own. */
export default function Activity() {
  const audit = useApi<AuditEvent[]>('/audit');
  const people = useApi<Person[]>('/users');
  const [text, setText] = useState('');
  const names = useMemo(
    () => new Map((people.data || []).map((p) => [p.id, p.name])),
    [people.data],
  );
  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return (audit.data || []).filter((event) => {
      const line = `${WORDS[event.action] || event.action} ${names.get(event.actor_id) || ''} ${summary(event)} ${event.target_id || ''}`;
      return !needle || line.toLowerCase().includes(needle);
    });
  }, [audit.data, text, names]);
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
                    <th>{WORDS[event.action] || event.action}</th>
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
