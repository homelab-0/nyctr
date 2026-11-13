import { useApi } from '../api';
import type { CollectionSchedule, ScheduleSummary } from '../types';
import { span } from './format';

/** Said wherever a time would be promised but the schedule is off. */
export const ON_REQUEST = 'Only when you press Collect';

/** The collection schedule in force, as an administrator's screens read it. */
export const useSchedule = () => useApi<CollectionSchedule>('/collection');

/** The part a member may read: on or off, the interval and the next time. */
export const useScheduleSummary = () => useApi<ScheduleSummary>('/collection');

/** "every 15 minutes" while the schedule is on; null when it is off or not known. */
export const everyText = (schedule: ScheduleSummary | null | undefined) =>
  schedule?.enabled ? `every ${span(Math.round(schedule.interval_seconds / 60))}` : null;

/**
 * When sources are next collected, in words that never promise a collection that will not happen.
 * `lead` goes before a time only, so a label and a sentence can share the wording.
 */
export function nextCollection(schedule: CollectionSchedule, now = Date.now(), lead = '') {
  if (schedule.source === 'demo') return 'Sample data is not collected';
  const due = schedule.enabled && schedule.next_at ? Date.parse(schedule.next_at) : NaN;
  if (!Number.isFinite(due)) return ON_REQUEST;
  const minutes = Math.ceil((due - now) / 60_000);
  if (minutes <= 1) return `${lead}within a minute`;
  return minutes < 60
    ? `${lead}in ${minutes} min`
    : `${lead}in about ${Math.round(minutes / 60)} hr`;
}
