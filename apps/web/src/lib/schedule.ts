import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, api } from '../api';
import type { CollectionSchedule, ScheduleSummary } from '../types';
import { span } from './format';

/** Said wherever a time would be promised but the schedule is off. */
export const ON_REQUEST = 'Only when you press Collect';

/** Said when Nyctr gives no answer at all, in place of the browser's own words. */
export const UNREACHABLE = 'Unable to reach Nyctr.';

/** A failure in words a person can read: the server's own sentence, or that it gave no answer. */
export const failureText = (error: unknown) =>
  error instanceof ApiError ? error.message : UNREACHABLE;

/** How long after the promised time to ask again, so the collection has had time to start. */
const SETTLE_MS = 5_000;
/** The first wait when the promised time has passed or a read failed. It doubles up to the cap. */
const RETRY_MS = 30_000;
const RETRY_CAP_MS = 300_000;

/**
 * Reads the schedule when the page opens and again once the promised time has passed, so a page
 * left open never keeps a promise that has already been kept. One timer, aimed at `next_at`:
 * nothing is asked while the schedule is off, and the timer stops when the page is left.
 * The newest answer wins: a read that was already on its way cannot overwrite a later one.
 */
function useCollection<T extends ScheduleSummary>() {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  /** Reads that have come back, failed ones included. Above one, the page has re-read. */
  const [reads, setReads] = useState(0);
  const newest = useRef(0);
  const wait = useRef(RETRY_MS);
  const reload = useCallback(async () => {
    const mine = ++newest.current;
    try {
      const value = await api<T>('/collection');
      if (mine !== newest.current) return;
      setData(value);
      setError(null);
    } catch (e) {
      if (mine !== newest.current) return;
      setError(failureText(e));
    }
    setReads((count) => count + 1);
  }, []);
  /** Puts the answer to a save on screen as the schedule in force. */
  const replace = useCallback((value: T) => {
    newest.current += 1;
    setData(value);
    setError(null);
  }, []);
  useEffect(() => {
    void reload();
    return () => {
      newest.current += 1;
    };
  }, [reload]);
  useEffect(() => {
    if (!data?.enabled) return;
    const due = data.next_at ? Date.parse(data.next_at) : NaN;
    if (!Number.isFinite(due)) return;
    const ahead = due - Date.now();
    let delay = ahead + SETTLE_MS;
    if (ahead > 0 && !error) wait.current = RETRY_MS;
    else {
      // Still overdue, or the last read failed: ask again, less and less often.
      delay = wait.current;
      wait.current = Math.min(wait.current * 2, RETRY_CAP_MS);
    }
    const timer = window.setTimeout(() => void reload(), delay);
    return () => window.clearTimeout(timer);
    // `reads` restarts the timer after a read that changed nothing else, such as a second failure.
  }, [data, error, reads, reload]);
  return { data, error, reads, reload, replace };
}

/** The collection schedule in force, as an administrator's screens read it. */
export const useSchedule = () => useCollection<CollectionSchedule>();

/** The part a member may read: on or off, the interval and the next time. */
export const useScheduleSummary = () => useCollection<ScheduleSummary>();

/** "every 15 minutes" while the schedule is on; null when it is off or not known. */
export const everyText = (schedule: ScheduleSummary | null | undefined) =>
  schedule?.enabled && Number.isFinite(schedule.interval_seconds)
    ? `every ${span(Math.round(schedule.interval_seconds / 60))}`
    : null;

/**
 * When sources are next collected, in words that never promise a collection that will not happen.
 * `lead` goes before a time only, so a label and a sentence can share the wording.
 */
export function nextCollection(schedule: CollectionSchedule, now = Date.now(), lead = '') {
  if (schedule.source === 'demo') return 'Sample data is not collected';
  if (!schedule.enabled) return ON_REQUEST;
  const due = schedule.next_at ? Date.parse(schedule.next_at) : NaN;
  // On, but the time is missing: name no time rather than say collection is only on request.
  if (!Number.isFinite(due)) return lead ? `${lead}on schedule` : 'On schedule';
  const minutes = Math.ceil((due - now) / 60_000);
  if (minutes <= 1) return `${lead}within a minute`;
  return minutes < 60
    ? `${lead}in ${minutes} min`
    : `${lead}in about ${Math.round(minutes / 60)} hr`;
}
