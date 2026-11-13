import type { CollectionSchedule, ScheduleSummary } from '../types';

/** A fabricated schedule: on every 15 minutes with the next run 12 minutes away, unless overridden. */
export const scheduleFixture = (extra: Partial<CollectionSchedule> = {}): CollectionSchedule => ({
  enabled: true,
  interval_seconds: 900,
  source: 'console',
  choices: [5, 15, 30, 60, 180, 360, 720, 1440],
  next_at: new Date(Date.now() + 12 * 60_000).toISOString(),
  ...extra,
});

/** The same installation with the schedule switched off. */
export const scheduleOff = () => scheduleFixture({ enabled: false, next_at: null });

/** What the API tells a member: on or off, the interval and the next time, and nothing else. */
export const memberSchedule = (enabled: boolean): ScheduleSummary => ({
  enabled,
  interval_seconds: 900,
  next_at: enabled ? new Date(Date.now() + 12 * 60_000).toISOString() : null,
});
