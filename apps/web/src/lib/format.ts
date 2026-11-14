import { useEffect, useState } from 'react';
import type { Execution, WriteMode } from '../types';

/** Re-renders a component on an interval so countdowns and ages stay current. */
export function useNow(everyMs = 15000) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), everyMs);
    return () => window.clearInterval(timer);
  }, [everyMs]);
  return now;
}

/** "12 min ago", "3 hr ago". An absent or invalid time is said plainly. */
export function ago(value: string | null | undefined, now = Date.now()) {
  if (!value) return 'never';
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return 'unknown time';
  const seconds = Math.max(0, Math.floor((now - time) / 1000));
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hr ago`;
  const days = Math.floor(seconds / 86400);
  return `${days} day${days === 1 ? '' : 's'} ago`;
}

/** "38 min left", "2 hr 5 min left", or null once the time has passed. */
export function left(value: string | null | undefined, now = Date.now()) {
  if (!value) return null;
  const seconds = Math.floor((Date.parse(value) - now) / 1000);
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  const minutes = Math.ceil(seconds / 60);
  if (minutes < 60) return `${minutes} min left`;
  const hours = Math.floor(minutes / 60);
  return minutes % 60 ? `${hours} hr ${minutes % 60} min left` : `${hours} hr left`;
}

/** A clock time in the viewer's locale. */
export const clock = (value: string) =>
  new Date(value).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });

/** "1 hour", "45 minutes", "2 days". */
export function span(minutes: number) {
  if (minutes % 1440 === 0) return `${minutes / 1440} day${minutes === 1440 ? '' : 's'}`;
  if (minutes % 60 === 0) return `${minutes / 60} hour${minutes === 60 ? '' : 's'}`;
  return `${minutes} minute${minutes === 1 ? '' : 's'}`;
}

/** Megabytes or gigabytes from a byte count. */
export function bytes(value: number | undefined) {
  if (!value) return 'nothing yet';
  return value >= 1e9
    ? `${(value / 1e9).toFixed(1)} GB`
    : `${Math.max(1, Math.round(value / 1e6))} MB`;
}

/** Counts with the right noun form. */
export const plural = (count: number, one: string, many = `${one}s`) =>
  `${count} ${count === 1 ? one : many}`;

const WORDS = ['No', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine', 'Ten'];
/** Small counts as words for headlines. */
export const word = (count: number) => WORDS[count] ?? String(count);

/** Says what happened at the source in plain words. */
export function executionText(execution: Execution) {
  return {
    simulated: 'Simulated. Demo mode never contacts a source.',
    applied: 'Changed at the source and checked.',
    not_applied: 'Not changed. Nyctr is read-only for this source.',
    failed: 'The source refused the change.',
  }[execution];
}

/** What ending an exception did at the source, by the code its record keeps. */
export const REMOVAL: Record<string, string> = {
  removed: 'removed at the source',
  already_gone: 'nothing to remove, the entry was already gone at the source',
  kept_for_another: 'left at the source, another open exception still needs it',
  not_owned: "nothing to remove, the entry was not Nyctr's",
  // Settling an opening that was never confirmed: nothing was there, or Nyctr could not tell whose it was.
  nothing_removed: 'nothing was removed at the source',
};

/** "A", "A and B", "A, B and C", then "A, B and 5 more": a long list of names stays one phrase. */
export function someNames(names: string[], max = 3) {
  const shown =
    names.length > max ? [...names.slice(0, max - 1), `${names.length - max + 1} more`] : names;
  return shown.length > 1 ? `${shown.slice(0, -1).join(', ')} and ${shown.at(-1)}` : shown[0] || '';
}

/**
 * What Nyctr may change, as the words after "may change": '' when it is read-only for every source.
 * Only sources Nyctr has read are named: one never collected has nothing of Nyctr's to change.
 */
export function mayChange(sources: { name: string; write_mode: string; collected?: boolean }[]) {
  const allowed = sources.filter((source) => source.write_mode === 'enabled');
  const read = allowed.filter((source) => source.collected !== false).map((source) => source.name);
  if (!allowed.length) return '';
  return read.length ? someNames(read) : 'sources once they are collected';
}

/** Says how Nyctr may act on a source. */
export function writeText(mode: WriteMode) {
  return {
    simulated: 'Simulated in demo',
    enabled: 'Nyctr may change it',
    disabled: 'Read-only',
  }[mode];
}

export type DeviceOs = 'mac' | 'windows' | 'iphone' | 'android' | 'other';
/** Guesses the operating system of the browser in use, only to pick reconnect steps. */
export function detectOs(agent = navigator.userAgent): DeviceOs {
  if (/iPhone|iPad|iPod/i.test(agent)) return 'iphone';
  if (/Android/i.test(agent)) return 'android';
  if (/Macintosh|Mac OS X/i.test(agent)) return 'mac';
  if (/Windows/i.test(agent)) return 'windows';
  return 'other';
}
