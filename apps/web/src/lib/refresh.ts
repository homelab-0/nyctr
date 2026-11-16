import { useEffect, useRef, useState } from 'react';

/** How often to read again during the first two minutes, and after that. */
const SOON_MS = 5_000;
const LATER_MS = 30_000;
/** Fast reads last this long from the moment the page began waiting. */
const SOON_FOR_MS = 120_000;

/**
 * A quiet line when the latest check failed and the page is still showing what it already has.
 * `againMs` is how long until the next check. With no further check coming, the line says only
 * that this one failed.
 */
export function checkFailedLine(againMs: number | null): string {
  if (againMs === null) return 'The latest check failed.';
  return `The latest check failed. Trying again in ${Math.round(againMs / 1000)} seconds.`;
}

/**
 * Reads again while `waiting` is true, so a page left open shows an answer when it comes.
 * Every 5 seconds for the first two minutes, then every 30. Nothing is read while the tab
 * is hidden. Showing the tab reads once straight away when a check is already due, and does
 * not push a check that is not yet due any later. The two minutes keep running while the tab
 * is hidden. A check that is still in flight is left to finish; the next one waits until it
 * does. Reading stops as soon as `waiting` is false.
 * Returns how long the current gap is, or null when the page is not waiting.
 */
export function useRefreshWhile(
  waiting: boolean,
  read: () => void | Promise<unknown>,
): number | null {
  const readRef = useRef(read);
  readRef.current = read;
  const began = useRef<number | null>(null);
  const due = useRef<number | null>(null);
  const [pace, setPace] = useState<number | null>(null);

  useEffect(() => {
    if (!waiting) {
      began.current = null;
      due.current = null;
      setPace(null);
      return;
    }
    if (began.current === null) began.current = Date.now();
    const delayFor = (at: number) => (at - began.current! < SOON_FOR_MS ? SOON_MS : LATER_MS);
    if (due.current === null) due.current = Date.now() + delayFor(Date.now());
    setPace(delayFor(Date.now()));

    let timer = 0;
    let stopped = false;
    let busy = false;
    const hidden = () => document.visibilityState === 'hidden';

    const arm = () => {
      window.clearTimeout(timer);
      if (stopped || hidden() || busy) return;
      const wait = Math.max(0, (due.current ?? Date.now()) - Date.now());
      timer = window.setTimeout(run, wait);
    };

    const run = () => {
      if (stopped || hidden() || busy) return;
      busy = true;
      window.clearTimeout(timer);
      // Wait for this check to finish before starting another, so a slow answer is not aborted.
      Promise.resolve(readRef.current()).finally(() => {
        busy = false;
        if (stopped) return;
        const now = Date.now();
        const delay = delayFor(now);
        due.current = now + delay;
        setPace(delay);
        if (!hidden()) arm();
      });
    };

    const onVisibility = () => {
      if (hidden()) {
        window.clearTimeout(timer);
        return;
      }
      setPace(delayFor(Date.now()));
      if ((due.current ?? 0) <= Date.now()) run();
      else arm();
    };

    document.addEventListener('visibilitychange', onVisibility);
    arm();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [waiting]);

  return waiting ? pace : null;
}
