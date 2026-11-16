import { useEffect, useRef } from 'react';

/** How often to read again during the first two minutes, and after that. */
const SOON_MS = 5_000;
const LATER_MS = 30_000;
/** Fast reads last this long from the moment the page began waiting. */
const SOON_FOR_MS = 120_000;

/**
 * Reads again while `waiting` is true, so a page left open shows an answer when it comes.
 * Every 5 seconds for the first two minutes, then every 30. Nothing is read while the tab
 * is hidden; showing the tab again resumes the wait. The two minutes keep running while
 * the tab is hidden. Reading stops as soon as `waiting` is false.
 */
export function useRefreshWhile(waiting: boolean, read: () => void) {
  const readRef = useRef(read);
  readRef.current = read;
  const began = useRef<number | null>(null);

  useEffect(() => {
    if (!waiting) {
      began.current = null;
      return;
    }
    if (began.current === null) began.current = Date.now();
    let timer = 0;
    let stopped = false;
    const hidden = () => document.visibilityState === 'hidden';
    const arm = () => {
      window.clearTimeout(timer);
      if (stopped || hidden()) return;
      const elapsed = Date.now() - (began.current ?? Date.now());
      timer = window.setTimeout(
        () => {
          if (stopped || hidden()) return;
          readRef.current();
          arm();
        },
        elapsed < SOON_FOR_MS ? SOON_MS : LATER_MS,
      );
    };
    const onVisibility = () => arm();
    document.addEventListener('visibilitychange', onVisibility);
    arm();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [waiting]);
}
