import { useCallback, useEffect, useRef, useState } from 'react';

let csrfToken = '';
/** Replaces the session's in-memory mutation token; an empty value clears it on sign-out. */
export const setCsrfToken = (value: string) => {
  csrfToken = value;
};

/** Retains HTTP status so callers can distinguish expired sessions from retryable failures. */
export class ApiError extends Error {
  /** Stores the displayable API message without retaining the response body or credentials. */
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

/**
 * Calls a relative API endpoint with same-origin cookies and CSRF on mutations.
 * Non-authentication 401s invalidate the shared session; authentication callers
 * handle their own errors so a rejected sign-in does not trigger an expiry event.
 * HTTP failures become ApiError; transport failures retain their original type.
 */
export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body) headers.set('Content-Type', 'application/json');
  if (options.method && !['GET', 'HEAD'].includes(options.method.toUpperCase()) && csrfToken) {
    headers.set('X-CSRF-Token', csrfToken);
  }
  const response = await fetch(`/api${path}`, { ...options, headers, credentials: 'same-origin' });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && !path.startsWith('/auth/'))
      window.dispatchEvent(new Event('nyctr:session-expired'));
    const detail = body?.detail;
    const message =
      typeof detail === 'string'
        ? detail
        : Array.isArray(detail)
          ? detail.map((d: { msg?: string }) => d.msg ?? 'Invalid input').join('. ')
          : `Request failed (${response.status}). Please try again.`;
    throw new ApiError(message, response.status);
  }
  return body as T;
}

/** Sends a JSON mutation through the shared cookie, CSRF, and error-handling boundary. */
export const post = <T>(path: string, value: unknown = {}) =>
  api<T>(path, { method: 'POST', body: JSON.stringify(value) });

/** Sends a JSON replacement through the same cookie, CSRF, and error-handling boundary. */
export const put = <T>(path: string, value: unknown = {}) =>
  api<T>(path, { method: 'PUT', body: JSON.stringify(value) });

/**
 * Loads one API resource and discards results from aborted or superseded reads.
 * A null path disables collection. Data is cleared when the path changes so a view
 * cannot mistake evidence from its previous scope for the newly selected scope.
 * `reload` re-reads the same path and keeps the current data on screen until the
 * fresh result arrives, so a list does not blank out after every action.
 */
export function useApi<T>(path: string | null) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  const loaded = useRef<string | null>(null);
  /** Invalidates this read without changing its scope or bypassing API authorization. */
  const reload = useCallback(() => setRevision((x) => x + 1), []);
  /** Owns the request lifetime; cleanup prevents late responses from updating the next view. */
  useEffect(() => {
    if (!path) {
      setLoading(false);
      setData(null);
      loaded.current = null;
      return;
    }
    const controller = new AbortController();
    const refresh = loaded.current === path;
    if (!refresh) {
      // The data on screen is cleared, so nothing is loaded any more. Without this a failed
      // read of another path would leave "loaded" pointing at data that is no longer held.
      loaded.current = null;
      setLoading(true);
      setData(null);
    }
    setError(null);
    api<T>(path, { signal: controller.signal })
      .then((value) => {
        if (controller.signal.aborted) return;
        loaded.current = path;
        setData(value);
      })
      .catch((err: Error) => {
        if (!controller.signal.aborted) setError(err.message || 'Unable to reach Nyctr.');
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [path, revision]);
  return { data, error, loading, reload };
}

/** Formats provider enum labels while keeping missing values explicitly unknown. */
export const label = (value: string | null | undefined) =>
  (value || 'unknown').replace(/_/g, ' ').replace(/\b\w/g, (x) => x.toUpperCase());
/** Formats collection age or future expiry without treating missing/invalid timestamps as fresh. */
export function relativeTime(value: string | null | undefined) {
  if (!value) return 'Not collected';
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return 'Unknown time';
  const seconds = Math.floor((Date.now() - time) / 1000);
  if (seconds < 0) return `in ${Math.max(1, Math.ceil(-seconds / 60))} min`;
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hr ago`;
  return `${Math.floor(seconds / 86400)} days ago`;
}
/** Displays a source timestamp in the viewer's locale, preserving an absent-collection label. */
export const dateTime = (value: string | null | undefined) =>
  value ? new Date(value).toLocaleString() : 'Not collected';
/** Converts source attributes to plain display text; consumers render it as escaped React text. */
export const stringify = (value: unknown) =>
  typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value ?? '—');
