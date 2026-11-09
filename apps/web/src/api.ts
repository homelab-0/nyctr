import { useCallback, useEffect, useState } from 'react';

let csrfToken = '';
export const setCsrfToken = (value: string) => {
  csrfToken = value;
};

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

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

export const post = <T>(path: string, value: unknown = {}) =>
  api<T>(path, { method: 'POST', body: JSON.stringify(value) });

export function useApi<T>(path: string | null) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  const reload = useCallback(() => setRevision((x) => x + 1), []);
  useEffect(() => {
    if (!path) {
      setLoading(false);
      setData(null);
      return;
    }
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    setData(null);
    api<T>(path, { signal: controller.signal })
      .then((value) => {
        if (!controller.signal.aborted) setData(value);
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

export const label = (value: string | null | undefined) =>
  (value || 'unknown').replace(/_/g, ' ').replace(/\b\w/g, (x) => x.toUpperCase());
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
export const dateTime = (value: string | null | undefined) =>
  value ? new Date(value).toLocaleString() : 'Not collected';
export const stringify = (value: unknown) =>
  typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value ?? '—');
