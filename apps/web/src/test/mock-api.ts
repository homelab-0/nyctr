import { vi } from 'vitest';

type Handler = unknown | ((body: unknown) => unknown);

/**
 * Replaces fetch with fabricated JSON responses keyed by "METHOD /path".
 * An unexpected request fails the test loudly instead of silently returning nothing.
 */
export function mockApi(routes: Record<string, Handler>) {
  const calls: { method: string; path: string; body: unknown }[] = [];
  const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (input, options) => {
    const method = (options?.method || 'GET').toUpperCase();
    const path = String(input).replace(/^\/api/, '');
    const body = options?.body ? JSON.parse(String(options.body)) : undefined;
    calls.push({ method, path, body });
    const handler = routes[`${method} ${path}`];
    if (handler === undefined) throw new Error(`Unexpected synthetic request: ${method} ${path}`);
    const value =
      typeof handler === 'function' ? (handler as (b: unknown) => unknown)(body) : handler;
    const status =
      value && typeof value === 'object' && '__status' in value
        ? Number((value as { __status: number }).__status)
        : 200;
    return new Response(JSON.stringify(value), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  });
  vi.stubGlobal('fetch', fetchMock);
  return calls;
}
