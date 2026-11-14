import { vi } from 'vitest';
import type { Block, BlockList } from '../types';

/** A fixed answer, or a function giving one; a function may give a promise to answer later. */
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
    const value = await (typeof handler === 'function'
      ? (handler as (b: unknown) => unknown)(body)
      : handler);
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

/** The answer the blocks route gives for these stored lookups when they all fit on one page. */
export function blockList(rows: Block[], extra: Partial<BlockList> = {}): BlockList {
  const band = { high: 0, medium: 0, low: 0, unknown: 0 };
  const source: BlockList['counts']['source'] = {};
  for (const row of rows) {
    band[row.risk_band] += 1;
    const kind = (source[row.source] ||= { total: 0, unnamed: 0 });
    kind.total += 1;
    if (row.attribution === 'unattributed') kind.unnamed += 1;
  }
  const unnamed = rows.filter((row) => row.attribution === 'unattributed').length;
  const times = rows.map((row) => row.observed_at).sort();
  return {
    rows,
    next: null,
    page_size: 200,
    total: rows.length,
    matching: rows.length,
    oldest_at: times[0] || null,
    newest_at: times.at(-1) || null,
    counts: { band, source, named: rows.length - unnamed, unnamed },
    ...extra,
  };
}
