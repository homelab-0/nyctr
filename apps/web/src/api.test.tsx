// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { useApi } from './api';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('useApi', () => {
  /**
   * Load A, switch to B and fail, switch back to A. While A is being read again the hook holds
   * no data, so it must say it is loading; screens that read `data` once loading ends rely on it.
   */
  it('reports loading again when returning to a path after another path failed', async () => {
    let releaseSecondA: () => void = () => {};
    let readsOfA = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockImplementation(async (input) => {
        const path = String(input);
        if (path.endsWith('/b'))
          return new Response(JSON.stringify({ detail: 'No such scope' }), {
            status: 404,
            headers: { 'Content-Type': 'application/json' },
          });
        readsOfA += 1;
        if (readsOfA === 2) await new Promise<void>((resolve) => (releaseSecondA = resolve));
        return new Response(JSON.stringify({ name: 'a' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    );
    const { result, rerender } = renderHook(({ path }) => useApi<{ name: string }>(path), {
      initialProps: { path: '/a' },
    });
    await waitFor(() => expect(result.current.data).toEqual({ name: 'a' }));
    rerender({ path: '/b' });
    await waitFor(() => expect(result.current.error).toBe('No such scope'));
    expect(result.current.data).toBeNull();
    rerender({ path: '/a' });
    await waitFor(() => expect(readsOfA).toBe(2));
    expect(result.current.data).toBeNull();
    expect(result.current.loading).toBe(true);
    await act(async () => releaseSecondA());
    await waitFor(() => expect(result.current.data).toEqual({ name: 'a' }));
    expect(result.current.loading).toBe(false);
  });

  /** A reload of the same path keeps what is on screen, which is the behaviour to preserve. */
  it('keeps data on screen while the same path is read again', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockImplementation(
        async () =>
          new Response(JSON.stringify({ name: 'a' }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          }),
      ),
    );
    const { result } = renderHook(() => useApi<{ name: string }>('/a'));
    await waitFor(() => expect(result.current.data).toEqual({ name: 'a' }));
    act(() => result.current.reload());
    expect(result.current.data).toEqual({ name: 'a' });
    expect(result.current.loading).toBe(false);
  });
});
