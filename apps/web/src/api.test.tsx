// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError, setCsrfToken, useApi } from './api';

afterEach(() => {
  cleanup();
  setCsrfToken('');
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('session-owned failures', () => {
  it.each(['new-token', 'same-token'])(
    'keeps a later session after an older 401 with %s',
    async (next) => {
      let release: (response: Response) => void = () => {};
      const held = new Promise<Response>((resolve) => {
        release = resolve;
      });
      const fetchMock = vi.fn<typeof fetch>().mockReturnValueOnce(held);
      vi.stubGlobal('fetch', fetchMock);
      const events = vi.spyOn(window, 'dispatchEvent');
      setCsrfToken('same-token');
      const old = api('/statements', {
        method: 'POST',
        body: JSON.stringify({ domain: 'ads.example' }),
      }).catch((error: unknown) => error);
      setCsrfToken(next);
      release(
        new Response(JSON.stringify({ detail: 'Injected old session expired' }), { status: 401 }),
      );
      const failure = await old;
      expect(failure).toBeInstanceOf(ApiError);
      expect(failure).toMatchObject({ status: 401, message: 'Injected old session expired' });
      expect(events).not.toHaveBeenCalled();
      expect(fetchMock.mock.calls[0][1]?.credentials).toBe('same-origin');
      expect(new Headers(fetchMock.mock.calls[0][1]?.headers).get('X-CSRF-Token')).toBe(
        'same-token',
      );
      fetchMock.mockResolvedValueOnce(new Response('{}'));
      await api('/statements', { method: 'POST', body: '{}' });
      expect(new Headers(fetchMock.mock.calls[1][1]?.headers).get('X-CSRF-Token')).toBe(next);
    },
  );

  it('still expires the current session on its own 401 and preserves its refusal', async () => {
    const events = vi.spyOn(window, 'dispatchEvent');
    setCsrfToken('current-token');
    vi.stubGlobal(
      'fetch',
      vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ detail: 'Current session expired' }), { status: 401 }),
        ),
    );
    await expect(api('/statements', { method: 'POST', body: '{}' })).rejects.toMatchObject({
      status: 401,
      message: 'Current session expired',
    });
    expect(events).toHaveBeenCalledTimes(1);
    expect(events.mock.calls[0][0].type).toBe('nyctr:session-expired');
  });

  it.each([
    ['/auth/login', 401],
    ['/statements', 403],
  ] as const)(
    'keeps %s HTTP %s with its caller and does not expire a session',
    async (path, status) => {
      const events = vi.spyOn(window, 'dispatchEvent');
      setCsrfToken('current-token');
      vi.stubGlobal(
        'fetch',
        vi
          .fn<typeof fetch>()
          .mockResolvedValueOnce(
            new Response(JSON.stringify({ detail: 'Injected refusal' }), { status }),
          ),
      );
      await expect(api(path, { method: 'POST', body: '{}' })).rejects.toMatchObject({
        status,
        message: 'Injected refusal',
      });
      expect(events).not.toHaveBeenCalled();
    },
  );
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
    act(() => {
      void result.current.reload();
    });
    expect(result.current.data).toEqual({ name: 'a' });
    expect(result.current.loading).toBe(false);
  });

  /**
   * Two reloads in one turn commit only the later revision. The earlier promise has to settle
   * with that read, and a read that starts afterwards has to wait for its own answer.
   */
  it('settles an earlier reload when a later read is the one that runs', async () => {
    let release: () => void = () => {};
    let reads = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn<typeof fetch>().mockImplementation(async (_input, options) => {
        reads += 1;
        if (reads > 1) {
          await new Promise<void>((resolve, reject) => {
            const stop = () => reject(new DOMException('aborted', 'AbortError'));
            options?.signal?.addEventListener('abort', stop, { once: true });
            release = () => {
              options?.signal?.removeEventListener('abort', stop);
              resolve();
            };
          });
        }
        return new Response(JSON.stringify({ name: 'a' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }),
    );
    const { result } = renderHook(() => useApi<{ name: string }>('/a'));
    await waitFor(() => expect(result.current.data).toEqual({ name: 'a' }));
    expect(reads).toBe(1);

    let first = false;
    let second = false;
    let third = false;
    let firstDone: Promise<void> = Promise.resolve();
    let secondDone: Promise<void> = Promise.resolve();
    act(() => {
      firstDone = result.current.reload().then(() => {
        first = true;
      });
    });
    await waitFor(() => expect(reads).toBe(2));
    act(() => {
      secondDone = result.current.reload().then(() => {
        second = true;
      });
      void result.current.reload().then(() => {
        third = true;
      });
    });
    await waitFor(() => expect(first).toBe(true));
    expect(second).toBe(false);
    expect(third).toBe(false);
    expect(reads).toBe(3);
    await act(async () => release());
    await firstDone;
    await secondDone;
    await waitFor(() => expect(third).toBe(true));
    expect(second).toBe(true);
    expect(result.current.data).toEqual({ name: 'a' });
  });
});
