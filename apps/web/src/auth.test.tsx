import { useState } from 'react';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { post, setCsrfToken } from './api';
import { AuthProvider, useAuth } from './auth';
import type { User } from './types';

const user: User = {
  id: 'test-admin',
  email: 'admin@example.test',
  name: 'Test administrator',
  role: 'admin',
  mode: 'live',
  csrf_token: 'fabricated-csrf-token',
};

/** Exposes the real provider's identity and caller-visible logout errors to DOM assertions. */
function SessionHarness() {
  const { user: identity, loading, logout } = useAuth();
  const [failure, setFailure] = useState('');
  return (
    <>
      <p>{loading ? 'Loading session' : (identity?.email ?? 'Signed out')}</p>
      <button onClick={() => void logout().catch((error: Error) => setFailure(error.message))}>
        Sign out
      </button>
      {failure && <p role="alert">{failure}</p>}
    </>
  );
}

/** Creates a synthetic HTTP response while retaining the actual API helper's error handling. */
function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** Boots a server-authenticated session; only the transport is replaced by a test double. */
async function openSession() {
  const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(jsonResponse(user));
  vi.stubGlobal('fetch', fetchMock);
  render(
    <AuthProvider>
      <SessionHarness />
    </AuthProvider>,
  );
  await screen.findByText(user.email);
  return { fetchMock, interaction: userEvent.setup() };
}

/** Observes the token on a later mutation without exposing an API-only token getter. */
async function csrfAfterLogout(fetchMock: ReturnType<typeof vi.fn<typeof fetch>>) {
  fetchMock.mockResolvedValueOnce(jsonResponse({}));
  await post('/test-probe');
  const [, options] = fetchMock.mock.calls.at(-1)!;
  return new Headers(options?.headers).get('X-CSRF-Token');
}

/** Isolates each test from the previous session's in-memory token and landing route. */
beforeEach(() => {
  setCsrfToken('');
  window.location.hash = '/explorer';
});

/** Unmounts the provider so event subscriptions and credentials cannot leak between cases. */
afterEach(() => {
  cleanup();
  setCsrfToken('');
});

/** Exercises the real auth/API boundary, distinguishing session expiry from failed revocation. */
describe('AuthProvider logout', () => {
  /** Both terminal server outcomes must clear identity and future CSRF headers after the request. */
  it.each([200, 401])('clears identity and CSRF, then redirects after HTTP %s', async (status) => {
    const { fetchMock, interaction } = await openSession();
    fetchMock.mockResolvedValueOnce(jsonResponse({ detail: 'Session expired' }, status));

    await interaction.click(screen.getByRole('button', { name: 'Sign out' }));

    await screen.findByText('Signed out');
    expect(window.location.hash).toBe('#/');
    expect(screen.queryByRole('alert')).toBeNull();
    const [path, request] = fetchMock.mock.calls[1];
    expect(path).toBe('/api/auth/logout');
    expect(request?.method).toBe('POST');
    expect(request?.credentials).toBe('same-origin');
    expect(new Headers(request?.headers).get('X-CSRF-Token')).toBe(user.csrf_token);
    expect(await csrfAfterLogout(fetchMock)).toBeNull();
  });

  /** Authorization/server errors cannot be interpreted as proof that a session was revoked. */
  it.each([403, 500])(
    'preserves the session and reports the real HTTP %s failure',
    async (status) => {
      const { fetchMock, interaction } = await openSession();
      fetchMock.mockResolvedValueOnce(jsonResponse({ detail: 'Logout was rejected' }, status));

      await interaction.click(screen.getByRole('button', { name: 'Sign out' }));

      expect((await screen.findByRole('alert')).textContent).toBe('Logout was rejected');
      expect(screen.getByText(user.email)).toBeDefined();
      expect(screen.queryByText('Signed out')).toBeNull();
      expect(window.location.hash).toBe('#/explorer');
      expect(await csrfAfterLogout(fetchMock)).toBe(user.csrf_token);
    },
  );

  /** A transport error has no authoritative session outcome and must reach the caller unchanged. */
  it('preserves the session and exposes a network failure instead of claiming success', async () => {
    const { fetchMock, interaction } = await openSession();
    fetchMock.mockRejectedValueOnce(new TypeError('Network connection failed'));

    await interaction.click(screen.getByRole('button', { name: 'Sign out' }));

    await waitFor(() =>
      expect(screen.getByRole('alert').textContent).toBe('Network connection failed'),
    );
    expect(screen.getByText(user.email)).toBeDefined();
    expect(window.location.hash).toBe('#/explorer');
    expect(await csrfAfterLogout(fetchMock)).toBe(user.csrf_token);
  });
});
