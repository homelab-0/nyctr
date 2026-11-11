import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AuthProvider } from '../auth';
import { mockApi } from '../test/mock-api';
import SignIn from './SignIn';

function open(config: Record<string, unknown>) {
  mockApi({
    'GET /auth/me': { __status: 401, detail: 'Sign in to continue' },
    'GET /auth/config': { mode: 'live', local_enabled: false, oidc_enabled: true, ...config },
  });
  render(
    <AuthProvider>
      <SignIn />
    </AuthProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('sign-in page', () => {
  it('speaks to someone with a blocked site on the member portal address', async () => {
    open({ site: 'portal', portal_url: 'https://blocked.example' });
    expect(await screen.findByRole('heading', { name: /A site would not open/ })).toBeDefined();
    expect(screen.queryByText(/hypervisor/)).toBeNull();
    expect(screen.queryByRole('link', { name: /blocked sites page/ })).toBeNull();
    expect(screen.getByRole('link', { name: /single sign-on/ })).toBeDefined();
  });

  it('points members from the console address to the portal address', async () => {
    open({ site: 'console', portal_url: 'https://blocked.example' });
    const link = await screen.findByRole('link', { name: /blocked sites page/ });
    expect(link.getAttribute('href')).toBe('https://blocked.example');
    expect(screen.getByText(/for administrators/)).toBeDefined();
    expect(screen.getByRole('heading', { name: /See what is connected/ })).toBeDefined();
  });

  it('is unchanged when there is one address for everyone', async () => {
    open({});
    expect(await screen.findByText(/Sign in to see why and ask to open it/)).toBeDefined();
    expect(screen.queryByText(/for administrators/)).toBeNull();
    expect(screen.queryByRole('link', { name: /blocked sites page/ })).toBeNull();
  });
});
