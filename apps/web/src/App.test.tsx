import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { setCsrfToken } from './api';
import { AuthProvider } from './auth';
import { mockApi } from './test/mock-api';
import type { User } from './types';

const admin: User = {
  id: 'test-admin',
  email: 'admin@example.test',
  name: 'Test administrator',
  role: 'admin',
  mode: 'live',
  csrf_token: 'fabricated-csrf-token',
};

// jsdom has no element scrolling; the console resets the page scroll on every screen change.
const scrollTo = Object.getOwnPropertyDescriptor(Element.prototype, 'scrollTo');

/** Opens the console for a signed-in administrator at one address, with fabricated empty data. */
function openConsole(hash: string) {
  window.location.hash = hash;
  Element.prototype.scrollTo = vi.fn();
  mockApi({
    'GET /auth/me': admin,
    'GET /attention': [],
    'GET /rules': { sources: [] },
    'GET /integrations/catalog': { capabilities: [], providers: [] },
    'GET /assistant': { __status: 404 },
    'GET /overview': { __status: 404 },
    'GET /leases': [],
    'GET /integrations': [],
  });
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
}

afterEach(() => {
  cleanup();
  setCsrfToken('');
  window.location.hash = '';
  // Put element scrolling back exactly as jsdom had it, so the stand-in stays in these tests.
  if (scrollTo) Object.defineProperty(Element.prototype, 'scrollTo', scrollTo);
  else delete (Element.prototype as Partial<Element>).scrollTo;
});

describe('console landing', () => {
  // "/#/" is where the server sends an administrator after single sign-on
  // (services/api/nyctr/oidc.py, pinned in services/api/tests/test_sites.py).
  // An address with no fragment at all must open the same screen.
  it.each([
    ['the address single sign-on lands on', '#/'],
    ['an address with no fragment', ''],
  ])('shows the Briefing at %s', async (_name, hash) => {
    openConsole(hash);
    expect(await screen.findByText('Nothing needs you right now.')).toBeTruthy();
    expect(screen.queryByText('This screen could not be found')).toBeNull();
    expect(document.title).toBe('Briefing · Nyctr');
  });

  // "overview" is where single sign-on used to send administrators. The console has never had
  // a screen with that id; if one is added on purpose, drop that case and keep the made-up one.
  it.each([
    ['a made-up screen', '#/no-such-screen'],
    ['the old single sign-on landing', '#/overview'],
  ])('says the screen could not be found for %s', async (_name, hash) => {
    openConsole(hash);
    expect(await screen.findByText('This screen could not be found')).toBeTruthy();
    expect(document.title).toBe('Not found · Nyctr');
  });
});
