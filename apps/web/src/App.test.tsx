import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App, { writeLine } from './App';
import { setCsrfToken } from './api';
import { AuthProvider } from './auth';
import { mockApi } from './test/mock-api';
import type { Rules, User } from './types';

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
function openConsole(hash: string, routes: Record<string, unknown> = {}) {
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
    ...routes,
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
  // A title left by the last case must not satisfy the next one.
  document.title = '';
  vi.unstubAllGlobals();
  // Put element scrolling back exactly as jsdom had it, so the stand-in stays in these tests.
  if (scrollTo) Object.defineProperty(Element.prototype, 'scrollTo', scrollTo);
  else delete (Element.prototype as Partial<Element>).scrollTo;
});

describe('the footer line', () => {
  const source = (name: string, write_mode: string, collected = true) =>
    ({ id: name, name, write_mode, collected }) as unknown as Rules['sources'][number];
  const line = (...sources: Rules['sources']) => writeLine({ sources } as Rules, false);

  it('names only sources that have been read, and keeps a long list short', () => {
    expect(line(source('A', 'enabled'), source('B', 'disabled'))).toBe('May change A');
    expect(line(source('A', 'enabled'), source('Never read', 'enabled', false))).toBe(
      'May change A',
    );
    expect(line(...['A', 'B', 'C', 'D', 'E'].map((name) => source(name, 'enabled')))).toBe(
      'May change A, B and 3 more',
    );
    expect(line(source('Never read', 'enabled', false))).toBe(
      'May change sources once they are collected',
    );
    expect(line(source('B', 'disabled'))).toBe('Read-only for every source');
  });
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
    await waitFor(() => expect(document.title).toBe('Briefing · Nyctr'));
  });

  // "overview" is where single sign-on used to send administrators. The console has never had
  // a screen with that id; if one is added on purpose, drop that case and keep the made-up one.
  it.each([
    ['a made-up screen', '#/no-such-screen'],
    ['the old single sign-on landing', '#/overview'],
  ])('says the screen could not be found for %s', async (_name, hash) => {
    openConsole(hash);
    expect(await screen.findByText('This screen could not be found')).toBeTruthy();
    // The title is set after the screen is drawn, so reading it at once reads the one before.
    await waitFor(() => expect(document.title).toBe('Not found · Nyctr'));
  });
});

describe('a Needs-you list that could not be read', () => {
  it.each([
    ['the server failing', () => ({ __status: 500, detail: 'Internal Server Error' })],
    [
      'the connection dropping',
      () => {
        throw new TypeError('Failed to fetch');
      },
    ],
  ])('is never shown as nothing to do, with %s', async (_name, fail) => {
    let broken = true;
    const waiting = { kind: 'request', id: 'r1', severity: 'high', title: 'Sam is waiting' };
    openConsole('#/briefing', {
      'GET /attention': () => (broken ? fail() : [{ ...waiting, detail: '', at: null }]),
    });
    expect(await screen.findByText('Nyctr could not find out what needs you.')).toBeTruthy();
    const page = document.body.textContent!;
    expect(page).not.toContain('Nothing needs you right now.');
    expect(page).not.toContain('No cut-off guests');
    // Each count in the sidebar says it could not be counted; none is left out as if it were zero.
    const counts = screen.getAllByTitle('Could not be counted');
    expect(counts.map((item) => item.closest('a')!.textContent)).toEqual([
      'Findings?',
      'Requests?',
      'Guests?',
      'Sources?',
    ]);
    broken = false;
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('One thing needs you.')).toBeTruthy();
    expect(screen.getByRole('link', { name: /Requests/ }).textContent).toBe('Requests1');
    expect(screen.queryByTitle('Could not be counted')).toBeNull();
  });
});

describe('the A key hint', () => {
  const hint = async () => {
    openConsole('#/briefing');
    fireEvent.click(await screen.findByRole('button', { name: /Ask Nyctr/ }));
    await screen.findByRole('complementary', { name: 'Ask Nyctr' });
    return document.body.textContent!.includes('Open and close this with the A key');
  };

  it('is offered where there is a keyboard', async () => {
    expect(await hint()).toBe(true);
    expect(document.querySelector('.ask kbd')).toBeTruthy();
  });

  it('is not offered on a screen worked by touch alone', async () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query.includes('pointer: coarse'),
    }));
    expect(await hint()).toBe(false);
    expect(document.querySelector('.ask kbd')).toBeNull();
  });
});

describe('a retry after a failed re-read of a list that was empty', () => {
  it('does not say nothing needs you until the retry has an answer', async () => {
    let answer: () => unknown = () => [];
    let release: (value: unknown) => void = () => {};
    openConsole('#/access', {
      'GET /attention': () => answer(),
      'GET /suggestions': [
        { domain: 'docs.example', times: 2, people: [], last_at: null, scope: 'Everyone' },
      ],
      'POST /suggestions': {},
    });
    // The list answers empty once; then a change on another screen re-reads it, and that read fails.
    answer = () => ({ __status: 500, detail: 'Internal Server Error' });
    fireEvent.click(await screen.findByRole('button', { name: 'Dismiss' }));
    await screen.findAllByTitle('Could not be counted');
    window.location.hash = '#/briefing';
    expect(await screen.findByText('Nyctr could not find out what needs you.')).toBeTruthy();
    // Try again, with the answer held back: the empty list from before the failure is not shown as the answer.
    answer = () => new Promise((resolve) => (release = resolve));
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('Checking what needs you.')).toBeTruthy();
    expect(document.body.textContent).not.toContain('Nothing needs you right now.');
    expect(screen.getAllByTitle('Could not be counted')).toHaveLength(4);
    release([]);
    expect(await screen.findByText('Nothing needs you right now.')).toBeTruthy();
    expect(screen.queryByTitle('Could not be counted')).toBeNull();
  });
});

describe('the A key where it is not offered', () => {
  const pressA = async () => {
    openConsole('#/briefing');
    await screen.findByText('Nothing needs you right now.');
    fireEvent.keyDown(document.body, { key: 'a' });
    return screen.queryByRole('complementary', { name: 'Ask Nyctr' });
  };

  it('opens the assistant where there is a keyboard', async () => {
    expect(await pressA()).toBeTruthy();
  });

  it('does nothing on a screen worked by touch alone, where it cannot be turned off', async () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query.includes('pointer: coarse'),
    }));
    expect(await pressA()).toBeNull();
  });
});
