import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { mockApi } from '../test/mock-api';
import { scheduleFixture, scheduleOff } from '../test/schedule';
import type { CollectionSchedule, Rules } from '../types';
import Setup from './Setup';

const rules: Rules = {
  access: { enabled: false, max_score: 25, max_minutes: 60, per_day: 4 },
  guest: { enabled: false, hits: 3, minutes: 5 },
  writes: { access: 'none', guests: 'none' },
  sources: [],
};

/** Opens the installation tab over a fabricated schedule that a save replaces. */
function open(first: CollectionSchedule, mode: 'live' | 'demo' = 'live') {
  let current = first;
  const calls = mockApi({
    'GET /rules': rules,
    'GET /auth/config': { mode, local_enabled: true, oidc_enabled: false },
    'GET /assistant': { provider: 'off', model: null },
    'GET /collection': () => current,
    'PUT /collection': (body: unknown) => {
      const sent = body as { enabled: boolean; minutes: number };
      current = scheduleFixture({
        enabled: sent.enabled,
        interval_seconds: sent.minutes * 60,
        next_at: sent.enabled ? new Date(Date.now() + sent.minutes * 60_000).toISOString() : null,
      });
      return current;
    },
  });
  render(<Setup params={new URLSearchParams('tab=system')} />);
  const saved = () => calls.filter((call) => call.method === 'PUT').map((call) => call.body);
  return { saved, user: userEvent.setup() };
}

const toggle = () => screen.findByRole('switch', { name: 'Scheduled collection' });
const interval = () => screen.getByLabelText('How often to collect') as HTMLSelectElement;

const system = {
  'GET /rules': rules,
  'GET /auth/config': { mode: 'live', local_enabled: true, oidc_enabled: false },
  'GET /assistant': { provider: 'off', model: null },
};

/** Holds back every later request of one kind until `release` is called. */
function holdBack(method: string, path: string) {
  const inner = globalThis.fetch;
  let release = () => {};
  const held = new Promise<void>((resolve) => (release = resolve));
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, options?: RequestInit) => {
    // The request reaches the server at once; only its answer is held back.
    const answer = inner(input, options).catch((error: unknown) => ({ error }));
    if ((options?.method || 'GET') === method && String(input) === `/api${path}`) await held;
    const settled = await answer;
    if (settled instanceof Response) return settled;
    throw settled.error;
  });
  return release;
}

/** Moves a closed list one choice with an arrow key, as a browser does on Linux and Windows. */
function arrowTo(value: string) {
  fireEvent.keyDown(interval(), { key: 'ArrowDown' });
  fireEvent.change(interval(), { target: { value } });
}

beforeEach(() => setCsrfToken('csrf'));
afterEach(() => {
  cleanup();
  setCsrfToken('');
  vi.unstubAllGlobals();
});

describe('collection schedule in Setup', () => {
  it('shows the schedule in force and saves a new interval from the list', async () => {
    const { saved, user } = open(scheduleFixture({ source: 'default' }));
    expect((await toggle()).getAttribute('aria-checked')).toBe('true');
    expect(interval().value).toBe('15');
    expect([...interval().options].map((option) => option.text)).toEqual([
      'Every 5 minutes',
      'Every 15 minutes',
      'Every 30 minutes',
      'Every 1 hour',
      'Every 3 hours',
      'Every 6 hours',
      'Every 12 hours',
      'Every 1 day',
    ]);
    expect(screen.getByText('Next collection in 12 min')).toBeDefined();
    expect(screen.getByText(/Nobody has changed this yet/)).toBeDefined();
    expect(screen.getByText(/can cut a guest off when nobody is at the console/)).toBeDefined();
    await user.selectOptions(interval(), '60');
    await waitFor(() => expect(interval().value).toBe('60'));
    expect(saved()).toEqual([{ enabled: true, minutes: 60 }]);
    expect(screen.getByText('Next collection in about 1 hr')).toBeDefined();
    expect(screen.queryByText(/Nobody has changed this yet/)).toBeNull();
  });

  it('turns the schedule off and then promises no collection', async () => {
    const { saved, user } = open(scheduleFixture());
    await user.click(await toggle());
    expect(await screen.findByText('Only when you press Collect')).toBeDefined();
    expect(saved()).toEqual([{ enabled: false, minutes: 15 }]);
    expect((await toggle()).getAttribute('aria-checked')).toBe('false');
    expect(interval().disabled).toBe(true);
  });

  it('shows a deployment value that is not on the list and saves the nearest choice', async () => {
    const { saved, user } = open(scheduleFixture({ source: 'deployment', interval_seconds: 5400 }));
    await toggle();
    expect(interval().selectedOptions[0].text).toBe('Every 90 minutes');
    expect(screen.getByText(/NYCTR_COLLECT_INTERVAL_SECONDS/)).toBeDefined();
    await user.click(await toggle());
    await waitFor(() => expect(saved()).toEqual([{ enabled: false, minutes: 60 }]));
  });

  it('shows a refused save and keeps the schedule that is really in force', async () => {
    mockApi({
      'GET /rules': rules,
      'GET /auth/config': { mode: 'live', local_enabled: true, oidc_enabled: false },
      'GET /assistant': { provider: 'off', model: null },
      'GET /collection': scheduleFixture(),
      'PUT /collection': { __status: 403, detail: 'Administrator access required' },
    });
    render(<Setup params={new URLSearchParams('tab=system')} />);
    await userEvent.setup().click(await toggle());
    expect(await screen.findByText('Administrator access required')).toBeDefined();
    expect((await toggle()).getAttribute('aria-checked')).toBe('true');
  });

  it('keeps keyboard focus on the list during a save and saves once for several arrow steps', async () => {
    const { saved } = open(scheduleFixture());
    await toggle();
    const release = holdBack('PUT', '/collection');
    interval().focus();
    arrowTo('30');
    arrowTo('60');
    arrowTo('180');
    expect(interval().value).toBe('180');
    expect(saved()).toEqual([]);
    await waitFor(() => expect(saved()).toEqual([{ enabled: true, minutes: 180 }]));
    // The save is on its way: the list keeps focus, is not disabled, and takes no second change.
    expect(interval().disabled).toBe(false);
    expect(interval().getAttribute('aria-disabled')).toBe('true');
    expect(document.activeElement).toBe(interval());
    arrowTo('360');
    release();
    await waitFor(() => expect(interval().getAttribute('aria-disabled')).toBeNull());
    expect(interval().value).toBe('180');
    expect(document.activeElement).toBe(interval());
    expect(saved()).toHaveLength(1);
    // The list still works from the keyboard afterwards.
    arrowTo('360');
    await waitFor(() => expect(saved()).toHaveLength(2));
    expect(saved()[1]).toEqual({ enabled: true, minutes: 360 });
  });

  it('saves a choice made with the keyboard as soon as focus leaves the list', async () => {
    const { saved } = open(scheduleFixture());
    await toggle();
    interval().focus();
    arrowTo('30');
    expect(saved()).toEqual([]);
    fireEvent.blur(interval());
    expect(saved()).toEqual([{ enabled: true, minutes: 30 }]);
    await waitFor(() => expect(screen.getByText(/^Next collection in 3[01] min$/)).toBeDefined());
  });

  it('keeps keyboard focus on the switch during a save and ignores a second press', async () => {
    const { saved, user } = open(scheduleFixture());
    const button = (await toggle()) as HTMLButtonElement;
    const release = holdBack('PUT', '/collection');
    button.focus();
    await user.keyboard(' ');
    await waitFor(() => expect(saved()).toHaveLength(1));
    expect(button.disabled).toBe(false);
    expect(document.activeElement).toBe(button);
    await user.keyboard(' ');
    release();
    await waitFor(() => expect(button.getAttribute('aria-checked')).toBe('false'));
    expect(document.activeElement).toBe(button);
    expect(saved()).toEqual([{ enabled: false, minutes: 15 }]);
  });

  it('shows the schedule the save answered with even when no later read gets through', async () => {
    let reads = 0;
    mockApi({
      ...system,
      'GET /collection': () => {
        reads += 1;
        if (reads > 1) throw new TypeError('Failed to fetch');
        return scheduleFixture();
      },
      'PUT /collection': scheduleOff(),
    });
    render(<Setup params={new URLSearchParams('tab=system')} />);
    await userEvent.setup().click(await toggle());
    await waitFor(async () => expect((await toggle()).getAttribute('aria-checked')).toBe('false'));
    expect(screen.getByText('Only when you press Collect')).toBeDefined();
    expect(screen.queryByText(/Next collection in/)).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('cannot turn the schedule back on from a list that still showed it on', async () => {
    const { saved, user } = open(scheduleFixture());
    const button = await toggle();
    // Any read after the save never answers, so only the save's own answer can update the panel.
    const release = holdBack('GET', '/collection');
    await user.click(button);
    await waitFor(() => expect(saved()).toHaveLength(1));
    await waitFor(() => expect(interval().disabled).toBe(true));
    await user.selectOptions(interval(), '30').catch(() => undefined);
    await user.click(button);
    await waitFor(() => expect(saved()).toHaveLength(2));
    expect(saved()).toEqual([
      { enabled: false, minutes: 15 },
      { enabled: true, minutes: 15 },
    ]);
    release();
  });

  it('reads the schedule in force when a save gets no answer, and says so in plain words', async () => {
    let current = scheduleFixture();
    const calls = mockApi({
      ...system,
      'GET /collection': () => current,
      'PUT /collection': () => {
        // The save lands, and the answer is lost on the way back.
        current = scheduleOff();
        throw new TypeError('Failed to fetch');
      },
    });
    render(<Setup params={new URLSearchParams('tab=system')} />);
    const user = userEvent.setup();
    const button = await toggle();
    const release = holdBack('GET', '/collection');
    await user.click(button);
    expect((await screen.findByRole('alert')).textContent).toBe(
      'Unable to reach Nyctr. Check the schedule shown here before you try again.',
    );
    // Until the schedule in force is back on screen, the stale switch does nothing.
    await user.click(button);
    expect(calls.filter((call) => call.method === 'PUT')).toHaveLength(1);
    release();
    await waitFor(() => expect(button.getAttribute('aria-checked')).toBe('false'));
    expect(screen.getByText('Only when you press Collect')).toBeDefined();
    expect(screen.queryByText(/Failed to fetch/)).toBeNull();
    expect(calls.filter((call) => call.method === 'PUT')).toHaveLength(1);
  });

  it('says the schedule on screen may be out of date when it cannot be read again', async () => {
    let reads = 0;
    mockApi({
      ...system,
      'GET /collection': () => {
        reads += 1;
        if (reads > 1) throw new TypeError('Failed to fetch');
        return scheduleFixture();
      },
      'PUT /collection': () => {
        throw new TypeError('Failed to fetch');
      },
    });
    render(<Setup params={new URLSearchParams('tab=system')} />);
    await userEvent.setup().click(await toggle());
    await waitFor(() => expect(screen.getAllByRole('alert')).toHaveLength(2));
    expect(screen.getAllByRole('alert').map((alert) => alert.textContent)).toEqual([
      'Unable to reach Nyctr. Nyctr could not read the schedule again, so what is shown here may be out of date.',
      'Unable to reach Nyctr. Check the schedule shown here before you try again.',
    ]);
    expect(screen.queryByText(/Failed to fetch/)).toBeNull();
  });

  it('cannot be switched on in demo mode, which never collects', async () => {
    open(scheduleFixture({ ...scheduleOff(), source: 'demo' }), 'demo');
    expect(((await toggle()) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('Demo mode uses sample data and never collects.')).toBeDefined();
    expect(screen.getByText('Sample data is not collected')).toBeDefined();
  });

  it('keeps the other installation facts read-only and no longer lists the schedule among them', async () => {
    open(scheduleFixture());
    await toggle();
    expect(
      screen.getByText(
        'These are set by whoever runs the server. They cannot be changed from the browser.',
      ),
    ).toBeDefined();
    expect(await screen.findByText('NYCTR_MODE')).toBeDefined();
    expect(screen.queryByText('Automatic collection')).toBeNull();
    expect(screen.queryByText('NYCTR_COLLECT_INTERVAL_SECONDS')).toBeNull();
  });
});
