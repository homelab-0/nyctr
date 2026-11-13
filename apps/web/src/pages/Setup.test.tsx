import { cleanup, render, screen, waitFor } from '@testing-library/react';
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
