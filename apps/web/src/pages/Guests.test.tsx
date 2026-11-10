import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { AuthProvider } from '../auth';
import { mockApi } from '../test/mock-api';
import type { GuestOverview, User } from '../types';
import Guests from './Guests';

const admin: User = {
  id: 'a',
  email: 'a@example.test',
  name: 'Alex',
  role: 'admin',
  mode: 'live',
  csrf_token: 'csrf',
};
const overview = (writes: GuestOverview['writes']): GuestOverview => ({
  writes,
  rule: { enabled: true, hits: 3, minutes: 5 },
  sources: [{ id: 'unifi', name: 'UniFi' }],
  passes: [],
  not_collected: ['Connection attempts and port scans'],
  devices: [
    {
      id: 'g1',
      name: 'Visitor phone',
      integration_id: 'unifi',
      mac: 'de:ad:00:00:00:01',
      ip: null,
      connected_at: null,
      access_point: { id: 'ap', name: 'Hall' },
      authorized: true,
      authorization: null,
      state: 'online',
      observed_at: new Date().toISOString(),
      pass: null,
      risk: {
        score: null,
        band: 'unknown',
        factors: [
          {
            label: 'No blocked lookups are tied to this device. That does not prove it is safe.',
            points: null,
          },
        ],
      },
      lookups: { blocked: 0, threat: 0 },
      timeline: [],
    },
  ],
});

function open(writes: GuestOverview['writes'], extra: Record<string, unknown> = {}) {
  const calls = mockApi({ 'GET /auth/me': admin, 'GET /guests': overview(writes), ...extra });
  render(
    <AuthProvider>
      <Guests params={new URLSearchParams('id=g1')} onChange={() => {}} />
    </AuthProvider>,
  );
  return { calls, user: userEvent.setup() };
}

afterEach(() => {
  cleanup();
  setCsrfToken('');
  vi.unstubAllGlobals();
});

describe('guests', () => {
  it('shows guests but disables every change while Nyctr is read-only for UniFi', async () => {
    open('disabled');
    expect(await screen.findByText('Nyctr is read-only for UniFi.')).toBeDefined();
    expect((screen.getByRole('button', { name: /Cut off/ }) as HTMLButtonElement).disabled).toBe(
      true,
    );
    expect((screen.getByRole('button', { name: /Lock out/ }) as HTMLButtonElement).disabled).toBe(
      true,
    );
    expect((screen.getByRole('button', { name: /Issue pass/ }) as HTMLButtonElement).disabled).toBe(
      true,
    );
    expect(screen.getByText(/a match is reported as a finding and nothing is cut/)).toBeDefined();
    expect(screen.getAllByText('No score').length).toBeGreaterThan(0);
    expect(screen.getByText('Connection attempts and port scans')).toBeDefined();
    expect(screen.queryByText(/Demo: make this device/)).toBeNull();
  });

  it('sends a cut-off as an explicit administrator action and the rule as the written values', async () => {
    const { user, calls } = open('enabled', {
      'POST /guests/actions': {
        ...overview('enabled').devices[0],
        state: 'cut',
        authorized: false,
      },
      'PUT /rules/guest': { enabled: true, hits: 4, minutes: 5 },
    });
    await user.click(await screen.findByRole('button', { name: /Cut off/ }));
    expect(calls.find((call) => call.path === '/guests/actions')?.body).toEqual({
      device_id: 'g1',
      action: 'cut',
    });
    await user.click(screen.getByRole('button', { name: 'Raise lookups' }));
    expect(calls.find((call) => call.path === '/rules/guest')?.body).toEqual({
      enabled: true,
      hits: 4,
      minutes: 5,
    });
  });
});
