import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { AuthProvider } from '../auth';
import { mockApi } from '../test/mock-api';
import { scheduleFixture, scheduleOff } from '../test/schedule';
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
  portal: {
    served_by: ['UniFi Network'],
    nyctr_in_guest_path: false,
    wifi: [
      { name: 'Home', enabled: true, captive_portal: false, network: 'LAN' },
      { name: 'Home Guest', enabled: true, captive_portal: true, network: 'Guest' },
    ],
    notice: 'This guest Wi-Fi is monitored for security.',
    nudge: false,
  },
  sources: [
    {
      id: 'unifi',
      name: 'Office network',
      provider_name: 'UniFi Network',
      passes: writes,
      control: writes,
    },
  ],
  passes: [],
  not_collected: ['Connection attempts and port scans'],
  devices: [
    {
      id: 'g1',
      name: 'Visitor phone',
      integration_id: 'unifi',
      source: 'UniFi Network',
      mac: 'de:ad:00:00:00:01',
      ip: null,
      connected_at: null,
      access_point: { id: 'ap', name: 'Hall' },
      authorized: true,
      authorization: null,
      state: 'online',
      observed_at: new Date().toISOString(),
      pass: null,
      joined_by: null,
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
  it('leads with why it cannot tell who is a guest, and does not say nobody is on', async () => {
    const base = overview('enabled');
    const ungated = {
      ...base,
      devices: [],
      portal: { ...base.portal, wifi: [base.portal.wifi[0]] },
    };
    open('enabled', { 'GET /guests': ungated });
    expect(
      await screen.findByText('Office network reports that no Wi-Fi name uses a sign-in page.'),
    ).toBeDefined();
    const page = document.body.textContent!;
    expect(page.indexOf('no Wi-Fi name uses a sign-in page.')).toBeLessThan(
      page.indexOf('Who is on'),
    );
    expect(page).toContain('Nyctr cannot tell who is a guest here.');
    expect(page).not.toContain('Nobody is on the guest Wi-Fi');
    expect(page).not.toContain('No guest devices are connected');
    cleanup();
    open('disabled', {
      'GET /guests': {
        ...ungated,
        sources: [],
        portal: { ...base.portal, served_by: [], wifi: [] },
      },
    });
    expect(
      await screen.findByText('No connected source can tell guests from other devices.'),
    ).toBeDefined();
    expect(screen.queryByText(/read-only/)).toBeNull();
  });

  it('says how often the cut-off rule is applied, and promises nothing while the schedule is off', async () => {
    open('enabled', { 'GET /collection': scheduleFixture() });
    expect(
      await screen.findByText(
        'A rule you write. Nyctr applies it after each collection, every 15 minutes.',
      ),
    ).toBeDefined();
    cleanup();
    open('enabled', { 'GET /collection': scheduleOff() });
    expect(
      await screen.findByText('A rule you write. Nyctr applies it when a source is collected.'),
    ).toBeDefined();
    expect(screen.queryByText(/each collection/)).toBeNull();
  });

  it('shows guests but disables every change while Nyctr is read-only for the source', async () => {
    open('disabled');
    expect(await screen.findByText('Nyctr is read-only for Office network.')).toBeDefined();
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

  it('says the network source serves the sign-in page and lets a waiting device on for a chosen time', async () => {
    const waiting = overview('enabled');
    waiting.devices[0] = { ...waiting.devices[0], state: 'waiting', authorized: false };
    const calls = mockApi({
      'GET /auth/me': admin,
      'GET /guests': waiting,
      'POST /guests/actions': {
        ...waiting.devices[0],
        state: 'online',
        authorized: true,
        joined_by: 'administrator',
      },
    });
    const user = userEvent.setup();
    render(
      <AuthProvider>
        <Guests params={new URLSearchParams('id=g1')} onChange={() => {}} />
      </AuthProvider>,
    );
    expect(
      await screen.findByText('UniFi Network shows the sign-in page. Nyctr never does.'),
    ).toBeDefined();
    expect(screen.getByText('Guests never need to reach Nyctr.')).toBeDefined();
    expect(screen.getByText('Sign-in page on')).toBeDefined();
    expect(screen.getByText('No sign-in page')).toBeDefined();
    expect(screen.getByText('This guest Wi-Fi is monitored for security.')).toBeDefined();
    expect(screen.getByText('Nothing yet. It is on the sign-in page.')).toBeDefined();
    await user.selectOptions(screen.getByLabelText('Let it on for'), '60');
    await user.click(screen.getByRole('button', { name: /Let it on/ }));
    expect(calls.find((call) => call.path === '/guests/actions')?.body).toEqual({
      device_id: 'g1',
      action: 'admit',
      minutes: 60,
    });
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
