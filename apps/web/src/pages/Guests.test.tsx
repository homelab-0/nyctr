import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { AuthProvider } from '../auth';
import { mockApi } from '../test/mock-api';
import { scheduleFixture, scheduleOff } from '../test/schedule';
import type { GuestOverview, GuestStanding, User } from '../types';
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
      await screen.findByText(
        'No Wi-Fi name reported by Office network uses a sign-in page, and Nyctr has no guest devices from Office network.',
      ),
    ).toBeDefined();
    const page = document.body.textContent!;
    expect(page.indexOf('uses a sign-in page, and')).toBeLessThan(page.indexOf('Who is on'));
    expect(page).not.toContain('tells guests apart');
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

  it('never says it cannot tell who is a guest above a list of guest devices', async () => {
    const base = overview('enabled');
    for (const wifi of [[base.portal.wifi[0]], []]) {
      open('enabled', { 'GET /guests': { ...base, portal: { ...base.portal, wifi } } });
      expect(await screen.findByText(/1 guest device seen/)).toBeDefined();
      expect(screen.getAllByText('Visitor phone').length).toBeGreaterThan(0);
      expect(document.querySelector('.note[role="status"]')).toBeNull();
      expect(document.body.textContent).not.toContain('cannot tell who is a guest');
      cleanup();
    }
  });

  it('says it reads only from sources that have been read, and shortens a long list', async () => {
    const base = overview('enabled');
    const named = (name: string, collected: boolean) => ({
      ...base.sources[0],
      id: name,
      name,
      collected,
    });
    const read = ['A', 'B', 'C', 'D'].map((name) => named(name, true));
    open('enabled', { 'GET /guests': { ...base, sources: [...read, named('Never read', false)] } });
    const link = await screen.findByRole('link', { name: 'A, B and 2 more' });
    expect(link.getAttribute('title')).toBe('A, B, C, D');
    expect(link.getAttribute('href')).toBe('#/sources');
    expect(link.parentElement!.textContent).toContain('reads who is on from A, B and 2 more.');
    cleanup();
    open('enabled', { 'GET /guests': { ...base, sources: [named('Never read', false)] } });
    expect(
      await screen.findByText(/has not read who is on yet: no source has been collected\./),
    ).toBeDefined();
  });

  it('says what it has, not that Wi-Fi names are still to be collected', async () => {
    const base = overview('enabled');
    open('enabled', {
      'GET /guests': { ...base, devices: [], portal: { ...base.portal, wifi: [] } },
    });
    expect(
      await screen.findByText('Nyctr has no Wi-Fi names and no guest devices from Office network.'),
    ).toBeDefined();
    expect(document.body.textContent).not.toMatch(/collected yet/i);
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

describe('a guest state said as the record has it', () => {
  const withState = (standing: GuestStanding) => {
    const data = overview('enabled');
    data.devices[0] = { ...data.devices[0], ...standing };
    open('enabled', { 'GET /guests': data });
  };
  /** The state chips on the page: one in the list and one on the device's panel. */
  const chips = () =>
    [...document.querySelectorAll('.tag')]
      .map((item) => item.textContent)
      .filter((text) => !/sign-in page (on|off)|No sign-in/i.test(text || ''));

  it.each([
    [{ state: 'cut', simulated: false }, 'Cut off'],
    [{ state: 'locked', simulated: false }, 'Locked out'],
    [{ state: 'online', simulated: false }, 'Online'],
    [{ state: 'cut', simulated: true }, 'Simulated: cut off'],
    [{ state: 'locked', simulated: true }, 'Simulated: locked out'],
    [{ state: 'online', simulated: true }, 'Simulated: let on'],
  ] as [GuestStanding, string][])('says %o as "%s"', async (standing, words) => {
    withState(standing);
    await screen.findByRole('heading', { name: 'Visitor phone' });
    expect(chips()).toEqual([words, words]);
  });

  it.each([
    ['not_applied', 'Decided to cut off, not changed at the source'],
    ['failed', 'Tried to cut off, it did not go through'],
  ] as const)('leaves a device online and says the cut-off was %s', async (execution, words) => {
    withState({ state: 'online', simulated: false, attempt: { action: 'cut', execution } });
    await screen.findByRole('heading', { name: 'Visitor phone' });
    expect(chips()).toEqual(['Online', 'Online']);
    expect(screen.getAllByText(words)).toHaveLength(2);
    expect(document.body.textContent).not.toMatch(/Simulated|Cut off\b(?! )/);
  });
});

describe('choosing a guest on a narrow screen', () => {
  const rect = Element.prototype.getBoundingClientRect;
  const into = Object.getOwnPropertyDescriptor(Element.prototype, 'scrollIntoView');
  afterEach(() => {
    Element.prototype.getBoundingClientRect = rect;
    if (into) Object.defineProperty(Element.prototype, 'scrollIntoView', into);
    else delete (Element.prototype as Partial<Element>).scrollIntoView;
  });
  /** Opens the page with nobody chosen and the panel column `top` pixels down the screen. */
  const choose = async (top: number) => {
    const scrolled = vi.fn();
    Element.prototype.scrollIntoView = scrolled;
    Element.prototype.getBoundingClientRect = () => ({ top }) as DOMRect;
    mockApi({ 'GET /auth/me': admin, 'GET /guests': overview('enabled') });
    render(
      <AuthProvider>
        <Guests params={new URLSearchParams()} onChange={() => {}} />
      </AuthProvider>,
    );
    await userEvent.click(await screen.findByRole('button', { name: 'Visitor phone' }));
    await screen.findByRole('heading', { name: 'Visitor phone' });
    return scrolled;
  };

  it('brings the panel into view when it sits far below the list', async () => {
    const scrolled = await choose(2350);
    expect(scrolled).toHaveBeenCalledTimes(1);
    expect((scrolled.mock.contexts[0] as HTMLElement).className).toContain('into-view');
  });

  it('leaves the page where it is when the panel is already in view', async () => {
    expect(await choose(120)).not.toHaveBeenCalled();
  });
});
