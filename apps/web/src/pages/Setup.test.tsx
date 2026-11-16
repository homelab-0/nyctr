import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { mockApi } from '../test/mock-api';
import { modelFixture } from '../test/model';
import { scheduleFixture, scheduleOff } from '../test/schedule';
import type { AddressSeen, CollectionSchedule, Rules } from '../types';
import Setup, { addressText } from './Setup';

const rules: Rules = {
  access: {
    enabled: true,
    per_day: 4,
    daily_total: 10,
    ad_tracker: { mode: 'on', max_score: 25, max_minutes: 30, analysis_required: false },
    threat_feed: { mode: 'off', max_minutes: 30, min_registered_days: 180 },
  },
  guest: { enabled: false, hits: 3, minutes: 5 },
  writes: { access: 'none', guests: 'none' },
  sources: [],
};

/** What the address check answers behind one listed proxy that passed on a forged entry and the real one. */
const seen: AddressSeen = {
  address: '198.51.100.21',
  peer: '10.42.0.10',
  via_proxy: true,
  why: 'forwarded',
  entry: 1,
  entries: 2,
  unlisted: null,
  address_is_proxy: false,
  proxy_hops: 1,
  old_name: false,
};

/** Opens the installation tab over a fabricated schedule that a save replaces. */
function open(first: CollectionSchedule, mode: 'live' | 'demo' = 'live') {
  let current = first;
  const calls = mockApi({
    'GET /rules': rules,
    'GET /auth/config': { mode, local_enabled: true, oidc_enabled: false },
    'GET /model': modelFixture(),
    'GET /me/address': seen,
    'GET /presence': { items: [], enabled: false, reach_back_hours: 2 },
    'GET /notices': notices,
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

/** A notice setting with nothing saved, so the installation tab's notice card stays quiet. */
const notices = {
  target: '',
  secret_ref: '',
  unsigned: true,
  signing: 'Notices are sent without a signature. Name a secret to sign them.',
  problem: null,
  editable: true,
  hosts: [],
  recent: [],
};

const system = {
  'GET /rules': rules,
  'GET /auth/config': { mode: 'live', local_enabled: true, oidc_enabled: false },
  'GET /model': modelFixture(),
  'GET /me/address': seen,
  'GET /presence': { items: [], enabled: false, reach_back_hours: 2 },
  'GET /notices': notices,
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

describe('access rule in Setup', () => {
  /** Opens the rule tab over the fabricated rule; a save replaces it, as the server does. */
  function openRule() {
    let current = rules;
    const calls = mockApi({
      'GET /rules': () => current,
      'PUT /rules/access': (body: unknown) => {
        current = { ...current, access: body as Rules['access'] };
        return body;
      },
    });
    render(<Setup params={new URLSearchParams('tab=rule')} />);
    const saved = () => calls.filter((call) => call.method === 'PUT').map((call) => call.body);
    return { saved, user: userEvent.setup() };
  }
  const tier = async (name: string) => within(await screen.findByRole('region', { name }));

  it('says which kinds of block can open by themselves and which always come to the administrator', async () => {
    openRule();
    const ads = await tier('Advertising and tracker lists');
    const pressed = ads.getAllByRole('button', { pressed: true });
    expect(pressed.map((button) => button.textContent)).toEqual(['On']);
    expect(ads.getByText(/On: Nyctr opens these by itself/)).toBeDefined();
    expect(ads.getByText(/A check can only stop an opening/)).toBeDefined();
    const threats = await tier('Threat feeds');
    expect(threats.getByRole('button', { name: 'Off', pressed: true })).toBeDefined();
    expect(
      threats.getByText(/only when the check says the block does not look justified/),
    ).toBeDefined();
    expect(threats.getAllByRole('listitem').map((item) => item.textContent)).toEqual([
      'the name does not look machine-made or disguised',
      'the address was registered at least 180 days ago',
      'nobody said no to it before',
      'it is opened for 30 minutes at most',
    ]);
    // The kinds that never open are listed with why, and nothing there can be pressed.
    const never = document.querySelector<HTMLElement>('.rows.boxed')!;
    expect([...never.querySelectorAll('.t')].map((kind) => kind.textContent)).toEqual([
      'Kinds of site you chose to block',
      'Addresses on a deny list',
      'Firewall rules',
      'Intrusion prevention',
      'Anything Nyctr does not recognise',
    ]);
    expect(never.querySelectorAll('.d')).toHaveLength(5);
    expect(within(never).getByText(/newly registered, dynamic or parked address/)).toBeDefined();
    expect(within(never).getAllByText('Never automatic')).toHaveLength(5);
    expect(never.querySelectorAll('button, input, select')).toHaveLength(0);
  });

  it('saves record only for advertising lists and says that nothing is opened', async () => {
    const { saved, user } = openRule();
    const ads = await tier('Advertising and tracker lists');
    await user.click(ads.getByRole('button', { name: 'Record only' }));
    await waitFor(() =>
      expect(saved()).toEqual([
        {
          ...rules.access,
          ad_tracker: { mode: 'shadow', max_score: 25, max_minutes: 30, analysis_required: false },
        },
      ]),
    );
    expect(await ads.findByText(/Record only: Nyctr opens nothing/)).toBeDefined();
  });

  it('lowers the threat limit with the advertising minutes and saves the daily total for everyone', async () => {
    const { saved, user } = openRule();
    const ads = await tier('Advertising and tracker lists');
    await user.click(ads.getByRole('button', { name: 'Lower minutes' }));
    const shorter = {
      ...rules.access,
      ad_tracker: { mode: 'on', max_score: 25, max_minutes: 15, analysis_required: false },
      threat_feed: { mode: 'off', max_minutes: 15, min_registered_days: 180 },
    };
    await waitFor(() => expect(saved()).toEqual([shorter]));
    expect(await screen.findByText('it is opened for 15 minutes at most')).toBeDefined();
    await user.click(screen.getByRole('button', { name: 'Lower openings per day for everyone' }));
    await waitFor(() => expect(saved()[1]).toEqual({ ...shorter, daily_total: 9 }));
  });
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
      'GET /model': modelFixture(),
      'GET /me/address': seen,
      'GET /presence': { items: [], enabled: false, reach_back_hours: 2 },
      'GET /notices': notices,
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

describe('the address Nyctr sees for you, in Setup', () => {
  /** Opens the installation tab over one fabricated answer of the address check. */
  const check = (answer: unknown) => {
    mockApi({ ...system, 'GET /collection': scheduleFixture(), 'GET /me/address': answer });
    render(<Setup params={new URLSearchParams('tab=system')} />);
  };
  /** Waits for the answer to be on screen for as long as a busy machine may need. */
  const shown = (text: string) => screen.findByText(text, undefined, { timeout: 20_000 });
  const patient = 30_000;

  it(
    'shows the address, the proxy the connection came from and which passed-on address was read',
    async () => {
      check(seen);
      expect(await shown('198.51.100.21')).toBeDefined();
      expect(
        screen.getByText(
          'The connection came from 10.42.0.10, which is on your list of proxies. Nyctr read address 1 of the 2 it passed on, counted from the right: the one your proxy wrote.',
        ),
      ).toBeDefined();
      expect(
        screen.getByText(/something in front of your proxy is hiding your address/),
      ).toBeDefined();
    },
    patient,
  );

  it(
    'says so when it cannot tell the address, and never shows the proxy as if it were you',
    async () => {
      check({ ...seen, address: null, why: 'missing', entry: null, entries: 0 });
      expect(await shown('Nyctr cannot tell your address')).toBeDefined();
      // The line that states the address never holds the proxy's, and the sentence under it
      // names the proxy only as where the connection came from.
      expect(document.querySelector('p.rule')?.textContent).toBe('Nyctr cannot tell your address');
      expect(
        screen.getByText(
          'The connection came from 10.42.0.10, which is on your list of proxies, but it passed no address on. Set the proxy to add the address it saw (X-Forwarded-For).',
        ),
      ).toBeDefined();
      expect(screen.getByText(/counted together, and no device is recognised/)).toBeDefined();
      expect(screen.queryByText(/hiding your address/)).toBeNull();
    },
    patient,
  );

  it(
    'says to raise the number of proxies counted when the address shown is on the list of proxies',
    async () => {
      check({ ...seen, address: '10.42.0.11', address_is_proxy: true });
      expect(await shown('10.42.0.11')).toBeDefined();
      expect(
        screen.getByText(
          /^This address is on your list of proxies\. If it is one of your proxies and not your device, something in front of your proxy is hiding your address, or raise the number of proxies Nyctr counts\./,
        ),
      ).toBeDefined();
      cleanup();
      check(seen);
      expect(await shown('198.51.100.21')).toBeDefined();
      expect(screen.queryByText(/raise the number of proxies Nyctr counts/)).toBeNull();
      expect(screen.getByText(/^If this is a router or load balancer/)).toBeDefined();
    },
    patient,
  );

  it(
    'warns that the list of proxies is under the old name only while it is',
    async () => {
      check({ ...seen, old_name: true });
      expect(await shown('Your list of proxies is set under an old name.')).toBeDefined();
      expect(screen.getByText(/That name will\s+stop working in a later release/)).toBeDefined();
      expect(screen.getByText('FORWARDED_ALLOW_IPS')).toBeDefined();
      cleanup();
      check(seen);
      expect(await shown('198.51.100.21')).toBeDefined();
      expect(screen.queryByText('Your list of proxies is set under an old name.')).toBeNull();
      expect(screen.queryByText('FORWARDED_ALLOW_IPS')).toBeNull();
    },
    patient,
  );

  it(
    'shows a refusal instead of an address',
    async () => {
      check({ __status: 403, detail: 'Administrator access required' });
      expect(await shown('Administrator access required')).toBeDefined();
      expect(screen.queryByText('Nyctr cannot tell your address')).toBeNull();
    },
    patient,
  );

  it('explains every way an address is or is not worked out', () => {
    const say = (change: Partial<AddressSeen>) => addressText({ ...seen, ...change });
    expect(say({ why: 'peer', via_proxy: false, entry: null })).toMatch(
      /^The connection came straight from this address\. It is not on your list of proxies/,
    );
    expect(say({ why: 'short', entry: null, entries: 1, proxy_hops: 2 })).toMatch(
      /passed on 1 and Nyctr is set to read number 2 from the right/,
    );
    expect(
      say({ why: 'unlisted', address: null, entry: 1, unlisted: '10.42.0.11', proxy_hops: 2 }),
    ).toMatch(
      /but 10\.42\.0\.11, at position 1 from the right of what it passed on, is not on the list\. Nyctr is set to count 2 proxies, and every one of them must be on the list/,
    );
    expect(say({ why: 'zone', address: null, peer: 'fe80::1%eth0', via_proxy: false })).toMatch(
      /^The connection came from fe80::1%eth0, an address that only works on one network link/,
    );
    expect(say({ why: 'hops', address: null, proxy_hops: 0 })).toMatch(
      /Nyctr is set to count 0 proxies\. The number must be 1 or more\.$/,
    );
    expect(say({ why: 'malformed', entry: 1 })).toMatch(
      /position 1 from the right is not an address/,
    );
    expect(say({ why: 'no_peer', peer: null })).toBe(
      'The server did not say where the connection came from.',
    );
  });
});

describe('recognising devices at sign-in, in Setup', () => {
  const wait = { timeout: 20_000 };
  const patient = 30_000;
  const signIn = (id: string, kind: string, who: string, ended_at: string | null = null) => ({
    id,
    kind,
    user_id: who.toLowerCase(),
    user_name: who,
    device_id: 'laptop',
    device_name: 'Laptop',
    address: '192.0.2.10',
    first_at: '2026-11-14T09:00:00Z',
    last_at: '2026-11-15T09:00:00Z',
    ended_at,
  });

  it(
    'is off until switched on, sits before the address check it points at, and saves the reach',
    async () => {
      let current = { items: [], enabled: false, reach_back_hours: 2 };
      const calls = mockApi({
        ...system,
        'GET /collection': scheduleFixture(),
        'GET /presence': () => current,
        'PUT /presence': (body: unknown) => (current = { ...current, ...(body as object) }),
      });
      render(<Setup params={new URLSearchParams('tab=system')} />);
      const name = "Recognise members' devices when they sign in";
      const toggle = await screen.findByRole('switch', { name }, wait);
      expect(toggle.getAttribute('aria-checked')).toBe('false');
      expect(document.body.textContent).toContain(
        'check that the panel below shows the address of the device you are on now',
      );
      const below = await screen.findByText('The address Nyctr sees for you', undefined, wait);
      expect(toggle.compareDocumentPosition(below) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
      const saved = () => calls.filter((call) => call.method === 'PUT').map((call) => call.body);
      fireEvent.click(toggle);
      // Each save carries only what was changed.
      await waitFor(() => expect(saved()).toEqual([{ enabled: true }]), wait);
      await waitFor(() => expect(toggle.getAttribute('aria-checked')).toBe('true'), wait);
      fireEvent.click(screen.getByRole('button', { name: 'Raise hours before the first sign-in' }));
      await waitFor(() => expect(saved()[1]).toEqual({ reach_back_hours: 3 }), wait);
    },
    patient,
  );

  const name = "Recognise members' devices when they sign in";
  const raise = () => screen.getByRole('button', { name: 'Raise hours before the first sign-in' });
  /** A server that keeps the setting and changes only the part a save carries, as the real one does. */
  const server = (first: { enabled: boolean; reach_back_hours: number }) => {
    const kept = { now: first };
    const calls = mockApi({
      ...system,
      'GET /collection': scheduleFixture(),
      'GET /presence': () => ({ items: [], ...kept.now }),
      'PUT /presence': (body: unknown) => (kept.now = { ...kept.now, ...(body as object) }),
    });
    const saved = () => calls.filter((call) => call.method === 'PUT').map((call) => call.body);
    return { kept, saved };
  };

  it(
    'cannot switch recognition back on by changing the hours before the page has read it again',
    async () => {
      const { kept, saved } = server({ enabled: true, reach_back_hours: 2 });
      render(<Setup params={new URLSearchParams('tab=system')} />);
      const toggle = await screen.findByRole('switch', { name }, wait);
      expect(toggle.getAttribute('aria-checked')).toBe('true');
      // No read after this gets an answer until released: only the saves' own answers reach the page.
      const release = holdBack('GET', '/presence');
      fireEvent.click(toggle);
      await waitFor(() => expect(toggle.getAttribute('aria-checked')).toBe('false'), wait);
      fireEvent.click(raise());
      await waitFor(() => expect(saved()).toHaveLength(2), wait);
      expect(saved()).toEqual([{ enabled: false }, { reach_back_hours: 3 }]);
      expect(kept.now).toEqual({ enabled: false, reach_back_hours: 3 });
      const hours = () => raise().parentElement!.querySelector('output')!.textContent;
      expect(toggle.getAttribute('aria-checked')).toBe('false');
      expect(hours()).toBe('3');
      // And once the setting is read again it says the same.
      release();
      await waitFor(() => expect(hours()).toBe('3'), wait);
      expect(toggle.getAttribute('aria-checked')).toBe('false');
    },
    patient,
  );

  it(
    'ignores a second press while a save is under way and keeps keyboard focus on the switch',
    async () => {
      const { saved } = server({ enabled: false, reach_back_hours: 2 });
      render(<Setup params={new URLSearchParams('tab=system')} />);
      const toggle = (await screen.findByRole('switch', { name }, wait)) as HTMLButtonElement;
      const release = holdBack('PUT', '/presence');
      toggle.focus();
      fireEvent.click(toggle);
      await waitFor(() => expect(saved()).toHaveLength(1), wait);
      expect(toggle.closest('[aria-busy="true"]')).not.toBeNull();
      // Pressed again, and the hours changed, before the first save has answered: neither is sent.
      fireEvent.click(toggle);
      fireEvent.click(raise());
      expect(toggle.disabled).toBe(false);
      expect(document.activeElement).toBe(toggle);
      release();
      await waitFor(() => expect(toggle.getAttribute('aria-checked')).toBe('true'), wait);
      expect(saved()).toEqual([{ enabled: true }]);
      expect(toggle.closest('[aria-busy="true"]')).toBeNull();
    },
    patient,
  );

  it(
    'shows what the save answered and says so when the setting cannot be read again',
    async () => {
      let reads = 0;
      let failing = true;
      mockApi({
        ...system,
        'GET /collection': scheduleFixture(),
        'GET /presence': () => {
          reads += 1;
          if (reads > 1 && failing) throw new TypeError('Failed to fetch');
          return { items: [], enabled: reads > 1, reach_back_hours: 2 };
        },
        'PUT /presence': { enabled: true, reach_back_hours: 2 },
      });
      render(<Setup params={new URLSearchParams('tab=system')} />);
      const toggle = await screen.findByRole('switch', { name }, wait);
      fireEvent.click(toggle);
      // The switch shows On, as the server has it, although the read after the save failed.
      const said = await screen.findByText(
        /Nyctr could not read this setting again, so what is shown here may be out of date\./,
        undefined,
        wait,
      );
      expect(said.getAttribute('role')).toBe('alert');
      expect(toggle.getAttribute('aria-checked')).toBe('true');
      failing = false;
      fireEvent.click(within(said).getByRole('button', { name: 'Try again' }));
      await waitFor(
        () => expect(screen.queryByText(/could not read this setting again/)).toBeNull(),
        wait,
      );
      expect(toggle.getAttribute('aria-checked')).toBe('true');
    },
    patient,
  );

  it(
    'says so, with a way to try again, when who signed in on which device cannot be read',
    async () => {
      let failing = true;
      mockApi({
        'GET /rules': rules,
        'GET /users': [{ id: 'sam', name: 'Sam', active: true }],
        'GET /device-links': [],
        'GET /devices': [
          {
            id: 'laptop',
            name: 'Laptop',
            kind: 'client',
            classification: 'unassigned',
            attributes: {},
          },
        ],
        'GET /presence': () => {
          if (failing) throw new TypeError('Failed to fetch');
          return { items: [signIn('t1', 'tie', 'Sam')], enabled: true, reach_back_hours: 2 };
        },
      });
      render(<Setup params={new URLSearchParams('tab=people')} />);
      const said = await screen.findByText(
        /Nyctr could not read who signed in on which device/,
        undefined,
        wait,
      );
      expect(said.getAttribute('role')).toBe('alert');
      expect(screen.queryByText(/signed in on it/)).toBeNull();
      failing = false;
      fireEvent.click(within(said).getByRole('button', { name: 'Try again' }));
      expect(await screen.findByText(/Sam signed in on it/, undefined, wait)).toBeDefined();
      expect(screen.queryByText(/could not read who signed in/)).toBeNull();
    },
    patient,
  );

  it(
    'lists who signed in on a device under it, and an administrator ends a tie there',
    async () => {
      const calls = mockApi({
        'GET /rules': rules,
        'GET /users': [{ id: 'sam', name: 'Sam', active: true }],
        'GET /device-links': [],
        'GET /devices': [
          {
            id: 'laptop',
            name: 'Laptop',
            kind: 'client',
            classification: 'unassigned',
            attributes: {},
          },
        ],
        'GET /presence': {
          items: [
            signIn('t1', 'tie', 'Sam'),
            signIn('c1', 'conflict', 'Kim'),
            signIn('t0', 'tie', 'Lee', '2026-11-10T09:00:00Z'),
          ],
          enabled: true,
          reach_back_hours: 2,
        },
        'DELETE /presence/t1': { ok: true },
      });
      render(<Setup params={new URLSearchParams('tab=people')} />);
      expect(
        await screen.findByText(/Sam signed in on it from 192\.0\.2\.10, last on/, undefined, wait),
      ).toBeDefined();
      expect(
        screen.getByText(/Kim signed in on it from 192\.0\.2\.10 on .+ and was not tied to it/),
      ).toBeDefined();
      expect(document.body.textContent).not.toContain('Lee'); // an ended tie is not listed under the device
      expect(screen.getAllByRole('button', { name: /^End / })).toHaveLength(1);
      expect(screen.getByText('End this tie')).toBeDefined();
      fireEvent.click(screen.getByRole('button', { name: "End Sam's tie to Laptop" }));
      await waitFor(
        () =>
          expect(calls.map((call) => `${call.method} ${call.path}`)).toContain(
            'DELETE /presence/t1',
          ),
        wait,
      );
    },
    patient,
  );
});
