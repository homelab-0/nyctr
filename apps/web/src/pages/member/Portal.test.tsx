import { act, cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../../App';
import { setCsrfToken } from '../../api';
import { AuthProvider } from '../../auth';
import { blockList, mockApi } from '../../test/mock-api';
import { memberSchedule } from '../../test/schedule';
import type { AccessRequest, Block, Lease, User } from '../../types';

const member: User = {
  id: 'sam',
  email: 'sam@example.test',
  name: 'Sam',
  role: 'member',
  mode: 'live',
  csrf_token: 'csrf',
};
const block = (id: string, domain: string, device: string, extra: Partial<Block> = {}): Block => ({
  id,
  device_id: device,
  device_name: device === 'laptop' ? "Sam's laptop" : 'Front desk tablet',
  domain,
  source: 'nextdns',
  reason: 'HaGeZi Multi PRO++',
  observed_at: new Date(Date.now() - 5 * 60_000).toISOString(),
  expires_at: new Date(Date.now() + 3_600_000).toISOString(),
  evidence_kind: 'observed',
  attribution: 'assigned',
  risk_score: 16,
  risk_band: 'low',
  risk_category: 'privacy_list',
  risk_factors: [
    { label: 'A privacy and ad-blocking list covers it, not a security feed', points: 16 },
  ],
  risk_explanation: 'A privacy and ad-blocking list covers it, not a security feed.',
  reason_codes: [],
  ...extra,
});
const request = (extra: Partial<AccessRequest>): AccessRequest => ({
  id: 'r1',
  block_id: 'b1',
  domain: 'photos.example',
  device_name: "Sam's laptop",
  requester_id: 'sam',
  reason: 'Wedding photos',
  duration_minutes: 60,
  status: 'auto_approved',
  created_at: new Date().toISOString(),
  review_note: null,
  risk_score: 16,
  risk_category: 'privacy_list',
  risk_factors: [
    { label: 'A privacy and ad-blocking list covers it, not a security feed', points: 16 },
  ],
  decided_by: 'rule',
  decision_note: 'Opened for 60 minutes by the access rule.',
  ...extra,
});
const lease = (extra: Partial<Lease> = {}): Lease => ({
  id: 'l1',
  request_id: 'r1',
  integration_id: 'dns',
  domain: 'photos.example',
  device_name: "Sam's laptop",
  requester_id: 'sam',
  kind: 'temporary',
  status: 'active',
  ended_reason: null,
  execution: 'applied',
  owned: true,
  scope: 'Everyone using Office DNS',
  decided_by: 'rule',
  risk_score: 16,
  created_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 58 * 60_000).toISOString(),
  ended_at: null,
  last_error: null,
  ...extra,
});

function open(routes: Record<string, unknown>, hash = '/portal') {
  window.location.hash = hash;
  const given = routes['GET /blocks'];
  const calls = mockApi({
    'GET /auth/me': member,
    'GET /me/device': { device_id: 'laptop', name: "Sam's laptop", simulated: false },
    'GET /requests': [],
    'GET /leases': [],
    'GET /devices': [{ id: 'laptop', name: "Sam's laptop" }],
    'GET /blocks/coverage': { collected: 'yes', unassigned: false },
    ...routes,
    // Tests give the lookups; the route answers with them as its one page.
    'GET /blocks': Array.isArray(given) ? blockList(given as Block[]) : (given ?? blockList([])),
  });
  render(
    <AuthProvider>
      <App />
    </AuthProvider>,
  );
  return { calls, user: userEvent.setup() };
}

const scrollTo = window.scrollTo.bind(window);
beforeEach(() => setCsrfToken(''));
afterEach(() => {
  cleanup();
  window.scrollTo = scrollTo;
  vi.useRealTimers();
  Reflect.deleteProperty(document, 'visibilityState');
  setCsrfToken('');
  vi.unstubAllGlobals();
});

describe('member portal', () => {
  it('tells a member with no devices that first, with who to ask', async () => {
    open({
      'GET /me/device': { device_id: null, name: null, simulated: false },
      'GET /devices': [],
    });
    expect(await screen.findByText('No devices are assigned to you yet.')).toBeDefined();
    const page = document.body.textContent!;
    expect(page).toContain('Ask whoever runs Nyctr to add your devices.');
    expect(page).not.toContain('could not tell which of your devices');
    expect(page).not.toContain('Nothing has been blocked');
  });

  it('says why it cannot show blocked sites instead of saying nothing was blocked', async () => {
    const cases = [
      [{ collected: 'no', unassigned: false }, 'Blocked sites have not been collected yet'],
      [{ collected: 'failed', unassigned: false }, 'Blocked sites could not be collected'],
      [{ __status: 500 }, 'Nyctr cannot tell right now whether anything was blocked'],
    ] as const;
    for (const [coverage, title] of cases) {
      open({ 'GET /blocks/coverage': coverage });
      expect(await screen.findByText(title)).toBeDefined();
      expect(document.body.textContent).toContain('Ask whoever runs Nyctr');
      expect(document.body.textContent).not.toContain('Nothing has been blocked');
      cleanup();
    }
  });

  it('does not tell a member to ask when blocked sites will be collected if nothing collects them', async () => {
    open({ 'GET /blocks/coverage': { collected: 'none', unassigned: false } });
    expect(
      await screen.findByText('Blocked sites are not collected on this network'),
    ).toBeDefined();
    expect(document.body.textContent).toContain('Ask whoever runs Nyctr if a page will not load.');
    expect(document.body.textContent).not.toMatch(/when it will|not been collected yet/);
  });

  it('says once that the device is not recognised and that some sites are tied to no device', async () => {
    open({
      'GET /me/device': { device_id: null, name: null, simulated: false },
      'GET /blocks': [block('b1', 'photos.example', 'laptop')],
      'GET /blocks/coverage': { collected: 'yes', unassigned: true },
    });
    await screen.findByText(/could not tell which of your devices this is/);
    expect(document.body.textContent!.match(/cannot be tied to a device/g)).toHaveLength(1);
    expect(document.body.textContent!.match(/one of yours may be missing/g)).toHaveLength(1);
  });

  it('never calls an empty list clean when the device is not recognised and some sites are tied to no device', async () => {
    open({
      'GET /me/device': { device_id: null, name: null, simulated: false },
      'GET /blocks/coverage': { collected: 'yes', unassigned: true },
    });
    expect(
      await screen.findByText(
        'Nyctr has not seen anything blocked on your devices in the last day',
      ),
    ).toBeDefined();
    const page = document.body.textContent!;
    expect(page).not.toContain('Nothing has been blocked');
    // The sentence at the top carries the caveat, once.
    expect(page).toContain('could not tell which of your devices this is');
    expect(page.match(/cannot be tied to a device/g)).toHaveLength(1);
    expect(page.match(/one of yours may be missing/g)).toHaveLength(1);
  });

  it('keeps one caveat when the device is not recognised and collection is failing or unfinished', async () => {
    const cases = [
      [
        'failed',
        'Blocked sites could not be collected',
        'Nyctr could not read what was blocked just now',
      ],
      [
        'no',
        'Blocked sites have not been collected yet',
        'Nyctr has not finished reading what was blocked',
      ],
    ] as const;
    const unknown = { device_id: null, name: null, simulated: false };
    for (const [collected, title, unread] of cases) {
      // Nothing listed: the reason stands instead of a clean result.
      open({ 'GET /me/device': unknown, 'GET /blocks/coverage': { collected, unassigned: true } });
      expect(await screen.findByText(title)).toBeDefined();
      expect(
        screen.getByText(
          'Nyctr could not tell which of your devices this is, so it is showing all of them.',
        ),
      ).toBeDefined();
      expect(document.body.textContent).not.toMatch(
        /Nothing has been blocked|has not seen anything/,
      );
      cleanup();
      // Something listed: one note under the list says both.
      open({
        'GET /me/device': unknown,
        'GET /blocks': [block('b1', 'photos.example', 'laptop')],
        'GET /blocks/coverage': { collected, unassigned: true },
      });
      expect(await screen.findByText('photos.example')).toBeDefined();
      expect(
        screen.getByText(
          `${unread}, and some sites blocked on this network cannot be tied to a device, so one of yours may be missing here. Ask whoever runs Nyctr if a page will not load.`,
        ),
      ).toBeDefined();
      expect(document.body.textContent!.match(/cannot be tied to a device/g)).toHaveLength(1);
      expect(document.body.textContent!.match(/may be missing here/g)).toHaveLength(1);
      cleanup();
    }
  });

  it('claims only what is known when some blocked sites are tied to no device', async () => {
    open({ 'GET /blocks/coverage': { collected: 'yes', unassigned: true } });
    expect(
      await screen.findByText(
        'Nyctr has not seen anything blocked on your devices in the last day',
      ),
    ).toBeDefined();
    expect(screen.getByText(/one of yours may be missing here/)).toBeDefined();
    expect(document.body.textContent).not.toContain('Nothing has been blocked');
    cleanup();
    // The same caveat stands under a list that is not empty: a third site may be among the untied.
    open({
      'GET /blocks': [block('b1', 'photos.example', 'laptop')],
      'GET /blocks/coverage': { collected: 'yes', unassigned: true },
    });
    expect(await screen.findByText('photos.example')).toBeDefined();
    expect(screen.getByText(/one of yours may be missing here/)).toBeDefined();
    cleanup();
    open({ 'GET /blocks': [block('b1', 'photos.example', 'laptop')] });
    expect(await screen.findByText('photos.example')).toBeDefined();
    expect(screen.queryByText(/may be missing/)).toBeNull();
  });

  it('says under a list that a newer block may be missing while collection is failing or unfinished', async () => {
    const cases = [
      [
        'failed',
        false,
        'Nyctr could not read what was blocked just now, so a newer block may be missing here. Ask whoever runs Nyctr if a page will not load.',
      ],
      [
        'no',
        false,
        'Nyctr has not finished reading what was blocked, so a newer block may be missing here. Ask whoever runs Nyctr if a page will not load.',
      ],
      [
        'failed',
        true,
        'Nyctr could not read what was blocked just now, and some sites blocked on this network cannot be tied to a device, so one of yours may be missing here. Ask whoever runs Nyctr if a page will not load.',
      ],
      [
        'no',
        true,
        'Nyctr has not finished reading what was blocked, and some sites blocked on this network cannot be tied to a device, so one of yours may be missing here. Ask whoever runs Nyctr if a page will not load.',
      ],
    ] as const;
    for (const [collected, unassigned, line] of cases) {
      open({
        'GET /blocks': [block('b1', 'photos.example', 'laptop')],
        'GET /blocks/coverage': { collected, unassigned },
      });
      expect(await screen.findByText('photos.example')).toBeDefined();
      expect(screen.getByText(line)).toBeDefined();
      // One note, never two stacked.
      expect(screen.getAllByText(/may be missing here/)).toHaveLength(1);
      cleanup();
    }
  });

  it('never tells a member with a blocked site listed that there is nothing to ask about', async () => {
    for (const collected of ['failed', 'no'] as const) {
      const { user } = open({
        'GET /blocks': [block('b1', 'photos.example', 'laptop')],
        'GET /blocks/coverage': { collected, unassigned: false },
      });
      expect(await screen.findByText('photos.example')).toBeDefined();
      await user.click(screen.getByRole('link', { name: /My requests/ }));
      expect(
        await screen.findByText(
          'When a page is blocked, find it under Blocked sites and ask to open it.',
        ),
      ).toBeDefined();
      expect(document.body.textContent).not.toContain('nothing to ask about');
      cleanup();
      // With nothing listed the reason is still given.
      const empty = open({ 'GET /blocks/coverage': { collected, unassigned: false } });
      await empty.user.click(await screen.findByRole('link', { name: /My requests/ }));
      expect(await screen.findByText(/so there is nothing to ask about yet/)).toBeDefined();
      cleanup();
    }
  });

  it('does not say nothing was blocked before it knows why the list is empty', async () => {
    let release = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    open({});
    const answer = globalThis.fetch;
    vi.stubGlobal('fetch', (input: RequestInfo | URL, options?: RequestInit) =>
      String(input).endsWith('/blocks/coverage')
        ? gate.then(() => answer(input, options))
        : answer(input, options),
    );
    expect(await screen.findByText('Looking for blocked sites…')).toBeDefined();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.getByText('Looking for blocked sites…')).toBeDefined();
    expect(document.body.textContent).not.toContain('Nothing has been blocked');
    release();
    expect(
      await screen.findByText('Nothing has been blocked on your devices in the last day'),
    ).toBeDefined();
  });

  it('only tells a member to come back when a collection is scheduled', async () => {
    open({ 'GET /collection': memberSchedule(true) });
    expect(
      await screen.findByText(
        'If a page will not load, open it again, then come back here in a while. Nyctr looks for new blocks every 15 minutes.',
      ),
    ).toBeDefined();
    cleanup();
    open({ 'GET /collection': memberSchedule(false) });
    expect(
      await screen.findByText(
        'If a page will not load, open it again, then ask whoever runs Nyctr to collect. New blocks show up here only after that.',
      ),
    ).toBeDefined();
    expect(screen.queryByText(/in a minute|in a while/)).toBeNull();
  });

  it('names no interval when the schedule is on but the answer carries none', async () => {
    open({ 'GET /collection': { enabled: true, next_at: null } });
    expect(
      await screen.findByText('If a page will not load, open it again, then come back here later.'),
    ).toBeDefined();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByText(/NaN|ask whoever runs Nyctr/)).toBeNull();
    expect(
      screen.getByText('If a page will not load, open it again, then come back here later.'),
    ).toBeDefined();
  });

  it('offers the console only to an administrator who opened the portal address', async () => {
    open({});
    await screen.findByRole('heading', { name: /blocked/i, level: 1 });
    expect(screen.queryByRole('link', { name: 'Open the console' })).toBeNull();
    cleanup();
    open({ 'GET /auth/me': { ...member, console_url: 'https://console.example' } });
    const link = await screen.findByRole('link', { name: 'Open the console' });
    expect(link.getAttribute('href')).toBe('https://console.example');
    expect(screen.queryByText('Briefing')).toBeNull();
  });

  it('lists blocks on the device in hand first and never shows the administrator console', async () => {
    open({
      'GET /blocks': [
        block('b2', 'training.example', 'tablet'),
        block('b1', 'photos.example', 'laptop'),
        block('b3', 'photos.example', 'laptop'),
      ],
    });
    const here = (await screen.findByRole('heading', { name: 'Blocked on this device' })).closest(
      'section',
    )!;
    expect(within(here).getAllByRole('link')).toHaveLength(1);
    expect(within(here).getByText('photos.example')).toBeDefined();
    const other = screen
      .getByRole('heading', { name: 'On your other devices' })
      .closest('section')!;
    expect(within(other).getByText('training.example')).toBeDefined();
    expect(screen.getByText(/You're on/).textContent).toContain("Sam's laptop");
    expect(screen.queryByText('Briefing')).toBeNull();
    expect(screen.queryByRole('button', { name: /Ask Nyctr/ })).toBeNull();
  });

  it('always shows the score and what it is based on before anyone can ask', async () => {
    const { user, calls } = open(
      {
        'GET /blocks': [block('b1', 'photos.example', 'laptop')],
        'POST /requests': request({}),
      },
      '/portal?block=b1',
    );
    expect(await screen.findByRole('heading', { name: 'Low risk' })).toBeDefined();
    expect(screen.getByRole('img', { name: 'Risk score 16 out of 100' })).toBeDefined();
    expect(screen.getAllByText(/privacy and ad-blocking list/).length).toBeGreaterThan(0);
    const ask = screen.getByRole('button', { name: 'Ask to open it' });
    expect((ask as HTMLButtonElement).disabled).toBe(true);
    await user.type(screen.getByLabelText('What do you need it for?'), 'Wedding photos');
    await user.click(ask);
    const sent = calls.find((call) => call.method === 'POST' && call.path === '/requests');
    expect(sent?.body).toEqual({ block_id: 'b1', reason: 'Wedding photos', duration_minutes: 60 });
  });

  it('opens a block found by its address that is older than the page it holds', async () => {
    const latest = block('b1', 'photos.example', 'laptop');
    const old = { ...block('b9', 'older.example', 'laptop'), risk_explanation: 'A privacy list.' };
    const { user, calls } = open(
      {
        'GET /blocks': blockList([latest], { total: 250 }),
        'GET /blocks/one?id=b9': old,
        'POST /requests': request({}),
      },
      '/portal?block=b9',
    );
    expect(await screen.findByText('older.example')).toBeDefined();
    expect(screen.queryByText('That block is no longer listed')).toBeNull();
    await user.type(screen.getByLabelText('What do you need it for?'), 'Needed for work');
    await user.click(screen.getByRole('button', { name: 'Ask to open it' }));
    const sent = calls.find((call) => call.method === 'POST' && call.path === '/requests');
    expect(sent?.body).toEqual({ block_id: 'b9', reason: 'Needed for work', duration_minutes: 60 });
  });

  it('shows nothing of one older block while the next one opened is still loading', async () => {
    const first = block('b9', 'first-older.example', 'laptop');
    const second = block('b8', 'second-older.example', 'laptop');
    let answerSecond = (_: unknown) => {};
    const { user } = open(
      {
        'GET /blocks/one?id=b9': first,
        'GET /blocks/one?id=b8': () => new Promise((resolve) => (answerSecond = resolve)),
      },
      '/portal?block=b9',
    );
    expect(await screen.findByText('first-older.example')).toBeDefined();
    await user.type(screen.getByLabelText('What do you need it for?'), 'For the first one');
    // Straight to another older block, without leaving the portal. Every render is looked at,
    // the first one included: the first block must never stand under the second's address.
    const shown: string[] = [];
    const watch = new MutationObserver(() => shown.push(document.body.textContent || ''));
    watch.observe(document.body, { childList: true, subtree: true, characterData: true });
    await act(async () => {
      window.location.hash = '/portal?block=b8';
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    expect(screen.queryByText('first-older.example')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Ask to open it' })).toBeNull();
    await act(async () => answerSecond(second));
    expect(await screen.findByText('second-older.example')).toBeDefined();
    watch.disconnect();
    // What was typed for the first block is not carried into a request for the second.
    const reason = screen.getByLabelText('What do you need it for?') as HTMLTextAreaElement;
    expect(reason.value).toBe('');
    expect(
      (screen.getByRole('button', { name: 'Ask to open it' }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(shown.some((text) => text.includes('first-older.example'))).toBe(false);
  });

  it('says the same of a block the member may not see as of one that does not exist', async () => {
    const refused = { __status: 404, detail: 'Block event not found' };
    const said = [];
    for (const id of ['someone-elses', 'never-stored']) {
      open({ [`GET /blocks/one?id=${id}`]: refused }, `/portal?block=${id}`);
      expect(await screen.findByText('That block is no longer listed')).toBeDefined();
      said.push(document.body.textContent);
      cleanup();
    }
    expect(said[0]).toBe(said[1]);
    // A read that failed for another reason is not called a block that has gone.
    open({ 'GET /blocks/one?id=b9': { __status: 500, detail: 'Unavailable' } }, '/portal?block=b9');
    expect(await screen.findByText('This block could not be read just now.')).toBeDefined();
    expect(screen.queryByText('That block is no longer listed')).toBeNull();
  });

  it('says a block with no score is unknown, not safe', async () => {
    open(
      {
        'GET /blocks': [
          block('b1', 'odd.example', 'laptop', {
            risk_score: null,
            risk_band: 'unknown',
            risk_factors: [
              {
                label:
                  'Nyctr does not recognise the reason this was blocked, so it cannot score it',
                points: null,
              },
            ],
            risk_explanation:
              'Nyctr could not tell how risky this is, so a person will look at it.',
          }),
        ],
      },
      '/portal?block=b1',
    );
    expect(
      await screen.findByRole('heading', { name: 'Nyctr could not score this one' }),
    ).toBeDefined();
    expect(screen.getByRole('img', { name: 'Risk is unknown' })).toBeDefined();
    expect(screen.getByText('No score')).toBeDefined();
    expect(screen.queryByText(/Low risk/)).toBeNull();
  });

  it('tells an opened request how long it lasts and how to reconnect on this kind of device', async () => {
    vi.spyOn(window.navigator, 'userAgent', 'get').mockReturnValue(
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    );
    open({ 'GET /requests': [request({})], 'GET /leases': [lease()] }, '/portal?request=r1');
    expect(await screen.findByRole('heading', { name: "It's open." })).toBeDefined();
    expect(screen.getByText(/works for the next 58 min/)).toBeDefined();
    expect(screen.getByRole('heading', { name: 'One more step on your Mac' })).toBeDefined();
    expect(screen.getByText(/press Command \(⌘\) and Q together/)).toBeDefined();
  });

  it('never says open when the provider was not changed', async () => {
    open(
      {
        'GET /requests': [request({ status: 'approved', decided_by: 'admin' })],
        'GET /leases': [lease({ execution: 'not_applied', owned: false })],
      },
      '/portal?request=r1',
    );
    expect(
      await screen.findByRole('heading', { name: 'Approved, but not switched on yet.' }),
    ).toBeDefined();
    expect(screen.queryByText("It's open.")).toBeNull();
    expect(screen.queryByText(/One more step/)).toBeNull();
  });

  it('explains a waiting request with the reason the rule gave', async () => {
    open(
      {
        'GET /requests': [
          request({
            status: 'pending',
            risk_score: 72,
            decided_by: null,
            decision_note:
              "This was blocked for safety or by an administrator's rule, so a person decides.",
          }),
        ],
      },
      '/portal?request=r1',
    );
    expect(
      await screen.findByRole('heading', { name: 'A person needs to look at this.' }),
    ).toBeDefined();
    expect(screen.getByText(/blocked for safety or by an administrator's rule/)).toBeDefined();
    expect(screen.getByText('72')).toBeDefined();
  });

  it('says a request that was only looked at changed nothing', async () => {
    open(
      {
        'GET /requests': [
          request({ status: 'reviewed', decided_by: 'admin', review_note: 'Ask me on Monday' }),
        ],
      },
      '/portal?request=r1',
    );
    expect(
      await screen.findByRole('heading', { name: 'Looked at, nothing changed.' }),
    ).toBeDefined();
    expect(screen.getByText('The note says: “Ask me on Monday”')).toBeDefined();
    expect(screen.queryByText(/Approved/)).toBeNull();
    expect(screen.queryByText("It's open.")).toBeNull();
  });

  it('shows a countdown in My requests only when the change really happened', async () => {
    const { user } = open({
      'GET /requests': [
        request({ id: 'r1', domain: 'photos.example' }),
        request({ id: 'r2', domain: 'bank.example', status: 'approved', decided_by: 'admin' }),
        request({ id: 'r3', domain: 'shop.example', status: 'approved', decided_by: 'admin' }),
      ],
      'GET /leases': [
        lease({ id: 'l1', request_id: 'r1' }),
        lease({ id: 'l2', request_id: 'r2', execution: 'not_applied', owned: false }),
        lease({ id: 'l3', request_id: 'r3', execution: 'failed', owned: false }),
      ],
    });
    await user.click(await screen.findByRole('link', { name: /My requests/ }));
    const row = (domain: string) => within(screen.getByText(domain).closest('a') as HTMLElement);
    expect(row('photos.example').getByText(/min left/)).toBeDefined();
    for (const domain of ['bank.example', 'shop.example']) {
      expect(row(domain).getByText('Approved, not on yet')).toBeDefined();
      expect(row(domain).queryByText(/left/)).toBeNull();
    }
  });
});

describe('what the member portal says happened', () => {
  it.each([
    ['the server failing', () => ({ __status: 500, detail: 'Internal Server Error' })],
    [
      'the connection dropping',
      () => {
        throw new TypeError('Failed to fetch');
      },
    ],
  ])(
    'never says nothing was asked for when the list could not be read, with %s',
    async (_n, fail) => {
      let broken = true;
      const { user } = open(
        { 'GET /requests': () => (broken ? fail() : [request({})]) },
        '/requests',
      );
      const retry = await screen.findByRole('button', { name: 'Try again' });
      expect(document.body.textContent).not.toContain('You have not asked for anything yet');
      broken = false;
      await user.click(retry);
      expect(await screen.findByText('photos.example')).toBeDefined();
    },
  );

  it('never shows an outcome for a request when the lists could not be read', async () => {
    open(
      { 'GET /requests': [request({})], 'GET /leases': { __status: 500, detail: 'Unavailable' } },
      '/portal?request=r1',
    );
    expect(await screen.findByRole('button', { name: 'Try again' })).toBeDefined();
    expect(document.body.textContent).not.toMatch(/It's open|not switched on|could not be found/);
  });

  it('says a simulated opening is a demonstration and that nothing was opened', async () => {
    const { user } = open(
      {
        'GET /requests': [request({})],
        'GET /leases': [lease({ execution: 'simulated' })],
        'GET /blocks': [block('b1', 'photos.example', 'laptop')],
      },
      '/portal?request=r1',
    );
    expect(await screen.findByRole('heading', { name: 'This is a demonstration.' })).toBeDefined();
    expect(
      screen.getByText(/^Nothing was opened: the demonstration never changes a real network\./),
    ).toBeDefined();
    expect(document.body.textContent).not.toMatch(/It's open|One more step|works for the next/);
    // The rule's note, "Opened for 60 minutes…", is not repeated under "Nothing was opened".
    expect(screen.getByText('The access rule said yes to this one.')).toBeDefined();
    expect(document.body.textContent).not.toContain('Opened for 60 minutes');
    // The same in both lists: no countdown and no "Opened" for something that opened nothing.
    for (const link of [/My requests/, /Blocked sites/]) {
      await user.click(screen.getAllByRole('link', { name: link })[0]);
      const row = within((await screen.findByText('photos.example')).closest('a') as HTMLElement);
      expect(row.getByText('Demonstration, nothing opened')).toBeDefined();
      expect(row.queryByText(/left|Opened/)).toBeNull();
    }
  });

  it.each([
    ['revoked', 'An administrator closed it.'],
    ['expired', 'The time ran out.'],
  ])('says how an opening that ended as %s ended', async (ended_reason, heading) => {
    open(
      {
        'GET /requests': [request({})],
        'GET /leases': [lease({ status: 'ended', ended_reason, closed: true })],
      },
      '/portal?request=r1',
    );
    expect(await screen.findByRole('heading', { name: heading })).toBeDefined();
    expect(screen.getByText(/^Access to photos.example has closed again\./)).toBeDefined();
  });

  it('does not repeat a decision to the member as if it were a note', async () => {
    open(
      { 'GET /requests': [request({ status: 'denied', review_note: 'Not approved' })] },
      '/portal?request=r1',
    );
    expect(await screen.findByText('The request was not approved.')).toBeDefined();
    expect(document.body.textContent).not.toContain('The note says');
  });

  it.each([
    ['high', 72, 'This one waits for a person to decide.'],
    ['unknown', null, 'This one waits for a person to decide.'],
    ['low', 16, 'Safe ones open in a few seconds.'],
  ] as const)(
    'ends the form for a %s score with a footnote that fits it',
    async (band, score, words) => {
      open(
        {
          'GET /blocks': [
            block('b1', 'odd.example', 'laptop', { risk_band: band, risk_score: score }),
          ],
        },
        '/portal?block=b1',
      );
      const note = await screen.findByText(/^Nyctr checks the address straight away\./);
      expect(note.textContent).toBe(`Nyctr checks the address straight away. ${words}`);
    },
  );
});

describe('the list of blocked sites when the requests could not be read', () => {
  it('says it cannot show which sites were already asked about, and reads again when told to', async () => {
    let broken = true;
    const { user } = open({
      'GET /blocks': [block('b1', 'photos.example', 'laptop')],
      'GET /requests': () =>
        broken ? { __status: 500, detail: 'Internal Server Error' } : [request({})],
      'GET /leases': [lease()],
    });
    const note = (await screen.findByText(/^Nyctr could not read your requests just now/)).closest(
      'p',
    )!;
    expect(note.textContent).toContain(
      'so it cannot show which of these sites you have already asked about.',
    );
    broken = false;
    await user.click(within(note).getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText(/min left/)).toBeDefined();
    expect(screen.queryByText(/could not read your requests/)).toBeNull();
  });
});

describe('an exception that ended with the address still allowed', () => {
  it.each([
    ['revoked', 'An administrator ended it.'],
    ['expired', 'The time ran out.'],
  ])('says it ended (%s) and never that access closed', async (ended_reason, heading) => {
    const { user } = open(
      {
        'GET /requests': [request({})],
        // Applied, and its ending left the address as it was: the server says `closed: false`.
        'GET /leases': [lease({ status: 'ended', ended_reason, owned: false, closed: false })],
      },
      '/portal?request=r1',
    );
    expect(await screen.findByRole('heading', { name: heading })).toBeDefined();
    expect(screen.getByText(/^The approval for photos.example has ended\./)).toBeDefined();
    expect(document.body.textContent).not.toMatch(/closed again|closed it/i);
    await user.click(screen.getByRole('link', { name: /My requests/ }));
    const row = within((await screen.findByText('photos.example')).closest('a') as HTMLElement);
    expect(row.getByText('Ended')).toBeDefined();
    expect(row.queryByText('Closed again')).toBeNull();
  });

  it('says closed again when the ending did close it', async () => {
    const { user } = open({
      'GET /requests': [request({})],
      'GET /leases': [lease({ status: 'ended', ended_reason: 'expired', closed: true })],
    });
    await user.click(await screen.findByRole('link', { name: /My requests/ }));
    expect(await screen.findByText('Closed again')).toBeDefined();
  });
});

describe('an opening that was not confirmed, if a member were ever sent one', () => {
  it('is never told as not on: the status is read before the result', async () => {
    const { user } = open(
      {
        'GET /requests': [request({ status: 'approved', decided_by: 'admin' })],
        'GET /leases': [lease({ status: 'unconfirmed', execution: 'not_applied', owned: true })],
        'GET /blocks': [block('b1', 'photos.example', 'laptop')],
      },
      '/portal?request=r1',
    );
    expect(await screen.findByRole('heading', { name: 'Not confirmed yet.' })).toBeDefined();
    expect(screen.getByText(/so it may or may not work/)).toBeDefined();
    for (const link of [/My requests/, /Blocked sites/]) {
      await user.click(screen.getAllByRole('link', { name: link })[0]);
      const row = within((await screen.findByText('photos.example')).closest('a') as HTMLElement);
      expect(row.getByText('Not confirmed yet')).toBeDefined();
    }
    expect(document.body.textContent).not.toMatch(/not on yet|not switched on|It's open/);
  });
});

describe('the device a member signed in on', () => {
  const wait = { timeout: 20_000 };
  const patient = 30_000;
  const tie = {
    id: 't1',
    kind: 'tie',
    device_id: 'laptop',
    device_name: "Sam's laptop",
    ended_at: null,
  };

  it(
    'says how the device was recognised and forgets it with one plain button',
    async () => {
      let tied = true;
      const { calls } = open({
        'GET /me/device': () =>
          tied
            ? { device_id: 'laptop', name: "Sam's laptop", simulated: false, how: 'signed_in' }
            : {
                device_id: null,
                name: null,
                simulated: false,
                how: null,
                reason: 'forgotten',
                message:
                  'Nyctr was asked to forget this device. Sign in again to have it recognised.',
              },
        'GET /devices': () =>
          tied ? [{ id: 'laptop', name: "Sam's laptop", classification: 'unassigned' }] : [],
        'GET /presence': () => ({ items: tied ? [tie] : [] }),
        'DELETE /presence/t1': () => {
          tied = false;
          return { ok: true };
        },
      });
      const forget = await screen.findByRole('button', { name: 'Forget this device' }, wait);
      expect(document.body.textContent).toContain(
        "You're on Sam's laptop, recognised because you signed in on it.",
      );
      await act(async () => forget.click());
      expect(
        await screen.findByText(
          /Nyctr was asked to forget this device\. Sign in again/,
          undefined,
          wait,
        ),
      ).toBeDefined();
      expect(calls.map((call) => `${call.method} ${call.path}`)).toContain('DELETE /presence/t1');
      expect(screen.queryByRole('button', { name: 'Forget this device' })).toBeNull();
    },
    patient,
  );

  it(
    'lists what was blocked on a device first signed in on without the page being opened again',
    async () => {
      // The tie is made by the answer to `/me/device`. Until then the lists know nothing of the device.
      let tied = false;
      const { calls } = open({
        'GET /me/device': () => {
          tied = true;
          return { device_id: 'laptop', name: "Sam's laptop", simulated: false, how: 'signed_in' };
        },
        'GET /devices': () => (tied ? [{ id: 'laptop', name: "Sam's laptop" }] : []),
        'GET /presence': () => ({ items: tied ? [tie] : [] }),
        'GET /blocks': () => blockList(tied ? [block('b1', 'blocked-0.example', 'laptop')] : []),
      });
      expect(await screen.findByText(/blocked-0\.example/, undefined, wait)).toBeDefined();
      expect(document.body.textContent).toContain(
        "You're on Sam's laptop, recognised because you signed in on it.",
      );
      expect(screen.getByRole('button', { name: 'Forget this device' })).toBeDefined();
      // Read once more, not over and over.
      await new Promise((done) => setTimeout(done, 50));
      const asked = (path: string) =>
        calls.filter((call) => call.method === 'GET' && call.path === path).length;
      expect([
        asked('/blocks'),
        asked('/devices'),
        asked('/presence'),
        asked('/me/device'),
      ]).toEqual([2, 2, 2, 1]);
    },
    patient,
  );

  it(
    'says in the words it was given why this device is not recognised, and offers nothing to forget',
    async () => {
      const message =
        'This request did not come from your network, so Nyctr cannot tell which device this is.';
      open({
        'GET /me/device': {
          device_id: null,
          name: null,
          simulated: false,
          how: null,
          reason: 'outside',
          message,
        },
        'GET /presence': { items: [] },
      });
      expect(
        await screen.findByText(
          `${message} Nyctr is showing all of your devices.`,
          undefined,
          wait,
        ),
      ).toBeDefined();
      expect(document.body.textContent).not.toContain('could not tell which of your devices');
      expect(screen.queryByRole('button', { name: /^Forget/ })).toBeNull();
    },
    patient,
  );

  for (const [view, hash] of [
    ['the first page', '/portal'],
    ['My devices', '/devices'],
  ]) {
    it(
      `says on ${view} that the devices signed in on could not be read, and reads them again when told to`,
      async () => {
        let failing = true;
        open(
          {
            'GET /me/device': {
              device_id: 'laptop',
              name: "Sam's laptop",
              simulated: false,
              how: 'signed_in',
            },
            'GET /devices': [{ id: 'laptop', name: "Sam's laptop", classification: 'unassigned' }],
            'GET /presence': () => {
              if (failing) throw new TypeError('Failed to fetch');
              return { items: [tie] };
            },
          },
          hash,
        );
        const said = await screen.findByText(
          /Nyctr could not read which devices you signed in on, so it cannot offer to forget one here\./,
          undefined,
          wait,
        );
        expect(said.getAttribute('role')).toBe('alert');
        expect(screen.queryByRole('button', { name: /^Forget/ })).toBeNull();
        failing = false;
        await act(async () => within(said).getByRole('button', { name: 'Try again' }).click());
        expect(await screen.findByRole('button', { name: /^Forget/ }, wait)).toBeDefined();
        expect(screen.queryByText(/could not read which devices you signed in on/)).toBeNull();
      },
      patient,
    );
  }

  it(
    'tells an assigned device from one signed in on under My devices, and only a tie can be forgotten',
    async () => {
      open(
        {
          'GET /me/device': {
            device_id: 'laptop',
            name: "Sam's laptop",
            simulated: false,
            how: 'signed_in',
          },
          'GET /devices': [
            { id: 'laptop', name: "Sam's laptop", classification: 'unassigned' },
            { id: 'desk', name: 'Desk computer', classification: 'personal' },
          ],
          'GET /presence': { items: [tie] },
        },
        '/devices',
      );
      expect(await screen.findByText('You signed in on it', undefined, wait)).toBeDefined();
      expect(screen.getByText('Yours')).toBeDefined();
      expect(
        screen.getAllByRole('button', { name: /^Forget/ }).map((button) => button.textContent),
      ).toEqual(["Forget Sam's laptop"]);
    },
    patient,
  );
});

const FAKED = ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] as const;
const OWN = new Set([
  '/auth/me',
  '/me/device',
  '/requests',
  '/leases',
  '/devices',
  '/blocks',
  '/blocks/coverage',
  '/presence',
]);
type Calls = { method: string; path: string }[];
const reads = (calls: Calls, path: string) =>
  calls.filter((call) => call.method === 'GET' && call.path === path).length;
const pending = {
  status: 'pending',
  decided_by: null,
  decision_note: 'It will not open by itself.',
};
const quiet = { 'GET /presence': { items: [] } };

function clock() {
  vi.useFakeTimers({ now: Date.now(), toFake: [...FAKED] });
}
/** Lets the open page finish its first read without moving the fake clock. */
async function paint() {
  for (let turn = 0; turn < 20; turn += 1)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
}
async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}
function hide(hidden: boolean) {
  act(() => {
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => (hidden ? 'hidden' : 'visible'),
    });
    document.dispatchEvent(new Event('visibilitychange'));
  });
}
/** The abort signal of each read, in the order the page started them. */
function signals(path: string) {
  const mocked = globalThis.fetch as unknown as {
    mock: { calls: [unknown, RequestInit?][] };
  };
  return mocked.mock.calls
    .filter((call) => String(call[0]).replace(/^\/api/, '') === path)
    .map((call) => call[1]?.signal as AbortSignal);
}
function onlyOwn(calls: Calls) {
  expect(calls.every((call) => OWN.has(call.path))).toBe(true);
}

describe('an answer while the member page stays open', () => {
  it('shows a decision within five seconds, in place, and then stops', async () => {
    clock();
    const moved = vi.fn();
    window.scrollTo = moved;
    let decided = false;
    const { calls } = open(
      {
        ...quiet,
        'GET /requests': () => [
          request(decided ? { status: 'approved', decided_by: 'admin' } : pending),
        ],
        'GET /leases': () => (decided ? [lease()] : []),
      },
      '/portal?request=r1',
    );
    await paint();
    expect(screen.getByRole('heading', { name: 'A person needs to look at this.' })).toBeDefined();
    expect(document.body.textContent).toContain('The answer will show up here.');
    const main = document.getElementById('main-content');
    const place = window.location.hash;
    moved.mockClear();
    await advance(4_999);
    expect(reads(calls, '/requests')).toBe(1);
    expect(screen.getByRole('heading', { name: 'A person needs to look at this.' })).toBeDefined();
    decided = true;
    await advance(1);
    expect(screen.getByRole('heading', { name: "It's open." })).toBeDefined();
    expect(document.body.textContent).not.toContain('The answer will show up here');
    expect(document.body.textContent).not.toContain('A person needs to look at this');
    expect(document.getElementById('main-content')).toBe(main);
    expect(window.location.hash).toBe(place);
    expect(moved).not.toHaveBeenCalled();
    expect(reads(calls, '/requests')).toBe(2);
    expect(reads(calls, '/leases')).toBe(2);
    onlyOwn(calls);
    await advance(60_000);
    expect(reads(calls, '/requests')).toBe(2);
    expect(reads(calls, '/leases')).toBe(2);
  });

  it('shows a decision in My requests within five seconds, in the same row', async () => {
    clock();
    let decided = false;
    const { calls } = open(
      {
        ...quiet,
        'GET /requests': () => [
          request(
            decided ? { status: 'denied', decided_by: 'admin', decision_note: null } : pending,
          ),
        ],
        'GET /leases': [],
      },
      '/requests',
    );
    await paint();
    const row = screen.getByText('photos.example').closest('a');
    expect(row?.textContent).toContain('Waiting for a person');
    decided = true;
    await advance(5_000);
    expect(screen.getByText('photos.example').closest('a')).toBe(row);
    expect(row?.textContent).toContain('Not approved');
    expect(row?.textContent).not.toContain('Waiting for a person');
    expect(reads(calls, '/requests')).toBe(2);
    onlyOwn(calls);
    await advance(60_000);
    expect(reads(calls, '/requests')).toBe(2);
  });

  it('reads every five seconds for two minutes, then every thirty', async () => {
    clock();
    const moved = vi.fn();
    window.scrollTo = moved;
    let decided = false;
    const { calls } = open(
      {
        ...quiet,
        'GET /requests': () => [
          request(
            decided ? { status: 'denied', decided_by: 'admin', decision_note: null } : pending,
          ),
        ],
        'GET /leases': [],
      },
      '/portal?request=r1',
    );
    await paint();
    const main = document.getElementById('main-content');
    moved.mockClear();
    let expected = 1;
    expect(reads(calls, '/requests')).toBe(expected);
    for (let second = 5; second <= 120; second += 5) {
      await advance(5_000);
      expected += 1;
      expect(reads(calls, '/requests')).toBe(expected);
      expect(reads(calls, '/leases')).toBe(expected);
    }
    expect(screen.getByRole('heading', { name: 'A person needs to look at this.' })).toBeDefined();
    await advance(29_999);
    expect(reads(calls, '/requests')).toBe(expected);
    decided = true;
    await advance(1);
    expected += 1;
    expect(reads(calls, '/requests')).toBe(expected);
    expect(screen.getByRole('heading', { name: 'Not this time.' })).toBeDefined();
    expect(document.body.textContent).not.toContain('The answer will show up here');
    expect(document.getElementById('main-content')).toBe(main);
    expect(moved).not.toHaveBeenCalled();
    const blocks = reads(calls, '/blocks');
    await advance(60_000);
    expect(reads(calls, '/requests')).toBe(expected);
    expect(reads(calls, '/blocks')).toBe(blocks);
  });

  it('reads nothing while the tab is hidden, and reads once as soon as it is shown', async () => {
    clock();
    const { calls } = open(
      { ...quiet, 'GET /requests': [request(pending)], 'GET /leases': [] },
      '/portal?request=r1',
    );
    await paint();
    expect(screen.getByRole('heading', { name: 'A person needs to look at this.' })).toBeDefined();
    const before = reads(calls, '/requests');
    hide(true);
    await advance(10_000);
    expect(reads(calls, '/requests')).toBe(before);
    hide(false);
    await paint();
    expect(reads(calls, '/requests')).toBe(before + 1);
    await advance(4_999);
    expect(reads(calls, '/requests')).toBe(before + 1);
    await advance(1);
    expect(reads(calls, '/requests')).toBe(before + 2);
    // Time hidden still counts. Once two minutes have passed, showing the tab reads at once,
    // and the check after that waits 30 seconds.
    hide(true);
    await advance(120_000);
    expect(reads(calls, '/requests')).toBe(before + 2);
    hide(false);
    await paint();
    expect(reads(calls, '/requests')).toBe(before + 3);
    await advance(29_999);
    expect(reads(calls, '/requests')).toBe(before + 3);
    await advance(1);
    expect(reads(calls, '/requests')).toBe(before + 4);
    expect(reads(calls, '/leases')).toBe(before + 4);
  });

  it('does not postpone the next check when the tab is only hidden for a moment', async () => {
    clock();
    const { calls } = open(
      { ...quiet, 'GET /requests': [request(pending)], 'GET /leases': [] },
      '/portal?request=r1',
    );
    await paint();
    const before = reads(calls, '/requests');
    await advance(1_000);
    hide(true);
    await advance(1_000);
    hide(false);
    await advance(2_999);
    expect(reads(calls, '/requests')).toBe(before);
    await advance(1);
    expect(reads(calls, '/requests')).toBe(before + 1);
  });

  it('reads nothing once every request is decided, or away from My requests and the request', async () => {
    clock();
    const decided = open(
      {
        ...quiet,
        'GET /requests': [request({ status: 'denied', decided_by: 'admin', decision_note: null })],
        'GET /leases': [],
      },
      '/portal?request=r1',
    );
    await paint();
    expect(screen.getByRole('heading', { name: 'Not this time.' })).toBeDefined();
    const held = reads(decided.calls, '/requests');
    await advance(180_000);
    expect(reads(decided.calls, '/requests')).toBe(held);
    cleanup();

    const home = open(
      {
        ...quiet,
        'GET /collection': { enabled: false, interval_seconds: 900, next_at: null },
        'GET /requests': [request(pending)],
        'GET /leases': [],
      },
      '/portal',
    );
    await paint();
    expect(screen.getByRole('heading', { name: 'What got blocked?' })).toBeDefined();
    const homeReads = reads(home.calls, '/requests');
    await advance(30_000);
    expect(reads(home.calls, '/requests')).toBe(homeReads);
    cleanup();

    const devices = open(
      { ...quiet, 'GET /requests': [request(pending)], 'GET /leases': [] },
      '/devices',
    );
    await paint();
    expect(screen.getByRole('heading', { name: 'My devices' })).toBeDefined();
    const deviceReads = reads(devices.calls, '/requests');
    await advance(30_000);
    expect(reads(devices.calls, '/requests')).toBe(deviceReads);
  });

  it("reads each member's own requests, and a second member never sees the first", async () => {
    clock();
    let samDecided = false;
    const sam = open(
      {
        ...quiet,
        'GET /requests': () => [
          request(
            samDecided ? { status: 'denied', decided_by: 'admin', decision_note: null } : pending,
          ),
        ],
        'GET /leases': [],
      },
      '/portal?request=r1',
    );
    await paint();
    expect(screen.getByRole('heading', { name: 'A person needs to look at this.' })).toBeDefined();
    expect(document.body.textContent).not.toContain('files.example');
    samDecided = true;
    await advance(5_000);
    expect(screen.getByRole('heading', { name: 'Not this time.' })).toBeDefined();
    expect(document.body.textContent).toContain('photos.example');
    expect(document.body.textContent).not.toContain('files.example');
    onlyOwn(sam.calls);
    expect(reads(sam.calls, '/requests')).toBe(2);
    expect(reads(sam.calls, '/leases')).toBe(2);
    cleanup();

    const riley: User = {
      id: 'riley',
      email: 'riley@example.test',
      name: 'Riley',
      role: 'member',
      mode: 'live',
      csrf_token: 'csrf',
    };
    let rileyDecided = false;
    const own = {
      id: 'r2',
      domain: 'files.example',
      requester_id: 'riley',
      device_name: "Riley's phone",
    };
    const other = open(
      {
        ...quiet,
        'GET /auth/me': riley,
        'GET /me/device': { device_id: 'phone', name: "Riley's phone", simulated: false },
        'GET /devices': [{ id: 'phone', name: "Riley's phone" }],
        'GET /requests': () => [
          request(
            rileyDecided
              ? { ...own, status: 'denied', decided_by: 'admin', decision_note: null }
              : { ...own, ...pending },
          ),
        ],
        'GET /leases': [],
      },
      '/portal?request=r2',
    );
    await paint();
    expect(screen.getByRole('heading', { name: 'A person needs to look at this.' })).toBeDefined();
    expect(document.body.textContent).toContain('files.example');
    expect(document.body.textContent).not.toContain('photos.example');
    expect(document.body.textContent).not.toContain('Sam');
    rileyDecided = true;
    await advance(5_000);
    expect(screen.getByRole('heading', { name: 'Not this time.' })).toBeDefined();
    expect(document.body.textContent).toContain('files.example');
    expect(document.body.textContent).not.toContain('photos.example');
    expect(document.body.textContent).not.toContain('Sam');
    onlyOwn(other.calls);
    expect(reads(other.calls, '/requests')).toBe(2);
    expect(other.calls.some((call) => call.path.includes('r1') || call.path.includes('sam'))).toBe(
      false,
    );
  });

  it('keeps the answer on screen when a later check fails, and tries again', async () => {
    clock();
    let mode: 'pending' | 'fail' | 'open' = 'pending';
    const down = { __status: 503, detail: 'Down' };
    const { calls } = open(
      {
        ...quiet,
        'GET /requests': () => {
          if (mode === 'fail') return down;
          if (mode === 'open') return [request({ status: 'approved', decided_by: 'admin' })];
          return [request(pending)];
        },
        'GET /leases': () => (mode === 'open' ? [lease()] : mode === 'fail' ? down : []),
      },
      '/portal?request=r1',
    );
    await paint();
    const heading = screen.getByRole('heading', { name: 'A person needs to look at this.' });
    const main = document.getElementById('main-content');
    mode = 'fail';
    await advance(5_000);
    expect(screen.getByRole('heading', { name: 'A person needs to look at this.' })).toBe(heading);
    expect(document.body.textContent).toContain(
      'The latest check failed. Trying again in 5 seconds.',
    );
    expect(screen.queryByText('Unable to load this view')).toBeNull();
    expect(document.getElementById('main-content')).toBe(main);
    const during = reads(calls, '/requests');
    await advance(4_999);
    expect(reads(calls, '/requests')).toBe(during);
    expect(screen.getByRole('heading', { name: 'A person needs to look at this.' })).toBe(heading);
    expect(screen.queryByText('Unable to load this view')).toBeNull();
    // The read at 120 seconds is the last of the fast checks. The next gap is 30 seconds.
    for (let step = 0; step < 23; step += 1) await advance(5_000);
    expect(document.body.textContent).toContain(
      'The latest check failed. Trying again in 30 seconds.',
    );
    expect(screen.getByRole('heading', { name: 'A person needs to look at this.' })).toBe(heading);
    const beforeSlow = reads(calls, '/requests');
    await advance(29_999);
    expect(reads(calls, '/requests')).toBe(beforeSlow);
    mode = 'open';
    await advance(1);
    expect(screen.getByRole('heading', { name: "It's open." })).toBeDefined();
    expect(document.body.textContent).not.toContain('The latest check failed');
    expect(document.body.textContent).not.toContain('Unable to load this view');
    expect(document.getElementById('main-content')).toBe(main);
  });

  it('keeps reading after the decision when the lease list failed', async () => {
    clock();
    let phase: 'pending' | 'approved' | 'open' = 'pending';
    const { calls } = open(
      {
        ...quiet,
        'GET /requests': () => [
          request(phase === 'pending' ? pending : { status: 'approved', decided_by: 'admin' }),
        ],
        'GET /leases': () => {
          if (phase === 'open') return [lease()];
          if (phase === 'approved') return { __status: 503, detail: 'Down' };
          return [];
        },
      },
      '/portal?request=r1',
    );
    await paint();
    expect(screen.getByRole('heading', { name: 'A person needs to look at this.' })).toBeDefined();
    phase = 'approved';
    await advance(5_000);
    expect(
      screen.getByRole('heading', { name: 'Approved, but not switched on yet.' }),
    ).toBeDefined();
    expect(document.body.textContent).toContain(
      'The latest check failed. Trying again in 5 seconds.',
    );
    const during = reads(calls, '/leases');
    await advance(5_000);
    expect(reads(calls, '/leases')).toBe(during + 1);
    expect(reads(calls, '/requests')).toBe(during + 1);
    expect(
      screen.getByRole('heading', { name: 'Approved, but not switched on yet.' }),
    ).toBeDefined();
    phase = 'open';
    await advance(5_000);
    expect(screen.getByRole('heading', { name: "It's open." })).toBeDefined();
    expect(document.body.textContent).not.toContain('The latest check failed');
    const settled = reads(calls, '/leases');
    await advance(30_000);
    expect(reads(calls, '/leases')).toBe(settled);
    expect(reads(calls, '/requests')).toBe(settled);
  });

  it('keeps My requests on screen when a later check fails', async () => {
    clock();
    let fail = false;
    const { calls } = open(
      {
        ...quiet,
        'GET /requests': () => (fail ? { __status: 503, detail: 'Down' } : [request(pending)]),
        'GET /leases': [],
      },
      '/requests',
    );
    await paint();
    const row = screen.getByText('photos.example').closest('a');
    expect(row?.textContent).toContain('Waiting for a person');
    fail = true;
    await advance(5_000);
    expect(screen.getByText('photos.example').closest('a')).toBe(row);
    expect(row?.textContent).toContain('Waiting for a person');
    expect(document.body.textContent).toContain(
      'The latest check failed. Trying again in 5 seconds.',
    );
    expect(screen.queryByText('Unable to load this view')).toBeNull();
    expect(screen.getByRole('heading', { name: 'My requests' })).toBeDefined();
    const during = reads(calls, '/requests');
    await advance(4_999);
    expect(reads(calls, '/requests')).toBe(during);
    await advance(1);
    expect(reads(calls, '/requests')).toBe(during + 1);
    expect(screen.getByText('photos.example').closest('a')).toBe(row);
  });

  it('does not drop a slow check when the next moment comes', async () => {
    clock();
    let release: () => void = () => {};
    let n = 0;
    const { calls } = open(
      {
        ...quiet,
        'GET /requests': () => {
          n += 1;
          if (n === 1) return [request(pending)];
          if (n === 2)
            return new Promise((resolve) => {
              release = () => resolve([request(pending)]);
            });
          return [request({ status: 'denied', decided_by: 'admin', decision_note: null })];
        },
        'GET /leases': [],
      },
      '/portal?request=r1',
    );
    await paint();
    await advance(5_000);
    expect(reads(calls, '/requests')).toBe(2);
    const slow = signals('/requests')[1];
    expect(slow.aborted).toBe(false);
    await advance(20_000);
    expect(reads(calls, '/requests')).toBe(2);
    expect(reads(calls, '/leases')).toBe(2);
    expect(slow.aborted).toBe(false);
    expect(signals('/leases')[1].aborted).toBe(false);
    await act(async () => {
      release();
    });
    await paint();
    expect(screen.getByRole('heading', { name: 'A person needs to look at this.' })).toBeDefined();
    expect(reads(calls, '/requests')).toBe(2);
    expect(slow.aborted).toBe(false);
    await advance(4_999);
    expect(reads(calls, '/requests')).toBe(2);
    await advance(1);
    expect(reads(calls, '/requests')).toBe(3);
    expect(screen.getByRole('heading', { name: 'Not this time.' })).toBeDefined();
  });

  it('reads nothing after the page is left', async () => {
    clock();
    const { calls } = open(
      { ...quiet, 'GET /requests': [request(pending)], 'GET /leases': [] },
      '/portal?request=r1',
    );
    await paint();
    const before = reads(calls, '/requests');
    cleanup();
    document.dispatchEvent(new Event('visibilitychange'));
    await advance(60_000);
    expect(reads(calls, '/requests')).toBe(before);
    expect(reads(calls, '/leases')).toBe(before);
  });
});
