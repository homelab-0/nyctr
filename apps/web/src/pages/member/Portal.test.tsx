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

beforeEach(() => setCsrfToken(''));
afterEach(() => {
  cleanup();
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
