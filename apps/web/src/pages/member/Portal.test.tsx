import { cleanup, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from '../../App';
import { setCsrfToken } from '../../api';
import { AuthProvider } from '../../auth';
import { mockApi } from '../../test/mock-api';
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
  device_name: device === 'laptop' ? "Sam's laptop" : 'Family tablet',
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
  scope: 'Everyone using Home DNS',
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
  const calls = mockApi({
    'GET /auth/me': member,
    'GET /me/device': { device_id: 'laptop', name: "Sam's laptop", simulated: false },
    'GET /blocks': [],
    'GET /requests': [],
    'GET /leases': [],
    ...routes,
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
        block('b2', 'kids.example', 'tablet'),
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
    expect(within(other).getByText('kids.example')).toBeDefined();
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
