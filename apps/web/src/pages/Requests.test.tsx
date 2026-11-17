import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import type { AccessRequest, Lease } from '../types';
import Requests from './Requests';

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const FAKED = ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] as const;
const times = (calls: { path: string }[], path: string) =>
  calls.filter((call) => call.path === path).length;

function clock() {
  vi.useFakeTimers({ now: Date.now(), toFake: [...FAKED] });
}
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

describe('approving a request the server refuses', () => {
  it('says why above the Approve button and leaves the request waiting', async () => {
    const detail =
      'Nyctr has not collected from Resolver yet, so it changes nothing there. Collect from it first, then try again.';
    const waiting = {
      id: 'request',
      block_id: 'block',
      domain: 'docs.example',
      device_name: 'Tablet',
      requester_id: 'member',
      reason: 'Needed for a report',
      duration_minutes: 60,
      status: 'pending',
      created_at: '2026-11-13T10:00:00Z',
      risk_score: 20,
      integration_id: 'resolver',
    } as AccessRequest;
    mockApi({
      'GET /requests': [waiting],
      'GET /users': [],
      'GET /rules': { __status: 500, detail: 'Unavailable' },
      'GET /leases': [],
      'POST /requests/request/review': { __status: 409, detail },
    });
    render(<Requests params={new URLSearchParams()} onChange={() => {}} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect((await screen.findByRole('alert')).textContent).toBe(detail);
    expect(screen.getByRole('button', { name: 'Approve' })).toBeTruthy();
    expect(document.body.textContent).not.toContain('Request failed');
  });
});

describe('a decided request', () => {
  const decided = (more: Partial<AccessRequest>) =>
    ({
      id: 'r1',
      block_id: 'block',
      domain: 'cdn.printshop.example',
      device_name: 'Tablet',
      requester_id: 'member',
      reason: 'Needed for a report',
      duration_minutes: 60,
      status: 'approved',
      created_at: '2026-11-13T10:00:00Z',
      risk_score: 20,
      review_note: null,
      ...more,
    }) as AccessRequest;
  const lease = (more: Partial<Lease>) =>
    ({
      id: 'l1',
      request_id: 'r1',
      status: 'active',
      execution: 'applied',
      owned: true,
      ...more,
    }) as Lease;
  const show = async (row: AccessRequest, leases: unknown) => {
    const calls = mockApi({
      'GET /requests': [row],
      'GET /users': [],
      'GET /rules': { __status: 500, detail: 'Unavailable' },
      'GET /leases': leases,
      'POST /requests/r1/review': { ...row, status: 'approved' },
    });
    render(<Requests params={new URLSearchParams('id=r1')} onChange={() => {}} />);
    await screen.findAllByText('cdn.printshop.example');
    return calls;
  };
  const atSource = async () =>
    (await screen.findByText('At the source')).parentElement!.textContent!.replace(
      'At the source',
      '',
    );

  it.each([
    [{ execution: 'applied' }, 'Changed at the source and checked.'],
    [{ execution: 'simulated' }, 'Simulated. Demo mode never contacts a source.'],
    [{ execution: 'not_applied' }, 'Not changed. Nyctr is read-only for this source.'],
    [{ execution: 'failed' }, 'The source refused the change.'],
    [
      { execution: 'applied', status: 'ended' },
      'Changed at the source and checked. It has ended since.',
    ],
  ] as [Partial<Lease>, string][])(
    'says what happened at the source for %o',
    async (more, words) => {
      await show(decided({}), [lease(more)]);
      expect(await atSource()).toBe(words);
    },
  );

  it('says nothing was changed for a refusal, and that it could not read when it could not', async () => {
    await show(decided({ status: 'denied' }), []);
    expect(await atSource()).toBe('Nothing was changed at the source.');
    cleanup();
    await show(decided({}), { __status: 500, detail: 'Internal Server Error' });
    expect(await atSource()).toBe('Nyctr could not read what happened at the source.');
  });

  it('shows a note only when a person wrote one', async () => {
    await show(decided({ review_note: 'Approved' }), []);
    await atSource();
    expect(document.body.textContent).not.toContain('Your note');
    cleanup();
    await show(decided({ review_note: 'Only for the print run' }), []);
    expect((await screen.findByText('Your note')).parentElement!.textContent).toContain(
      'Only for the print run',
    );
  });

  it('sends an empty note as empty, not as the decision repeated', async () => {
    const calls = await show(decided({ status: 'pending' }), []);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(calls.some((call) => call.method === 'POST')).toBe(true));
    expect(calls.find((call) => call.method === 'POST')!.body).toEqual({
      decision: 'approved',
      note: '',
      minutes: 60,
    });
  });
});

describe('a request that is being checked', () => {
  it('says the check is still running and shows the stored analysis to the administrator', async () => {
    const row = {
      id: 'r1',
      block_id: 'block',
      domain: 'shop.example',
      device_name: 'Laptop',
      requester_id: 'member',
      reason: 'Need the page',
      duration_minutes: 30,
      status: 'analysing',
      created_at: '2026-11-16T10:00:00Z',
      risk_score: null,
      analysis: {
        id: 'a1',
        verdict: 'not_justified',
        risk: 'low',
        uncertainty: 'The registry date is the only age on record.',
        model_state: 'ok',
        facts: { facts: [{ id: 'f1', kind: 'registration', state: 'known' }] },
        reasons: [{ fact: 'f1', text: 'The block does not look justified.' }],
      },
    } as AccessRequest;
    mockApi({
      'GET /requests': [row],
      'GET /users': [],
      'GET /rules': { __status: 500, detail: 'Unavailable' },
      'GET /leases': [],
    });
    render(<Requests params={new URLSearchParams('id=r1')} onChange={() => {}} />);
    expect(await screen.findByText('Nyctr is still checking this request.')).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Check of this address' })).toBeTruthy();
    expect(screen.getByText('not_justified')).toBeTruthy();
    expect(screen.getByText('low')).toBeTruthy();
    expect(screen.getByText('registration: known')).toBeTruthy();
    expect(screen.getByText('The block does not look justified.')).toBeTruthy();
  });

  it('shows the finished check without a browser reload, then stops reading', async () => {
    clock();
    let done = false;
    const row = {
      id: 'r1',
      block_id: 'block',
      domain: 'shop.example',
      device_name: 'Laptop',
      requester_id: 'member',
      reason: 'Need the page',
      duration_minutes: 30,
      status: 'analysing',
      created_at: '2026-11-16T10:00:00Z',
      risk_score: null,
    } as AccessRequest;
    const calls = mockApi({
      'GET /requests': () => [done ? { ...row, status: 'auto_approved' } : row],
      'GET /users': [],
      'GET /rules': { __status: 500, detail: 'Unavailable' },
      'GET /leases': [],
    });
    render(<Requests params={new URLSearchParams('id=r1')} onChange={() => {}} />);
    await paint();
    expect(screen.getByText('Nyctr is still checking this request.')).toBeTruthy();
    expect(screen.getAllByText('Checking').length).toBeGreaterThan(0);
    const before = times(calls, '/requests');
    done = true;
    await advance(5_000);
    expect(screen.getAllByText('Opened by the rule').length).toBeGreaterThan(0);
    expect(screen.queryByText('Nyctr is still checking this request.')).toBeNull();
    expect(screen.getAllByText('shop.example').length).toBeGreaterThan(0);
    const finished = times(calls, '/requests');
    expect(finished).toBe(before + 1);
    await advance(60_000);
    expect(times(calls, '/requests')).toBe(finished);
  });

  it('stops reading when the page is left while a check is still running', async () => {
    clock();
    const calls = mockApi({
      'GET /requests': [
        {
          id: 'r1',
          block_id: 'block',
          domain: 'shop.example',
          device_name: 'Laptop',
          requester_id: 'member',
          reason: 'Need the page',
          duration_minutes: 30,
          status: 'analysing',
          created_at: '2026-11-16T10:00:00Z',
          risk_score: null,
        } as AccessRequest,
      ],
      'GET /users': [],
      'GET /rules': { __status: 500, detail: 'Unavailable' },
      'GET /leases': [],
    });
    render(<Requests params={new URLSearchParams('id=r1')} onChange={() => {}} />);
    await paint();
    expect(screen.getByText('Nyctr is still checking this request.')).toBeTruthy();
    const before = times(calls, '/requests');
    cleanup();
    await advance(60_000);
    expect(times(calls, '/requests')).toBe(before);
  });
});
