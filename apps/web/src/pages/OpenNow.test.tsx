import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import type { Lease } from '../types';
import OpenNow from './OpenNow';

const lease = (id: string, more: Partial<Lease>) =>
  ({
    id,
    integration_id: 'resolver',
    domain: `${id}.example`,
    kind: 'temporary',
    status: 'active',
    execution: 'applied',
    owned: true,
    scope: 'Everyone using the resolver',
    risk_score: 20,
    created_at: '2026-11-13T10:00:00Z',
    expires_at: '2026-11-13T11:00:00Z',
    last_error: null,
    ...more,
  }) as Lease;
const row = (domain: string) => within(screen.getByText(domain).closest('tr, .row') as HTMLElement);

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('ending an exception', () => {
  it('offers "I removed it by hand" only where the server ends it that way', async () => {
    const calls = mockApi({
      'GET /leases': [
        lease('reachable', {}),
        lease('gone', { source_removed: true, last_error: 'Remove it there by hand.' }),
        // Its source is gone too, but Nyctr added nothing there, so it ends the ordinary way.
        lease('recorded', { source_removed: true, execution: 'not_applied', owned: false }),
        lease('found', { source_removed: true, owned: false }),
      ],
      'GET /suggestions': [],
      'POST /leases/gone/end': {},
      'POST /leases/recorded/end': {},
    });
    render(<OpenNow onChange={() => {}} />);
    await screen.findByText('gone.example');
    expect(screen.getAllByRole('button', { name: 'I removed it by hand' })).toHaveLength(1);
    for (const name of ['reachable', 'recorded', 'found'])
      expect(row(`${name}.example`).getByRole('button', { name: 'End now' })).toBeTruthy();
    fireEvent.click(row('gone.example').getByRole('button', { name: 'I removed it by hand' }));
    fireEvent.click(row('recorded.example').getByRole('button', { name: 'End now' }));
    await vi.waitFor(() => expect(calls.filter((call) => call.method === 'POST')).toHaveLength(2));
    expect(calls.filter((call) => call.method === 'POST').map((call) => call.body)).toEqual([
      { by_hand: true },
      {},
    ]);
  });

  it("says a refusal beside the button that was pressed, in the server's words", async () => {
    const never =
      'Nyctr has not collected from Resolver yet, so it changes nothing there. Collect from it first, then try again.';
    const stuck = 'Nyctr could not remove the entry at the provider. It is still open.';
    mockApi({
      'GET /leases': [lease('open', {}), lease('other', {})],
      'GET /suggestions': [
        {
          domain: 'often.example',
          times: 3,
          people: ['Alex'],
          last_at: '2026-11-13T09:00:00Z',
          risk_score: 10,
          integration_id: 'resolver',
          scope: 'Everyone using the resolver',
        },
      ],
      'POST /suggestions': { __status: 409, detail: never },
      'POST /leases/open/end': { __status: 502, detail: stuck },
    });
    render(<OpenNow onChange={() => {}} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Make permanent' }));
    expect((await row('often.example').findByRole('alert')).textContent).toBe(never);
    fireEvent.click(row('open.example').getByRole('button', { name: 'End now' }));
    expect((await row('open.example').findByRole('alert')).textContent).toBe(stuck);
    expect(row('other.example').queryByRole('alert')).toBeNull();
    expect(document.body.textContent).not.toContain('Request failed');
  });
});
