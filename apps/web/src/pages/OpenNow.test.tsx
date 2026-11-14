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
/** The row directly under an exception, which holds what was refused for it. */
const under = (domain: string) => screen.getByText(domain).closest('tr')?.nextElementSibling;

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

  it('ends an unconfirmed opening by hand only once its source is gone', async () => {
    const record = { status: 'unconfirmed', execution: 'not_applied', owned: false } as const;
    const calls = mockApi({
      'GET /leases': [
        lease('unchecked', { ...record, source_removed: true, last_error: 'Check at Resolver.' }),
        lease('reachable', { ...record, last_error: 'Check at Resolver.' }),
      ],
      'GET /suggestions': [],
      'POST /leases/unchecked/end': {},
      'POST /leases/reachable/end': {},
    });
    render(<OpenNow onChange={() => {}} />);
    await screen.findByText('unchecked.example');
    fireEvent.click(row('unchecked.example').getByRole('button', { name: 'I removed it by hand' }));
    fireEvent.click(row('reachable.example').getByRole('button', { name: 'End now' }));
    await vi.waitFor(() => expect(calls.filter((call) => call.method === 'POST')).toHaveLength(2));
    expect(calls.filter((call) => call.method === 'POST').map((call) => call.body)).toEqual([
      { by_hand: true },
      {},
    ]);
  });

  it("says a refusal with the row whose button was pressed, in the server's words", async () => {
    const never =
      'Nyctr has not collected from Resolver yet, so it changes nothing there. Collect from it first, then try again.';
    const stuck = 'Nyctr could not remove the entry at the source. It is still open.';
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
    const suggestion = await row('often.example').findByRole('alert');
    expect(suggestion.textContent).toBe(never);
    // A block of its own across the row, never squeezed into the text column beside the buttons.
    expect(suggestion.parentElement?.className).toBe('row');
    fireEvent.click(row('open.example').getByRole('button', { name: 'End now' }));
    // A row of its own across every column, directly under the exception it is about.
    const alert = await screen.findByText(stuck);
    expect(under('open.example')).toBe(alert.closest('tr'));
    expect(alert.closest('td')?.colSpan).toBe(7);
    expect(row('open.example').queryByRole('alert')).toBeNull();
    expect(screen.getAllByRole('alert')).toHaveLength(1);
    expect(document.body.textContent).not.toContain('Request failed');
  });

  it('never says Nyctr changed an entry that was at the source before its exception', async () => {
    mockApi({
      'GET /leases': [
        lease('ours', {}),
        lease('theirs', { owned: false }),
        lease('hand', { status: 'ended', ended_reason: 'removed_by_hand' }),
        lease('gone', { status: 'ended', ended_reason: 'source_removed' }),
        lease('early', { status: 'ended', ended_reason: 'revoked' }),
        lease('late', { status: 'ended', ended_reason: 'expired', removal: 'removed' }),
        lease('kept', { status: 'ended', ended_reason: 'expired', removal: 'not_owned' }),
      ],
      'GET /suggestions': [],
    });
    render(<OpenNow onChange={() => {}} />);
    await screen.findByText('ours.example');
    expect(row('ours.example').getByText('Changed at the source and checked.')).toBeTruthy();
    expect(row('theirs.example').queryByText(/Changed/)).toBeNull();
    expect(
      row('theirs.example').getByText(
        'Already allowed there before this exception. Nyctr left the entry as it was.',
      ),
    ).toBeTruthy();
    expect(row('hand.example').getByText(/^Marked as removed by hand/)).toBeTruthy();
    expect(row('gone.example').getByText(/^Closed when its source was removed/)).toBeTruthy();
    expect(row('early.example').getByText(/^Ended early/)).toBeTruthy();
    expect(row('late.example').getByText(/^Ran out .* · removed at the source$/)).toBeTruthy();
    expect(
      row('kept.example').getByText(/ · nothing to remove, the entry was not Nyctr's$/),
    ).toBeTruthy();
    // A record from before endings kept this says nothing about the source.
    expect(row('early.example').getByText(/^Ended early/).textContent).not.toMatch(/source/);
  });

  it('lists an opening that was not confirmed in plain words and never as open access', async () => {
    const words =
      'Nyctr tried to open slow.example at Resolver and has not confirmed it. It may be open there. ' +
      'Unless the opening completes, Nyctr removes it.';
    mockApi({
      'GET /leases': [
        lease('open', {}),
        lease('slow', {
          status: 'unconfirmed',
          execution: 'not_applied',
          decided_by: '',
          last_error: words,
        }),
        lease('settled', { status: 'ended', ended_reason: 'not_confirmed' }),
      ],
      'GET /suggestions': [],
    });
    render(<OpenNow onChange={() => {}} />);
    expect(await screen.findByText(/^1 exception open\./)).toBeTruthy();
    const text = screen.getByText('slow.example').closest('tr')!.textContent;
    expect(text).toContain('Not opened');
    expect(text).toContain('Not confirmed');
    expect(text).toContain(words);
    expect(text).not.toMatch(/left|Closing|An administrator/);
    expect(row('settled.example').getByText(/^Not opened/)).toBeTruthy();
  });

  it('does not say nothing is open above an opening that may be open at the source', async () => {
    mockApi({
      'GET /leases': [
        lease('slow', { status: 'unconfirmed', execution: 'not_applied', last_error: 'x' }),
      ],
      'GET /suggestions': [],
    });
    render(<OpenNow onChange={() => {}} />);
    expect(
      await screen.findByText(/^No exception is open\. What is listed below was not confirmed/),
    ).toBeTruthy();
    expect(document.body.textContent).not.toContain('Nothing is open');
  });
});
