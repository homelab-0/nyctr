import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { blockList, mockApi } from '../test/mock-api';
import type { Block, Integration } from '../types';
import Blocks from './Blocks';

/** A fabricated blocked lookup some minutes ago. */
const block = (id: string, minutes: number): Block => ({
  id,
  device_id: null,
  device_name: 'Unknown device',
  domain: `${id}.example`,
  source: 'example_dns',
  reason: 'On a block list',
  observed_at: new Date(Date.now() - minutes * 60_000).toISOString(),
  expires_at: new Date(Date.now() + 60 * 60_000).toISOString(),
  evidence_kind: 'observed',
  attribution: 'unattributed',
  risk_score: null,
  risk_explanation: '',
  risk_band: 'unknown',
  risk_category: '',
  risk_factors: [],
  reason_codes: null,
});

const source = (name: string, status: string) =>
  ({ id: name, name, status, provider: 'example_dns' }) as Integration;

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('Blocks', () => {
  it('draws one page of thousands, counts from the server, and asks the server to filter', async () => {
    const stored = Array.from({ length: 3000 }, (_, index) => ({
      ...block(`host-${String(index).padStart(4, '0')}`, index + 1),
      risk_band: (index % 3 ? 'unknown' : 'high') as Block['risk_band'],
    }));
    /** What the server would answer: the filter and the counts over everything, then one page. */
    const serve = (band?: string, text?: string, before?: string) => {
      const matching = stored.filter(
        (row) => (!band || row.risk_band === band) && (!text || row.domain.includes(text)),
      );
      const from = before ? matching.findIndex((row) => row.id === before) + 1 : 0;
      const rows = matching.slice(from, from + 200);
      const next = from + 200 < matching.length ? rows.at(-1)!.id : null;
      return { ...blockList(stored), rows, next, matching: matching.length };
    };
    const dns = { ...source('Home DNS', 'connected'), last_sync: 'x', provides: ['dns.blocks'] };
    const calls = mockApi({
      'GET /blocks': serve(),
      'GET /blocks?before=host-0199': serve(undefined, undefined, 'host-0199'),
      'GET /blocks?band=high': serve('high'),
      'GET /blocks?band=high&q=host-29': serve('high', 'host-29'),
      'GET /integrations': [dns],
      'GET /integrations/catalog': { providers: [] },
    });
    render(<Blocks />);
    expect(await screen.findByText('host-0000.example')).toBeDefined();
    const drawn = () => document.querySelectorAll('tbody tr').length;
    expect(drawn()).toBe(200);
    expect(screen.getByRole('status').textContent).toBe(
      'Showing the latest 200 of 3,000 stored lookups.',
    );
    // The counts and the note are about all 3,000, though only 200 rows are on the page.
    expect(screen.getByRole('button', { name: /^All/ }).textContent).toBe('All3000');
    expect(screen.getByRole('button', { name: /^High/ }).textContent).toBe('High1000');
    expect(document.body.textContent).toContain('None of its 3,000 stored lookups');
    expect(document.body.textContent).toContain('3,000 blocked lookups stored');
    fireEvent.click(screen.getByRole('button', { name: 'Show older' }));
    expect(await screen.findByText('host-0399.example')).toBeDefined();
    expect(drawn()).toBe(400);
    expect(screen.getByRole('status').textContent).toContain('Showing the latest 400 of 3,000');
    fireEvent.click(screen.getByRole('button', { name: /^High/ }));
    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toBe(
        'Showing the latest 200 of 1,000 that match, out of 3,000 stored lookups.',
      ),
    );
    expect(drawn()).toBe(200);
    expect(screen.queryByText('host-0001.example')).toBeNull();
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: ' host-29 ' } });
    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toBe(
        'Showing all 33 that match, out of 3,000 stored lookups.',
      ),
    );
    expect(screen.queryByRole('button', { name: 'Show older' })).toBeNull();
    expect(
      calls.filter((call) => call.path.startsWith('/blocks')).map((call) => call.path),
    ).toEqual([
      '/blocks',
      '/blocks?before=host-0199',
      '/blocks?band=high',
      '/blocks?band=high&q=host-29',
    ]);
  });

  it('says once that a source names no device, and tells not collected from nothing blocked', async () => {
    const dns = { ...source('Home DNS', 'connected'), last_sync: 'x', provides: ['dns.blocks'] };
    const limits = [{ id: 'upstream_identity', title: 'T', summary: 'Declared by the source.' }];
    mockApi({
      'GET /blocks': blockList([block('one', 5), block('two', 9)]),
      'GET /integrations': [dns],
      'GET /integrations/catalog': { providers: [{ id: 'example_dns', limits }] },
    });
    render(<Blocks />);
    const note = await screen.findByText('Home DNS does not say which device made a lookup.');
    expect(note.closest('.note')!.textContent).toContain('None of its 2 stored lookups');
    expect(await screen.findByText(/Declared by the source\./)).toBeDefined();
    expect(screen.getAllByText('The source does not say')).toHaveLength(2);
    expect(screen.queryByText('No device known')).toBeNull();
    cleanup();
    mockApi({
      'GET /blocks': blockList([]),
      'GET /integrations': [
        { ...dns, last_sync: null, status: 'error', last_error: 'Key refused' },
      ],
    });
    render(<Blocks />);
    expect(await screen.findByText('Could not be collected')).toBeDefined();
    expect(document.body.textContent).toContain('Home DNS could not be collected: Key refused');
    expect(document.body.textContent).not.toContain('No blocked lookups are stored');
  });

  it('does not call the last collection empty when the source collected once and is failing now', async () => {
    const dns = { ...source('Home DNS', 'connected'), provides: ['dns.blocks'] };
    mockApi({
      'GET /blocks': blockList([]),
      'GET /integrations': [{ ...dns, last_sync: 'x', last_error: 'Key refused' }],
    });
    render(<Blocks />);
    expect(await screen.findByText('Could not be collected')).toBeDefined();
    const page = document.body.textContent!;
    expect(page).toContain('Blocked lookups could not be collected.');
    expect(page).toContain('since its last collection that worked is missing here');
    expect(page).not.toContain('No blocked lookups are stored');
    expect(page).not.toContain('The last collection brought none back');
    cleanup();
    mockApi({ 'GET /blocks': blockList([]), 'GET /integrations': [{ ...dns, last_sync: 'x' }] });
    render(<Blocks />);
    expect(await screen.findByText('No blocked lookups are stored')).toBeDefined();
  });

  it('does not say a source names no device when one of its lookups names one', async () => {
    const dns = { ...source('Home DNS', 'connected'), last_sync: 'x', provides: ['dns.blocks'] };
    const named = { ...block('two', 9), device_id: 'd1', attribution: 'assigned' } as Block;
    mockApi({ 'GET /blocks': blockList([block('one', 5), named]), 'GET /integrations': [dns] });
    render(<Blocks />);
    expect(await screen.findByText('one.example')).toBeDefined();
    expect(screen.queryByText(/does not say which device/)).toBeNull();
    expect(screen.queryByText('The source does not say')).toBeNull();
  });

  it('says the span the stored lookups cover and which source was only partly read', async () => {
    mockApi({
      'GET /blocks': blockList([block('new', 12), block('mid', 200), block('old', 565)]),
      'GET /integrations': [source('Busy DNS', 'partial'), source('Quiet DNS', 'connected')],
    });
    render(<Blocks />);
    const lede = await screen.findByText(/blocked lookups stored/);
    expect(lede.textContent).toContain(
      '3 blocked lookups stored, going back to 9 hr ago (newest 12 min ago).',
    );
    expect(lede.textContent).not.toContain('last day');
    const note = (await screen.findByText('Busy DNS')).closest('.note')!;
    expect(note.textContent).toContain('only the most recent blocked lookups were read');
    expect(screen.queryByText('Quiet DNS')).toBeNull();
  });

  it('keeps the lookups and says completeness could not be checked when sources fail to load', async () => {
    let fail = true;
    mockApi({
      'GET /blocks': blockList([block('new', 12)]),
      'GET /integrations': () =>
        fail ? { __status: 500, detail: 'Unavailable' } : [source('Busy DNS', 'partial')],
    });
    render(<Blocks />);
    const warning = await screen.findByText(/could not be checked/);
    expect(warning.closest('.note')).toBeTruthy();
    expect(screen.getByText('new.example')).toBeTruthy();
    fail = false;
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('Busy DNS')).toBeTruthy();
    expect(screen.queryByText(/could not be checked/)).toBeNull();
  });
});
