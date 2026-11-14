import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
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
    /**
     * What the server would answer: the filter and the counts over everything, then one page.
     * The page here is 50 rows: its size is the server's choice and the screen draws what it is sent.
     */
    const everything = blockList(stored);
    const serve = (band?: string, text?: string, before?: string) => {
      const matching = stored.filter(
        (row) => (!band || row.risk_band === band) && (!text || row.domain.includes(text)),
      );
      const from = before ? matching.findIndex((row) => row.id === before) + 1 : 0;
      const rows = matching.slice(from, from + 50);
      const next = from + 50 < matching.length ? rows.at(-1)!.id : null;
      return { ...everything, rows, next, page_size: 50, matching: matching.length };
    };
    const dns = { ...source('Home DNS', 'connected'), last_sync: 'x', provides: ['dns.blocks'] };
    const calls = mockApi({
      'GET /blocks': serve(),
      'GET /blocks?before=host-0049': serve(undefined, undefined, 'host-0049'),
      'GET /blocks?band=high': serve('high'),
      'GET /blocks?band=high&q=host-29': serve('high', 'host-29'),
      'GET /integrations': [dns],
      'GET /integrations/catalog': { providers: [] },
    });
    render(<Blocks />);
    // Looking an element up by its role or its text walks every element on the page, and this page
    // holds several thousand. The table is read by selector and the controls within their own bar.
    const drawn = () => document.querySelectorAll('tbody tr').length;
    const address = (row: number) => document.querySelectorAll('tbody th')[row]?.textContent;
    const line = () => document.querySelector('[role=status]')?.textContent;
    const filters = () => within(document.querySelector<HTMLElement>('.seg')!);
    const older = () =>
      within(document.querySelector<HTMLElement>('[role=status]')!.parentElement!).queryByRole(
        'button',
        { name: 'Show older' },
      );
    await waitFor(() => expect(drawn()).toBe(50));
    expect(address(0)).toBe('host-0000.example');
    expect(line()).toBe('Showing the latest 50 of 3,000 stored lookups.');
    // The counts and the note are about all 3,000, though only 50 rows are on the page.
    expect(filters().getByRole('button', { name: /^All/ }).textContent).toBe('All3,000');
    expect(filters().getByRole('button', { name: /^High/ }).textContent).toBe('High1,000');
    const head = document.querySelector('.page-head')!.textContent;
    expect(head).toContain('None of its 3,000 stored lookups');
    expect(head).toContain('3,000 blocked lookups stored');
    fireEvent.click(older()!);
    await waitFor(() => expect(drawn()).toBe(100));
    expect(address(99)).toBe('host-0099.example');
    expect(line()).toContain('Showing the latest 100 of 3,000');
    fireEvent.click(filters().getByRole('button', { name: /^High/ }));
    // Until the server answers, the line still describes the rows on screen, not the new filter.
    expect(line()).toBe('Showing the latest 100 of 3,000 stored lookups. Reading…');
    expect(older()).toBeNull();
    await waitFor(() =>
      expect(line()).toBe(
        'Showing the latest 50 of 1,000 that match, out of 3,000 stored lookups.',
      ),
    );
    expect(drawn()).toBe(50);
    expect(address(1)).toBe('host-0003.example');
    fireEvent.change(document.querySelector('input[type=search]')!, {
      target: { value: ' host-29 ' },
    });
    await waitFor(() =>
      expect(line()).toBe('Showing all 33 that match, out of 3,000 stored lookups.'),
    );
    expect(older()).toBeNull();
    expect(
      calls.filter((call) => call.path.startsWith('/blocks')).map((call) => call.path),
    ).toEqual([
      '/blocks',
      '/blocks?before=host-0049',
      '/blocks?band=high',
      '/blocks?band=high&q=host-29',
    ]);
    // Four draws and a typing pause: about a second. The room is for a machine at full load.
  }, 20_000);

  it('offers no older rows and keeps a true line when another filter could not be read', async () => {
    const stored = Array.from({ length: 6 }, (_, index) => block(`host-${index}`, index + 1));
    const first = { ...blockList(stored), rows: stored.slice(0, 3), next: 'host-2' };
    const calls = mockApi({
      'GET /blocks': first,
      'GET /blocks?band=high': { __status: 500, detail: 'Unavailable' },
      'GET /blocks?before=host-2': { ...blockList(stored), rows: stored.slice(3) },
      'GET /integrations': [],
      'GET /integrations/catalog': { providers: [] },
    });
    render(<Blocks />);
    expect(await screen.findByRole('button', { name: 'Show older' })).toBeDefined();
    fireEvent.click(screen.getByRole('button', { name: /^High/ }));
    expect(await screen.findByText('The list could not be read again.')).toBeDefined();
    // The rows on screen are still the unfiltered ones, and the line says so. Older rows are not
    // offered: they would be asked for with High and put under rows that are not High.
    expect(screen.getByRole('status').textContent).toBe(
      'Showing the latest 3 of 6 stored lookups.',
    );
    expect(screen.queryByRole('button', { name: 'Show older' })).toBeNull();
    expect(calls.some((call) => call.path.includes('before='))).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: /^All/ }));
    fireEvent.click(await screen.findByRole('button', { name: 'Show older' }));
    expect(await screen.findByText('host-5.example')).toBeDefined();
    expect(screen.getByRole('status').textContent).toBe('Showing all 6 stored lookups.');
    expect(calls.map((call) => call.path).filter((path) => path.includes('before='))).toEqual([
      '/blocks?before=host-2',
    ]);
    expect((screen.getByRole('searchbox') as HTMLInputElement).maxLength).toBe(120);
  });

  it('drops an older page that arrives after the same filter was read afresh', async () => {
    const stored = Array.from({ length: 6 }, (_, index) => block(`host-${index}`, index + 1));
    const arrived = block('arrived-since', 0);
    let reads = 0;
    let answerOlder = (_: unknown) => {};
    mockApi({
      // The second read of the unfiltered list holds a lookup collected since the first.
      'GET /blocks': () =>
        reads++
          ? {
              ...blockList([arrived, ...stored]),
              rows: [arrived, ...stored.slice(0, 2)],
              next: 'x',
            }
          : { ...blockList(stored), rows: stored.slice(0, 3), next: 'host-2' },
      'GET /blocks?band=high': { ...blockList(stored), rows: [], matching: 0 },
      'GET /blocks?before=host-2': () => new Promise((resolve) => (answerOlder = resolve)),
      'GET /integrations': [],
      'GET /integrations/catalog': { providers: [] },
    });
    render(<Blocks />);
    fireEvent.click(await screen.findByRole('button', { name: 'Show older' }));
    fireEvent.click(screen.getByRole('button', { name: /^High/ }));
    expect(await screen.findByText('No blocks match')).toBeDefined();
    fireEvent.click(screen.getByRole('button', { name: /^All/ }));
    expect(await screen.findByText('arrived-since.example')).toBeDefined();
    // Only now does the older page asked for under the first answer arrive.
    await act(async () => answerOlder({ ...blockList(stored), rows: stored.slice(3) }));
    expect(screen.getByText('arrived-since.example')).toBeDefined();
    expect(screen.queryByText('host-5.example')).toBeNull();
    expect(screen.getByRole('status').textContent).toBe(
      'Showing the latest 3 of 7 stored lookups.',
    );
    expect(screen.getByRole('button', { name: 'Show older' })).toBeDefined();
  });

  it('draws a row again when the same lookup comes back with other content', async () => {
    const one = block('one', 5);
    mockApi({
      'GET /blocks': blockList([one]),
      // The same lookup stays on screen through the search, and comes back with another reason.
      'GET /blocks?q=one': blockList([{ ...one, reason: 'Now on a threat list' }]),
      'GET /integrations': [],
      'GET /integrations/catalog': { providers: [] },
    });
    render(<Blocks />);
    const row = (await screen.findByText('On a block list')).closest('tr');
    fireEvent.change(screen.getByRole('searchbox'), { target: { value: 'one' } });
    expect(await screen.findByText('Now on a threat list')).toBeDefined();
    expect(screen.queryByText('On a block list')).toBeNull();
    // It is the row that was there, drawn again, not a new one put in its place.
    expect(screen.getByText('Now on a threat list').closest('tr')).toBe(row);
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
