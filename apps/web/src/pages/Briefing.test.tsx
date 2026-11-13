import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import { scheduleFixture, scheduleOff } from '../test/schedule';
import type { CollectionSchedule, Integration, Overview } from '../types';
import Briefing from './Briefing';

const overview: Overview = {
  resource_count: 1294,
  kind_counts: { client: 12, gateway: 1, switch: 2, network: 3, site: 1, policy: 4, domain: 1271 },
  relationship_count: 2,
  finding_count: 0,
  recent_block_count: 4000,
  oldest_block_at: new Date(Date.now() - (9 * 60 + 25) * 60_000).toISOString(),
  newest_block_at: new Date(Date.now() - 12 * 60_000).toISOString(),
  integration_count: 2,
  mode: 'live',
};

/** A fabricated source of an integration this app has never heard of, in a given collection state. */
const source = (id: string, status: string, last_error: string | null = null): Integration => ({
  id,
  provider: 'example_dns',
  name: `${id} source`,
  status,
  last_sync: new Date(Date.now() - 5 * 60_000).toISOString(),
  last_error,
  config: {},
  secret_ref: 'NYCTR_CONNECTOR_SECRET_EXAMPLE',
  capabilities: [],
  provider_name: 'Example DNS',
  provides: ['dns.blocks'],
});

/** Renders the landing screen over fabricated sources and returns each source's row. */
async function open(sources: Integration[], schedule: CollectionSchedule = scheduleFixture()) {
  mockApi({
    'GET /overview': overview,
    'GET /leases': [],
    'GET /integrations': sources,
    'GET /collection': schedule,
  });
  render(<Briefing attention={[]} loading={false} />);
  const rows = new Map<string, HTMLElement>();
  for (const item of sources) {
    rows.set(item.id, (await screen.findByText(item.name)).closest('a') as HTMLElement);
  }
  return rows;
}

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

const realTimeout = globalThis.setTimeout;

/** Opens the landing screen on a fake clock and returns how often each list has been read. */
async function openOnClock(schedule: () => CollectionSchedule) {
  vi.useFakeTimers({
    shouldAdvanceTime: true,
  });
  const calls = mockApi({
    'GET /overview': overview,
    'GET /leases': [],
    // Each read answers as the server would at that moment: collected five minutes before.
    'GET /integrations': () => [source('fine', 'connected')],
    'GET /collection': schedule,
  });
  const view = render(<Briefing attention={[]} loading={false} />);
  await screen.findByText('fine source');
  const count = (path: string) => calls.filter((call) => call.path === path).length;
  /** Moves the clock in half minutes, letting each answer land before the next step. */
  const pass = async (minutes: number) => {
    for (let step = 0; step < minutes * 2; step += 1)
      await act(async () => {
        await vi.advanceTimersByTimeAsync(30_000);
        await new Promise((resolve) => realTimeout(resolve, 0));
      });
  };
  return { count, pass, view };
}

describe('briefing sources', () => {
  it('does not show a partly read source as a clean one', async () => {
    const rows = await open([source('complete', 'connected'), source('partial', 'partial')]);
    const partial = rows.get('partial')!;
    expect(partial.textContent).toContain(
      'Collected 5 min ago. Only the most recent blocked lookups were read.',
    );
    expect(partial.querySelector('.dot')!.className).toBe('dot yellow');
    const complete = rows.get('complete')!;
    expect(complete.textContent).toContain('Collected 5 min ago');
    expect(complete.textContent).not.toContain('Only the most recent');
    expect(complete.querySelector('.dot')!.className).toBe('dot green');
  });

  it('still shows a failed collection as an error, with its reason', async () => {
    const rows = await open([
      source('failed', 'error', 'Provider denied access. Check the configured key.'),
      source('silent', 'error'),
    ]);
    const failed = rows.get('failed')!;
    expect(failed.textContent).toContain('Provider denied access. Check the configured key.');
    expect(failed.textContent).not.toContain('Collected');
    expect(failed.textContent).not.toContain('Only the most recent');
    expect(failed.querySelector('.dot')!.className).toBe('dot red');
    expect(rows.get('silent')!.textContent).toContain('Last collection failed');
    expect(rows.get('silent')!.querySelector('.dot')!.className).toBe('dot red');
  });

  it('says when each source is next collected, failed ones included', async () => {
    const rows = await open([source('fine', 'connected'), source('failed', 'error')]);
    await screen.findAllByText('Next collection in 12 min');
    expect(rows.get('fine')!.textContent).toContain('Next collection in 12 min');
    expect(rows.get('failed')!.textContent).toContain('Next collection in 12 min');
  });

  it('promises no next collection while the schedule is off', async () => {
    const rows = await open([source('fine', 'connected')], scheduleOff());
    await screen.findByText('Only when you press Collect');
    expect(rows.get('fine')!.textContent).not.toContain('Next collection');
  });

  it('names no time, and does not say collection is on request, when the schedule is on but the next time is missing', async () => {
    const rows = await open([source('fine', 'connected')], scheduleFixture({ next_at: null }));
    await screen.findByText('Next collection on schedule');
    expect(rows.get('fine')!.textContent).not.toContain('Only when you press Collect');
  });

  it('reads the schedule and the sources again once the promised time has passed', async () => {
    const { count, pass, view } = await openOnClock(() => scheduleFixture());
    await screen.findByText('Next collection in 12 min');
    await pass(11);
    expect(count('/collection')).toBe(1);
    expect(count('/integrations')).toBe(1);
    await pass(2);
    expect(count('/collection')).toBe(2);
    expect(count('/integrations')).toBe(2);
    expect(screen.getByText('Collected 5 min ago')).toBeDefined();
    expect(screen.getByText(/^Next collection in 1[12] min$/)).toBeDefined();
    expect(screen.queryByText('Next collection within a minute')).toBeNull();
    // Left open for an hour: one read per collection, not a steady poll.
    await pass(49);
    expect(screen.queryByText('Next collection within a minute')).toBeNull();
    expect(screen.queryByText(/Collected 1 hr ago/)).toBeNull();
    expect(count('/collection')).toBe(6);
    expect(count('/integrations')).toBe(6);
    // Nothing more is read once the page is left.
    view.unmount();
    await pass(60);
    expect(count('/collection')).toBe(6);
    expect(count('/integrations')).toBe(6);
  });

  it('asks less and less often while a collection stays overdue', async () => {
    const due = new Date(Date.now() + 60_000).toISOString();
    const { count, pass } = await openOnClock(() => scheduleFixture({ next_at: due }));
    await pass(2);
    expect(count('/collection')).toBe(3);
    // Waits of 1, 2, 4 and then 5 minutes: seven more reads in the next half hour, not sixty.
    await pass(30);
    expect(count('/collection')).toBe(10);
    expect(screen.getByText('Next collection within a minute')).toBeDefined();
  });
});

describe('Briefing counts', () => {
  it('names each kind with its own count and says the span the stored lookups cover', async () => {
    await open([source('fine', 'connected')]);
    const lede = await screen.findByText(/12 devices/);
    expect(lede.textContent).toBe(
      '12 devices, 3 pieces of network equipment, 3 networks, 4 rules and 1,271 blocked addresses ' +
        'from 2 sources. 4,000 blocked lookups stored, going back to 9 hr ago (newest 12 min ago).',
    );
    // No mixed total and no fixed window.
    expect(lede.textContent).not.toMatch(/1,?294|items|last day/);
  });
});
