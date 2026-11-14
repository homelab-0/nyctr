import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import type { AuditEvent, Integration } from '../types';
import Activity from './Activity';

const event = (id: string, action: string, details: Record<string, unknown>): AuditEvent => ({
  id,
  created_at: '2026-11-13T10:00:00Z',
  actor_id: 'admin',
  action,
  target_id: `source-${id}`,
  details,
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('Activity rows about a source', () => {
  it('names the source and says what a collection stored, never a raw id', async () => {
    mockApi({
      'GET /audit': [
        event('a', 'integration.collected', {
          name: 'Office DNS',
          resources: 6,
          observations: 4000,
          partial: true,
          rows_kept: 4000,
        }),
        event('b', 'integration.created', { provider: 'example_dns', name: 'Old name' }),
        // Older records hold no name: the current one is used, else the source is said to be gone.
        event('c', 'integration.diagnosed', { outcome: 'verified' }),
        event('d', 'integration.collection_failed', {}),
        event('e', 'integration.collected', {
          name: 'Gateway',
          resources: 3,
          observations: 0,
          partial: false,
          gaps: ['example_passes', 'example_ranges'],
          gap_causes: { example_passes: ['refused'] },
        }),
        event('f', 'integration.collected', { name: 'Whole', resources: 1, gaps: [] }),
      ],
      'GET /users': [{ id: 'admin', name: 'Alex' }],
      'GET /integrations': [{ id: 'source-c', name: 'Lab hypervisor' } as Integration],
    });
    render(<Activity />);
    const collected = (await screen.findByText('Collected from Office DNS')).closest('tr')!;
    expect(collected.textContent).toContain('6 items · 4,000 blocked lookups · most recent only');
    // What it could not read is counted; the codes themselves stay in the record.
    const gappy = (await screen.findByText('Collected from Gateway')).closest('tr')!;
    expect(gappy.textContent).toContain('2 things it could not read');
    expect(gappy.textContent).not.toMatch(/example_|refused/);
    const whole = screen.getByText('Collected from Whole').closest('tr')!;
    expect(whole.textContent).not.toContain('could not read');
    expect(screen.getByText('Added the source Old name')).toBeTruthy();
    expect(screen.getByText('Tested Lab hypervisor')).toBeTruthy();
    expect(screen.getByText('Could not collect from a source since removed')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/source-[abcd]/);
  });
});

describe('Activity rows the reviews found unworded', () => {
  it('reads each as a sentence, with no action name, setting key or reason code', async () => {
    mockApi({
      'GET /audit': [
        event('a', 'integration.retries_stopped', { name: 'Gateway', reason: 'schedule_off' }),
        event('b', 'collection.schedule_changed', {
          old: { enabled: false, interval_seconds: 900 },
          new: { enabled: true, interval_seconds: 1800 },
        }),
        event('c', 'integration.updated', {
          fields: ['name', 'config.lookback_hours'],
          retest: false,
        }),
        event('d', 'integration.removed', { name: 'Old resolver' }),
        event('e', 'access.open_undone', { domain: 'docs.example', execution: 'applied' }),
        event('f', 'guest.pass_undone', { execution: 'failed' }),
        event('g', 'access.closed', {
          domain: 'files.example',
          reason: 'removed_by_hand',
          execution: 'applied',
        }),
        event('h', 'guest.admit', { execution: 'not_applied' }),
        event('i', 'auth.sent_to_portal', {}),
        event('j', 'integration.nudged', {}),
        event('k', 'made.up_later', {}),
      ],
      'GET /users': [],
      'GET /integrations': [{ id: 'source-c', name: 'Lab hypervisor' } as Integration],
    });
    render(<Activity />);
    const row = async (what: string) => (await screen.findByText(what)).closest('tr')!.textContent;
    expect(await row('Stopped retrying Gateway and showed it as failed')).toContain(
      'scheduled collection was turned off',
    );
    expect(await row('Changed the collection schedule')).toContain('now every 30 minutes');
    expect(await row('Edited the source Lab hypervisor')).toContain('2 fields changed');
    expect(await row('Removed the source Old resolver')).toBeTruthy();
    expect(
      await row('Took back access opened while its source was being removed or changed'),
    ).toContain('docs.example · changed at the source');
    expect(
      await row('Took back a guest pass issued while its source was being removed or changed'),
    ).toContain('the source refused');
    expect(await row('Access closed')).toContain(
      'files.example · removed at the source by hand, so nothing was sent',
    );
    expect(await row('Let a waiting guest on')).toContain('nothing changed at the source');
    expect(await row('Was sent to the member portal to sign in')).toBeTruthy();
    expect(await row('Started a collection when the server was asked to')).toBeTruthy();
    expect(await row('Something this version of the page cannot describe')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/[a-z]+\.[a-z]+_|[a-z]_[a-z]|lookback/);
  });
});

describe('Activity when source names are unavailable', () => {
  it('never calls a source removed until the list loads, and offers to try again', async () => {
    let fail = true;
    mockApi({
      'GET /audit': [
        event('c', 'integration.diagnosed', {}),
        event('d', 'integration.collected', {}),
      ],
      'GET /users': [],
      'GET /integrations': () =>
        fail
          ? { __status: 500, detail: 'Unavailable' }
          : [{ id: 'source-c', name: 'Lab hypervisor' } as Integration],
    });
    render(<Activity />);
    expect(await screen.findByText('Source names could not be loaded.')).toBeTruthy();
    expect(screen.getByText('Tested a source')).toBeTruthy();
    expect(screen.getByText('Collected from a source')).toBeTruthy();
    expect(document.body.textContent).not.toContain('since removed');
    fail = false;
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('Tested Lab hypervisor')).toBeTruthy();
    expect(screen.getByText('Collected from a source since removed')).toBeTruthy();
    expect(screen.queryByText('Source names could not be loaded.')).toBeNull();
  });
});
