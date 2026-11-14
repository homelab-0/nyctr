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
    expect(await row('Access opened while its source was being removed or changed')).toContain(
      'docs.example · taken back out at the source',
    );
    expect(
      await row('A guest pass issued while its source was being removed or changed'),
    ).toContain('could not be ended, so end it at the source by hand');
    expect(await row('Access closed')).toContain(
      'files.example · removed at the source by hand, so nothing was sent',
    );
    expect(await row('Decided to let a waiting guest on')).toContain(
      'nothing changed at the source',
    );
    expect(await row('Was sent to the member portal to sign in')).toBeTruthy();
    expect(await row('Started a collection when the server was asked to')).toBeTruthy();
    expect(await row('Something this version of the page cannot describe')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/[a-z]+\.[a-z]+_|[a-z]_[a-z]|lookback/);
  });
});

describe('Activity rows about a change at a source', () => {
  it('says no more than the record knows, and never a change that was not applied', async () => {
    const closed = { domain: 'files.example', reason: 'revoked' };
    mockApi({
      'GET /audit': [
        event('a', 'access.opened', { domain: 'new.example', execution: 'applied', owned: true }),
        // Already allowed at the source before the exception: recorded as applied, nothing added.
        event('b', 'access.opened', { domain: 'was.example', execution: 'applied', owned: false }),
        event('c', 'access.opened', { domain: 'demo.example', execution: 'simulated' }),
        event('d', 'access.opened', { domain: 'read.example', execution: 'not_applied' }),
        // A close keeps how the exception was opened; it may have sent nothing.
        event('e', 'access.closed', { ...closed, execution: 'applied' }),
        event('f', 'access.closed', { ...closed, domain: 'sim.example', execution: 'simulated' }),
        event('g', 'access.open_undone', { domain: 'stuck.example', execution: 'failed' }),
        event('h', 'access.open_undone', { domain: 'left.example', execution: 'not_applied' }),
        // Recorded as applied when the guest was already without access and nothing was sent.
        event('i', 'guest.cut', { execution: 'applied', reason: 'Asked to leave' }),
        // Any error: the secret not set, no site found, a timeout. The source may never be asked.
        event('j', 'guest.lock', { execution: 'failed' }),
        event('k', 'guest.pass_issued', { execution: 'simulated', minutes: 60 }),
        event('l', 'guest.pass_ended', { execution: 'applied' }),
        event('m', 'access.approved', { execution: 'applied' }),
        event('n', 'access.denied', { execution: 'not_performed' }),
        event('o', 'made.up_later', { execution: 'applied' }),
        // What an ending did at the source, one row for each thing the record can say.
        ...['removed', 'already_gone', 'kept_for_another', 'not_owned'].map((removal) =>
          event(removal, 'access.closed', {
            domain: `${removal.replace(/_/g, '-')}.example`,
            execution: 'applied',
            removal,
          }),
        ),
        event('p', 'access.close_failed', { domain: 'held.example' }),
        event('q', 'guest.pass_ended', { execution: 'failed' }),
        event('r', 'integration.collection_failed', {
          name: 'Resolver',
          why: 'The source returned HTTP 500.',
          retry_at: '2026-11-13T10:42:00Z',
        }),
        event('s', 'integration.collection_failed', { name: 'Gateway', why: 'Could not connect.' }),
        // An opening the source did not confirm, and how its record ended: here the record does say.
        event('u', 'access.open_unconfirmed', { domain: 'unsure.example', execution: 'failed' }),
        event('v', 'access.closed', {
          domain: 'undone.example',
          reason: 'not_confirmed',
          execution: 'applied',
        }),
        event('w', 'access.closed', {
          domain: 'never.example',
          reason: 'not_confirmed',
          execution: 'not_applied',
        }),
        ...['secret', 'secret_ref', 'missing'].map((reason) =>
          event(reason, 'integration.retries_stopped', { name: `Source ${reason}`, reason }),
        ),
      ],
      'GET /users': [],
      'GET /integrations': [],
    });
    render(<Activity />);
    await screen.findAllByText('Access opened');
    const detail = (text: string) =>
      screen.getByText(text, { selector: 'th' }).closest('tr')!.lastElementChild!.textContent;
    const about = (domain: string) =>
      screen.getByText(new RegExp(`^${domain.replace('.', '\\.')} · `)).textContent;
    expect(about('new.example')).toBe('new.example · allowed at the source');
    expect(about('was.example')).toBe(
      'was.example · already allowed at the source, left as it was',
    );
    expect(about('demo.example')).toBe('demo.example · simulated, nothing was sent to the source');
    expect(about('read.example')).toBe('read.example · nothing changed at the source');
    expect(about('files.example')).toBe(
      'files.example · this record does not say what was sent to the source · ended early by a person',
    );
    expect(about('sim.example')).toBe(
      'sim.example · simulated, nothing was sent to the source · ended early by a person',
    );
    expect(about('stuck.example')).toBe(
      'stuck.example · could not be taken back out, so remove it at the source by hand',
    );
    expect(about('left.example')).toBe(
      'left.example · already allowed at the source, left as it was',
    );
    expect(about('unsure.example')).toBe(
      'unsure.example · the source did not confirm it, so it may be open there',
    );
    expect(about('undone.example')).toBe(
      'undone.example · taken back out at the source · the opening was never confirmed',
    );
    expect(about('never.example')).toBe(
      'never.example · nothing was removed at the source · the opening was never confirmed',
    );
    expect(detail('Cut a guest off')).toBe('without access at the source · Asked to leave');
    // A headline reads as done only when the record says applied.
    expect(detail('Tried to lock a guest out')).toBe('did not go through');
    expect(detail('Tried to end a guest pass')).toBe('did not go through');
    expect(detail('Simulated: issue a guest pass')).toBe(
      'simulated, nothing was sent to the source · 60 min',
    );
    expect(screen.getByText('Simulated: open access', { selector: 'th' })).toBeTruthy();
    expect(screen.getByText('Decided to open access', { selector: 'th' })).toBeTruthy();
    expect(screen.getByText('Simulated: close access', { selector: 'th' })).toBeTruthy();
    expect(screen.queryByText('Locked a guest out')).toBeNull();
    expect(about('removed.example')).toBe('removed.example · removed at the source');
    expect(about('already-gone.example')).toMatch(/nothing to remove, the entry was already gone/);
    expect(about('kept-for-another.example')).toMatch(/another open exception still needs it/);
    expect(about('not-owned.example')).toMatch(/nothing to remove, the entry was not Nyctr's$/);
    expect(detail('Access could not be closed')).toBe(
      'held.example · could not be removed at the source, so it is still open',
    );
    expect(detail('Could not collect from Resolver')).toMatch(
      /^The source returned HTTP 500\. · next try at \d/,
    );
    expect(detail('Could not collect from Gateway')).toBe('Could not connect.');
    expect(detail('Ended a guest pass')).toBe('ended at the source');
    expect(detail('Approved a request')).toBe('allowed at the source');
    expect(detail('Said no to a request')).toBe('');
    // An action this page does not know claims nothing about the source.
    expect(detail('Something this version of the page cannot describe')).toBe('');
    expect(detail('Stopped retrying Source secret and showed it as failed')).toBe(
      'its secret is no longer set on the server',
    );
    expect(detail('Stopped retrying Source secret_ref and showed it as failed')).toBe(
      'the name of its secret on the server is not a valid one',
    );
    expect(detail('Stopped retrying Source missing and showed it as failed')).toBe(
      'the source is no longer there',
    );
    expect(document.body.textContent).not.toMatch(/changed at the source ·|the source refused/);
    expect(document.body.textContent).toContain('a sign-in that failed');
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
