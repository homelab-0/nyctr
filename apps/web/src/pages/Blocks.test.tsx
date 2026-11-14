import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
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
  it('says once that a source names no device, and tells not collected from nothing blocked', async () => {
    const dns = { ...source('Home DNS', 'connected'), last_sync: 'x', provides: ['dns.blocks'] };
    const limits = [{ id: 'upstream_identity', title: 'T', summary: 'Declared by the source.' }];
    mockApi({
      'GET /blocks': [block('one', 5), block('two', 9)],
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
      'GET /blocks': [],
      'GET /integrations': [
        { ...dns, last_sync: null, status: 'error', last_error: 'Key refused' },
      ],
    });
    render(<Blocks />);
    expect(await screen.findByText('Not collected yet')).toBeDefined();
    expect(document.body.textContent).toContain('Home DNS could not be collected: Key refused');
    expect(document.body.textContent).not.toContain('No blocked lookups are stored');
  });

  it('says the span the stored lookups cover and which source was only partly read', async () => {
    mockApi({
      'GET /blocks': [block('new', 12), block('mid', 200), block('old', 565)],
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
      'GET /blocks': [block('new', 12)],
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
