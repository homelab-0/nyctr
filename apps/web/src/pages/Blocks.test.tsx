import { cleanup, render, screen } from '@testing-library/react';
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
});
