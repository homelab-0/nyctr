import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import type { Integration, Overview } from '../types';
import Briefing from './Briefing';

const overview: Overview = {
  resource_count: 3,
  relationship_count: 2,
  finding_count: 0,
  recent_block_count: 30,
  integration_count: 3,
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
async function open(sources: Integration[]) {
  mockApi({ 'GET /overview': overview, 'GET /leases': [], 'GET /integrations': sources });
  render(<Briefing attention={[]} loading={false} />);
  const rows = new Map<string, HTMLElement>();
  for (const item of sources) {
    rows.set(item.id, (await screen.findByText(item.name)).closest('a') as HTMLElement);
  }
  return rows;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

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
});
