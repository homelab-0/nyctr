import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import type { Integration } from '../types';
import Briefing from './Briefing';
import Findings from './Findings';
import Inventory from './Inventory';

/** A fabricated source of a kind this app has never heard of. */
const source = (name: string, extra: Partial<Integration> = {}) =>
  ({
    id: name,
    name,
    provider: 'example_dns',
    status: 'connected',
    last_sync: new Date().toISOString(),
    last_error: null,
    provides: ['dns.blocks'],
    gaps: [],
    ...extra,
  }) as Integration;
const never = source('New DNS', { status: 'configured', last_sync: null });
const failed = source('Far DNS', { status: 'error', last_sync: null, last_error: 'Key refused' });
const catalog = {
  capabilities: [],
  providers: [
    {
      id: 'example_dns',
      limits: [{ id: 'upstream_identity', title: 'Lookups name no device', summary: 'Declared.' }],
    },
  ],
};
const checks = {
  checks: [
    { text: 'A DNS profile with logging switched off', active: true },
    { text: 'A hosted workload whose firewall is switched off', active: false },
  ],
  not_checked: ['Firewall rules'],
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('screens say what they do not know', () => {
  it('lists what findings check and what is collected but never checked', async () => {
    mockApi({ 'GET /findings': [], 'GET /resources': [], 'GET /findings/checks': checks });
    render(<Findings params={new URLSearchParams()} />);
    expect(
      await screen.findByText('No open findings from the 2 checks listed below'),
    ).toBeDefined();
    const page = document.body.textContent!;
    expect(page).toContain('A hosted workload whose firewall is switched off (no collected source');
    expect(page).toContain('Collected but not checked');
    expect(page).toContain('Firewall rules. You can see these on the Map');
  });

  it('shows no zero in Inventory for a source that never collected, and names a failure', async () => {
    mockApi({ 'GET /resources': [], 'GET /users': [], 'GET /integrations': [never, failed] });
    render(<Inventory params={new URLSearchParams()} />);
    expect(await screen.findByText('Not collected yet')).toBeDefined();
    const page = document.body.textContent!;
    expect(page).toContain('New DNS has not been collected yet');
    expect(page).toContain('Far DNS could not be collected: Key refused');
    expect(screen.getByRole('button', { name: 'Devices' }).textContent).toBe('Devices');
  });

  it('builds the Briefing list from the sources connected and agrees with Findings', async () => {
    const quiet = source('Home DNS', {
      gaps: [{ id: 'g1', title: 'Some settings could not be read', summary: '' }],
    });
    mockApi({
      'GET /overview': { kind_counts: {}, integration_count: 2, recent_block_count: 0 },
      'GET /leases': [],
      'GET /integrations': [quiet, never],
      'GET /integrations/catalog': catalog,
      'GET /findings/checks': checks,
    });
    render(<Briefing attention={[]} loading={false} />);
    expect(await screen.findByText('Home DNS: Lookups name no device')).toBeDefined();
    const page = document.body.textContent!;
    expect(page).toContain('Home DNS: Some settings could not be read');
    expect(page).toContain('New DNS has not been collected yet');
    expect(page).toContain('Not collected yet from 2 sources.');
    expect(page).toContain('Blocked lookups have not been collected yet.');
    expect(page).not.toContain('No blocked lookups are stored');
    expect(page).not.toContain('Workload firewall rules');
    expect(page).toContain('Findings come from 2 checks, 1 with nothing to look at here.');
    expect(page).toContain('Collected but not checked: Firewall rules.');
  });
});
