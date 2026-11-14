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
/** Collected once, failing now: the old `last_sync` stays while a retry is waiting. */
const stale = source('Old DNS', { last_error: 'Key refused' });
const catalog = {
  capabilities: [],
  providers: [
    {
      id: 'example_dns',
      limits: [{ id: 'upstream_identity', title: 'Lookups name no device', summary: 'Declared.' }],
      not_collected: ['DNS lookups that were allowed'],
    },
  ],
};
const briefing = (sources: Integration[], overview: Record<string, unknown> = {}) => {
  mockApi({
    'GET /overview': {
      kind_counts: {},
      integration_count: sources.length,
      recent_block_count: 0,
      ...overview,
    },
    'GET /leases': [],
    'GET /integrations': sources,
    'GET /integrations/catalog': catalog,
    'GET /findings/checks': checks,
  });
  render(<Briefing attention={[]} loading={false} />);
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
      await screen.findByText(
        'No open findings from the 1 of 2 checks below that had something to check',
      ),
    ).toBeDefined();
    const page = document.body.textContent!;
    expect(page).toContain('A hosted workload whose firewall is switched off (no collected source');
    expect(page).toContain('Collected but not checked');
    expect(page).toContain('Firewall rules. Nyctr stores these, but no check reads them');
    expect(page).not.toContain('in Inventory');
  });

  it('counts only checks with something to look at, and says so when none has', async () => {
    const all = checks.checks.map((check) => ({ ...check, active: true }));
    mockApi({
      'GET /findings': [],
      'GET /resources': [],
      'GET /findings/checks': { checks: all, not_checked: [] },
    });
    render(<Findings params={new URLSearchParams()} />);
    expect(
      await screen.findByText('No open findings from the 2 checks listed below'),
    ).toBeDefined();
    cleanup();
    const none = all.map((check) => ({ ...check, active: false }));
    mockApi({
      'GET /findings': [],
      'GET /resources': [],
      'GET /findings/checks': { checks: none, not_checked: [] },
    });
    render(<Findings params={new URLSearchParams()} />);
    expect(await screen.findByText('Nothing was checked, so there are no findings')).toBeDefined();
    expect(document.body.textContent).toContain(
      'No collected source reports anything the checks below look at.',
    );
    expect(document.body.textContent).not.toContain('No open findings');
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

  it('does not count a source that is failing now as collected in Inventory', async () => {
    const row = {
      id: 'n1',
      name: 'Office LAN',
      kind: 'network',
      provider: 'example_dns',
      source_id: 'n1',
      site_id: null,
      observed_at: new Date().toISOString(),
      evidence_kind: 'configured',
      classification: 'unknown',
      owner_id: null,
      attributes: {},
    };
    mockApi({
      'GET /resources': [row],
      'GET /users': [],
      'GET /integrations': [stale],
      'GET /integrations/catalog': catalog,
    });
    render(<Inventory params={new URLSearchParams()} />);
    expect(await screen.findByText('Old DNS could not be collected: Key refused.')).toBeDefined();
    expect(document.body.textContent).toContain('the last time a collection worked');
    expect(screen.getByRole('button', { name: 'Devices' }).textContent).toBe('Devices');
    expect(screen.getByRole('button', { name: /Networks/ }).textContent).toBe('Networks1');
  });

  it('builds the Briefing list from the sources connected and agrees with Findings', async () => {
    const quiet = source('Home DNS', {
      gaps: [{ id: 'g1', title: 'Some settings could not be read', summary: '' }],
    });
    briefing([quiet, never]);
    expect(await screen.findByText('Home DNS: Lookups name no device')).toBeDefined();
    const page = document.body.textContent!;
    expect(page).toContain('Home DNS: Some settings could not be read');
    expect(page).toContain('New DNS has not been collected yet');
    // One of the two was collected, so the sentence says how many of how many.
    expect(page).toContain('Nothing inventoried yet from 2 sources. 1 of 2 sources not collected');
    expect(page).not.toContain('Not collected yet from 2 sources');
    expect(page).toContain('Blocked lookups have not been collected yet.');
    expect(page).not.toContain('No blocked lookups are stored');
    expect(page).not.toContain('Workload firewall rules');
    expect(page).toContain('Findings come from 2 checks, 1 with nothing to look at here.');
    expect(page).toContain('Collected but not checked: Firewall rules.');
    // The source still waiting says so on its own row.
    expect(screen.getByText('Not collected yet')).toBeDefined();
    // What is not collected comes from what the kind of source declares; a caution is listed apart.
    const declared = page.indexOf('Home DNS: DNS lookups that were allowed');
    expect(declared).toBeGreaterThan(page.indexOf('Not collected'));
    expect(declared).toBeLessThan(page.indexOf('Keep in mind'));
    expect(page.indexOf('Home DNS: Lookups name no device')).toBeGreaterThan(
      page.indexOf('Keep in mind'),
    );
  });

  it('does not call a source collected on the Briefing while it is failing', async () => {
    briefing([stale]);
    expect(await screen.findByText('Old DNS could not be collected: Key refused')).toBeDefined();
    const page = document.body.textContent!;
    expect(page).toContain('1 of 1 source could not be collected.');
    expect(page).toContain('Blocked lookups could not be collected.');
    expect(page).not.toContain('No blocked lookups are stored');
    expect(screen.getByText('Key refused')).toBeDefined();
    expect(page).not.toMatch(/Collected .* ago/);
  });

  it('says nothing about blocked lookups on the Briefing with no sources connected', async () => {
    briefing([]);
    expect(await screen.findByText('No sources are connected yet.')).toBeDefined();
    expect(document.body.textContent).not.toContain('No blocked lookups are stored');
    expect(document.body.textContent).not.toContain('Nothing inventoried');
  });
});
