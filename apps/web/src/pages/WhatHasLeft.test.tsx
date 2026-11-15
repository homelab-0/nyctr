import { cleanup, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { notSeen } from '../lib/counts';
import { mockApi } from '../test/mock-api';
import { thing } from '../test/map-site';
import type { AuditEvent, Resource } from '../types';
import Activity from './Activity';
import Briefing from './Briefing';
import Inventory from './Inventory';
import MapPage from './MapPage';
import Setup from './Setup';

const gone = (row: Resource): Resource => ({
  ...row,
  attributes: { missing_from_latest_snapshot: true, missing_since: '2026-11-13T00:00:00Z' },
});
const items = [
  thing('laptop', 'client', 'Laptop'),
  gone(thing('tablet', 'client', 'Tablet')),
  gone(thing('phone', 'client', 'Phone')),
  thing('lan', 'network', 'Office LAN'),
];

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('what a source no longer reports', () => {
  it('is said as a count of its own, and not at all when there is none', () => {
    expect(notSeen(1264)).toBe('1,264 not seen at the last collection');
    expect(notSeen(0)).toBe('');
  });

  it('is left out of the Briefing headline and counted beside it', async () => {
    mockApi({
      'GET /overview': {
        kind_counts: { client: 79, domain: 1382 },
        missing_counts: { client: 9, network: 1 },
        integration_count: 2,
        recent_block_count: 0,
      },
      'GET /leases': [],
      'GET /integrations': [],
      'GET /integrations/catalog': { capabilities: [], providers: [] },
      'GET /findings/checks': { checks: [], not_checked: [] },
    });
    render(<Briefing attention={[]} loading={false} />);
    const lede = await screen.findByText(/79 devices and 1,382 blocked addresses from 2 sources\./);
    expect(lede.textContent).toContain('10 not seen at the last collection.');
  });

  it('is not in an Inventory tab count, and stays listed and marked', async () => {
    mockApi({ 'GET /resources': items, 'GET /users': [], 'GET /integrations': [] });
    render(<Inventory params={new URLSearchParams()} />);
    const tabs = await screen.findByRole('group', { name: 'Kind' });
    expect(within(tabs).getByRole('button', { name: /Everything/ }).textContent).toContain('2');
    expect(within(tabs).getByRole('button', { name: /Devices/ }).textContent).toContain('1');
    expect(screen.getByRole('status').textContent).toContain('2 not seen at the last collection.');
    expect(screen.getAllByText('Missing from last collection')).toHaveLength(2);
    expect(screen.getByText('Tablet')).toBeDefined();
  });

  it('is marked in the table that says whose device is whose', async () => {
    mockApi({
      'GET /rules': { sources: [] },
      'GET /devices': items.filter((row) => row.kind === 'client'),
      'GET /users': [],
      'GET /device-links': [],
    });
    render(<Setup params={new URLSearchParams('tab=people')} />);
    const row = (name: string) => screen.getByText(name).closest('tr')!;
    await screen.findByText('Tablet');
    expect(row('Tablet').textContent).toContain('Missing from last collection');
    expect(row('Phone').textContent).toContain('Missing from last collection');
    expect(row('Laptop').textContent).not.toContain('Missing');
  });

  it('is said in plain words when the Map is asked for an item it no longer draws', async () => {
    mockApi({ 'GET /graph': { nodes: [items[0], items[3]], edges: [] }, 'GET /findings': [] });
    render(<MapPage params={new URLSearchParams('focus=tablet')} />);
    const note = await screen.findByRole('complementary', { name: 'Not on the map' });
    expect(note.textContent).toContain('did not list it at the last collection');
    expect(within(note).getByRole('link', { name: 'Inventory' })).toBeDefined();
  });

  it('is recorded in Activity by source and count when it is dropped', async () => {
    const dropped: AuditEvent = {
      id: 'a',
      created_at: new Date().toISOString(),
      actor_id: null,
      action: 'inventory.dropped',
      target_id: 'dns',
      details: {
        name: 'Office DNS',
        resources: 1183,
        kinds: { domain: 1183 },
        assignments: 0,
        links: 0,
      },
    };
    mockApi({ 'GET /audit': [dropped], 'GET /users': [], 'GET /integrations': [] });
    render(<Activity />);
    const row = (await screen.findByText('Dropped what has left Office DNS')).closest('tr')!;
    expect(row.textContent).toContain('1,183 items');
  });
});
