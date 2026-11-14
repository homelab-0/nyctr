import { describe, expect, it } from 'vitest';
import type { Resource } from '../types';
import { GROUPS, UNLISTED, lookupSpan, namedCounts } from './counts';
import { drawn } from './map-layout';

const NOW = Date.parse('2026-11-13T12:00:00Z');
const before = (minutes: number) => new Date(NOW - minutes * 60_000).toISOString();

describe('named counts', () => {
  it('counts the same groups Inventory lists, and blocked addresses on their own', () => {
    const kinds = { client: 2, access_point: 1, workload: 3, dns_profile: 1, domain: 1, site: 1 };
    expect(namedCounts(kinds)).toBe(
      '2 devices, 1 piece of network equipment, 3 hosts, bridges and workloads, 1 rule and 1 blocked address',
    );
    // Every kind Inventory lists falls in a named group; sites and blocked addresses are not listed.
    const grouped = Object.values(GROUPS).flatMap((group) => group.kinds || []);
    expect(grouped).not.toContain('domain');
    expect([...UNLISTED]).toEqual(['site', 'domain']);
  });

  it('names bridges in the group that counts them, as Inventory does', () => {
    expect(GROUPS.compute.kinds).toContain('bridge');
    expect(GROUPS.compute.name).toBe('Hosts, bridges and workloads');
    expect(namedCounts({ bridge: 1 })).toBe('1 host, bridge or workload');
    expect(namedCounts({ host: 1, bridge: 2 })).toBe('3 hosts, bridges and workloads');
  });

  it('says nothing for an empty inventory rather than a zero total', () => {
    expect(namedCounts({})).toBe('');
    expect(namedCounts({ site: 1 })).toBe('');
  });
});

describe('the span of stored blocked lookups', () => {
  it('is worked out from the oldest and newest stored lookup, never a fixed window', () => {
    expect(lookupSpan(4000, before(565), before(12), NOW)).toBe(
      '4,000 blocked lookups stored, going back to 9 hr ago (newest 12 min ago).',
    );
    expect(lookupSpan(1, before(120), before(120), NOW)).toBe(
      '1 blocked lookup stored, from 2 hr ago.',
    );
  });

  it('says plainly when nothing is stored', () => {
    expect(lookupSpan(0, null, null, NOW)).toBe('No blocked lookups are stored.');
  });
});

describe('what the map draws', () => {
  const node = (kind: string) => ({ kind }) as Resource;
  it('leaves sites and blocked addresses off, so its counts leave them out too', () => {
    expect(drawn(node('client'))).toBe(true);
    expect(drawn(node('domain'))).toBe(false);
    expect(drawn(node('site'))).toBe(false);
  });
});
