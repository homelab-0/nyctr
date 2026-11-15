import { ago } from './format';

/** The kinds a person recognises, as Inventory groups them. The Briefing counts the same groups. */
export const GROUPS = {
  all: { name: 'Everything', kinds: null },
  devices: { name: 'Devices', kinds: ['client'] },
  gear: { name: 'Network equipment', kinds: ['gateway', 'switch', 'access_point'] },
  networks: { name: 'Networks', kinds: ['network'] },
  compute: { name: 'Hosts, bridges and workloads', kinds: ['host', 'bridge', 'workload'] },
  rules: { name: 'Rules', kinds: ['policy', 'dns_profile'] },
} as const;
export type Group = keyof typeof GROUPS;

/** Kinds Inventory does not list: the site is the whole picture, and blocked addresses have their own count. */
export const UNLISTED = new Set(['site', 'domain']);

/** "4,000" rather than "4000", so a large number reads at a glance. */
export const number = (value: number) => value.toLocaleString('en-US');

/** A count with its noun, in the right form. */
export const counted = (value: number, one: string, many = `${one}s`) =>
  `${number(value)} ${value === 1 ? one : many}`;

/** Whether an item's source left it out of its latest read. It stays listed, marked, until it is dropped. */
export const isMissing = (row: { attributes: Record<string, unknown> }) =>
  Boolean(row.attributes.missing_from_latest_snapshot);

/** The mark on a missing item, with how long ago a collection first missed it when that is on record. */
export const missingFor = (row: { attributes: Record<string, unknown> }, now = Date.now()) =>
  typeof row.attributes.missing_since === 'string'
    ? `Missing, first missed ${ago(row.attributes.missing_since, now)}`
    : 'Missing from last collection';

/** How many stored items were not in the latest collection, said wherever the present ones are counted. */
export const notSeen = (missing: number) =>
  missing ? `${number(missing)} not seen at the last collection` : '';

const NOUNS: [Exclude<Group, 'all'> | 'blocked', string, string][] = [
  ['devices', 'device', 'devices'],
  ['gear', 'piece of network equipment', 'pieces of network equipment'],
  ['networks', 'network', 'networks'],
  ['compute', 'host, bridge or workload', 'hosts, bridges and workloads'],
  ['rules', 'rule', 'rules'],
  ['blocked', 'blocked address', 'blocked addresses'],
];

/** Each recognisable kind with its own count, never one mixed total. Empty kinds are left out. */
export function namedCounts(kinds: Record<string, number>) {
  const total = (list: readonly string[]) =>
    list.reduce((sum, kind) => sum + (kinds[kind] || 0), 0);
  const parts = NOUNS.map(([group, one, many]) => {
    const value = group === 'blocked' ? kinds.domain || 0 : total(GROUPS[group].kinds);
    return value ? counted(value, one, many) : '';
  }).filter(Boolean);
  if (parts.length < 2) return parts.join('');
  return `${parts.slice(0, -1).join(', ')} and ${parts.at(-1)}`;
}

/**
 * How many blocked lookups are stored and the span they actually cover, from the oldest and
 * newest one kept. Never a fixed window: a busy source's stored lookups may cover far less.
 */
export function lookupSpan(
  count: number,
  oldest: string | null | undefined,
  newest: string | null | undefined,
  now = Date.now(),
) {
  if (!count) return 'No blocked lookups are stored.';
  const stored = `${counted(count, 'blocked lookup')} stored`;
  if (!oldest || !newest) return `${stored}.`;
  const from = ago(oldest, now);
  const to = ago(newest, now);
  return from === to
    ? `${stored}, from ${from}.`
    : `${stored}, going back to ${from} (newest ${to}).`;
}
