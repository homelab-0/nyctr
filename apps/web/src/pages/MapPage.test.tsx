import { describe, expect, it } from 'vitest';
import { kindText } from './Inventory';
import { kindBasis } from './MapPage';
import type { Resource } from '../types';

const gear = (attributes: Record<string, unknown>): Resource => ({
  id: 'g',
  name: 'Gateway',
  kind: 'gateway',
  provider: 'demo',
  source_id: 'g',
  site_id: null,
  observed_at: '2026-11-13T00:00:00Z',
  evidence_kind: 'observed',
  classification: 'infrastructure',
  owner_id: null,
  attributes,
});

describe('why a device is filed as a gateway', () => {
  it('says nothing when the source named it', () => {
    expect(kindBasis(gear({}))).toBeUndefined();
  });

  it('says Nyctr worked it out, and from what, for each basis', () => {
    const address = kindBasis(gear({ kind_basis: 'gateway_address' }))!;
    const position = kindBasis(gear({ kind_basis: 'outside_network_ranges' }))!;
    expect(address).toMatch(/^Worked out by Nyctr: .*gateway address of a network/);
    expect(position).toMatch(/^Worked out by Nyctr: .*outside every network range/);
    expect(address).not.toBe(position);
    // A basis this console does not know is still never shown as the source's statement.
    expect(kindBasis(gear({ kind_basis: 'something_new' }))).toMatch(/^Worked out by Nyctr/);
  });

  it('marks a deduced gateway in the Inventory kind cell and leaves a named one alone', () => {
    expect(kindText(gear({}))).toBe('Gateway');
    expect(kindText(gear({ kind_basis: 'outside_network_ranges' }))).toBe(
      'Gateway, worked out by Nyctr',
    );
    expect(kindText(gear({ kind_basis: 'gateway_address' }))).toBe('Gateway, worked out by Nyctr');
  });
});
