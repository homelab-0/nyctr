import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import { bigSite, link, thing } from '../test/map-site';
import { kindText } from './Inventory';
import MapPage, { kindBasis } from './MapPage';
import type { Graph, Resource } from '../types';

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

/** Nine devices on one network: the square draws five and a box holds four. */
const crowded: Graph = {
  nodes: [
    { ...thing('guest', 'network', 'Guest'), attributes: { vlan: 80 } },
    ...Array.from({ length: 9 }, (_, i) => thing(`d${i}`, 'client', `Device ${i}`)),
  ],
  edges: Array.from({ length: 9 }, (_, i) => link(`d${i}`, 'guest', 'member_of')),
};
const show = async (graph: Graph, focus = '') => {
  mockApi({ 'GET /graph': graph, 'GET /findings': [] });
  render(<MapPage params={new URLSearchParams(focus && `focus=${focus}`)} />);
  await screen.findByRole('group', { name: 'Network map' });
};
const panel = () => screen.queryByRole('complementary', { name: /^About / });

describe('what a full square on the Map could not draw', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    delete (Element.prototype as { scrollIntoView?: unknown }).scrollIntoView;
  });

  it('is a named control that opens from the keyboard and the mouse, and closes again', async () => {
    await show(crowded);
    const box = screen.getByRole('button', { name: '4 more devices on Guest' });
    expect(box.getAttribute('tabindex')).toBe('0');
    expect(box.getAttribute('aria-expanded')).toBe('false');
    fireEvent.keyDown(box, { key: 'Enter' });
    const list = screen.getByRole('complementary', { name: '4 more devices on Guest' });
    expect(box.getAttribute('aria-expanded')).toBe('true');
    expect(document.activeElement).toBe(list);
    expect(within(list).getByText(/gateways and networks first, then by name/)).toBeTruthy();
    expect(
      within(list)
        .getAllByRole('button', { name: /Device/ })
        .map((row) => row.textContent),
    ).toEqual([5, 6, 7, 8].map((n) => expect.stringContaining(`Device ${n}`)));
    fireEvent.keyDown(list, { key: 'Escape' });
    expect(screen.queryByRole('complementary')).toBeNull();
    expect(document.activeElement).toBe(box);
    fireEvent.keyDown(box, { key: ' ' });
    fireEvent.click(screen.getByRole('button', { name: 'Close the list' }));
    fireEvent.click(box);
    expect(screen.getByRole('complementary')).toBeTruthy();
    fireEvent.click(box);
    expect(screen.queryByRole('complementary')).toBeNull();
  });

  it('opens the same panel for a listed item as for a card, and forgets it when closed', async () => {
    await show(crowded);
    fireEvent.click(screen.getByRole('button', { name: /^Device 0, Device/ }));
    const card = panel()!.textContent!.replace('Device 0', '');
    fireEvent.click(screen.getByRole('button', { name: '4 more devices on Guest' }));
    const row = within(screen.getByRole('complementary', { name: /4 more/ })).getByRole('button', {
      name: /Device 7/,
    });
    fireEvent.click(row);
    expect(row.getAttribute('aria-pressed')).toBe('true');
    expect(panel()!.getAttribute('aria-label')).toBe('About Device 7');
    expect(panel()!.textContent!.replace('Device 7', '')).toBe(card);
    // Closing the list that shows the selection clears it, so nothing is selected unseen.
    fireEvent.click(screen.getByRole('button', { name: 'Close the list' }));
    expect(panel()).toBeNull();
    expect(document.querySelector('.map .dim')).toBeNull();
  });

  it('opens the box, selects the item and shows its panel when arriving at one not drawn', async () => {
    // A current browser answers a scroll with a promise; the test browser has no scroll at all.
    const scroll = vi.fn(() => Promise.resolve());
    Object.assign(Element.prototype, { scrollIntoView: scroll });
    const complaint = vi.spyOn(console, 'error');
    await show(crowded, 'd8');
    const list = await screen.findByRole('complementary', { name: '4 more devices on Guest' });
    const row = within(list).getByRole('button', { name: /Device 8/ });
    expect(row.getAttribute('aria-pressed')).toBe('true');
    expect(panel()!.getAttribute('aria-label')).toBe('About Device 8');
    const box = screen.getByRole('button', { name: '4 more devices on Guest' });
    // The box that holds it is marked and stays lit; unrelated cards step back.
    expect(box.getAttribute('class')).toContain('sel');
    expect(box.getAttribute('class')).not.toContain('dim');
    expect(
      screen.getByRole('button', { name: /^Device 0, Device/ }).getAttribute('class'),
    ).toContain('dim');
    // The row and the panel are both brought into sight, and moving on leaves nothing broken.
    expect(scroll.mock.contexts).toEqual(expect.arrayContaining([row, panel()]));
    fireEvent.click(within(list).getByRole('button', { name: /Device 5/ }));
    expect(panel()!.getAttribute('aria-label')).toBe('About Device 5');
    expect(complaint).not.toHaveBeenCalled();
  });

  it('reaches every one of 280 items on a site of real size, and opens them', async () => {
    const site = bigSite();
    const started = performance.now();
    await show(site);
    const drew = performance.now() - started;
    const all = (query: string) => [...document.querySelectorAll<HTMLElement>(query)];
    const pick = (control: HTMLElement, name: string) => {
      fireEvent.click(control);
      expect(document.querySelector('.inspector h2')!.textContent).toBe(name);
    };
    const cards = all('.map [role=button][aria-pressed]');
    const reached = cards.map((card) => card.getAttribute('aria-label')!.split(', ')[0]);
    pick(cards[0], reached[0]);
    pick(cards.at(-1)!, reached.at(-1)!);
    const boxes = all('.map [role=button][aria-expanded]');
    let slowest = 0;
    for (const box of boxes) {
      const opening = performance.now();
      fireEvent.click(box);
      slowest = Math.max(slowest, performance.now() - opening);
      const rows = all('.map-list button.row');
      expect(rows).toHaveLength(parseInt(box.getAttribute('aria-label')!, 10));
      const names = rows.map((row) => row.querySelector('.t')!.textContent!);
      reached.push(...names);
      // Every row is the same control; the first and last of each list are opened.
      pick(rows[0], names[0]);
      pick(rows.at(-1)!, names.at(-1)!);
    }
    // Each item is on the Map once: as a card or in one list, never both and never neither.
    expect(reached.sort()).toEqual(site.nodes.map((item) => item.name).sort());
    expect(cards.length + boxes.length).toBeLessThan(110);
    // Measured under the test's simulated browser, which is slower than a real one.
    expect(drew).toBeLessThan(2000);
    expect(slowest).toBeLessThan(1000);
  });
});
