import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import { bigSite, link, thing } from '../test/map-site';
import * as ui from '../components/ui';
import { kindText } from './Inventory';
import MapPage, { kindBasis } from './MapPage';
import type { Graph, Resource, Rules } from '../types';

// Every card asks for its icon once each time it is drawn, so these calls count the cards drawn.
vi.mock('../components/ui', async (original) => {
  const real = await original<typeof import('../components/ui')>();
  return { ...real, kindIcon: vi.fn(real.kindIcon) };
});

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
    { ...thing('guest', 'network', 'Guest'), attributes: { vlan: 40 } },
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

  it('brings an opened list into sight, and clears a selection left in another box', async () => {
    const scroll = vi.fn(() => Promise.resolve());
    Object.assign(Element.prototype, { scrollIntoView: scroll });
    await show(bigSite());
    fireEvent.click(screen.getByRole('button', { name: '28 more devices on Network 0' }));
    const list = screen.getByRole('complementary', { name: /28 more devices/ });
    // Nothing is selected, so the list itself is what is scrolled to.
    expect(scroll.mock.contexts).toEqual([list]);
    fireEvent.click(within(list).getByRole('button', { name: /Device 29/ }));
    expect(panel()!.getAttribute('aria-label')).toBe('About Device 29');
    // Opening another box would shut the list showing Device 29, so it stops being selected.
    fireEvent.click(screen.getByRole('button', { name: /more rules not tied to one network/ }));
    expect(screen.getByRole('complementary', { name: /more rules/ })).toBeTruthy();
    expect(panel()).toBeNull();
    expect(document.querySelector('.map .sel')).toBeNull();
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
    await show(site);
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
    // Work is counted, not timed: a clock measures how busy the machine is. Opening a list
    // draws no card again, and picking an item draws each card once at most (those that dim).
    const drawn = vi.mocked(ui.kindIcon);
    const draws = (act: () => void) => {
      drawn.mockClear();
      act();
      return drawn.mock.calls.length;
    };
    for (const box of boxes) {
      expect(draws(() => fireEvent.click(box))).toBe(0);
      const rows = all('.map-list button.row');
      expect(rows).toHaveLength(parseInt(box.getAttribute('aria-label')!, 10));
      const names = rows.map((row) => row.querySelector('.t')!.textContent!);
      reached.push(...names);
      // Every row is the same control; the first and last of each list are opened.
      expect(draws(() => pick(rows[0], names[0]))).toBeLessThanOrEqual(cards.length);
      expect(draws(() => pick(rows.at(-1)!, names.at(-1)!))).toBeLessThanOrEqual(cards.length);
      // Closing the list clears the pick, so the next box opens with nothing selected.
      fireEvent.click(box);
    }
    // Each item is on the Map once: as a card or in one list, never both and never neither.
    expect(reached.sort()).toEqual(site.nodes.map((item) => item.name).sort());
    expect(cards.length + boxes.length).toBeLessThan(110);
    expect(boxes.length).toBeGreaterThan(2);
  });

  it('says which source each of two things with one name is from, and cuts a name in the middle', async () => {
    const of = (id: string, kind: string, name: string, integration_id: string) => ({
      ...thing(id, kind, name),
      integration_id,
    });
    const site: Graph = {
      nodes: [
        ...['one', 'two'].flatMap((source) => [
          of(`lan-${source}`, 'network', 'Office LAN', source),
          of(`gw-${source}`, 'gateway', 'Main gateway', source),
        ]),
        of('ap1', 'access_point', 'Example access point 1', 'one'),
        of('ap8', 'access_point', 'Example access point 8', 'one'),
      ],
      edges: [],
    };
    mockApi({ 'GET /graph': site, 'GET /findings': [] });
    const sources = [
      { id: 'one', name: 'First site' },
      { id: 'two', name: 'Second site' },
    ] as Rules['sources'];
    render(<MapPage params={new URLSearchParams()} sources={sources} />);
    await screen.findByRole('group', { name: 'Network map' });
    const text = (query: string) =>
      [...document.querySelectorAll(query)].map((item) => item.textContent);
    for (const name of ['First site', 'Second site']) {
      expect(
        screen.getByRole('button', { name: `Main gateway, Gateway, from ${name}` }),
      ).toBeTruthy();
      expect(text('.node .sub')).toContain(name);
      expect(text('.node title')).toContain(`Main gateway, from ${name}`);
      expect(text('.lane-sub')).toContain(`No VLAN number · ${name}`);
    }
    // A name only one source uses is left as it was, and a cut name keeps the end that differs.
    const point = screen.getByRole('button', {
      name: 'Example access point 8, Access point, from Example',
    });
    expect(point.querySelector('.sub')!.textContent).toBe('Access point');
    expect(point.querySelector('.name')!.textContent).toBe('Example ac…s point 8');
    expect(point.querySelector('title')!.textContent).toBe('Example access point 8');
    expect(text('.node .name')).toContain('Example ac…s point 1');
  });

  it('keeps the part of a long source name that differs on a column with no VLAN number', async () => {
    const site: Graph = {
      nodes: ['south', 'north'].map((source) => ({
        ...thing(`lan-${source}`, 'network', 'Office LAN'),
        integration_id: source,
      })),
      edges: [],
    };
    mockApi({ 'GET /graph': site, 'GET /findings': [] });
    const sources = [
      { id: 'south', name: 'South office gateway' },
      { id: 'north', name: 'North office gateway' },
    ] as Rules['sources'];
    render(<MapPage params={new URLSearchParams()} sources={sources} />);
    await screen.findByRole('group', { name: 'Network map' });
    const lines = [...document.querySelectorAll('.lane-sub')].map((item) => item.textContent);
    expect(lines).toContain('No VLAN number · South…teway');
    expect(lines).toContain('No VLAN number · North…teway');
  });

  it('draws a card again when its source is named after the Map was drawn', async () => {
    const site: Graph = { nodes: [thing('late', 'client', 'Late', 'arrives_later')], edges: [] };
    mockApi({ 'GET /graph': site, 'GET /findings': [] });
    const page = <MapPage params={new URLSearchParams()} />;
    const { rerender } = render(page);
    const card = await screen.findByRole('button', { name: 'Late, Device, from Arrives Later' });
    expect(card.getAttribute('class')).toContain('t-grey');
    ui.registerSources([{ id: 'arrives_later', name: 'Later source', letter: 'L', tone: 'teal' }]);
    rerender(<MapPage params={new URLSearchParams()} />);
    const named = screen.getByRole('button', { name: 'Late, Device, from Later source' });
    expect(named.getAttribute('class')).toContain('t-teal');
  });

  it('draws a row of an open list again when its source is named after the list was opened', async () => {
    const site: Graph = {
      nodes: [
        thing('net', 'network', 'Net'),
        ...Array.from({ length: 9 }, (_, i) => thing(`r${i}`, 'client', `Item ${i}`, 'row_later')),
      ],
      edges: Array.from({ length: 9 }, (_, i) => link(`r${i}`, 'net', 'member_of')),
    };
    mockApi({ 'GET /graph': site, 'GET /findings': [] });
    const { rerender } = render(<MapPage params={new URLSearchParams()} />);
    fireEvent.click(await screen.findByRole('button', { name: '4 more devices on Net' }));
    const chips = () =>
      within(screen.getByRole('complementary'))
        .getAllByRole('button', { name: /Item/ })
        .map((row) => row.querySelector('.src')!);
    expect(chips()).toHaveLength(4);
    expect(chips().map((chip) => chip.getAttribute('title'))).toEqual(Array(4).fill('Row Later'));
    ui.registerSources([{ id: 'row_later', name: 'Later rows', letter: 'R', tone: 'teal' }]);
    rerender(<MapPage params={new URLSearchParams()} />);
    for (const chip of chips()) {
      expect(chip.getAttribute('title')).toBe('Later rows');
      expect(chip.getAttribute('class')).toContain('t-teal');
      expect(chip.textContent).toBe('R');
    }
  });
});
