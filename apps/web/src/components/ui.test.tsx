import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { registerSources, SourceTag } from './ui';

// A one-pixel picture; the chip only needs something a browser would accept as an image.
const PNG = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==';
const SVG = `data:image/svg+xml;base64,${btoa('<svg xmlns="http://www.w3.org/2000/svg"/>')}`;
const kind = (id: string, logo?: string) => ({ id, name: `${id} source`, letter: 'A', tone: 'rose', logo });

afterEach(cleanup);

describe('SourceTag', () => {
  it('shows a declared logo as an image on a neutral tile, named once', () => {
    registerSources([kind('acme', PNG), kind('vector', SVG)]);
    const { container } = render(
      <>
        <SourceTag provider="acme" />
        <SourceTag provider="vector" named big />
      </>,
    );
    const [alone, beside] = Array.from(container.querySelectorAll('img'));
    expect(alone.getAttribute('src')).toBe(PNG);
    expect(alone.parentElement?.className.trim()).toBe('src logo');
    // On its own the picture carries the name; beside the written name it stays silent.
    expect(screen.getAllByRole('img', { name: 'acme source' })).toHaveLength(1);
    expect(beside.getAttribute('alt')).toBe('');
    expect(beside.parentElement?.className).toBe('src logo big');
    expect(screen.getAllByText('vector source')).toHaveLength(1);
    expect(container.querySelector('svg, script')).toBeNull();
  });

  it('keeps the letter on its colour without a logo, for unknown kinds and for Nyctr itself', () => {
    registerSources([kind('plain'), kind('empty', '')]);
    const { container } = render(
      <>
        <SourceTag provider="plain" />
        <SourceTag provider="empty" />
        <SourceTag provider="never_heard_of_it" />
        <SourceTag provider="nyctr" />
      </>,
    );
    expect(container.querySelector('img')).toBeNull();
    const chips = Array.from(container.querySelectorAll('.src'));
    expect(chips.map((chip) => chip.textContent)).toEqual(['A', 'A', 'N', 'N']);
    expect(chips.map((chip) => chip.className.trim())).toEqual([
      'src t-rose',
      'src t-rose',
      'src t-grey',
      'src t-nyctr',
    ]);
  });

  it('falls back to the letter when the logo does not load', () => {
    registerSources([kind('acme', PNG)]);
    const { container } = render(<SourceTag provider="acme" big />);
    fireEvent.error(container.querySelector('img')!);
    expect(container.querySelector('img')).toBeNull();
    const chip = container.querySelector('.src')!;
    expect(chip.textContent).toBe('A');
    expect(chip.className).toBe('src t-rose big');
  });

  it.each([
    'https://logos.example/acme.svg',
    '/api/logo.svg',
    'javascript:alert(1)',
    'data:text/html;base64,PHNjcmlwdD4=',
    'data:image/svg+xml,<svg onload="alert(1)"/>',
    `${PNG}" onerror="alert(1)`,
  ])('ignores a logo that is not an embedded image: %s', (logo) => {
    registerSources([kind('acme', logo)]);
    const { container } = render(<SourceTag provider="acme" />);
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('.src')?.textContent).toBe('A');
  });
});
