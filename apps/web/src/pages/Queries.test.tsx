import { describe, expect, it } from 'vitest';
import { SAVED } from './Queries';

describe('saved queries', () => {
  it('shows the evidence and basis of each link on a network, so a placed device reads as worked out', () => {
    const saved = SAVED.find((item) => item.name === 'Every network and what is on it')!;
    expect(saved.text).toMatch(/links\(first: 100\)\s*{\s*kind\s+evidence\s+basis/);
    expect(saved.text).not.toContain('neighbors');
  });
});
