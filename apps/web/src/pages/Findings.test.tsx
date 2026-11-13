import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import { scheduleFixture, scheduleOff } from '../test/schedule';
import Findings from './Findings';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('findings re-check wording', () => {
  it('names the interval while the schedule is on', async () => {
    mockApi({ 'GET /findings': [], 'GET /resources': [], 'GET /collection': scheduleFixture() });
    render(<Findings params={new URLSearchParams()} />);
    expect(
      await screen.findByText('Findings are re-checked after every collection, every 15 minutes.'),
    ).toBeDefined();
  });

  it('promises no regular re-check while the schedule is off', async () => {
    mockApi({ 'GET /findings': [], 'GET /resources': [], 'GET /collection': scheduleOff() });
    render(<Findings params={new URLSearchParams()} />);
    expect(
      await screen.findByText('Findings are re-checked when a source is collected.'),
    ).toBeDefined();
    expect(screen.queryByText(/every collection/)).toBeNull();
  });
});
