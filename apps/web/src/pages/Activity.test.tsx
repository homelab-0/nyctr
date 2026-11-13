import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import type { AuditEvent, Integration } from '../types';
import Activity from './Activity';

const event = (id: string, action: string, details: Record<string, unknown>): AuditEvent => ({
  id,
  created_at: '2026-11-13T10:00:00Z',
  actor_id: 'admin',
  action,
  target_id: `source-${id}`,
  details,
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('Activity rows about a source', () => {
  it('names the source and says what a collection stored, never a raw id', async () => {
    mockApi({
      'GET /audit': [
        event('a', 'integration.collected', {
          name: 'Home DNS',
          resources: 6,
          observations: 4000,
          partial: true,
          rows_kept: 4000,
        }),
        event('b', 'integration.created', { provider: 'example_dns', name: 'Old name' }),
        // Older records hold no name: the current one is used, else the source is said to be gone.
        event('c', 'integration.diagnosed', { outcome: 'verified' }),
        event('d', 'integration.collection_failed', {}),
      ],
      'GET /users': [{ id: 'admin', name: 'Alex' }],
      'GET /integrations': [{ id: 'source-c', name: 'Lab hypervisor' } as Integration],
    });
    render(<Activity />);
    const collected = (await screen.findByText('Collected from Home DNS')).closest('tr')!;
    expect(collected.textContent).toContain('6 items · 4,000 blocked lookups · most recent only');
    expect(screen.getByText('Added the source Old name')).toBeTruthy();
    expect(screen.getByText('Tested Lab hypervisor')).toBeTruthy();
    expect(screen.getByText('Could not collect from a source since removed')).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/source-[abcd]/);
  });
});
