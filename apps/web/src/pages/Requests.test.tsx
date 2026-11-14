import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { mockApi } from '../test/mock-api';
import type { AccessRequest } from '../types';
import Requests from './Requests';

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('approving a request the server refuses', () => {
  it('says why above the Approve button and leaves the request waiting', async () => {
    const detail =
      'Nyctr has not collected from Resolver yet, so it changes nothing there. Collect from it first, then try again.';
    const waiting = {
      id: 'request',
      block_id: 'block',
      domain: 'docs.example',
      device_name: 'Tablet',
      requester_id: 'member',
      reason: 'Needed for a report',
      duration_minutes: 60,
      status: 'pending',
      created_at: '2026-11-13T10:00:00Z',
      risk_score: 20,
      integration_id: 'resolver',
    } as AccessRequest;
    mockApi({
      'GET /requests': [waiting],
      'GET /users': [],
      'GET /rules': { __status: 500, detail: 'Unavailable' },
      'POST /requests/request/review': { __status: 409, detail },
    });
    render(<Requests params={new URLSearchParams()} onChange={() => {}} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect((await screen.findByRole('alert')).textContent).toBe(detail);
    expect(screen.getByRole('button', { name: 'Approve' })).toBeTruthy();
    expect(document.body.textContent).not.toContain('Request failed');
  });
});
