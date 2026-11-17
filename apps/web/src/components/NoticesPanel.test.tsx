import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../api';
import { mockApi } from '../test/mock-api';
import { NoticesPanel } from './NoticesPanel';

const empty = {
  target: '',
  secret_ref: '',
  unsigned: true,
  signing: 'Notices are sent without a signature. Name a secret to sign them.',
  problem: null,
  editable: true,
  hosts: [],
  recent: [],
};

beforeEach(() => setCsrfToken('csrf'));
afterEach(() => {
  cleanup();
  setCsrfToken('');
  vi.unstubAllGlobals();
});

describe('the Notices card in Setup', () => {
  it('says a notice is unsigned until a secret is named, and saves the address', async () => {
    let current = empty;
    const calls = mockApi({
      'GET /notices': () => current,
      'PUT /notices': (body: unknown) => {
        current = {
          ...empty,
          ...(body as { target: string; secret_ref: string }),
          unsigned: !(body as { secret_ref: string }).secret_ref,
          signing: 'Notices are signed with the secret named here. The secret stays on the server.',
        };
        return current;
      },
      'POST /notices/test': () => ({
        ...current,
        recent: [{ id: 'n1', kind: 'test', state: 'sent', words: 'Sent.' }],
      }),
    });
    const user = userEvent.setup();
    render(<NoticesPanel />);
    expect(await screen.findByText(/Notices are sent without a signature/)).toBeDefined();
    expect(screen.getByText(/Only a public HTTPS address/)).toBeDefined();
    expect((screen.getByRole('button', { name: 'Test' }) as HTMLButtonElement).disabled).toBe(true);
    await user.type(await screen.findByLabelText(/^Address/), 'https://hooks.example/nyctr');
    await user.type(screen.getByLabelText(/^Name of the secret/), 'NYCTR_NOTICE_SECRET_MAIN');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText('Saved.')).toBeDefined();
    expect(calls.filter((call) => call.method === 'PUT').map((call) => call.body)).toEqual([
      { target: 'https://hooks.example/nyctr', secret_ref: 'NYCTR_NOTICE_SECRET_MAIN' },
    ]);
    await user.click(screen.getByRole('button', { name: 'Test' }));
    expect(await screen.findAllByText('Sent.')).not.toHaveLength(0);
    expect(calls.some((call) => call.method === 'POST' && call.path === '/notices/test')).toBe(
      true,
    );
  });

  it('shows a failed test as an alert, and names the kind and time of a send', async () => {
    const current = {
      ...empty,
      target: 'https://hooks.example',
      recent: [],
    };
    mockApi({
      'GET /notices': () => current,
      'POST /notices/test': () => ({
        ...current,
        recent: [
          {
            id: 'n1',
            kind: 'test',
            state: 'gave_up',
            at: '2026-11-16T12:00:00Z',
            words: 'The server refused the notice, so Nyctr will not try again.',
          },
        ],
      }),
    });
    const user = userEvent.setup();
    render(<NoticesPanel />);
    const test = await screen.findByRole('button', { name: 'Test' });
    await waitFor(() => expect((test as HTMLButtonElement).disabled).toBe(false));
    await user.click(test);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('refused the notice');
    expect(screen.queryByRole('status')).toBeNull();
    const item = screen.getByRole('listitem');
    expect(item.textContent).toContain('Test');
    expect(item.querySelector('time')?.getAttribute('dateTime')).toBe('2026-11-16T12:00:00Z');
    expect(screen.getByText('The last few sends')).toBeDefined();
  });

  it('keeps an address typed while a test is still sending', async () => {
    let release: (value: unknown) => void = () => {};
    const pending = new Promise((resolve) => {
      release = resolve;
    });
    const current = { ...empty, target: 'https://hooks.example' };
    mockApi({
      'GET /notices': () => current,
      'POST /notices/test': () => pending,
    });
    const user = userEvent.setup();
    render(<NoticesPanel />);
    const address = await screen.findByLabelText(/^Address/);
    await waitFor(() => expect((address as HTMLInputElement).value).toBe('https://hooks.example'));
    const test = screen.getByRole('button', { name: 'Test' });
    await waitFor(() => expect((test as HTMLButtonElement).disabled).toBe(false));
    await user.click(test);
    await user.type(address, '/more');
    await user.type(screen.getByLabelText(/^Name of the secret/), 'NYCTR_NOTICE_SECRET_LATER');
    release({
      ...current,
      recent: [{ id: 'n1', kind: 'test', state: 'sent', words: 'Sent.' }],
    });
    expect(await screen.findByRole('status')).toBeDefined();
    expect((screen.getByLabelText(/^Address/) as HTMLInputElement).value).toBe(
      'https://hooks.example/more',
    );
    expect((screen.getByLabelText(/^Name of the secret/) as HTMLInputElement).value).toBe(
      'NYCTR_NOTICE_SECRET_LATER',
    );
  });

  it('reads the test when a newer send of another kind is first', async () => {
    const current = { ...empty, target: 'https://hooks.example' };
    mockApi({
      'GET /notices': () => current,
      'POST /notices/test': () => ({
        ...current,
        recent: [
          {
            id: 'stuck',
            kind: 'lease_stuck',
            state: 'sent',
            at: '2026-11-16T12:05:00Z',
            words: 'Sent.',
          },
          {
            id: 'n1',
            kind: 'test',
            state: 'gave_up',
            at: '2026-11-16T12:00:00Z',
            words: 'The server refused the notice, so Nyctr will not try again.',
          },
        ],
      }),
    });
    const user = userEvent.setup();
    render(<NoticesPanel />);
    const test = await screen.findByRole('button', { name: 'Test' });
    await waitFor(() => expect((test as HTMLButtonElement).disabled).toBe(false));
    await user.click(test);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('refused the notice');
    expect(screen.queryByRole('status')).toBeNull();
  });

  it('says when the test is missing from the last few sends', async () => {
    const current = { ...empty, target: 'https://hooks.example' };
    mockApi({
      'GET /notices': () => current,
      'POST /notices/test': () => ({
        ...current,
        recent: [
          {
            id: 'stuck',
            kind: 'lease_stuck',
            state: 'sent',
            words: 'Sent.',
          },
        ],
      }),
    });
    const user = userEvent.setup();
    render(<NoticesPanel />);
    const test = await screen.findByRole('button', { name: 'Test' });
    await waitFor(() => expect((test as HTMLButtonElement).disabled).toBe(false));
    await user.click(test);
    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('The test is not among the last few sends.');
  });
});
