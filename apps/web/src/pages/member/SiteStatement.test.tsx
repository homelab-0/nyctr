import { Suspense, StrictMode, startTransition, useCallback, useRef, useState } from 'react';
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../../api';
import { mockApi } from '../../test/mock-api';
import type { AccessRequest } from '../../types';
import { SiteStatement } from './SiteStatement';
import { useStatementRequests, type StatementModelInput } from './useStatementRequests';

function request(extra: Partial<AccessRequest> = {}): AccessRequest {
  return {
    id: 'r-ask',
    block_id: 'b1',
    domain: 'ads.example',
    device_name: "Sam's laptop",
    requester_id: 'sam',
    reason: 'The page did not open.',
    duration_minutes: 60,
    status: 'analysing',
    created_at: '2026-01-01T00:00:00Z',
    review_note: null,
    risk_score: null,
    risk_category: null,
    risk_factors: null,
    decided_by: null,
    decision_note: null,
    ...extra,
  };
}

function filed(extra: Partial<AccessRequest> = {}) {
  return { matched: true, message: 'Filed', request: request(extra) };
}

function gate<T>() {
  let resolve: (value: T) => void = () => {};
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function statements(queue: Promise<unknown>[]) {
  return mockApi({
    'POST /statements': () => {
      const next = queue.shift();
      if (!next) throw new Error('no queued statement response');
      return next;
    },
  });
}

function csrf(at = 0) {
  const init = vi.mocked(fetch).mock.calls[at]?.[1];
  return new Headers(init?.headers).get('X-CSRF-Token');
}

function props(extra: Partial<StatementModelInput> = {}): StatementModelInput {
  return {
    userId: 'sam',
    deviceId: 'laptop',
    view: 'home',
    openRequestId: null,
    blockId: null,
    requests: { availability: 'loaded', rows: [] },
    reloadEvidence: async () => {},
    ...extra,
  };
}

const snaps: { mounted: number; site: string }[] = [];
let edits = 0;
let closes = 0;
const never = new Promise<void>(() => {});

function Bomb(): never {
  throw never;
}

function Harness({
  open = true,
  bomb = false,
  userId = 'sam',
  deviceId = 'laptop',
}: {
  open?: boolean;
  bomb?: boolean;
  userId?: string;
  deviceId?: string;
}) {
  const model = useStatementRequests(props({ userId, deviceId }));
  const latest = useRef(model);
  latest.current = model;
  const openForm = useCallback(() => {
    const current = latest.current;
    snaps.push({ mounted: current.visits.current.mounted, site: current.draft.current.site });
    return current.openForm();
  }, []);
  const editDraft = useCallback((value: string) => {
    edits += 1;
    return latest.current.editDraft(value);
  }, []);
  const closeForm = useCallback((formId: number) => {
    closes += 1;
    latest.current.closeForm(formId);
  }, []);
  if (!open) return null;
  return (
    <>
      <SiteStatement
        userId={userId}
        deviceId={deviceId}
        ask={model.ask}
        notice={model.notice}
        draft={model.draft}
        openForm={openForm}
        closeForm={closeForm}
        editDraft={editDraft}
        onFile={model.file}
      />
      {bomb ? <Bomb /> : null}
    </>
  );
}

const field = () => screen.getByLabelText('Site that did not open') as HTMLInputElement;

function type(value: string) {
  const input = field();
  fireEvent.change(input, { target: { value } });
  return input;
}

function submit(input: HTMLInputElement = field()) {
  fireEvent.submit(input.closest('form')!);
}

beforeEach(() => {
  snaps.length = 0;
  edits = 0;
  closes = 0;
  window.location.hash = '/portal';
  setCsrfToken('member-csrf');
});

afterEach(() => {
  cleanup();
  setCsrfToken('');
  window.location.hash = '';
  vi.unstubAllGlobals();
});

describe('the site a member types', () => {
  it('keeps a blank name and does not send it', () => {
    const calls = statements([]);
    render(<Harness />);
    expect(screen.getByText('Site name')).toBeDefined();
    expect(screen.getByRole('heading', { name: 'A site did not open' })).toBeDefined();
    const input = type('   ');
    const button = screen.getByRole('button', { name: 'Ask about this site' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(input.disabled).toBe(false);
    submit(input);
    expect(calls).toHaveLength(0);
    expect(input.value).toBe('   ');
    expect(snaps.length).toBeGreaterThan(0);
    expect(snaps[0]).toEqual({ mounted: 0, site: '' });
  });

  it('shows the refusal and the miss without clearing the name', async () => {
    const calls = statements([
      Promise.resolve({ __status: 403, detail: 'Nyctr does not recognise this device as yours.' }),
    ]);
    render(<Harness />);
    const input = type('blocked.example');
    submit(input);
    expect((await screen.findByRole('alert')).textContent).toContain(
      'Nyctr does not recognise this device as yours.',
    );
    expect(input.value).toBe('blocked.example');
    expect(input.disabled).toBe(false);
    expect(calls.map((call) => call.body)).toEqual([{ domain: 'blocked.example' }]);
    expect(calls[0]).toMatchObject({ method: 'POST', path: '/statements' });
    expect(csrf()).toBe('member-csrf');
    expect(window.location.hash).toBe('#/portal');

    cleanup();
    window.location.hash = '/portal';
    statements([
      Promise.resolve({
        matched: false,
        message: 'Nyctr saw no recent block of that name.',
      }),
    ]);
    render(<Harness />);
    const again = type('missing.example');
    submit(again);
    expect(await screen.findByText(/saw no recent block/)).toBeDefined();
    expect(again.value).toBe('missing.example');
    expect(screen.getByRole('heading', { name: 'A site did not open' })).toBeDefined();
    expect(window.location.hash).toBe('#/portal');
  });

  it('does not send one unchanged draft twice, and an edit leaves the new name free', async () => {
    const first = gate<unknown>();
    const calls = statements([first.promise, new Promise(() => {})]);
    render(<Harness />);
    const input = type('old.example');
    submit(input);
    submit(input);
    expect(calls).toHaveLength(1);
    expect(input.disabled).toBe(false);
    expect(screen.getByRole('button', { name: 'Asking…' })).toBeDefined();
    type('new.example');
    expect(screen.queryByRole('button', { name: 'Asking…' })).toBeNull();
    expect(
      (screen.getByRole('button', { name: 'Ask about this site' }) as HTMLButtonElement).disabled,
    ).toBe(false);
    submit(input);
    expect(calls).toHaveLength(2);
    expect(calls.map((call) => call.body)).toEqual([
      { domain: 'old.example' },
      { domain: 'new.example' },
    ]);
    await act(async () => {
      first.resolve({ matched: false, message: 'Nyctr saw no recent block of old.example.' });
    });
    expect(input.value).toBe('new.example');
    expect(screen.queryByText(/old\.example/)).toBeNull();
    expect(screen.getByRole('button', { name: 'Asking…' })).toBeDefined();
    expect(window.location.hash).toBe('#/portal');
  });

  it('files the name the member left in the box and opens that request', async () => {
    const pending = gate<unknown>();
    const calls = statements([pending.promise]);
    render(<Harness />);
    const input = type('ads.example');
    submit(input);
    submit(input);
    expect(calls).toHaveLength(1);
    expect(csrf()).toBe('member-csrf');
    await act(async () => {
      pending.resolve(filed());
    });
    await waitFor(() => expect(window.location.hash).toBe('#/portal?request=r-ask'));
    expect(input.value).toBe('ads.example');
    expect(calls.some((call) => call.path.includes('/me/device'))).toBe(false);
  });

  it('keeps a replaced draft as its own request and does not follow it', async () => {
    const pending = gate<unknown>();
    const calls = statements([pending.promise]);
    render(<Harness />);
    const input = type('HTTPS://Ads.Example/path');
    submit(input);
    type('new.example');
    await act(async () => {
      pending.resolve(filed({ domain: 'ads.example' }));
    });
    expect(input.value).toBe('new.example');
    expect(calls.map((call) => call.body)).toEqual([{ domain: 'HTTPS://Ads.Example/path' }]);
    expect(window.location.hash).toBe('#/portal');
    const note = screen.getByRole('status');
    expect(note.textContent).toContain('ads.example');
    expect(note.textContent).not.toContain('new.example');
    expect(screen.getByRole('link', { name: 'Open that request' }).getAttribute('href')).toBe(
      '#/portal?request=r-ask',
    );
  });

  it('opens a fresh draft after the form was left, and ignores the old miss and the old success', async () => {
    const missed = gate<unknown>();
    statements([missed.promise, new Promise(() => {})]);
    const first = render(<Harness />);
    type('old.example');
    submit();
    const opened = snaps.length;
    first.rerender(<Harness open={false} />);
    expect(closes).toBeGreaterThan(0);
    first.rerender(<Harness />);
    expect(snaps.length).toBeGreaterThan(opened);
    const input = type('new.example');
    expect(screen.queryByRole('button', { name: 'Asking…' })).toBeNull();
    submit(input);
    await act(async () => {
      missed.resolve({ matched: false, message: 'Nyctr saw no recent block of old.example.' });
    });
    expect(input.value).toBe('new.example');
    expect(screen.queryByText(/old\.example/)).toBeNull();
    expect(screen.getByRole('button', { name: 'Asking…' })).toBeDefined();
    expect(window.location.hash).toBe('#/portal');

    cleanup();
    window.location.hash = '/portal';
    const filedAnswer = gate<unknown>();
    statements([filedAnswer.promise]);
    const second = render(<Harness />);
    type('old.example');
    submit();
    second.rerender(<Harness open={false} />);
    second.rerender(<Harness />);
    const returned = type('new.example');
    expect(screen.queryByRole('button', { name: 'Asking…' })).toBeNull();
    await act(async () => {
      filedAnswer.resolve(filed());
    });
    expect(returned.value).toBe('new.example');
    expect(window.location.hash).toBe('#/portal');
    expect(screen.getByRole('status').textContent).toContain('ads.example');
    expect(screen.queryByRole('button', { name: 'Asking…' })).toBeNull();
  });

  it('keeps the typed name when the same member changes device', () => {
    const calls = statements([new Promise(() => {})]);
    const view = render(<Harness />);
    type('keep.example');
    view.rerender(<Harness deviceId="phone" />);
    const kept = field();
    expect(kept.value).toBe('keep.example');
    submit(kept);
    expect(calls.map((call) => call.body)).toEqual([{ domain: 'keep.example' }]);
    expect(screen.getByRole('button', { name: 'Asking…' })).toBeDefined();
  });

  it('a discarded sign-in render leaves the typed name and the open visit', async () => {
    const pending = gate<unknown>();
    const calls = statements([pending.promise]);
    let change: (user: string) => void = () => {};
    function Parent() {
      const [user, setUser] = useState('sam');
      change = setUser;
      return (
        <Suspense fallback={<p>Loading</p>}>
          <Harness userId={user} bomb={user === 'kim'} />
        </Suspense>
      );
    }
    render(<Parent />);
    const input = type('ads.example');
    submit(input);
    expect(calls).toHaveLength(1);
    const seenSnaps = snaps.length;
    const seenEdits = edits;
    const seenCloses = closes;
    await act(async () => {
      startTransition(() => change('kim'));
    });
    expect(screen.getByLabelText('Site that did not open')).toBe(input);
    expect(input.value).toBe('ads.example');
    expect(snaps).toHaveLength(seenSnaps);
    expect(edits).toBe(seenEdits);
    expect(closes).toBe(seenCloses);
    expect(calls).toHaveLength(1);
    expect(screen.getByRole('button', { name: 'Asking…' })).toBeDefined();
    await act(async () => {
      pending.resolve(filed());
    });
    await waitFor(() => expect(window.location.hash).toBe('#/portal?request=r-ask'));
    expect(input.value).toBe('ads.example');
  });

  it('a committed member change opens a fresh visit after the previous draft is cleared', async () => {
    const pending = gate<unknown>();
    const calls = statements([pending.promise, new Promise(() => {})]);
    const view = render(<Harness />);
    const input = type('ads.example');
    submit(input);
    expect(calls).toHaveLength(1);
    const before = snaps.length;
    view.rerender(<Harness userId="kim" deviceId="phone" />);
    const opened = snaps.slice(before);
    expect(opened.length).toBeGreaterThan(0);
    expect(opened.every((snap) => snap.mounted === 0 && snap.site === '')).toBe(true);
    expect(field().value).toBe('');
    expect(screen.queryByRole('button', { name: 'Asking…' })).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
    const renamed = type('kim.example');
    submit(renamed);
    expect(calls.map((call) => call.body)).toEqual([
      { domain: 'ads.example' },
      { domain: 'kim.example' },
    ]);
    await act(async () => {
      pending.resolve(filed());
    });
    expect(renamed.value).toBe('kim.example');
    expect(window.location.hash).toBe('#/portal');
    expect(screen.queryByText('ads.example')).toBeNull();
    expect(screen.getByRole('button', { name: 'Asking…' })).toBeDefined();
  });

  it('still files after the development double mount closes the first visit', () => {
    const calls = statements([new Promise(() => {})]);
    render(
      <StrictMode>
        <Harness />
      </StrictMode>,
    );
    const input = type('once.example');
    submit(input);
    expect(calls.map((call) => call.body)).toEqual([{ domain: 'once.example' }]);
    expect(input.value).toBe('once.example');
    expect(snaps.length).toBeGreaterThan(1);
    expect(closes).toBeGreaterThan(0);
  });
});
