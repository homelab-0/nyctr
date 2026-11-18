import { Suspense, startTransition, useState } from 'react';
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../../api';
import { mockApi } from '../../test/mock-api';
import type { AccessRequest } from '../../types';
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

const model = { current: null as ReturnType<typeof useStatementRequests> | null };

function Host(props: StatementModelInput) {
  model.current = useStatementRequests(props);
  return null;
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

const use = () => {
  if (!model.current) throw new Error('the form controller is not mounted');
  return model.current;
};

function begin(site: string) {
  const formId = use().openForm();
  use().editDraft(site);
  return formId;
}

function send(site?: string) {
  if (site !== undefined) use().editDraft(site);
  const draft = use().draft.current;
  use().file(draft.site, draft.revision, draft.formId);
}

beforeEach(() => {
  window.location.hash = '/portal';
  setCsrfToken('member-csrf');
  model.current = null;
});

afterEach(() => {
  cleanup();
  setCsrfToken('');
  window.location.hash = '';
  vi.unstubAllGlobals();
});

describe('filing a typed site', () => {
  it('does not ask for a blank name, or when the account or device is missing', () => {
    const calls = statements([]);
    render(<Host {...props()} />);
    begin('   ');
    send();
    use().file('', 1, 1);
    expect(calls).toHaveLength(0);

    cleanup();
    const signedOut = statements([]);
    render(<Host {...props({ userId: '' })} />);
    begin('ads.example');
    send();
    cleanup();
    render(<Host {...props({ deviceId: '' })} />);
    begin('ads.example');
    send();
    expect(signedOut).toHaveLength(0);
  });

  it('keeps a refusal and a miss on that draft, and does not open a request', async () => {
    const calls = statements([
      Promise.resolve({ __status: 403, detail: 'Nyctr does not recognise this device as yours.' }),
    ]);
    render(<Host {...props()} />);
    begin('blocked.example');
    send();
    await waitFor(() => expect(use().ask?.phase).toBe('settled'));
    expect(use().ask).toMatchObject({
      site: 'blocked.example',
      message: 'Nyctr does not recognise this device as yours.',
    });
    expect(calls.map((call) => call.body)).toEqual([{ domain: 'blocked.example' }]);
    expect(csrf()).toBe('member-csrf');
    expect(window.location.hash).toBe('#/portal');
    expect(use().draft.current.site).toBe('blocked.example');

    cleanup();
    window.location.hash = '/portal';
    statements([
      Promise.resolve({ matched: false, message: 'Nyctr saw no recent block of that name.' }),
    ]);
    render(<Host {...props()} />);
    begin('missing.example');
    send();
    await waitFor(() => expect(use().ask?.message).toMatch(/saw no recent block/));
    expect(use().notice).toBeNull();
    expect(use().draft.current.site).toBe('missing.example');
    expect(window.location.hash).toBe('#/portal');
  });

  it('sends one unchanged draft once, and a later edit is its own request', async () => {
    const first = gate<unknown>();
    const calls = statements([first.promise, new Promise(() => {})]);
    render(<Host {...props()} />);
    begin('old.example');
    send();
    send();
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      method: 'POST',
      path: '/statements',
      body: { domain: 'old.example' },
    });
    expect(csrf()).toBe('member-csrf');
    send('new.example');
    expect(calls.map((call) => call.body)).toEqual([
      { domain: 'old.example' },
      { domain: 'new.example' },
    ]);
    await act(async () => {
      first.resolve({ matched: false, message: 'Nyctr saw no recent block of old.example.' });
    });
    await waitFor(() => expect(use().ask?.site).toBe('new.example'));
    expect(use().ask).toMatchObject({ phase: 'pending', message: null });
    expect(window.location.hash).toBe('#/portal');
    expect(calls.some((call) => call.path.includes('/me/device'))).toBe(false);
  });

  it('opens the same draft, and does not follow it after the address or the draft changed', async () => {
    const pending = gate<unknown>();
    const calls = statements([pending.promise]);
    render(<Host {...props()} />);
    begin('HTTPS://Ads.Example/path');
    send();
    await act(async () => {
      pending.resolve(filed({ status: 'auto_approved' }));
    });
    await waitFor(() => expect(use().kept('r-ask')?.refreshed).toBe(true));
    expect(window.location.hash).toBe('#/portal?request=r-ask');
    expect(calls[0].body).toEqual({ domain: 'HTTPS://Ads.Example/path' });
    expect(calls.some((call) => call.path.includes('/me/device'))).toBe(false);

    cleanup();
    window.location.hash = '/portal';
    const moved = gate<unknown>();
    statements([moved.promise]);
    render(<Host {...props()} />);
    begin('old.example');
    send();
    window.location.hash = '/requests';
    await act(async () => {
      moved.resolve(filed({ id: 'r-old' }));
    });
    await waitFor(() => expect(use().kept('r-old')?.parked).toBe(true));
    expect(window.location.hash).toBe('#/requests');
    expect(use().resolve('r-old')).toMatchObject({ source: 'retained', request: { id: 'r-old' } });

    cleanup();
    window.location.hash = '/portal';
    const edited = gate<unknown>();
    const editedCalls = statements([edited.promise, new Promise(() => {})]);
    render(<Host {...props()} />);
    begin('HTTPS://Ads.Example/path');
    send();
    send('new.example');
    await act(async () => {
      edited.resolve(filed({ domain: 'ads.example' }));
    });
    await waitFor(() => expect(use().notice?.request.domain).toBe('ads.example'));
    expect(editedCalls.map((call) => call.body)).toEqual([
      { domain: 'HTTPS://Ads.Example/path' },
      { domain: 'new.example' },
    ]);
    expect(window.location.hash).toBe('#/portal');
    expect(use().notice?.parked).toBe(true);
    expect(use().draft.current.site).toBe('new.example');
    expect(use().ask).toMatchObject({ site: 'new.example', phase: 'pending' });
  });

  it('drops an old answer after the form is left, and the new visit can still ask', async () => {
    const missed = gate<unknown>();
    const calls = statements([missed.promise, new Promise(() => {})]);
    render(<Host {...props()} />);
    const first = begin('old.example');
    send();
    use().closeForm(first);
    const next = begin('new.example');
    await act(async () => {
      missed.resolve({ matched: false, message: 'Nyctr saw no recent block of old.example.' });
    });
    send();
    expect(calls.map((call) => call.body)).toEqual([
      { domain: 'old.example' },
      { domain: 'new.example' },
    ]);
    await waitFor(() =>
      expect(use().ask).toMatchObject({
        formId: next,
        site: 'new.example',
        phase: 'pending',
        message: null,
      }),
    );
    expect(window.location.hash).toBe('#/portal');

    cleanup();
    window.location.hash = '/portal';
    const accepted = gate<unknown>();
    statements([accepted.promise]);
    render(<Host {...props()} />);
    const previous = begin('old.example');
    send();
    use().closeForm(previous);
    begin('new.example');
    await act(async () => {
      accepted.resolve(filed());
    });
    await waitFor(() => expect(use().notice?.parked).toBe(true));
    expect(use().notice?.request.domain).toBe('ads.example');
    expect(window.location.hash).toBe('#/portal');
    expect(use().draft.current).toMatchObject({ site: 'new.example', revision: 1 });
    expect(use().ask?.formId).toBe(previous);
  });
});

describe('forgetting and leaving the page', () => {
  it('drops a late answer after Forget is accepted, and opens one when it was not', async () => {
    const pending = gate<unknown>();
    const calls = statements([pending.promise]);
    render(<Host {...props()} />);
    begin('old.example');
    send();
    act(() => {
      use().acceptForget('laptop');
    });
    await act(async () => {
      pending.resolve(filed({ id: 'r-forget' }));
    });
    await waitFor(() => expect(use().ask).toBeNull());
    expect(window.location.hash).toBe('#/portal');
    expect(calls.some((call) => call.path.includes('/me/device'))).toBe(false);

    cleanup();
    window.location.hash = '/portal';
    const late = gate<unknown>();
    const failed = statements([late.promise]);
    render(<Host {...props()} />);
    begin('old.example');
    send();
    await act(async () => {
      late.resolve(filed({ id: 'r-kept' }));
    });
    await waitFor(() => expect(window.location.hash).toBe('#/portal?request=r-kept'));
    expect(failed.map((call) => call.path)).toEqual(['/statements']);
  });

  it('drops a late acceptance when the page is gone and does not read again', async () => {
    const pending = gate<unknown>();
    const calls = statements([pending.promise]);
    const reloads = vi.fn(async () => {});
    const view = render(<Host {...props({ reloadEvidence: reloads })} />);
    begin('old.example');
    send();
    const sent = calls.length;
    view.unmount();
    await act(async () => {
      pending.resolve(filed());
      await Promise.resolve();
      await Promise.resolve();
    });
    expect(window.location.hash).toBe('#/portal');
    expect(calls).toHaveLength(sent);
    expect(reloads).not.toHaveBeenCalled();
  });
});

describe('remembered requests', () => {
  it('keeps the earlier request when a later one finishes and the list lacks it', async () => {
    const first = gate<unknown>();
    const second = gate<unknown>();
    statements([first.promise, second.promise]);
    const base = props();
    const view = render(<Host {...base} />);
    begin('a.example');
    send();
    send('b.example');
    await act(async () => {
      second.resolve(filed({ id: 'r-b', domain: 'b.example', status: 'analysing' }));
    });
    await waitFor(() => expect(window.location.hash).toBe('#/portal?request=r-b'));
    await act(async () => {
      first.resolve(filed({ id: 'r-a', domain: 'a.example', status: 'auto_approved' }));
    });
    await waitFor(() => expect(use().kept('r-a')?.request.domain).toBe('a.example'));
    expect(window.location.hash).toBe('#/portal?request=r-b');
    expect(use().notice?.request.id).toBe('r-b');
    expect(use().kept('r-b')?.request.id).toBe('r-b');
    expect(use().resolve('r-a').source).toBe('retained');
    const listedB = request({ id: 'r-b', domain: 'b.example', status: 'auto_approved' });
    view.rerender(<Host {...base} requests={{ availability: 'loaded', rows: [listedB] }} />);
    expect(use().resolve('r-b')).toMatchObject({
      source: 'listed',
      request: { status: 'auto_approved' },
    });
    expect(use().resolve('r-a')).toMatchObject({
      source: 'retained',
      request: { domain: 'a.example' },
    });
    expect(use().kept('r-a')?.request.status).toBe('auto_approved');
  });

  it('clears remembered requests when the member changes and does not open the late one', async () => {
    const queue: Promise<unknown>[] = [Promise.resolve(filed({ id: 'r-a', domain: 'a.example' }))];
    statements(queue);
    const base = props();
    const view = render(<Host {...base} />);
    begin('a.example');
    send();
    await waitFor(() => expect(use().kept('r-a')).not.toBeNull());
    window.location.hash = '/portal';
    const late = gate<unknown>();
    queue.push(late.promise);
    send('b.example');
    view.rerender(<Host {...base} userId="kim" />);
    await act(async () => {
      late.resolve(filed({ id: 'r-b', domain: 'b.example' }));
      await Promise.resolve();
    });
    expect(window.location.hash).toBe('#/portal');
    expect(use().kept('r-a')).toBeNull();
    expect(use().kept('r-b')).toBeNull();
    expect(use().notice).toBeNull();
    expect(use().ask).toBeNull();
    view.rerender(<Host {...base} userId="sam" />);
    expect(use().kept('r-a')).toBeNull();
  });

  it('does not restore a response after the member leaves and comes back', async () => {
    for (const away of ['kim', '']) {
      cleanup();
      window.location.hash = '/portal';
      const old = gate<unknown>();
      const calls = statements([old.promise, new Promise(() => {})]);
      const base = props();
      const view = render(<Host {...base} />);
      begin('ads.example');
      send();
      view.rerender(<Host {...base} userId={away} />);
      view.rerender(<Host {...base} userId="sam" />);
      send();
      await act(async () => {
        old.resolve(filed({ id: 'r-old', domain: 'ads.example' }));
        await Promise.resolve();
      });
      expect(window.location.hash).toBe('#/portal');
      expect(use().kept('r-old')).toBeNull();
      expect(use().notice).toBeNull();
      expect(calls).toHaveLength(2);
      await waitFor(() =>
        expect(use().ask).toMatchObject({ site: 'ads.example', phase: 'pending' }),
      );
    }
  });

  it('keeps a listed decision when that list later fails, including one the list never had', async () => {
    statements([
      Promise.resolve(filed({ id: 'r-a', domain: 'a.example', status: 'analysing' })),
      Promise.resolve(filed({ id: 'r-b', domain: 'b.example', status: 'analysing' })),
    ]);
    const base = props();
    const view = render(<Host {...base} />);
    begin('a.example');
    send();
    await waitFor(() => expect(use().kept('r-a')).not.toBeNull());
    const flight = use().kept('r-a')?.flight;
    send('b.example');
    await waitFor(() => expect(use().kept('r-b')?.request.status).toBe('analysing'));
    const approved = request({ id: 'r-a', domain: 'a.example', status: 'approved' });
    view.rerender(<Host {...base} requests={{ availability: 'loaded', rows: [approved] }} />);
    expect(use().resolve('r-a')).toMatchObject({
      source: 'listed',
      request: { status: 'approved' },
    });
    expect(use().kept('r-a')).toMatchObject({
      flight,
      site: 'a.example',
      request: { status: 'approved' },
    });
    const denied = request({ id: 'r-a', domain: 'a.example', status: 'denied' });
    view.rerender(<Host {...base} requests={{ availability: 'loaded', rows: [denied] }} />);
    expect(use().kept('r-a')?.request.status).toBe('denied');
    expect(use().resolve('r-b')).toMatchObject({
      source: 'retained',
      request: { status: 'analysing' },
    });
    view.rerender(<Host {...base} requests={{ availability: 'error', rows: [] }} />);
    expect(use().resolve('r-a')).toMatchObject({ source: 'listed', request: { status: 'denied' } });
    expect(use().resolve('r-b')).toMatchObject({
      source: 'retained',
      request: { status: 'analysing' },
    });
    view.rerender(<Host {...base} requests={{ availability: 'unloaded', rows: [] }} />);
    expect(use().resolve('r-a').request?.status).toBe('denied');
    expect(use().kept('r-b')?.request.status).toBe('analysing');
  });

  it('shows a loaded decision in the notice and on the page', async () => {
    statements([Promise.resolve(filed({ id: 'r-ask', status: 'analysing' }))]);
    const base = props();
    function Page(input: StatementModelInput) {
      const api = useStatementRequests(input);
      model.current = api;
      const status = api.kept('r-ask')?.request.status ?? 'none';
      const noted = api.notice?.request.status ?? 'none';
      return <p>{noted + ':' + status}</p>;
    }
    const view = render(<Page {...base} />);
    begin('ads.example');
    send();
    await waitFor(() => expect(screen.getByText('analysing:analysing')).toBeTruthy());
    const filedRow = use().kept('r-ask');
    view.rerender(
      <Page
        {...base}
        requests={{ availability: 'loaded', rows: [request({ id: 'r-ask', status: 'denied' })] }}
      />,
    );
    expect(screen.getByText('denied:denied')).toBeTruthy();
    expect(use().notice?.request.status).toBe('denied');
    expect(use().kept('r-ask')).toMatchObject({
      flight: filedRow?.flight,
      site: 'ads.example',
      refreshed: filedRow?.refreshed,
      parked: filedRow?.parked,
      request: { status: 'denied' },
    });
    expect(use().resolve('r-ask').request?.status).toBe('denied');
  });

  it('drops a listed request when a later loaded list omits it, and keeps one the list never had', async () => {
    statements([
      Promise.resolve(filed({ id: 'r-a', domain: 'a.example', status: 'analysing' })),
      Promise.resolve(filed({ id: 'r-b', domain: 'b.example', status: 'analysing' })),
    ]);
    const base = props();
    const view = render(<Host {...base} />);
    begin('a.example');
    send();
    await waitFor(() => expect(use().notice?.request.id).toBe('r-a'));
    const denied = request({ id: 'r-a', domain: 'a.example', status: 'denied' });
    view.rerender(<Host {...base} requests={{ availability: 'loaded', rows: [denied] }} />);
    expect(use().resolve('r-a')).toMatchObject({
      source: 'listed',
      request: { status: 'denied', requester_id: 'sam' },
    });
    expect(use().kept('r-a')?.request.status).toBe('denied');
    view.rerender(<Host {...base} requests={{ availability: 'loaded', rows: [] }} />);
    expect(use().resolve('r-a')).toEqual({
      request: null,
      source: 'none',
      filedButUnlisted: false,
    });
    expect(use().kept('r-a')).toBeNull();
    expect(use().notice).toBeNull();
    send('b.example');
    await waitFor(() => expect(use().kept('r-b')?.request.status).toBe('analysing'));
    view.rerender(<Host {...base} requests={{ availability: 'loaded', rows: [] }} />);
    expect(use().resolve('r-b')).toMatchObject({
      source: 'retained',
      request: { id: 'r-b', status: 'analysing' },
    });
    expect(use().resolve('r-a').request).toBeNull();
    view.rerender(<Host {...base} requests={{ availability: 'error', rows: [] }} />);
    expect(use().resolve('r-a').request).toBeNull();
    expect(use().kept('r-b')?.request.status).toBe('analysing');
  });

  it('does not keep a loaded row that names a different member', () => {
    const sam = request({ id: 'r-sam', domain: 'sam.example', requester_id: 'sam' });
    const kim = request({ id: 'r-kim', domain: 'kim.example', requester_id: 'kim' });
    const held = { availability: 'loaded' as const, rows: [sam, kim] };
    const base = props();
    const view = render(<Host {...base} requests={held} />);
    expect(use().resolve('r-sam')).toMatchObject({
      source: 'listed',
      request: { requester_id: 'sam', domain: 'sam.example' },
    });
    expect(use().resolve('r-kim').request).toBeNull();
    view.rerender(<Host {...base} requests={{ availability: 'error', rows: [] }} />);
    expect(use().resolve('r-sam').request?.requester_id).toBe('sam');
    expect(use().resolve('r-kim').request).toBeNull();
    view.rerender(<Host {...base} userId="kim" requests={held} />);
    expect(use().resolve('r-sam').request).toBeNull();
    expect(use().resolve('r-kim')).toMatchObject({
      source: 'listed',
      request: { requester_id: 'kim', domain: 'kim.example' },
    });
    expect(use().kept('r-sam')).toBeNull();
    view.rerender(<Host {...base} userId="kim" requests={{ availability: 'error', rows: [] }} />);
    expect(use().resolve('r-sam').request).toBeNull();
    expect(use().resolve('r-kim')).toMatchObject({
      source: 'listed',
      request: { requester_id: 'kim' },
    });
  });

  it('a discarded sign-in render does not drop the member who is still signed in', async () => {
    const pending = gate<unknown>();
    statements([pending.promise]);
    let change: (user: string) => void = () => {};
    const signedIn = { current: null as ReturnType<typeof useStatementRequests> | null };
    const read = () => {
      if (!signedIn.current) throw new Error('the form controller is not mounted');
      return signedIn.current;
    };
    let attempted = false;
    const never = new Promise<void>(() => {});
    function Child({ user }: { user: string }) {
      const api = useStatementRequests(props({ userId: user }));
      if (user === 'kim') {
        attempted = true;
        throw never;
      }
      signedIn.current = api;
      return <p>Committed {user}</p>;
    }
    function Parent() {
      const [user, setUser] = useState('sam');
      change = setUser;
      return (
        <Suspense fallback={<p>Loading</p>}>
          <Child user={user} />
        </Suspense>
      );
    }
    render(<Parent />);
    act(() => {
      const form = read().openForm();
      const revision = read().editDraft('ads.example');
      read().file('ads.example', revision, form);
    });
    await act(async () => {
      startTransition(() => change('kim'));
    });
    expect(attempted).toBe(true);
    expect(screen.getByText('Committed sam')).toBeTruthy();
    await act(async () => {
      change('sam');
    });
    await act(async () => {
      pending.resolve(filed({ id: 'r-ask' }));
    });
    expect(read().kept('r-ask')).not.toBeNull();
    expect(window.location.hash).toBe('#/portal?request=r-ask');
  });

  it('a committed sign-in change still drops the previous member answer', async () => {
    const pending = gate<unknown>();
    statements([pending.promise]);
    let change: (user: string) => void = () => {};
    const signedIn = { current: null as ReturnType<typeof useStatementRequests> | null };
    const read = () => {
      if (!signedIn.current) throw new Error('the form controller is not mounted');
      return signedIn.current;
    };
    function Child({ user }: { user: string }) {
      signedIn.current = useStatementRequests(props({ userId: user }));
      return <p>Committed {user}</p>;
    }
    function Parent() {
      const [user, setUser] = useState('sam');
      change = setUser;
      return <Child user={user} />;
    }
    render(<Parent />);
    act(() => {
      const form = read().openForm();
      const revision = read().editDraft('ads.example');
      read().file('ads.example', revision, form);
    });
    await act(async () => {
      startTransition(() => change('kim'));
    });
    expect(screen.getByText('Committed kim')).toBeTruthy();
    await act(async () => {
      pending.resolve(filed({ id: 'r-ask' }));
    });
    expect(window.location.hash).toBe('#/portal');
    await act(async () => {
      startTransition(() => change('sam'));
    });
    expect(screen.getByText('Committed sam')).toBeTruthy();
    expect(read().kept('r-ask')).toBeNull();
  });

  it('a late duplicate does not restore a request a loaded list retired', async () => {
    const first = gate<unknown>();
    const second = gate<unknown>();
    statements([first.promise, second.promise]);
    const base = props();
    const view = render(<Host {...base} />);
    begin('https://ads.example');
    send();
    send('ads.example');
    await act(async () => {
      first.resolve(filed({ id: 'r-ask', domain: 'ads.example' }));
    });
    await waitFor(() => expect(use().kept('r-ask')).not.toBeNull());
    view.rerender(
      <Host
        {...base}
        requests={{ availability: 'loaded', rows: [request({ id: 'r-ask', status: 'denied' })] }}
      />,
    );
    expect(use().resolve('r-ask').request?.status).toBe('denied');
    view.rerender(<Host {...base} requests={{ availability: 'loaded', rows: [] }} />);
    expect(use().resolve('r-ask').request).toBeNull();
    await act(async () => {
      second.resolve(filed({ id: 'r-ask', domain: 'ads.example', status: 'analysing' }));
    });
    expect(use().resolve('r-ask').request).toBeNull();
    expect(use().kept('r-ask')).toBeNull();
  });

  it('a request started after a retirement can be filed again', async () => {
    const first = gate<unknown>();
    const again = gate<unknown>();
    const calls = statements([first.promise, again.promise]);
    const base = props();
    const view = render(<Host {...base} />);
    begin('ads.example');
    send();
    await act(async () => {
      first.resolve(filed({ id: 'r-ask', status: 'analysing' }));
    });
    await waitFor(() => expect(use().kept('r-ask')).not.toBeNull());
    view.rerender(
      <Host
        {...base}
        requests={{ availability: 'loaded', rows: [request({ id: 'r-ask', status: 'denied' })] }}
      />,
    );
    view.rerender(<Host {...base} requests={{ availability: 'loaded', rows: [] }} />);
    expect(use().resolve('r-ask').request).toBeNull();
    window.location.hash = '/portal';
    send('ads.example');
    await act(async () => {
      again.resolve(filed({ id: 'r-ask', status: 'approved' }));
    });
    await waitFor(() => expect(use().kept('r-ask')?.request.status).toBe('approved'));
    view.rerender(<Host {...base} requests={{ availability: 'loaded', rows: [] }} />);
    expect(use().resolve('r-ask')).toMatchObject({
      source: 'retained',
      request: { status: 'approved' },
    });
    view.rerender(<Host {...base} requests={{ availability: 'error', rows: [] }} />);
    expect(use().kept('r-ask')?.request.status).toBe('approved');
    expect(calls).toHaveLength(2);
  });
});
