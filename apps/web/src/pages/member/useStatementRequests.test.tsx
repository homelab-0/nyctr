import { Suspense, startTransition, useLayoutEffect, useState } from 'react';
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

  it('refuses a site, revision, or visit that is not the open draft', () => {
    const calls = statements([new Promise(() => {})]);
    render(<Host {...props()} />);
    const form = begin('ads.example');
    const revision = use().draft.current.revision;
    use().file('other.example', revision, form);
    use().file('ads.example', revision + 1, form);
    use().file('ads.example', revision, form + 1);
    use().file('ads.example', revision, 0);
    expect(calls).toHaveLength(0);
    expect(use().ask).toBeNull();
    send();
    expect(calls.map((call) => call.body)).toEqual([{ domain: 'ads.example' }]);
    expect(use().visits.current.mounted).toBe(form);
    expect(use().draft.current).toMatchObject({ formId: form, site: 'ads.example' });
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
    const reloads = vi.fn(async () => {});
    render(<Host {...props({ reloadEvidence: reloads })} />);
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
    expect(use().kept('r-forget')).toBeNull();
    expect(use().notice).toBeNull();
    expect(reloads).not.toHaveBeenCalled();
    expect(calls.map((call) => call.path)).toEqual(['/statements']);

    cleanup();
    window.location.hash = '/portal';
    const late = gate<unknown>();
    const failed = statements([late.promise]);
    const keptReloads = vi.fn(async () => {});
    render(<Host {...props({ reloadEvidence: keptReloads })} />);
    begin('old.example');
    send();
    await act(async () => {
      late.resolve(filed({ id: 'r-kept' }));
    });
    await waitFor(() => expect(window.location.hash).toBe('#/portal?request=r-kept'));
    expect(failed.map((call) => call.path)).toEqual(['/statements']);
    expect(use().kept('r-kept')?.request.id).toBe('r-kept');
    expect(use().notice?.request.id).toBe('r-kept');
    expect(keptReloads).toHaveBeenCalledTimes(1);
  });

  it('a newer ask stays when an older answer returns after Forget', async () => {
    const older = gate<unknown>();
    const newer = new Promise(() => {});
    const calls = statements([older.promise, newer]);
    const reloads = vi.fn(async () => {});
    const view = render(<Host {...props({ reloadEvidence: reloads })} />);
    begin('old.example');
    send();
    const olderFlight = use().ask?.flight;
    act(() => {
      use().acceptForget('laptop');
    });
    view.rerender(<Host {...props({ deviceId: 'tablet', reloadEvidence: reloads })} />);
    begin('new.example');
    send();
    expect(calls.map((call) => call.body)).toEqual([
      { domain: 'old.example' },
      { domain: 'new.example' },
    ]);
    await act(async () => {
      older.resolve(filed({ id: 'r-old' }));
    });
    expect(use().ask).toMatchObject({ site: 'new.example', phase: 'pending' });
    expect(use().ask?.flight).not.toBe(olderFlight);
    expect(use().kept('r-old')).toBeNull();
    expect(use().notice).toBeNull();
    expect(reloads).not.toHaveBeenCalled();
    expect(window.location.hash).toBe('#/portal');
    expect(calls.some((call) => call.path.includes('/me/device'))).toBe(false);
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
  it('closes eligibility synchronously at Forget and does not send another filing from that device', () => {
    const calls = statements([new Promise(() => {})]);
    render(<Host {...props()} />);
    begin('old.example');
    send();
    act(() => {
      use().acceptForget('laptop');
      send('new.example');
    });
    expect(use().canFile).toBe(false);
    expect(calls.map((call) => call.body)).toEqual([{ domain: 'old.example' }]);
  });

  it('lists retained owned filings, prefers committed decisions, and never lists retired or foreign rows', async () => {
    statements([Promise.resolve(filed())]);
    const view = render(<Host {...props()} />);
    begin('ads.example');
    send();
    await waitFor(() => expect(use().rows.map((row) => row.id)).toEqual(['r-ask']));
    const denied = request({ status: 'denied' });
    view.rerender(<Host {...props({ requests: { availability: 'loaded', rows: [denied] } })} />);
    expect(use().rows).toEqual([denied]);
    view.rerender(
      <Host
        {...props({
          requests: {
            availability: 'error',
            rows: [request({ requester_id: 'other', domain: 'private.example' })],
          },
        })}
      />,
    );
    expect(use().rows).toEqual([denied]);
    view.rerender(<Host {...props({ requests: { availability: 'loaded', rows: [] } })} />);
    expect(use().rows).toEqual([]);
    view.rerender(
      <Host
        {...props({ userId: 'riley', requests: { availability: 'loaded', rows: [denied] } })}
      />,
    );
    expect(use().rows).toEqual([]);
  });
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
      const first = begin('ads.example');
      send();
      view.rerender(<Host {...base} userId={away} />);
      view.rerender(<Host {...base} userId="sam" />);
      expect(use().visits.current.mounted).toBe(0);
      expect(use().draft.current).toEqual({ formId: 0, revision: 0, site: '' });
      expect(use().visits.current.next).toBe(first);
      const next = begin('ads.example');
      expect(next).toBeGreaterThan(first);
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

  it('keeps a listed decision when a newer filing of that request finishes during a list error', async () => {
    const again = gate<unknown>();
    statements([
      Promise.resolve(filed({ id: 'r-ask', domain: 'ads.example', status: 'analysing' })),
      again.promise,
      Promise.resolve(filed({ id: 'r-new', domain: 'new.example', status: 'analysing' })),
    ]);
    const base = props();
    const view = render(<Host {...base} />);
    begin('ads.example');
    send();
    await waitFor(() => expect(use().kept('r-ask')?.request.status).toBe('analysing'));
    const firstFlight = use().kept('r-ask')?.flight ?? 0;
    const denied = request({
      id: 'r-ask',
      domain: 'ads.example',
      status: 'denied',
      decision_note: 'A person declined',
    });
    view.rerender(<Host {...base} requests={{ availability: 'loaded', rows: [denied] }} />);
    expect(use().resolve('r-ask').request).toBe(denied);
    const hostile = request({ id: 'r-ask', domain: 'ads.example', status: 'approved' });
    const foreign = request({
      id: 'r-ask',
      domain: 'other.example',
      status: 'approved',
      requester_id: 'kim',
    });
    view.rerender(
      <Host {...base} requests={{ availability: 'error', rows: [hostile, foreign] }} />,
    );
    send('later.example');
    await act(async () => {
      again.resolve(filed({ id: 'r-ask', domain: 'later.example', status: 'analysing' }));
    });
    await waitFor(() => expect(use().kept('r-ask')?.site).toBe('later.example'));
    expect(use().kept('r-ask')?.flight).toBeGreaterThan(firstFlight);
    expect(use().kept('r-ask')?.request).toBe(denied);
    expect(use().notice?.request).toBe(denied);
    expect(use().notice?.site).toBe('later.example');
    expect(use().notice?.flight).toBe(use().kept('r-ask')?.flight);
    expect(use().resolve('r-ask')).toMatchObject({
      source: 'listed',
      request: { status: 'denied', decision_note: 'A person declined' },
    });
    const planted = request({ id: 'r-new', domain: 'planted.example', status: 'approved' });
    view.rerender(
      <Host {...base} requests={{ availability: 'unloaded', rows: [hostile, planted] }} />,
    );
    expect(use().kept('r-ask')?.request).toBe(denied);
    expect(use().resolve('r-ask').request?.status).toBe('denied');
    expect(use().notice?.request.status).toBe('denied');
    send('new.example');
    await waitFor(() => expect(use().kept('r-new')?.request.domain).toBe('new.example'));
    expect(use().kept('r-new')?.request.status).toBe('analysing');
    expect(use().resolve('r-new')).toMatchObject({
      source: 'retained',
      request: { id: 'r-new', status: 'analysing' },
    });
    expect(use().notice?.request.id).toBe('r-new');
    expect(use().kept('r-ask')?.request).toBe(denied);
    view.rerender(<Host {...base} requests={{ availability: 'loaded', rows: [] }} />);
    expect(use().kept('r-ask')).toBeNull();
    expect(use().resolve('r-ask')).toEqual({
      request: null,
      source: 'none',
      filedButUnlisted: false,
    });
    expect(use().kept('r-new')?.request.status).toBe('analysing');
    expect(use().notice?.request.id).toBe('r-new');
  });

  it('shows the newest request the current list still contains', async () => {
    statements([
      Promise.resolve(filed({ id: 'r-a', domain: 'a.example', status: 'analysing' })),
      Promise.resolve(filed({ id: 'r-b', domain: 'b.example', status: 'analysing' })),
    ]);
    const frames: string[] = [];
    function Page(input: StatementModelInput) {
      const api = useStatementRequests(input);
      model.current = api;
      const noted = api.notice?.request.id ?? 'none';
      frames.push(noted);
      return <p>{noted}</p>;
    }
    const base = props();
    const view = render(<Page {...base} />);
    begin('a.example');
    send();
    await waitFor(() => expect(screen.getByText('r-a')).toBeTruthy());
    send('b.example');
    await waitFor(() => expect(screen.getByText('r-b')).toBeTruthy());
    const listedA = request({ id: 'r-a', domain: 'a.example', status: 'denied' });
    const listedB = request({ id: 'r-b', domain: 'b.example', status: 'approved' });
    view.rerender(
      <Page {...base} requests={{ availability: 'loaded', rows: [listedA, listedB] }} />,
    );
    expect(screen.getByText('r-b')).toBeTruthy();
    expect(use().notice?.flight).toBeGreaterThan(use().kept('r-a')?.flight ?? 0);
    const foreignB = request({
      id: 'r-b',
      domain: 'b.example',
      status: 'approved',
      requester_id: 'kim',
    });
    frames.length = 0;
    view.rerender(
      <Page {...base} requests={{ availability: 'loaded', rows: [listedA, foreignB] }} />,
    );
    expect(frames.length).toBeGreaterThan(0);
    expect(frames.every((id) => id === 'r-a')).toBe(true);
    expect(screen.getByText('r-a')).toBeTruthy();
    expect(use().notice?.request).toBe(listedA);
    expect(use().kept('r-b')).toBeNull();
    frames.length = 0;
    view.rerender(<Page {...base} requests={{ availability: 'loaded', rows: [listedA] }} />);
    expect(frames.every((id) => id === 'r-a')).toBe(true);
    expect(screen.getByText('r-a')).toBeTruthy();
    frames.length = 0;
    view.rerender(<Page {...base} requests={{ availability: 'loaded', rows: [] }} />);
    expect(frames.every((id) => id === 'none')).toBe(true);
    expect(screen.getByText('none')).toBeTruthy();
    expect(use().notice).toBeNull();
    expect(use().kept('r-a')).toBeNull();
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
    const calls = statements([pending.promise]);
    let change: (user: string) => void = () => {};
    const signedIn = { current: null as ReturnType<typeof useStatementRequests> | null };
    const read = () => {
      if (!signedIn.current) throw new Error('the form controller is not mounted');
      return signedIn.current;
    };
    let attempted = false;
    let form = 0;
    let revision = 0;
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
      form = read().openForm();
      revision = read().editDraft('ads.example');
      read().file('ads.example', revision, form);
    });
    await act(async () => {
      startTransition(() => change('kim'));
    });
    expect(attempted).toBe(true);
    expect(screen.getByText('Committed sam')).toBeTruthy();
    expect(calls).toHaveLength(1);
    expect(read().visits.current.mounted).toBe(form);
    expect(read().visits.current.next).toBe(form);
    expect(read().draft.current).toEqual({ formId: form, revision, site: 'ads.example' });
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
    const calls = statements([pending.promise, new Promise(() => {})]);
    let change: (user: string) => void = () => {};
    const signedIn = { current: null as ReturnType<typeof useStatementRequests> | null };
    const read = () => {
      if (!signedIn.current) throw new Error('the form controller is not mounted');
      return signedIn.current;
    };
    let samForm = 0;
    let samRevision = 0;
    let postedDuringLayout = -1;
    let layoutMounted = -1;
    let layoutSite = 'unset';
    function Child({ user }: { user: string }) {
      const api = useStatementRequests(props({ userId: user }));
      signedIn.current = api;
      useLayoutEffect(() => {
        if (user !== 'kim') return;
        const before = calls.length;
        api.file('ads.example', samRevision, samForm);
        postedDuringLayout = calls.length - before;
        layoutMounted = api.visits.current.mounted;
        layoutSite = api.draft.current.site;
      });
      return <p>Committed {user}</p>;
    }
    function Parent() {
      const [user, setUser] = useState('sam');
      change = setUser;
      return <Child user={user} />;
    }
    render(<Parent />);
    act(() => {
      samForm = read().openForm();
      samRevision = read().editDraft('ads.example');
      read().file('ads.example', samRevision, samForm);
    });
    expect(calls).toHaveLength(1);
    await act(async () => {
      startTransition(() => change('kim'));
    });
    expect(screen.getByText('Committed kim')).toBeTruthy();
    expect(postedDuringLayout).toBe(0);
    expect(layoutMounted).toBe(0);
    expect(layoutSite).toBe('');
    expect(calls).toHaveLength(1);
    expect(read().visits.current.next).toBe(samForm);
    read().file('ads.example', samRevision, samForm);
    expect(calls).toHaveLength(1);
    let kimForm = 0;
    act(() => {
      kimForm = read().openForm();
      const revision = read().editDraft('kim.example');
      read().file('kim.example', revision, kimForm);
    });
    expect(kimForm).toBeGreaterThan(samForm);
    expect(read().visits.current.next).toBe(kimForm);
    expect(calls.map((call) => call.body)).toEqual([
      { domain: 'ads.example' },
      { domain: 'kim.example' },
    ]);
    await act(async () => {
      pending.resolve(filed({ id: 'r-ask' }));
    });
    expect(window.location.hash).toBe('#/portal');
    expect(read().kept('r-ask')).toBeNull();
    expect(read().ask).toMatchObject({ site: 'kim.example', phase: 'pending' });
    await act(async () => {
      startTransition(() => change('sam'));
    });
    expect(screen.getByText('Committed sam')).toBeTruthy();
    expect(read().kept('r-ask')).toBeNull();
    expect(read().visits.current.mounted).toBe(0);
    expect(read().draft.current.site).toBe('');
    expect(read().visits.current.next).toBe(kimForm);
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
