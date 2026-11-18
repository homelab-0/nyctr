import { act, cleanup, render, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrfToken } from '../../api';
import { mockApi } from '../../test/mock-api';
import type { AccessRequest, Execution, Lease } from '../../types';
import {
  useStatementRequests,
  type ListAvailability,
  type ResolvedRequest,
  type StatementModelInput,
} from './useStatementRequests';
import {
  acknowledgeRefresh,
  allowRetry,
  describeOpening,
  newFollow,
  noteDecision,
  openingEvidence,
  refreshNeed,
  replaceSession,
  startRefresh,
  type RefreshDecision,
  type RefreshFollow,
} from './statementEvidence';

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

function lease(execution: Execution, requestId = 'r-ask'): Lease {
  return {
    id: 'l1',
    request_id: requestId,
    integration_id: 'dns',
    domain: 'ads.example',
    device_name: "Sam's laptop",
    requester_id: 'sam',
    kind: 'temporary',
    status: 'active',
    ended_reason: null,
    execution,
    owned: execution === 'applied',
    scope: 'This device',
    decided_by: 'rule',
    risk_score: null,
    created_at: '2026-01-01T00:00:00Z',
    expires_at: null,
    ended_at: null,
    last_error: null,
  };
}

function held(
  status: string,
  source: ResolvedRequest['source'] = 'retained',
  id = 'r-ask',
): ResolvedRequest {
  return {
    request: request({ id, status, domain: id === 'r-ask' ? 'ads.example' : `${id}.example` }),
    source,
    filedButUnlisted: source === 'retained',
  };
}

function follow(): RefreshFollow {
  return newFollow();
}

function decide(input: {
  view?: 'home' | 'request' | 'requests';
  requestsAvailability: ListAvailability;
  resolved?: Record<string, ResolvedRequest>;
  leases: { availability: ListAvailability; rows: Lease[] };
  saw?: boolean;
  spent?: boolean;
  failed?: boolean;
  failedIds?: string[];
  checked?: string[];
  watchIds?: string[];
  openRequestId?: string | null;
}): RefreshDecision {
  const resolved = input.resolved ?? { 'r-ask': held('analysing') };
  return refreshNeed({
    view: input.view ?? 'request',
    openRequestId: input.openRequestId === undefined ? 'r-ask' : input.openRequestId,
    resolve: (id) => resolved[id] ?? { request: null, source: 'none', filedButUnlisted: false },
    watchIds: input.watchIds ?? Object.keys(resolved),
    requestsAvailability: input.requestsAvailability,
    leases: input.leases,
    sawUndecided: input.saw ?? false,
    spentFinal: input.spent ?? false,
    finalFailed: input.failed ?? false,
    failedLeaseIds: input.failedIds ?? [],
    checkedLeaseIds: input.checked ?? [],
  });
}

function deniesWithoutEvidence(explanation: string | null) {
  const text = explanation?.toLowerCase() ?? '';
  expect(text).not.toMatch(/simulated/);
  expect(text).not.toMatch(/not applied/);
  expect(text).not.toMatch(/unchanged/);
  expect(text).not.toMatch(/waiting for a person/);
  expect(text).not.toMatch(/practice/);
}

describe('lease evidence', () => {
  it.each(['loaded', 'error'] as const)(
    'keeps failed A manual while B gets a read, and rejects A’s late %s',
    (oldOutcome) => {
      const state = follow();
      const a = { 'r-ask': held('approved', 'listed') };
      const first = startRefresh(
        state,
        decide({
          view: 'requests',
          resolved: a,
          requestsAvailability: 'loaded',
          leases: { availability: 'loaded', rows: [] },
        }),
      );
      acknowledgeRefresh(state, first, 'error');
      expect([...state.failed]).toEqual(['r-ask']);
      const both = { ...a, 'r-b': held('approved', 'listed', 'r-b') };
      const b = decide({
        view: 'requests',
        resolved: both,
        requestsAvailability: 'loaded',
        leases: { availability: 'error', rows: [] },
        failed: state.finalFailed,
        failedIds: [...state.failed],
      });
      expect(b.openingIds).toEqual(['r-b']);
      expect(b.openingUnchecked).toBe(true);
      expect(b.continue).toBe(true);
      const next = startRefresh(state, b);
      acknowledgeRefresh(state, first, oldOutcome);
      expect([...state.failed]).toEqual(['r-ask']);
      expect([...state.checked]).toEqual([]);
      acknowledgeRefresh(state, next, 'loaded');
      expect([...state.failed]).toEqual(['r-ask']);
      expect([...state.checked]).toEqual(['r-b']);
      const stopped = decide({
        view: 'requests',
        resolved: both,
        requestsAvailability: 'loaded',
        leases: { availability: 'loaded', rows: [] },
        failed: state.finalFailed,
        failedIds: [...state.failed],
        checked: [...state.checked],
      });
      expect(stopped.confirmingIds).toEqual([]);
      expect(stopped.continue).toBe(false);
      allowRetry(state);
      const manual = decide({
        view: 'requests',
        resolved: both,
        requestsAvailability: 'loaded',
        leases: { availability: 'loaded', rows: [] },
        failed: state.finalFailed,
        failedIds: [...state.failed],
        checked: [...state.checked],
      });
      expect(manual.confirmingIds).toEqual(['r-ask']);
      replaceSession(state);
      expect([...state.failed]).toEqual([]);
      expect([...state.checked]).toEqual([]);
    },
  );
  it('calls a missing lease list unknown, and a loaded lease keeps what the source did', () => {
    const missing = openingEvidence({ status: 'auto_approved', lease: null, leaseList: 'error' });
    expect(missing).toMatchObject({
      availability: 'unknown',
      retry: true,
      lease: null,
      execution: null,
    });
    deniesWithoutEvidence(missing.explanation);
    const unloaded = openingEvidence({
      status: 'auto_approved',
      lease: null,
      leaseList: 'unloaded',
    });
    expect(unloaded.retry).toBe(true);
    expect(unloaded.availability).toBe('unknown');
    deniesWithoutEvidence(unloaded.explanation);
    const described = describeOpening({
      request: request({ status: 'auto_approved', domain: 'ads.example' }),
      lease: null,
      leaseList: 'error',
    });
    expect(described.request).toMatchObject({ id: 'r-ask', domain: 'ads.example' });
    expect(described.opening.availability).toBe('unknown');
    expect(described.opening.retry).toBe(true);

    const state = follow();
    const unchecked = decide({
      requestsAvailability: 'loaded',
      resolved: { 'r-ask': held('auto_approved') },
      leases: { availability: 'error', rows: [] },
    });
    expect(unchecked.openingUnchecked).toBe(true);
    expect(unchecked.continue).toBe(true);
    noteDecision(state, unchecked);
    const failedRound = startRefresh(state, unchecked);
    acknowledgeRefresh(state, failedRound, 'error');
    expect(state.finalFailed).toBe(true);
    expect(state.spent).toBe(false);
    const stalled = decide({
      requestsAvailability: 'loaded',
      resolved: { 'r-ask': held('auto_approved') },
      leases: { availability: 'error', rows: [] },
      failed: state.finalFailed,
      failedIds: [...state.failed],
    });
    expect(stalled.continue).toBe(false);
    expect(stalled.openingUnchecked).toBe(false);
    expect(
      openingEvidence({ status: 'auto_approved', lease: null, leaseList: 'error' }).execution,
    ).toBeNull();
    allowRetry(state);
    expect(
      decide({
        requestsAvailability: 'loaded',
        resolved: { 'r-ask': held('auto_approved') },
        leases: { availability: 'error', rows: [] },
        failed: state.finalFailed,
        failedIds: [...state.failed],
      }).continue,
    ).toBe(true);

    expect(openingEvidence({ status: 'auto_approved', lease: null, leaseList: 'loaded' })).toEqual({
      availability: 'read',
      retry: false,
      lease: null,
      execution: null,
      explanation: 'Nyctr found no opening recorded for this request.',
    });
    const approved = held('auto_approved', 'listed');
    const confirming = decide({
      requestsAvailability: 'loaded',
      resolved: { 'r-ask': approved },
      leases: { availability: 'loaded', rows: [] },
    });
    expect(confirming.confirmingIds).toEqual(['r-ask']);
    expect(confirming.continue).toBe(true);
    const confirmed = startRefresh(state, confirming);
    acknowledgeRefresh(state, confirmed, 'loaded');
    expect([...state.checked]).toEqual(['r-ask']);
    expect(
      decide({
        requestsAvailability: 'loaded',
        resolved: { 'r-ask': approved },
        leases: { availability: 'loaded', rows: [] },
        checked: [...state.checked],
        failed: state.finalFailed,
        failedIds: [...state.failed],
      }).continue,
    ).toBe(false);

    for (const execution of ['simulated', 'applied', 'not_applied', 'failed'] as const) {
      const row = lease(execution);
      expect(
        openingEvidence({ status: 'auto_approved', lease: row, leaseList: 'loaded' }),
      ).toMatchObject({ availability: 'read', retry: false, execution, lease: row });
    }
    const applied = openingEvidence({
      status: 'auto_approved',
      lease: lease('applied'),
      leaseList: 'loaded',
    });
    const simulated = openingEvidence({
      status: 'auto_approved',
      lease: lease('simulated'),
      leaseList: 'loaded',
    });
    const skipped = openingEvidence({
      status: 'auto_approved',
      lease: lease('not_applied'),
      leaseList: 'loaded',
    });
    const broken = openingEvidence({
      status: 'auto_approved',
      lease: lease('failed'),
      leaseList: 'loaded',
    });
    expect(
      new Set([applied.explanation, simulated.explanation, skipped.explanation, broken.explanation])
        .size,
    ).toBe(4);
    expect(
      openingEvidence({ status: 'analysing', lease: null, leaseList: 'error' }).availability,
    ).toBe('not-an-opening');
  });

  it('keeps reading a request the list does not have, then stops after a fresh lease read', () => {
    const state = follow();
    const missing = decide({
      requestsAvailability: 'error',
      leases: { availability: 'unloaded', rows: [] },
    });
    expect(missing.retainedPending).toBe(true);
    expect(missing.continue).toBe(true);
    expect(missing.listedStatusWins).toBe(false);
    expect(
      openingEvidence({ status: 'analysing', lease: null, leaseList: 'unloaded' }).availability,
    ).toBe('not-an-opening');
    noteDecision(state, missing);

    const empty = decide({
      requestsAvailability: 'loaded',
      leases: { availability: 'unloaded', rows: [] },
      saw: state.saw,
    });
    expect(empty.retainedPending).toBe(true);
    expect(empty.continue).toBe(true);

    const listed = decide({
      requestsAvailability: 'loaded',
      resolved: { 'r-ask': held('analysing', 'listed') },
      leases: { availability: 'unloaded', rows: [] },
      saw: state.saw,
    });
    expect(listed).toMatchObject({
      retainedPending: false,
      listedStatusWins: true,
      continue: true,
      finalLeaseRefresh: false,
    });
    noteDecision(state, listed);

    const applied = lease('applied');
    const done = decide({
      requestsAvailability: 'loaded',
      resolved: { 'r-ask': held('auto_approved', 'listed') },
      leases: { availability: 'loaded', rows: [applied] },
      saw: state.saw,
      spent: state.spent,
    });
    expect(
      openingEvidence({ status: 'auto_approved', lease: applied, leaseList: 'loaded' }).execution,
    ).toBe('applied');
    expect(done).toMatchObject({ retainedPending: false, finalLeaseRefresh: true, continue: true });
    const round = startRefresh(state, done);
    acknowledgeRefresh(state, round, 'loaded');
    expect(state.spent).toBe(true);
    expect(
      decide({
        requestsAvailability: 'loaded',
        resolved: { 'r-ask': held('auto_approved', 'listed') },
        leases: { availability: 'loaded', rows: [applied] },
        saw: state.saw,
        spent: state.spent,
      }),
    ).toMatchObject({ continue: false, finalLeaseRefresh: false });
  });

  it('does not spend a lease read that a later result revealed during this round', () => {
    const state = follow();
    const started = decide({
      requestsAvailability: 'loaded',
      resolved: { 'r-ask': held('analysing', 'listed') },
      leases: { availability: 'loaded', rows: [] },
    });
    expect(started.finalLeaseRefresh).toBe(false);
    expect(started.confirmingIds).toEqual([]);
    const round = startRefresh(state, started);
    noteDecision(state, started);

    const revealed = decide({
      requestsAvailability: 'loaded',
      resolved: { 'r-ask': held('approved', 'listed') },
      leases: { availability: 'loaded', rows: [] },
      saw: state.saw,
      spent: state.spent,
    });
    expect(revealed.finalLeaseRefresh).toBe(true);
    expect(revealed.continue).toBe(true);
    expect(revealed.confirmingIds).toEqual(['r-ask']);

    acknowledgeRefresh(state, round, 'loaded');
    expect(state.spent).toBe(false);
    expect([...state.checked]).toEqual([]);
    expect(
      decide({
        requestsAvailability: 'loaded',
        resolved: { 'r-ask': held('approved', 'listed') },
        leases: { availability: 'loaded', rows: [] },
        saw: state.saw,
        spent: state.spent,
        checked: [...state.checked],
      }).finalLeaseRefresh,
    ).toBe(true);
  });

  it('an older round or an older sign-in cannot clear a newer debt', () => {
    const state = follow();
    noteDecision(
      state,
      decide({
        requestsAvailability: 'loaded',
        resolved: { 'r-ask': held('analysing', 'listed') },
        leases: { availability: 'loaded', rows: [] },
      }),
    );
    const owed = decide({
      requestsAvailability: 'loaded',
      resolved: { 'r-ask': held('approved', 'listed') },
      leases: { availability: 'loaded', rows: [] },
      saw: state.saw,
    });
    expect(owed.finalLeaseRefresh).toBe(true);
    const older = startRefresh(state, owed);
    const newer = startRefresh(state, owed);
    acknowledgeRefresh(state, older, 'loaded');
    expect(state.spent).toBe(false);
    expect([...state.checked]).toEqual([]);
    acknowledgeRefresh(state, newer, 'error');
    expect(state.finalFailed).toBe(true);
    expect(state.spent).toBe(false);
    expect(
      decide({
        requestsAvailability: 'loaded',
        resolved: { 'r-ask': held('approved', 'listed') },
        leases: { availability: 'error', rows: [] },
        saw: state.saw,
        failed: state.finalFailed,
        failedIds: [...state.failed],
      }),
    ).toMatchObject({ continue: false, finalLeaseRefresh: false, openingUnchecked: false });
    const unknown = openingEvidence({ status: 'approved', lease: null, leaseList: 'error' });
    expect(unknown).toMatchObject({ availability: 'unknown', retry: true, execution: null });
    deniesWithoutEvidence(unknown.explanation);

    allowRetry(state);
    const retry = startRefresh(
      state,
      decide({
        requestsAvailability: 'loaded',
        resolved: { 'r-ask': held('approved', 'listed') },
        leases: { availability: 'loaded', rows: [] },
        saw: state.saw,
        failed: state.finalFailed,
        failedIds: [...state.failed],
      }),
    );
    replaceSession(state);
    acknowledgeRefresh(state, retry, 'loaded');
    expect(state.session).toBe(2);
    expect(state.spent).toBe(false);
    expect(state.finalFailed).toBe(false);
    expect([...state.checked]).toEqual([]);
  });

  it('treats a loaded unconfirmed lease as unknown, even when execution says not applied', () => {
    const row = { ...lease('not_applied'), status: 'unconfirmed' as const, owned: false };
    const opening = openingEvidence({
      status: 'auto_approved',
      lease: row,
      leaseList: 'loaded',
    });
    expect(opening).toMatchObject({
      availability: 'unknown',
      retry: true,
      lease: row,
      execution: null,
      explanation: 'Not confirmed yet.',
    });
    deniesWithoutEvidence(opening.explanation);

    const stale = openingEvidence({
      status: 'auto_approved',
      lease: row,
      leaseList: 'error',
    });
    expect(stale).toMatchObject({
      availability: 'unknown',
      retry: true,
      lease: null,
      execution: null,
      explanation: 'Nyctr could not tell whether this site opened. You can try again.',
    });
    deniesWithoutEvidence(stale.explanation);

    expect(
      openingEvidence({
        status: 'auto_approved',
        lease: lease('not_applied'),
        leaseList: 'loaded',
      }),
    ).toMatchObject({
      availability: 'read',
      retry: false,
      execution: 'not_applied',
      explanation: 'The network was left unchanged.',
    });
  });

  it('does not let an in-flight lease read spend a watch a later request still owes', () => {
    const state = follow();
    const analysing = decide({
      view: 'requests',
      openRequestId: null,
      requestsAvailability: 'loaded',
      resolved: { 'r-a': held('analysing', 'listed', 'r-a') },
      leases: { availability: 'loaded', rows: [] },
    });
    noteDecision(state, analysing);
    const decided = decide({
      view: 'requests',
      openRequestId: null,
      requestsAvailability: 'loaded',
      resolved: { 'r-a': held('auto_approved', 'listed', 'r-a') },
      leases: { availability: 'loaded', rows: [lease('applied', 'r-a')] },
      saw: state.saw,
      spent: state.spent,
    });
    expect(decided.finalLeaseRefresh).toBe(true);
    const inflight = startRefresh(state, decided);
    expect(inflight.finalLeaseRefresh).toBe(true);

    const later = decide({
      view: 'requests',
      openRequestId: null,
      requestsAvailability: 'loaded',
      resolved: {
        'r-a': held('auto_approved', 'listed', 'r-a'),
        'r-b': held('analysing', 'listed', 'r-b'),
      },
      leases: { availability: 'loaded', rows: [lease('applied', 'r-a')] },
      saw: state.saw,
      spent: state.spent,
    });
    expect(later.undecided).toBe(true);
    noteDecision(state, later);
    expect(state.watch).toBeGreaterThan(inflight.watch);

    acknowledgeRefresh(state, inflight, 'loaded');
    expect(state.spent).toBe(false);
    expect(state.finalFailed).toBe(false);

    const bothDecided = decide({
      view: 'requests',
      openRequestId: null,
      requestsAvailability: 'loaded',
      resolved: {
        'r-a': held('auto_approved', 'listed', 'r-a'),
        'r-b': held('denied', 'listed', 'r-b'),
      },
      leases: { availability: 'loaded', rows: [lease('applied', 'r-a')] },
      saw: state.saw,
      spent: state.spent,
      failed: state.finalFailed,
      failedIds: [...state.failed],
    });
    expect(bothDecided.undecided).toBe(false);
    expect(bothDecided.finalLeaseRefresh).toBe(true);
    expect(bothDecided.continue).toBe(true);
    const trailing = startRefresh(state, bothDecided);
    acknowledgeRefresh(state, inflight, 'error');
    expect(state.spent).toBe(false);
    expect(state.finalFailed).toBe(false);
    acknowledgeRefresh(state, trailing, 'loaded');
    expect(state.spent).toBe(true);
    expect(
      decide({
        view: 'requests',
        openRequestId: null,
        requestsAvailability: 'loaded',
        resolved: {
          'r-a': held('auto_approved', 'listed', 'r-a'),
          'r-b': held('denied', 'listed', 'r-b'),
        },
        leases: { availability: 'loaded', rows: [lease('applied', 'r-a')] },
        saw: state.saw,
        spent: state.spent,
        checked: [...state.checked],
      }).continue,
    ).toBe(false);
  });

  it('still owes the trailing lease read when the request list fails after a listed decision', () => {
    const approved = { 'r-ask': held('auto_approved', 'listed') };
    for (const requestsAvailability of ['error', 'unloaded'] as const) {
      for (const availability of ['loaded', 'unloaded'] as const) {
        const owed = decide({
          view: 'requests',
          openRequestId: null,
          requestsAvailability,
          resolved: approved,
          leases: {
            availability,
            rows: availability === 'loaded' ? [lease('applied')] : [],
          },
          saw: true,
        });
        expect(owed.undecided).toBe(false);
        expect(owed.finalLeaseRefresh).toBe(true);
        expect(owed.continue).toBe(true);
        expect(owed.confirmingIds).toEqual([]);
        expect(owed.openingUnchecked).toBe(false);
      }
    }
  });
});

function gate<T>() {
  let resolve: (value: T) => void = () => {};
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function modelProps(extra: Partial<StatementModelInput> = {}): StatementModelInput {
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

const model = { current: null as ReturnType<typeof useStatementRequests> | null };

function Host(props: StatementModelInput) {
  model.current = useStatementRequests(props);
  return null;
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

describe('retained requests through the controller', () => {
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

  it('keeps request A while B is filed, and a missing lease stays unknown', async () => {
    const first = gate<unknown>();
    const second = gate<unknown>();
    const queue = [first.promise, second.promise];
    mockApi({
      'POST /statements': () => {
        const next = queue.shift();
        if (!next) throw new Error('no queued statement response');
        return next;
      },
    });
    const view = render(<Host {...modelProps()} />);
    begin('a.example');
    send();
    await act(async () => {
      first.resolve({
        matched: true,
        message: 'Filed',
        request: request({ id: 'r-a', domain: 'a.example', status: 'analysing' }),
      });
    });
    await waitFor(() => expect(use().kept('r-a')?.request.domain).toBe('a.example'));
    window.location.hash = '/portal';
    send('b.example');
    await act(async () => {
      second.resolve({
        matched: true,
        message: 'Filed',
        request: request({ id: 'r-b', domain: 'b.example', status: 'auto_approved' }),
      });
    });
    await waitFor(() => expect(use().kept('r-b')?.request.status).toBe('auto_approved'));

    const foreign = request({ id: 'r-kim', domain: 'kim.example', requester_id: 'kim' });
    view.rerender(
      <Host {...modelProps({ requests: { availability: 'error', rows: [foreign] } })} />,
    );
    expect(use().resolve('r-a')).toMatchObject({
      source: 'retained',
      request: { id: 'r-a', domain: 'a.example', status: 'analysing' },
    });
    expect(use().resolve('r-b').request?.domain).toBe('b.example');
    expect(use().resolve('r-kim').request).toBeNull();

    view.rerender(<Host {...modelProps({ requests: { availability: 'loaded', rows: [] } })} />);
    expect(use().resolve('r-a').request?.id).toBe('r-a');
    expect(use().resolve('r-b')).toMatchObject({
      source: 'retained',
      request: { id: 'r-b', status: 'auto_approved' },
    });

    const watching = newFollow();
    const absent = refreshNeed({
      view: 'request',
      openRequestId: 'r-a',
      resolve: (id) => use().resolve(id),
      watchIds: ['r-a', 'r-b', 'r-kim'],
      requestsAvailability: 'loaded',
      leases: { availability: 'unloaded', rows: [] },
      sawUndecided: watching.saw,
      spentFinal: watching.spent,
      finalFailed: watching.finalFailed,
      failedLeaseIds: [...watching.failed],
      checkedLeaseIds: [...watching.checked],
    });
    expect(absent.retainedPending).toBe(true);
    expect(absent.continue).toBe(true);
    expect(absent.listedStatusWins).toBe(false);
    noteDecision(watching, absent);
    const early = startRefresh(watching, absent);

    const listed = request({ id: 'r-a', domain: 'a.example', status: 'auto_approved' });
    const ownedB = request({ id: 'r-b', domain: 'b.example', status: 'auto_approved' });
    view.rerender(
      <Host
        {...modelProps({
          requests: { availability: 'loaded', rows: [listed, ownedB, foreign] },
        })}
      />,
    );
    expect(use().resolve('r-a')).toMatchObject({
      source: 'listed',
      request: { status: 'auto_approved', domain: 'a.example' },
    });
    expect(use().resolve('r-b')).toMatchObject({
      source: 'listed',
      request: { status: 'auto_approved', requester_id: 'sam' },
    });
    expect(use().resolve('r-kim').request).toBeNull();
    const decided = refreshNeed({
      view: 'request',
      openRequestId: 'r-a',
      resolve: (id) => use().resolve(id),
      watchIds: ['r-a', 'r-b'],
      requestsAvailability: 'loaded',
      leases: { availability: 'loaded', rows: [] },
      sawUndecided: watching.saw,
      spentFinal: watching.spent,
      finalFailed: watching.finalFailed,
      failedLeaseIds: [...watching.failed],
      checkedLeaseIds: [...watching.checked],
    });
    expect(decided.finalLeaseRefresh).toBe(true);
    expect(decided.continue).toBe(true);
    expect(decided.retainedPending).toBe(false);
    acknowledgeRefresh(watching, early, 'loaded');
    expect(watching.spent).toBe(false);
    const trailing = startRefresh(watching, decided);
    const unknown = describeOpening({
      request: use().resolve('r-a').request,
      lease: null,
      leaseList: 'error',
    });
    expect(unknown.request).toMatchObject({ id: 'r-a', domain: 'a.example' });
    expect(unknown.opening).toMatchObject({
      availability: 'unknown',
      retry: true,
      execution: null,
    });
    deniesWithoutEvidence(unknown.opening.explanation);
    acknowledgeRefresh(watching, trailing, 'error');
    expect(watching.finalFailed).toBe(true);
    expect(watching.spent).toBe(false);
    const stopped = refreshNeed({
      view: 'request',
      openRequestId: 'r-a',
      resolve: (id) => use().resolve(id),
      watchIds: ['r-a', 'r-b'],
      requestsAvailability: 'loaded',
      leases: { availability: 'error', rows: [] },
      sawUndecided: watching.saw,
      spentFinal: watching.spent,
      finalFailed: watching.finalFailed,
      failedLeaseIds: [...watching.failed],
      checkedLeaseIds: [...watching.checked],
    });
    expect(stopped.continue).toBe(false);
    expect(use().resolve('r-b').request?.domain).toBe('b.example');

    allowRetry(watching);
    const again = refreshNeed({
      view: 'request',
      openRequestId: 'r-a',
      resolve: (id) => use().resolve(id),
      watchIds: ['r-a'],
      requestsAvailability: 'loaded',
      leases: { availability: 'loaded', rows: [lease('applied', 'r-a')] },
      sawUndecided: watching.saw,
      spentFinal: watching.spent,
      finalFailed: watching.finalFailed,
      failedLeaseIds: [...watching.failed],
      checkedLeaseIds: [...watching.checked],
    });
    expect(again.continue).toBe(true);
    expect(again.finalLeaseRefresh).toBe(true);
    const finished = startRefresh(watching, again);
    acknowledgeRefresh(watching, finished, 'loaded');
    expect(watching.spent).toBe(true);
    expect(
      describeOpening({
        request: use().resolve('r-a').request,
        lease: lease('applied', 'r-a'),
        leaseList: 'loaded',
      }).opening,
    ).toMatchObject({ availability: 'read', retry: false, execution: 'applied' });
    expect(
      refreshNeed({
        view: 'request',
        openRequestId: 'r-a',
        resolve: (id) => use().resolve(id),
        watchIds: ['r-a', 'r-b'],
        requestsAvailability: 'loaded',
        leases: { availability: 'loaded', rows: [lease('applied', 'r-a')] },
        sawUndecided: watching.saw,
        spentFinal: watching.spent,
        finalFailed: watching.finalFailed,
        failedLeaseIds: [...watching.failed],
        checkedLeaseIds: [...watching.checked],
      }).continue,
    ).toBe(false);
  });
});
