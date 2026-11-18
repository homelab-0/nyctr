import type { AccessRequest, Execution, Lease } from '../../types';
import type {
  EvidenceList,
  ListAvailability,
  ResolvedRequest,
  StatementView,
} from './useStatementRequests';

/**
 * How a filed request is read again, and what a lease list is allowed to prove.
 * The page does not use this yet. A model score does not decide an opening.
 * Retention stays in the statement controller: pass its resolve function.
 * The round that started a read is the only round its completion may acknowledge.
 */

export interface OpeningEvidence {
  /**
   * `unknown`: the request was approved and the lease list did not load.
   * `read`: the lease list loaded. A null lease was really absent.
   * `not-an-opening`: this request is not an approval, so a missing lease is not an opening.
   */
  availability: 'unknown' | 'read' | 'not-an-opening';
  retry: boolean;
  lease: Lease | null;
  /** Copied from a loaded lease. Null when the list did not load or the lease is absent. */
  execution: Execution | null;
  /** Plain words for the member. Null when this request is not an opening. */
  explanation: string | null;
}

export interface RefreshNeed {
  /** The open request page, or the request list, should read again. The timer stays upstairs. */
  continue: boolean;
  /** A remembered pending or analysing request is not on the loaded list. */
  retainedPending: boolean;
  /** The loaded list has the remembered request, so that row's status is the one that counts. */
  listedStatusWins: boolean;
  /** The requests became decided and the one trailing lease read has not happened. */
  finalLeaseRefresh: boolean;
  /** An approved request is open and the lease list is not loaded. */
  openingUnchecked: boolean;
}

export interface RefreshDecision extends RefreshNeed {
  undecided: boolean;
  confirmingIds: string[];
}

/** One sign-in's watch. `round` is the newest read this sign-in has started. */
export interface RefreshFollow {
  session: number;
  round: number;
  saw: boolean;
  /** The trailing lease read completed with a loaded list. */
  spent: boolean;
  /** That read failed. Automatic watching stops. The member can retry. */
  finalFailed: boolean;
  checked: Set<string>;
}

/** Debt captured when a read starts. A later decision is not this round's to clear. */
export interface RefreshRound {
  session: number;
  round: number;
  finalLeaseRefresh: boolean;
  confirmingIds: readonly string[];
  openingUnchecked: boolean;
}

const UNDECIDED = new Set(['pending', 'analysing']);
const APPROVED = new Set(['approved', 'auto_approved']);

const UNKNOWN_EXPLANATION = 'Nyctr could not tell whether this site opened. You can try again.';

function executionExplanation(execution: Execution): string {
  switch (execution) {
    case 'applied':
      return 'The network opened this site.';
    case 'simulated':
      return 'Nyctr practised this opening and left the network as it was.';
    case 'not_applied':
      return 'The network was left unchanged.';
    case 'failed':
      return 'Nyctr tried to open this site, and the network was left unchanged.';
  }
}

/**
 * An approval with no loaded lease list is unknown.
 * It is not described as unapplied, and it does not become a request for a person to decide.
 */
export function openingEvidence(input: {
  status: string | null;
  lease: Lease | null;
  leaseList: ListAvailability;
}): OpeningEvidence {
  if (!input.status || !APPROVED.has(input.status)) {
    return {
      availability: 'not-an-opening',
      retry: false,
      lease: null,
      execution: null,
      explanation: null,
    };
  }
  if (input.leaseList !== 'loaded') {
    return {
      availability: 'unknown',
      retry: true,
      lease: null,
      execution: null,
      explanation: UNKNOWN_EXPLANATION,
    };
  }
  const execution = input.lease?.execution ?? null;
  return {
    availability: 'read',
    retry: false,
    lease: input.lease,
    execution,
    explanation: execution
      ? executionExplanation(execution)
      : 'Nyctr found no opening recorded for this request.',
  };
}

/** The retained request stays with the opening verdict. A missing lease list does not replace it. */
export function describeOpening(input: {
  request: AccessRequest | null;
  lease: Lease | null;
  leaseList: ListAvailability;
}): { request: AccessRequest | null; opening: OpeningEvidence } {
  return {
    request: input.request,
    opening: openingEvidence({
      status: input.request?.status ?? null,
      lease: input.lease,
      leaseList: input.leaseList,
    }),
  };
}

export function newFollow(): RefreshFollow {
  return {
    session: 1,
    round: 0,
    saw: false,
    spent: false,
    finalFailed: false,
    checked: new Set(),
  };
}

/** A new sign-in drops the previous watch, including a read that has not come back. */
export function replaceSession(follow: RefreshFollow) {
  follow.session += 1;
  follow.round = 0;
  follow.saw = false;
  follow.spent = false;
  follow.finalFailed = false;
  follow.checked = new Set();
}

/** The member asked to read the lease list again after a failed read. */
export function allowRetry(follow: RefreshFollow) {
  follow.finalFailed = false;
}

/** Records that a render still saw an undecided request, so one later lease read can be owed. */
export function noteDecision(follow: RefreshFollow, decision: RefreshDecision) {
  if (decision.undecided) {
    follow.saw = true;
    follow.spent = false;
    follow.finalFailed = false;
  }
}

/**
 * Captures the debt this read is allowed to clear.
 * A newer round, or a later sign-in, keeps its own debt.
 */
export function startRefresh(follow: RefreshFollow, decision: RefreshDecision): RefreshRound {
  follow.round += 1;
  return {
    session: follow.session,
    round: follow.round,
    finalLeaseRefresh: decision.finalLeaseRefresh,
    confirmingIds: decision.confirmingIds.slice(),
    openingUnchecked: decision.openingUnchecked,
  };
}

/**
 * Spends only the debt captured when this round started, and only if this round is still current.
 * A loaded list can clear that debt. Any other result stops the automatic watch and leaves a retry.
 */
export function acknowledgeRefresh(
  follow: RefreshFollow,
  round: RefreshRound,
  outcome: ListAvailability,
) {
  if (round.session !== follow.session || round.round !== follow.round) return;
  const owed = round.finalLeaseRefresh || round.confirmingIds.length > 0 || round.openingUnchecked;
  if (!owed) return;
  if (outcome === 'loaded') {
    if (round.finalLeaseRefresh) follow.spent = true;
    follow.finalFailed = false;
    for (const id of round.confirmingIds) follow.checked.add(id);
    return;
  }
  follow.finalFailed = true;
  follow.spent = false;
}

function watchedIds(watchIds: readonly string[], openRequestId: string | null) {
  const ids = [...watchIds];
  if (openRequestId && !ids.includes(openRequestId)) ids.push(openRequestId);
  return ids;
}

export function refreshNeed(input: {
  view: StatementView;
  openRequestId: string | null;
  /** The controller's resolve. Rows from an error or unloaded list are not passed in. */
  resolve: (requestId: string) => ResolvedRequest;
  watchIds: readonly string[];
  /** Whether the request list that resolve just saw was a loaded list. */
  requestsAvailability: ListAvailability;
  leases: EvidenceList<Lease>;
  sawUndecided: boolean;
  spentFinal: boolean;
  finalFailed: boolean;
  checkedLeaseIds: readonly string[];
}): RefreshDecision {
  const listLoaded = input.requestsAvailability === 'loaded';
  let retainedPending = false;
  let listedStatusWins = false;
  let undecided = false;
  const resolved: { id: string; result: ResolvedRequest }[] = [];
  for (const id of watchedIds(input.watchIds, input.openRequestId)) {
    const result = input.resolve(id);
    if (!result.request) continue;
    resolved.push({ id, result });
    if (!UNDECIDED.has(result.request.status)) continue;
    undecided = true;
    if (listLoaded && result.source === 'listed') listedStatusWins = true;
    else retainedPending = true;
  }
  const watching = input.view === 'request' || input.view === 'requests';
  const leasesLoaded = input.leases.availability === 'loaded';
  const leaseIds = new Set(
    leasesLoaded
      ? input.leases.rows.flatMap((row) => (row.request_id ? [row.request_id] : []))
      : [],
  );
  const confirmingIds =
    !undecided && listLoaded && leasesLoaded && !input.finalFailed
      ? resolved
          .filter((row) => {
            if (!watching) return false;
            if (input.view === 'request' && row.id !== input.openRequestId) return false;
            const status = row.result.request?.status;
            return (
              !!status &&
              APPROVED.has(status) &&
              !leaseIds.has(row.id) &&
              !input.checkedLeaseIds.includes(row.id)
            );
          })
          .map((row) => row.id)
      : [];
  const finalLeaseRefresh =
    input.sawUndecided && !undecided && listLoaded && !input.spentFinal && !input.finalFailed;
  const open = input.openRequestId
    ? resolved.find((row) => row.id === input.openRequestId)?.result.request
    : undefined;
  const openingUnchecked = Boolean(
    watching &&
    input.view === 'request' &&
    input.openRequestId &&
    !leasesLoaded &&
    !input.finalFailed &&
    open &&
    APPROVED.has(open.status),
  );
  return {
    continue:
      watching && (undecided || openingUnchecked || finalLeaseRefresh || confirmingIds.length > 0),
    retainedPending,
    listedStatusWins,
    finalLeaseRefresh,
    openingUnchecked,
    undecided,
    confirmingIds,
  };
}
