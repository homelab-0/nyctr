import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { post } from '../../api';
import type { AccessRequest } from '../../types';

/**
 * Files a site a member typed and remembers that request for this sign-in.
 * The portal does not mount this yet, and nothing here turns access on.
 * A model score and the administrator switch are not inputs.
 * Opening evidence and repeated reading live in a later change.
 */

export interface StatementDraft {
  formId: number;
  revision: number;
  site: string;
}

export interface StatementFlight {
  userId: string;
  deviceId: string;
  formId: number;
  flight: number;
  revision: number;
  site: string;
  phase: 'pending' | 'settled';
  message: string | null;
}

export interface KeptStatement {
  userId: string;
  deviceId: string;
  formId: number;
  flight: number;
  revision: number;
  site: string;
  request: AccessRequest;
  /** The request list was read again after this filing. */
  refreshed: boolean;
  /** The member had already left the form, so the page must not jump back. */
  parked: boolean;
}

/** One mounted form. `next` only grows, so a new visit never reuses an old id. */
export interface StatementVisits {
  next: number;
  mounted: number;
}

/** Home does not follow a filed request into another view. */
export type StatementView = 'home' | 'request' | 'requests' | 'devices' | 'block';

/**
 * `loaded` is the only state whose rows are evidence.
 * `error` and `unloaded` are not an empty result, and their rows are not read.
 * A loaded row belongs to this sign-in only when its requester is the signed-in member.
 * A row taken from such a list stays until a later loaded list omits it, or this sign-in ends.
 * Omitting it drops the remembered copy, and a submit already started cannot put it back.
 * A submit started after that omission can file the same request again.
 * A request this sign-in accepted, and no loaded list has shown, stays as filed.
 * While a loaded list is on screen, the remembered request shows that list's row.
 * While the list is not loaded, a request the list has shown keeps that decision.
 * A newer filing of that request keeps the visit it was sent from.
 * The notice is the newest request this list still shows for the signed-in member.
 * If none remain, there is no notice.
 * The signed-in member changes only when that render commits.
 * That commit closes the open visit and clears its draft. The caller starts a new visit afterward.
 * Visit ids only grow. A render that is thrown away leaves the visit and the draft in place.
 * Filing sends only the open visit, and only its current text, revision, and id.
 * An accepted Forget drops that device's returned request before it is kept, noted, or followed.
 * A newer ask on that device stays. Clearing one flight does not clear the other.
 */
export type ListAvailability = 'loaded' | 'error' | 'unloaded';

export interface EvidenceList<T> {
  availability: ListAvailability;
  rows: readonly T[];
}

export interface ResolvedRequest {
  request: AccessRequest | null;
  source: 'listed' | 'retained' | 'none';
  /** The follow-up read finished and the list still has no row for this id. */
  filedButUnlisted: boolean;
}

export interface StatementModelInput {
  userId: string;
  deviceId: string;
  view: StatementView;
  openRequestId: string | null;
  blockId: string | null;
  requests: EvidenceList<AccessRequest>;
  /** Reads the request list again. It does not read the device. */
  reloadEvidence: () => Promise<void>;
}

interface StatementAnswer {
  matched: boolean;
  message: string;
  request?: AccessRequest;
}

interface Stamp {
  userId: string;
  deviceId: string;
  site: string;
  revision: number;
  formId: number;
  flight: number;
  /** Which sign-in filed this. Returning to the same member is a later one. */
  generation: number;
}

interface Busy {
  formId: number;
  revision: number;
  deviceId: string;
  flight: number;
  generation: number;
}

const keptKey = (userId: string, requestId: string) => `${userId}:${requestId}`;

/** The note on the form names the latest request. Older ones stay reachable by id. */
function newestKept(rows: ReadonlyMap<string, KeptStatement>, userId: string) {
  let best: KeptStatement | null = null;
  for (const row of rows.values()) {
    if (row.userId !== userId) continue;
    if (!best || row.flight > best.flight) best = row;
  }
  return best;
}

/** The visit stays as filed. A loaded row replaces only the request body a reader sees. */
function withLoadedBody(
  stored: KeptStatement,
  userId: string,
  requests: EvidenceList<AccessRequest>,
): KeptStatement {
  if (requests.availability !== 'loaded') return stored;
  const listed =
    requests.rows.find((row) => row.id === stored.request.id && row.requester_id === userId) ??
    null;
  if (!listed || listed === stored.request) return stored;
  return { ...stored, request: listed };
}

/**
 * A loaded list supplies the body. When the list is unavailable, the body last taken
 * from a loaded list stays, and the filing keeps its own visit. Rows on an error or
 * unloaded list are ignored. A request no loaded list has shown keeps the filed answer.
 */
function shownFiling(
  stored: KeptStatement,
  userId: string,
  requests: EvidenceList<AccessRequest>,
  remembered: ReadonlyMap<string, AccessRequest>,
): KeptStatement {
  if (requests.availability === 'loaded') return withLoadedBody(stored, userId, requests);
  const earlier = remembered.get(keptKey(userId, stored.request.id)) ?? null;
  if (!earlier || earlier.requester_id !== userId || earlier === stored.request) return stored;
  return { ...stored, request: earlier };
}

/** A loaded list left out an id it had already shown for this member. */
function omittedByLoadedList(
  userId: string,
  requestId: string,
  requests: EvidenceList<AccessRequest>,
  remembered: ReadonlyMap<string, AccessRequest>,
): boolean {
  if (requests.availability !== 'loaded') return false;
  if (!remembered.has(keptKey(userId, requestId))) return false;
  return !requests.rows.some((row) => row.id === requestId && row.requester_id === userId);
}

function readKept(
  userId: string,
  requestId: string,
  requests: EvidenceList<AccessRequest>,
  retained: ReadonlyMap<string, KeptStatement>,
  remembered: ReadonlyMap<string, AccessRequest>,
): KeptStatement | null {
  if (omittedByLoadedList(userId, requestId, requests, remembered)) return null;
  const stored = retained.get(keptKey(userId, requestId)) ?? null;
  if (!stored || stored.userId !== userId) return null;
  return shownFiling(stored, userId, requests, remembered);
}

/** Newest filing this sign-in can still show. This read does not change the maps. */
function newestVisible(
  userId: string,
  requests: EvidenceList<AccessRequest>,
  retained: ReadonlyMap<string, KeptStatement>,
  remembered: ReadonlyMap<string, AccessRequest>,
): KeptStatement | null {
  let best: KeptStatement | null = null;
  for (const row of retained.values()) {
    const shown = readKept(userId, row.request.id, requests, retained, remembered);
    if (!shown) continue;
    if (!best || shown.flight > best.flight) best = shown;
  }
  return best;
}

function resolveKept(
  userId: string,
  requestId: string,
  requests: EvidenceList<AccessRequest>,
  retained: ReadonlyMap<string, KeptStatement>,
  remembered: ReadonlyMap<string, AccessRequest>,
): ResolvedRequest {
  const key = keptKey(userId, requestId);
  if (requests.availability === 'loaded') {
    const listed =
      requests.rows.find((row) => row.id === requestId && row.requester_id === userId) ?? null;
    if (listed) return { request: listed, source: 'listed', filedButUnlisted: false };
    if (omittedByLoadedList(userId, requestId, requests, remembered)) {
      return { request: null, source: 'none', filedButUnlisted: false };
    }
  } else {
    const earlier = remembered.get(key) ?? null;
    if (earlier?.requester_id === userId) {
      return { request: earlier, source: 'listed', filedButUnlisted: false };
    }
  }
  const kept = retained.get(key) ?? null;
  if (kept && kept.userId === userId) {
    return { request: kept.request, source: 'retained', filedButUnlisted: kept.refreshed };
  }
  return { request: null, source: 'none', filedButUnlisted: false };
}

function reconcileLoaded(
  userId: string,
  rows: readonly AccessRequest[],
  retained: Map<string, KeptStatement>,
  remembered: Map<string, AccessRequest>,
  retired: Map<string, number>,
  flightNow: number,
) {
  const prefix = `${userId}:`;
  const seen = new Set<string>();
  for (const row of rows) {
    if (row.requester_id !== userId) continue;
    const key = keptKey(userId, row.id);
    seen.add(key);
    remembered.set(key, row);
    const stored = retained.get(key);
    if (stored) retained.set(key, { ...stored, request: row });
  }
  for (const key of [...remembered.keys()]) {
    if (!key.startsWith(prefix) || seen.has(key)) continue;
    const mark = retired.get(key);
    if (mark === undefined || flightNow > mark) retired.set(key, flightNow);
    remembered.delete(key);
    retained.delete(key);
  }
}

/**
 * Owns the visit, the draft, and every accepted request for this sign-in.
 * The device id is the one the API already returned. This hook does not decide it.
 */
export function useStatementRequests(input: StatementModelInput) {
  const [ask, setAsk] = useState<StatementFlight | null>(null);
  const [, setNotice] = useState<KeptStatement | null>(null);
  const inputRef = useRef(input);
  const visits = useRef<StatementVisits>({ next: 0, mounted: 0 });
  const draft = useRef<StatementDraft>({ formId: 0, revision: 0, site: '' });
  const kept = useRef(new Map<string, KeptStatement>());
  const listed = useRef(new Map<string, AccessRequest>());
  const flight = useRef(0);
  const generation = useRef(0);
  const committedUser = useRef(input.userId);
  /** Submit flight at which a loaded list retired this id. Older submits stay retired. */
  const retiredFlight = useRef(new Map<string, number>());
  const left = useRef(false);
  const busy = useRef<Busy | null>(null);
  const revoked = useRef(new Set<string>());

  // A discarded render must not publish its member or its list. This runs before
  // paint, so a committed sign-in blocks an older answer before that answer can land.
  useLayoutEffect(() => {
    if (committedUser.current !== input.userId) {
      committedUser.current = input.userId;
      generation.current += 1;
      kept.current.clear();
      listed.current.clear();
      retiredFlight.current.clear();
      revoked.current.clear();
      busy.current = null;
      visits.current.mounted = 0;
      draft.current = { formId: 0, revision: 0, site: '' };
    }
    inputRef.current = input;
    if (input.requests.availability === 'loaded') {
      reconcileLoaded(
        input.userId,
        input.requests.rows,
        kept.current,
        listed.current,
        retiredFlight.current,
        flight.current,
      );
    }
  });

  useEffect(() => {
    left.current = false;
    return () => {
      left.current = true;
    };
  }, []);

  useEffect(() => {
    setAsk((current) => (current && current.userId === input.userId ? current : null));
    setNotice((current) => (current && current.userId === input.userId ? current : null));
  }, [input.userId]);

  const releaseBusy = (stamp: Stamp) => {
    if (busy.current?.flight === stamp.flight) busy.current = null;
  };

  const stillHere = (stamp: Stamp) => {
    const place = inputRef.current;
    const current = draft.current;
    return (
      !left.current &&
      generation.current === stamp.generation &&
      !revoked.current.has(stamp.deviceId) &&
      visits.current.mounted === stamp.formId &&
      current.formId === stamp.formId &&
      current.revision === stamp.revision &&
      place.deviceId === stamp.deviceId &&
      place.userId === stamp.userId &&
      flight.current === stamp.flight
    );
  };

  const clearRevoked = (stamp: Stamp) => {
    if (revoked.current.has(stamp.deviceId) && flight.current === stamp.flight) setAsk(null);
  };

  const sameSession = (stamp: Stamp) =>
    !left.current &&
    inputRef.current.userId === stamp.userId &&
    generation.current === stamp.generation;

  /** Records a successful Forget before the caller reads the device again. */
  const acceptForget = useCallback((deviceId: string) => {
    revoked.current.add(deviceId);
  }, []);

  /** Starts one visit. A later call is a new visit and never reuses this id. */
  const openForm = useCallback(() => {
    const formId = ++visits.current.next;
    visits.current.mounted = formId;
    draft.current = { formId, revision: 0, site: '' };
    return formId;
  }, []);

  /** Drops this visit only when a newer one has not already taken the page. */
  const closeForm = useCallback((formId: number) => {
    if (visits.current.mounted === formId) visits.current.mounted = 0;
  }, []);

  /** The next revision of the open visit. The text replaces what was there. */
  const editDraft = useCallback((site: string) => {
    const current = draft.current;
    const revision = current.revision + 1;
    draft.current = { ...current, revision, site };
    return revision;
  }, []);

  const file = useCallback((site: string, revision: number, formId: number) => {
    const seen = inputRef.current;
    const open = draft.current;
    if (
      !seen.userId ||
      !seen.deviceId ||
      !site.trim() ||
      formId === 0 ||
      visits.current.mounted !== formId ||
      open.formId !== formId ||
      open.revision !== revision ||
      open.site !== site
    ) {
      return;
    }
    if (
      busy.current?.generation === generation.current &&
      busy.current.formId === formId &&
      busy.current.revision === revision &&
      busy.current.deviceId === seen.deviceId
    ) {
      return;
    }
    const stamp: Stamp = {
      userId: seen.userId,
      deviceId: seen.deviceId,
      site,
      revision,
      formId,
      flight: ++flight.current,
      generation: generation.current,
    };
    busy.current = {
      formId,
      revision,
      deviceId: seen.deviceId,
      flight: stamp.flight,
      generation: stamp.generation,
    };
    setAsk({ ...stamp, phase: 'pending', message: null });
    void (async () => {
      try {
        const answer = await post<StatementAnswer>('/statements', { domain: site });
        if (!sameSession(stamp)) {
          releaseBusy(stamp);
          return;
        }
        if (answer.request) {
          if (revoked.current.has(stamp.deviceId)) {
            setAsk((current) => (current && current.flight === stamp.flight ? null : current));
            releaseBusy(stamp);
            return;
          }
          // Read the address bar itself. The route props can still say the form is open.
          const place = inputRef.current;
          const addressIsForm =
            window.location.hash === '#/portal' &&
            place.view === 'home' &&
            place.openRequestId === null &&
            place.blockId === null;
          const stay = stillHere(stamp) && addressIsForm;
          const drafted: KeptStatement = {
            ...stamp,
            request: answer.request,
            refreshed: false,
            parked: !stay,
          };
          const key = keptKey(stamp.userId, answer.request.id);
          const retired = retiredFlight.current.get(key);
          if (retired !== undefined && stamp.flight <= retired) {
            if (stillHere(stamp)) setAsk(null);
            releaseBusy(stamp);
            return;
          }
          const filed = shownFiling(drafted, stamp.userId, place.requests, listed.current);
          const previous = kept.current.get(key);
          if (!previous || previous.flight <= stamp.flight) kept.current.set(key, filed);
          setNotice(newestKept(kept.current, stamp.userId));
          if (stay) window.location.hash = `/portal?request=${answer.request.id}`;
          let refreshed = false;
          try {
            await place.reloadEvidence();
            refreshed = true;
          } catch {
            refreshed = false;
          }
          if (!sameSession(stamp)) {
            releaseBusy(stamp);
            return;
          }
          const stored = kept.current.get(key);
          if (stored?.flight === stamp.flight) {
            kept.current.set(key, { ...stored, refreshed });
            setNotice(newestKept(kept.current, stamp.userId));
          }
          if (stillHere(stamp)) setAsk({ ...stamp, phase: 'settled', message: null });
          else clearRevoked(stamp);
          releaseBusy(stamp);
          return;
        }
        if (!stillHere(stamp)) {
          clearRevoked(stamp);
          releaseBusy(stamp);
          return;
        }
        setAsk({ ...stamp, phase: 'settled', message: answer.message });
        releaseBusy(stamp);
      } catch (caught) {
        if (!stillHere(stamp)) {
          clearRevoked(stamp);
          releaseBusy(stamp);
          return;
        }
        const message =
          caught instanceof Error ? caught.message : 'Nyctr could not take that request.';
        setAsk({ ...stamp, phase: 'settled', message });
        releaseBusy(stamp);
      }
    })();
  }, []);

  const memberAsk = ask && ask.userId === input.userId ? ask : null;
  const memberNotice = newestVisible(input.userId, input.requests, kept.current, listed.current);
  return {
    ask: memberAsk,
    notice: memberNotice,
    visits,
    draft,
    openForm,
    closeForm,
    editDraft,
    kept: (requestId: string) =>
      readKept(input.userId, requestId, input.requests, kept.current, listed.current),
    resolve: (requestId: string) =>
      resolveKept(input.userId, requestId, input.requests, kept.current, listed.current),
    file,
    acceptForget,
  };
}
