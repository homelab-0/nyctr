import type { Integration } from '../types';
import { counted } from './counts';

/** A source whose latest collection failed, whether or not an earlier one stored something. */
export const failing = (source: Integration) => source.status === 'error' || !!source.last_error;

/**
 * Sources with no working collection behind them now: never collected, or failing at the moment.
 * What a failing source stored earlier is still listed, but its counts and its silence are not current.
 */
export function uncollected(sources: Integration[] | null | undefined, capability?: string) {
  return (sources || []).filter(
    (source) =>
      (!source.last_sync || failing(source)) &&
      (!capability || source.provides?.includes(capability)),
  );
}

/** Why such a source has nothing current to show: not collected yet, or the failure it gave. */
export const whyEmpty = (source: Integration) =>
  failing(source)
    ? `${source.name} could not be collected: ${source.last_error || 'its last collection failed'}`
    : `${source.name} has not been collected yet`;

/** How many of the connected sources are waiting and how many are failing, as short sentences. */
export function waitingText(sources: Integration[] | null | undefined) {
  const waiting = uncollected(sources);
  const stuck = waiting.filter(failing).length;
  const of = `of ${counted(sources?.length || 0, 'source')}`;
  return [
    waiting.length > stuck ? `${waiting.length - stuck} ${of} not collected yet.` : '',
    stuck ? `${stuck} ${of} could not be collected.` : '',
  ]
    .filter(Boolean)
    .join(' ');
}
