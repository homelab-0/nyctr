import type { Integration } from '../types';

/** Sources with no stored collection behind them: never collected, or failed before storing anything. */
export function uncollected(sources: Integration[] | null | undefined, capability?: string) {
  return (sources || []).filter(
    (source) => !source.last_sync && (!capability || source.provides?.includes(capability)),
  );
}

/** Why such a source has nothing to show: it has not been collected yet, or the failure it gave. */
export const whyEmpty = (source: Integration) =>
  source.status === 'error'
    ? `${source.name} could not be collected: ${source.last_error || 'its last collection failed'}`
    : `${source.name} has not been collected yet`;
