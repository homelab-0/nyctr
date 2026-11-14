/** Builds the console route for something the attention list or the assistant points at. */
export function hrefFor(kind: string, id: string) {
  const value = encodeURIComponent(id);
  switch (kind) {
    case 'guest':
      return `#/guests?id=${value}`;
    case 'request':
      return `#/requests?id=${value}`;
    case 'finding':
      return `#/findings?id=${value}`;
    case 'lease':
    case 'suggestion':
      return '#/access';
    case 'source':
      return '#/sources';
    case 'resource':
      return `#/map?focus=${value}`;
    default:
      return '#/briefing';
  }
}

/**
 * Brings a chosen item's panel into view when its top is off the screen or low on it, as on a
 * phone, where the panel sits under the list it was chosen from. A panel already in view stays put.
 */
export function bringIntoView(panel: HTMLElement | null) {
  if (!panel?.scrollIntoView) return;
  const top = panel.getBoundingClientRect().top;
  if (top < 0 || top > window.innerHeight / 2)
    panel.scrollIntoView({ block: 'start', behavior: 'smooth' });
}

/** Opens the assistant, optionally with a question to ask straight away. */
export function askNyctr(question?: string, findingId?: string) {
  window.dispatchEvent(new CustomEvent('nyctr:ask', { detail: { question, findingId } }));
}
