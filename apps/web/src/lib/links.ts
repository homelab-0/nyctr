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

/** Opens the assistant, optionally with a question to ask straight away. */
export function askNyctr(question?: string, findingId?: string) {
  window.dispatchEvent(new CustomEvent('nyctr:ask', { detail: { question, findingId } }));
}
