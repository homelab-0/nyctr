/**
 * The one single-key shortcut in the console: A opens or closes the assistant.
 *
 * A bare letter can be triggered by accident, and by speech input in particular, so it must be
 * possible to turn it off (WCAG 2.1.4). The choice is a per-browser convenience kept in local
 * storage; storage can be unavailable, in which case the shortcut simply stays on for the visit.
 */
const KEY = 'nyctr.assistant-key';

/** Reads whether the A shortcut is on. Defaults to on when nothing was saved or storage fails. */
export function shortcutEnabled(): boolean {
  try {
    return window.localStorage.getItem(KEY) !== 'off';
  } catch {
    return true;
  }
}

/** Remembers the choice for this browser. A failed write only means it is not remembered. */
export function rememberShortcut(enabled: boolean) {
  try {
    window.localStorage.setItem(KEY, enabled ? 'on' : 'off');
  } catch {
    // Private windows and blocked site data: the choice still applies until the page reloads.
  }
}

/**
 * Decides whether a key press should toggle the assistant. Never while typing, never with a
 * modifier held, never from a key held down, and never when the person turned the shortcut off.
 */
export function isAssistantKey(
  event: Pick<KeyboardEvent, 'key' | 'metaKey' | 'ctrlKey' | 'altKey' | 'repeat' | 'target'>,
  enabled: boolean,
): boolean {
  if (!enabled || event.repeat || event.metaKey || event.ctrlKey || event.altKey) return false;
  const target = event.target as HTMLElement | null;
  if (target && (/^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName) || target.isContentEditable))
    return false;
  return event.key.toLowerCase() === 'a';
}
