// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest';
import { isAssistantKey, rememberShortcut, shortcutEnabled } from './shortcut';

/** Builds the part of a key event the shortcut looks at. */
function press(key: string, extra: Partial<KeyboardEvent> = {}, tag = 'DIV') {
  return {
    key,
    metaKey: false,
    ctrlKey: false,
    altKey: false,
    repeat: false,
    target: document.createElement(tag),
    ...extra,
  } as Pick<KeyboardEvent, 'key' | 'metaKey' | 'ctrlKey' | 'altKey' | 'repeat' | 'target'>;
}

describe('the assistant shortcut', () => {
  afterEach(() => window.localStorage.clear());

  /** The letter works on its own, in either case, outside anything a person types into. */
  it('toggles on a bare A outside form fields', () => {
    expect(isAssistantKey(press('a'), true)).toBe(true);
    expect(isAssistantKey(press('A'), true)).toBe(true);
    expect(isAssistantKey(press('b'), true)).toBe(false);
  });

  /** Typing, shortcuts with a modifier and a held key must never open the drawer. */
  it('ignores typing, modifier chords and key repeat', () => {
    for (const tag of ['INPUT', 'TEXTAREA', 'SELECT'])
      expect(isAssistantKey(press('a', {}, tag), true)).toBe(false);
    const editable = document.createElement('div');
    Object.defineProperty(editable, 'isContentEditable', { value: true });
    expect(isAssistantKey(press('a', { target: editable }), true)).toBe(false);
    expect(isAssistantKey(press('a', { ctrlKey: true }), true)).toBe(false);
    expect(isAssistantKey(press('a', { metaKey: true }), true)).toBe(false);
    expect(isAssistantKey(press('a', { altKey: true }), true)).toBe(false);
    expect(isAssistantKey(press('a', { repeat: true }), true)).toBe(false);
  });

  /** Turning it off stops the key entirely and the choice survives a reload of the page. */
  it('can be turned off and remembers the choice', () => {
    expect(shortcutEnabled()).toBe(true);
    rememberShortcut(false);
    expect(shortcutEnabled()).toBe(false);
    expect(isAssistantKey(press('a'), shortcutEnabled())).toBe(false);
    rememberShortcut(true);
    expect(shortcutEnabled()).toBe(true);
  });
});
