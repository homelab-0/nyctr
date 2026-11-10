import { describe, expect, it } from 'vitest';
import { ago, bytes, detectOs, left, span, word } from './format';

describe('formatting', () => {
  const now = Date.parse('2026-11-10T12:00:00Z');
  it('says ages and remaining time plainly and never treats a missing time as fresh', () => {
    expect(ago('2026-11-10T11:52:00Z', now)).toBe('8 min ago');
    expect(ago(null, now)).toBe('never');
    expect(ago('nonsense', now)).toBe('unknown time');
    expect(left('2026-11-10T12:38:10Z', now)).toBe('39 min left');
    expect(left('2026-11-10T14:05:00Z', now)).toBe('2 hr 5 min left');
    expect(left('2026-11-10T11:59:00Z', now)).toBeNull();
    expect(left(null, now)).toBeNull();
  });
  it('formats spans, sizes and small counts', () => {
    expect([span(45), span(60), span(120), span(1440)]).toEqual([
      '45 minutes',
      '1 hour',
      '2 hours',
      '1 day',
    ]);
    expect([bytes(undefined), bytes(9_400_000), bytes(2_300_000_000)]).toEqual([
      'nothing yet',
      '9 MB',
      '2.3 GB',
    ]);
    expect([word(0), word(5), word(14)]).toEqual(['No', 'Five', '14']);
  });
  it('picks reconnect steps from the browser, falling back to generic ones', () => {
    expect(detectOs('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)')).toBe('mac');
    expect(detectOs('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)')).toBe('iphone');
    expect(detectOs('Mozilla/5.0 (Linux; Android 15; Pixel 8)')).toBe('android');
    expect(detectOs('Mozilla/5.0 (Windows NT 10.0; Win64; x64)')).toBe('windows');
    expect(detectOs('Mozilla/5.0 (X11; Linux x86_64)')).toBe('other');
  });
});
