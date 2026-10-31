import { describe, expect, it } from 'vitest';
import { escapeHtml, formatMs } from './report';

describe('measurement presentation', () => {
  it('does not invent zero latency for missing or invalid measurements', () => {
    expect(formatMs(null)).toBe('Unavailable');
    expect(formatMs(Number.NaN)).toBe('Unavailable');
    expect(formatMs(1.235)).toBe('1.24 ms');
  });
  it('escapes untrusted endpoint metadata in exported HTML', () => {
    expect(escapeHtml('<script>"&\'</script>')).toBe(
      '&lt;script&gt;&quot;&amp;&#39;&lt;/script&gt;',
    );
  });
});
