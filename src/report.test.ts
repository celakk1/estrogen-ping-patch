import { describe, expect, it } from 'vitest';
import { escapeHtml, formatMs, reportHtml } from './report';
import type { BenchmarkRun } from './types';

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
  it('explains a stopped test and escapes its server name in the readable report', () => {
    const run = {
      startedAt: '<time>',
      status: 'cancelled',
      appVersion: '0.1.0',
      protocol: 'icmpEcho',
      samples: [],
      results: [
        {
          endpoint: { id: '<server>', address: '127.0.0.1' },
          summary: { attempted: 3, successful: 1, medianMs: 1 },
        },
      ],
    } as unknown as BenchmarkRun;
    const html = reportHtml(run);
    expect(html).toContain('<h1>Connection test report</h1>');
    expect(html).toContain('This test did not finish');
    expect(html).toContain('Typical time');
    expect(html).toContain('Lower times mean faster replies');
    expect(html).toContain('&lt;server&gt;');
    expect(html).toContain('&lt;time&gt;');
    expect(html).not.toContain('<server>');
    expect(html).toContain('ICMP echo RTT');
  });
});
