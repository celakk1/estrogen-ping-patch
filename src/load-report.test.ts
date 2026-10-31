import { describe, expect, it } from 'vitest';
import { formatMbps, loadReportHtml } from './load-report';
import type { LoadRun } from './load-types';

describe('transfer reports', () => {
  it('keeps missing and failed throughput unavailable', () => {
    expect(formatMbps(null)).toBe('Unavailable');
    expect(formatMbps(Number.NaN)).toBe('Unavailable');
    expect(formatMbps(12.345)).toBe('12.35 Mbps');
    const run = {
      id: 1,
      startedAt: '',
      finishedAt: '',
      appVersion: '0.1.0',
      status: 'partialFailure',
      config: {},
      plan: {},
      latencySamples: [],
      latencySummaries: [],
      transfers: [{ providerIndex: 0, phase: 'download', result: null, error: '<failed>' }],
    } as unknown as LoadRun;
    const html = loadReportHtml(run);
    expect(html).toContain('Unavailable');
    expect(html).toContain('&lt;failed&gt;');
    expect(html).toContain('Saturation is not guaranteed');
    expect(html).toContain('outside the payload budget');
    expect(html).not.toContain('0.00 Mbps');
    expect(html).not.toContain('Connection failures');
  });
});
