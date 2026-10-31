import { describe, expect, it } from 'vitest';
import { baselineLimitSeconds, runExplanation } from './benchmark-guide';
import type { BenchmarkRun, Config } from './types';

const config: Config = {
  schemaVersion: 1,
  profile: 'balanced',
  sampleCount: 12,
  intervalMs: 500,
  timeoutMs: 1500,
  sessionMinutes: 15,
  maxDownloadBytes: 100_000_000,
  maxUploadBytes: 25_000_000,
  aiMode: 'disabled',
  cloudBudget: 0,
};
function run(successful: number, attempted: number, status = 'completed'): BenchmarkRun {
  return {
    id: 1,
    startedAt: '',
    finishedAt: '',
    appVersion: '0.1.0',
    status,
    protocol: 'icmpEcho',
    config,
    samples: [],
    results: [0, 1].map((index) => ({
      endpoint: { id: `server ${index}`, address: '127.0.0.1', protocol: 'icmpEcho' },
      summary: {
        successful,
        attempted,
        medianMs: successful ? 1 : null,
        p95Ms: null,
        p99Ms: null,
        iqrMs: null,
        successiveVariationMs: null,
      },
    })),
  };
}

describe('beginner benchmark explanations', () => {
  it('bases the displayed time allowance on actual request and deadline limits', () => {
    expect(baselineLimitSeconds(config)).toBe(48);
    expect(baselineLimitSeconds({ ...config, sampleCount: 120, sessionMinutes: 1 })).toBe(60);
    expect(baselineLimitSeconds({ ...config, sampleCount: Number.NaN })).toBeNull();
    expect(baselineLimitSeconds(null)).toBeNull();
  });
  it('does not describe a stopped or empty test as a successful connection', () => {
    expect(runExplanation(run(3, 3, 'cancelled')).title).toBe('This test did not finish');
    expect(runExplanation(run(0, 0)).title).toBe('No response times measured');
    expect(runExplanation(run(0, 3)).detail).toContain('block ping');
  });
  it('keeps failures specific to the measurement instead of diagnosing game packet loss', () => {
    const partial = run(2, 3);
    expect(runExplanation(partial).title).toBe('Some checks did not succeed');
    expect(runExplanation(partial).detail).toContain(
      'do not directly measure packet loss in games',
    );
    expect(runExplanation({ ...partial, protocol: 'dnsLookup' }).detail).toContain(
      'alone cannot tell us what went wrong',
    );
  });
  it('describes complete replies as a snapshot rather than a universal health score', () => {
    const result = runExplanation(run(3, 3));
    expect(result.title).toBe('All checks succeeded');
    expect(result.detail).toContain('these servers at this time');
    expect(result.detail).toContain('Repeat the same test');
  });
});
