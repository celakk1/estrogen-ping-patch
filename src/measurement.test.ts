import { describe, expect, it } from 'vitest';
import { failurePercent, formatProbeMs, sampleLatency } from './measurement';
import { reportHtml } from './report';
import type { BenchmarkRun, Sample, Summary } from './types';

describe('protocol-specific measurements', () => {
  const summary: Summary = {
    attempted: 2,
    successful: 1,
    medianMs: 0,
    p95Ms: 0,
    p99Ms: 0,
    iqrMs: 0,
    successiveVariationMs: null,
  };

  it('keeps whole-millisecond echo reporting separate from missing RTT and precise TCP timings', () => {
    expect(formatProbeMs(0, 'icmpEcho')).toBe('<1 ms');
    expect(formatProbeMs(1, 'icmpEcho')).toBe('1.00 ms');
    expect(formatProbeMs(null, 'icmpEcho')).toBe('Unavailable');
    expect(formatProbeMs(Number.NaN, 'icmpEcho')).toBe('Unavailable');
    expect(formatProbeMs(0.25, 'tcpConnect')).toBe('0.25 ms');
  });

  it('does not reuse TCP failure percentages for unavailable echo timeout rates', () => {
    expect(failurePercent({ ...summary, connectionFailurePercent: 50 }, 'icmpEcho')).toBe(
      'Unavailable',
    );
    expect(failurePercent({ ...summary, echoTimeoutPercent: 50 }, 'icmpEcho')).toBe('50.0%');
    expect(failurePercent({ ...summary, echoTimeoutPercent: 50 }, 'tcpConnect')).toBe(
      'Unavailable',
    );
  });

  it('never substitutes a connection timer for a failed echo reply', () => {
    const sample: Sample = {
      endpointId: 'echo',
      address: '::1',
      timestamp: '',
      connectMs: 0,
      error: 'IP error',
      echo: {
        status: 'ipError',
        rttMs: null,
        rttUnitMs: 1,
        callDurationMs: 2,
        responder: null,
        responderScopeId: null,
        nativeCode: 11003,
      },
    };
    expect(sampleLatency(sample)).toBeNull();
    expect(sampleLatency({ ...sample, echo: undefined, connectMs: 0.25 })).toBe(0.25);
  });

  it('exports echo reports with protocol labels, error counts, and escaped sub-millisecond RTT', () => {
    const run: BenchmarkRun = {
      id: 1,
      startedAt: '',
      finishedAt: '',
      status: 'completed',
      appVersion: '0.1.0',
      protocol: 'icmpEcho',
      config: {
        schemaVersion: 1,
        profile: 'balanced',
        sampleCount: 3,
        intervalMs: 250,
        timeoutMs: 500,
        sessionMinutes: 1,
        maxDownloadBytes: 0,
        maxUploadBytes: 0,
        aiMode: 'disabled',
        cloudBudget: 0,
      },
      samples: [],
      results: [
        {
          endpoint: { id: '<unsafe>', address: '::1', protocol: 'icmpEcho' },
          summary,
          echoCounts: {
            replies: 1,
            timeouts: 0,
            ipErrors: 1,
            osErrors: 0,
            invalidReplies: 0,
            unsupported: 0,
          },
        },
      ],
    };
    const html = reportHtml(run);
    expect(html).toContain('ICMP echo RTT');
    expect(html).toContain('ICMP echo timeouts');
    expect(html).toContain('IP errors 1');
    expect(html).toContain('&lt;1 ms');
    expect(html).toContain('&lt;unsafe&gt;');
    expect(html).toContain('Unavailable');
    expect(html).not.toContain('TCP connection establishment');
    expect(html).not.toContain('Connection failures');
  });
});
