import type { ProbeProtocol, Sample, Summary } from './types';
export const formatMs = (value: number | null | undefined): string =>
  value == null || !Number.isFinite(value) ? 'Unavailable' : `${value.toFixed(2)} ms`;

export function sampleLatency(sample: Sample): number | null {
  return sample.echo ? sample.echo.rttMs : sample.connectMs;
}

export function formatProbeMs(value: number | null | undefined, protocol: ProbeProtocol): string {
  if (protocol === 'icmpEcho' && value != null && Number.isFinite(value) && value >= 0 && value < 1)
    return '<1 ms';
  return formatMs(value);
}

export function failurePercent(summary: Summary | undefined, protocol: ProbeProtocol): string {
  const value =
    protocol === 'icmpEcho' ? summary?.echoTimeoutPercent : summary?.connectionFailurePercent;
  return value == null || !Number.isFinite(value) ? 'Unavailable' : `${value.toFixed(1)}%`;
}

export const protocolNotes: Record<ProbeProtocol, string> = {
  tcpConnect:
    'Connection time includes TCP handshake overhead. This is not a throughput, ICMP loss, or loaded-latency test.',
  icmpEcho:
    'Windows reports ICMP echo RTT in whole milliseconds; a raw zero is shown as <1 ms. ICMP may be blocked or rate-limited. Echo timeouts are not application packet loss. Timeout percentage is unavailable when IP, system, or invalid-reply errors occur. This test does not measure throughput or loaded latency.',
};
