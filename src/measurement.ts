import type { DnsCounts, DnsOutcome, ProbeProtocol, Sample, Summary } from './types';
export const formatMs = (value: number | null | undefined): string =>
  value == null || !Number.isFinite(value) ? 'Unavailable' : `${value.toFixed(2)} ms`;

export function sampleLatency(sample: Sample): number | null {
  return sample.dns ? sample.dns.lookupMs : sample.echo ? sample.echo.rttMs : sample.connectMs;
}

export function formatProbeMs(value: number | null | undefined, protocol: ProbeProtocol): string {
  if (protocol === 'icmpEcho' && value != null && Number.isFinite(value) && value >= 0 && value < 1)
    return '<1 ms';
  return formatMs(value);
}

export function failurePercent(summary: Summary | undefined, protocol: ProbeProtocol): string {
  const value =
    protocol === 'dnsLookup'
      ? summary?.dnsFailurePercent
      : protocol === 'icmpEcho'
        ? summary?.echoTimeoutPercent
        : summary?.connectionFailurePercent;
  return value == null || !Number.isFinite(value) ? 'Unavailable' : `${value.toFixed(1)}%`;
}

export const protocolNotes: Record<ProbeProtocol, string> = {
  tcpConnect:
    'Connection time includes TCP handshake overhead. This is not a throughput, ICMP loss, or loaded-latency test.',
  icmpEcho:
    'Windows reports ICMP echo RTT in whole milliseconds; a raw zero is shown as <1 ms. ICMP may be blocked or rate-limited. Echo timeouts are not application packet loss. Timeout percentage is unavailable when IP, system, or invalid-reply errors occur. This test does not measure throughput or loaded latency.',
  dnsLookup:
    'Direct resolver queries bypass the Windows client cache. Resolver cache state is unknown; repeated queries do not prove cold or uncached performance. Only successful A/AAAA resolution contributes to lookup timings. Negative answers and errors remain separate. The AD flag is resolver-reported, not independent DNSSEC validation. DNS speed does not measure established game RTT.',
};

export const protocolNames: Record<ProbeProtocol, string> = {
  tcpConnect: 'TCP connection establishment',
  icmpEcho: 'ICMP echo RTT',
  dnsLookup: 'DNS resolution',
};
export const failureNames: Record<ProbeProtocol, string> = {
  tcpConnect: 'Connection failures',
  icmpEcho: 'ICMP echo timeouts',
  dnsLookup: 'Unsuccessful DNS lookups',
};
export function dnsCountsText(counts: DnsCounts): string {
  return `NODATA ${counts.noData}; NXDOMAIN ${counts.nxDomain}; DNS errors ${counts.dnsErrors}; timeouts ${counts.timeouts}; invalid replies ${counts.invalidResponses}; system errors ${counts.osErrors}; TCP fallbacks ${counts.tcpFallbacks}; address-set changes ${counts.addressSetChanges} (informational)`;
}
export function dnsAnswerText(dns: DnsOutcome): string {
  const addresses = dns.answers
    .map((answer) => `${answer.address} (TTL ${answer.ttlSeconds}s)`)
    .join(', ');
  return `${dns.query.name} ${dns.query.recordType}; ${dns.status}; ${dns.transport}; response code ${dns.responseCode ?? 'unavailable'}; AD reported ${dns.authenticatedDataReported ?? 'unavailable'}${addresses ? `; ${addresses}` : ''}`;
}
