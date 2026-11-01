import type { EchoOutcome } from './types';

export type PacketOutcome =
  | 'testedLimitReached'
  | 'sizeBoundaryObserved'
  | 'smallPacketsUnavailable'
  | 'inconclusive'
  | 'cancelled'
  | 'budgetExpired'
  | 'clockChanged'
  | 'unsupported';

export interface PacketSample {
  sequence: number;
  timestampUnixMs: number;
  packetBytes: number;
  control: boolean;
  dontFragment: boolean;
  echo: EchoOutcome;
}

export interface PacketCheck {
  schemaVersion: number;
  id: number;
  report: {
    schemaVersion: number;
    plan: {
      source: string;
      destination: string;
      interfaceMtu: number;
      timeoutMs: number;
      intervalMs: number;
      budgetMs: number;
    };
    outcome: PacketOutcome;
    startedAtUnixMs: number;
    finishedAtUnixMs: number;
    maximumTestedBytes: number;
    largestSuccessfulBytes: number | null;
    smallestTooBigBytes: number | null;
    confirmedBoundaryBytes: number | null;
    requestedIpv4Bytes: number;
    samples: PacketSample[];
    error: string | null;
  };
  contextUnchanged: boolean;
  context: {
    routeBefore: { adapterGuid: string; interfaceIndex: number };
    interfaceBefore: { alias: string };
    routeAfter: unknown;
    interfaceAfter: unknown;
    afterError: string | null;
  };
}

export function packetExplanation(check: PacketCheck): { title: string; detail: string } {
  const { report } = check;
  if (report.outcome === 'cancelled')
    return {
      title: 'Check stopped',
      detail: 'Partial measurements were saved. Start a new check when you are ready.',
    };
  if (!check.contextUnchanged)
    return {
      title: 'Connection could not be verified',
      detail:
        'The local route or adapter changed, or its final details were unavailable. These results cannot establish a stable packet-size limit. Try again on a steady connection.',
    };
  switch (report.outcome) {
    case 'testedLimitReached':
      return {
        title: `Packets up to ${report.maximumTestedBytes.toLocaleString()} bytes replied`,
        detail:
          'This check found no reason to reduce the packet size for this destination. Other destinations and different network conditions may behave differently.',
      };
    case 'sizeBoundaryObserved':
      return {
        title: 'A packet-size boundary was observed',
        detail: `Repeated ${report.confirmedBoundaryBytes?.toLocaleString()} byte requests replied, while requests one byte larger received explicit “too large” errors. Windows may already handle this limit. This is evidence to investigate, not proof that changing MTU will improve gaming.`,
      };
    case 'smallPacketsUnavailable':
      return {
        title: 'The server did not reliably answer small requests',
        detail:
          'The server may filter these checks, or the connection may be unavailable. A packet-size limit cannot be determined. Try another destination.',
      };
    case 'budgetExpired':
      return {
        title: 'The check reached its limit',
        detail:
          'There was not enough time to finish confirming a result. Partial measurements were saved; no packet-size change is recommended.',
      };
    case 'clockChanged':
      return {
        title: 'The system clock changed',
        detail:
          'Timing evidence could not be kept consistent. Start a new check after the clock is stable.',
      };
    case 'unsupported':
      return {
        title: 'This check is unavailable',
        detail: 'Source-bound IPv4 packet checks require the supported Windows networking API.',
      };
    default:
      return {
        title: 'No reliable size limit was found',
        detail:
          'Missing or inconsistent replies do not prove that packets are too large. No packet-size change is recommended. You can try another destination.',
      };
  }
}
