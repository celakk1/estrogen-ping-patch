export type Profile = 'latency' | 'balanced' | 'download';
export type ProbeProtocol = 'tcpConnect' | 'icmpEcho' | 'dnsLookup';
export interface DnsQuery {
  name: string;
  recordType: 'A' | 'AAAA';
}
export interface DnsOutcome {
  query: DnsQuery;
  cacheMode: 'directResolverCacheUnknown';
  status:
    | 'resolved'
    | 'noData'
    | 'nxDomain'
    | 'dnsError'
    | 'timedOut'
    | 'invalidResponse'
    | 'osError'
    | 'cancelled';
  transport: 'udp' | 'tcpFallback';
  lookupMs: number | null;
  responseMs: number | null;
  responseCode: number | null;
  authenticatedDataReported: boolean | null;
  recursionAvailable: boolean | null;
  answers: { owner: string; address: string; ttlSeconds: number }[];
  aliases: { name: string; target: string; ttlSeconds: number }[];
  rejectedResponses: number;
  requestBytes: number;
  responseBytes: number;
  error: string | null;
}
export interface DnsCounts {
  resolved: number;
  noData: number;
  nxDomain: number;
  dnsErrors: number;
  timeouts: number;
  invalidResponses: number;
  osErrors: number;
  tcpFallbacks: number;
  addressSetChanges: number;
}
export interface Config {
  schemaVersion: number;
  profile: Profile;
  sampleCount: number;
  intervalMs: number;
  timeoutMs: number;
  sessionMinutes: number;
  maxDownloadBytes: number;
  maxUploadBytes: number;
  aiMode: string;
  cloudBudget: number;
  [key: string]: unknown;
}
export interface Adapter {
  interfaceIndex: number;
  id: string;
  name: string;
  description: string;
  status: string;
  linkSpeed: string;
  mediaType: string;
  physical: boolean;
  driverVersion: string;
}
export interface Inventory {
  capturedAt: string;
  os: { version: string; build: string; architecture: string; elevated: boolean };
  adapters: Adapter[];
  routes: { interfaceIndex: number; nextHop: string; routeMetric: number; destination: string }[];
  interfaces: {
    interfaceIndex: number;
    addressFamily: string;
    mtu: number;
    metric: number;
    dhcp: string;
    state: string;
  }[];
  dns: { interfaceIndex: number; servers: string[] }[];
  limitations: string[];
}
export interface Summary {
  attempted: number;
  successful: number;
  connectionFailurePercent?: number;
  echoTimeoutPercent?: number;
  dnsFailurePercent?: number;
  medianMs: number | null;
  p95Ms: number | null;
  p99Ms: number | null;
  iqrMs: number | null;
  successiveVariationMs: number | null;
}
export interface Endpoint {
  id: string;
  address: string;
  protocol?: ProbeProtocol;
  dnsQuery?: DnsQuery;
}
export interface EchoOutcome {
  status:
    'reply' | 'timedOut' | 'ipError' | 'osError' | 'invalidReply' | 'cancelled' | 'unsupported';
  rttMs: number | null;
  rttUnitMs: number;
  callDurationMs: number;
  responder: string | null;
  responderScopeId: number | null;
  nativeCode: number | null;
}
export interface EchoCounts {
  replies: number;
  timeouts: number;
  ipErrors: number;
  osErrors: number;
  invalidReplies: number;
  unsupported: number;
}
export interface Sample {
  endpointId: string;
  address: string;
  timestamp: string;
  connectMs: number | null;
  error: string | null;
  echo?: EchoOutcome;
  dns?: DnsOutcome;
}
export interface BenchmarkRun {
  id: number;
  startedAt: string;
  finishedAt: string;
  status: string;
  protocol: ProbeProtocol;
  appVersion: string;
  config: Config;
  results: {
    endpoint: Endpoint;
    summary: Summary;
    echoCounts?: EchoCounts;
    dnsCounts?: DnsCounts;
  }[];
  samples: Sample[];
  routing?: RoutingEvidence;
}
export interface RoutingEvidence {
  schemaVersion: number;
  status: 'unchanged' | 'changed' | 'unavailable';
  beforeFingerprint: string | null;
  afterFingerprint: string | null;
  before: unknown;
  after: unknown;
}
export interface Progress {
  sample: Sample;
  completed: number;
  total: number;
  remainingLowSeconds: number;
  remainingHighSeconds: number;
}
export interface AppStatus {
  version: string;
  service: string;
  privilegedService: string;
  mcp: string;
  busy: boolean;
  config: Config;
  dataDirectory: string;
}

export interface ServiceReport {
  state: string;
  detail: string;
  response: {
    schemaVersion: number;
    serviceVersion: string;
    servicePid: number;
    mode: string;
    modificationsPermitted: boolean;
    rollbackAvailable: boolean;
    recovery: {
      phase: 'running' | 'completed' | 'recoveryRequired';
      verifiedCount: number;
      detail: string | null;
    } | null;
    checkpointStore: {
      schemaVersion: number;
      verifiedAtUnixMs: number;
      pendingRecoveryCount: number;
    };
  } | null;
}

export interface BackupSummary {
  id: number;
  capturedAt: string;
  sha256: string;
  capturedSections: number;
  unavailableSections: number;
}

export interface BackupExport {
  summary: BackupSummary;
  payloadJson: string;
}

export interface BackupPayload {
  capturedAt: string;
  inventory: Inventory;
  settings: {
    sections: {
      name: string;
      adapterId: string;
      status: 'captured' | 'unavailable';
      values: unknown[];
      error: string | null;
    }[];
  };
  limitations: string[];
}
