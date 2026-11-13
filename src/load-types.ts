import type { BenchmarkRun, Config, Endpoint, Sample } from './types';

export type TransferProvider = { kind: 'cloudflare' } | { kind: 'userOwnedHttp'; origin: string };
export type LoadPhase = 'idle' | 'download' | 'upload' | 'recovery';
export interface LoadPlan {
  providers: TransferProvider[];
  downloadBytesPerProvider: number;
  uploadBytesPerProvider: number;
  streams: number;
  phaseTimeoutMs: number;
  idleRounds: number;
  intervalMs: number;
  probeTimeoutMs: number;
  latencyEndpoints: Endpoint[];
}
export interface LoadSample {
  providerIndex: number;
  phase: LoadPhase;
  sample: Sample;
  inFlightRequestsAtStart: number;
  inFlightRequestsAtEnd: number;
  payloadProgressDuringProbe: number;
}
export interface TransferResult {
  workerCpu?: CpuEvidence<{
    schemaVersion: number;
    creationTime100ns: string;
    exitTime100ns: string;
    kernelTime100ns: string;
    userTime100ns: string;
  }>;
  systemCpu?: CpuEvidence<{
    schemaVersion: number;
    before: SystemCpuSnapshot;
    after: SystemCpuSnapshot;
    elapsedNs: string;
  }>;
  plan: {
    direction: 'download' | 'upload';
    bytes: number;
    streams: number;
    timeoutMs: number;
    provider: TransferProvider;
  };
  provider: {
    id: string;
    origin: string;
    serverSelection: string;
    protocol: string;
    privacyNotice: string;
    documentation: string;
  };
  status: string;
  startedAt: string;
  finishedAt: string;
  elapsedMs: number;
  acceptedPayloadBytes: number;
  applicationGoodputMbps: number | null;
  streams: {
    ordinal: number;
    requestedBytes: number;
    downloadBytesRead: number;
    uploadBodyBytesProvided: number;
    acceptedPayloadBytes: number;
    elapsedMs: number;
    status: string;
    httpStatus: number | null;
    remoteAddress: string | null;
    retryAfter: string | null;
    error: string | null;
  }[];
}
export type CpuEvidence<T> =
  { status: 'measured'; usage: T } | { status: 'unavailable'; reason: string };
export interface SystemCpuSnapshot {
  capturedAt: string;
  queryElapsedNs: string;
  processorGroups: number;
  activeProcessors: number;
  idleTime100ns: string;
  kernelTime100ns: string;
  userTime100ns: string;
}
export interface LoadRun {
  id: number;
  startedAt: string;
  finishedAt: string;
  appVersion: string;
  status: string;
  transferExecution?:
    | 'restrictedWorkerV1'
    | 'restrictedWorkerV2'
    | 'restrictedWorkerV3'
    | 'recordedRestrictedWorkerV1'
    | 'recordedRestrictedWorkerV2'
    | 'recordedRestrictedWorkerV3';
  config: Config;
  plan: LoadPlan;
  transfers: {
    providerIndex: number;
    phase: LoadPhase;
    result: TransferResult | null;
    error: string | null;
    interruptedProgress?:
      | {
          status: 'observed';
          capturedAt: string;
          counters: {
            downloadBytesRead: number;
            uploadBodyBytesProvided: number;
            activeRequests: number;
          };
        }
      | { status: 'unavailable'; detail: string };
  }[];
  latencySamples: LoadSample[];
  latencySummaries: { providerIndex: number; phase: LoadPhase; results: BenchmarkRun['results'] }[];
}
export interface LoadProgress {
  providerIndex: number;
  providerCount: number;
  phase: LoadPhase;
  downloadBytesRead: number;
  uploadBodyBytesProvided: number;
  sample: LoadSample | null;
}
