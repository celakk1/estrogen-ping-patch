use super::{
    Direction, Provider, TransferPlan, TransferProgress, TransferResult, TransferStatus, measure,
};
use crate::{
    AppResult,
    benchmark::{
        Endpoint, EndpointResult, ProbeProtocol, Sample, measureOnce, summarizeEndpoint,
        validateEndpoints,
    },
    config::Config,
    icmp::EchoProbe,
};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionPlan {
    pub providers: Vec<Provider>,
    pub downloadBytesPerProvider: u64,
    pub uploadBytesPerProvider: u64,
    pub streams: u8,
    pub phaseTimeoutMs: u64,
    pub idleRounds: u8,
    pub intervalMs: u64,
    pub probeTimeoutMs: u64,
    pub latencyEndpoints: Vec<Endpoint>,
}

impl SessionPlan {
    pub fn validate(&self, config: &Config) -> AppResult<()> {
        config.validate()?;
        if !(1..=4).contains(&self.providers.len())
            || !(3..=20).contains(&self.idleRounds)
            || !(250..=1000).contains(&self.intervalMs)
            || !(100..=1000).contains(&self.probeTimeoutMs)
        {
            return Err("Load sessions require 1..4 providers, 3..20 idle/recovery rounds, 250..1000 ms pacing, and a 100..1000 ms probe timeout".into());
        }
        validateEndpoints(&self.latencyEndpoints)?;
        if self.latencyEndpoints[0].protocol == ProbeProtocol::DnsLookup {
            return Err("Concurrent latency endpoints must use ICMP echo or TCP connects, not DNS lookup time".into());
        }
        let mut origins = Vec::new();
        for provider in &self.providers {
            let origin = provider.info()?.origin;
            if origins.contains(&origin) {
                return Err("Choose distinct provider origins; duplicate servers are not independent measurements".into());
            }
            origins.push(origin);
            for (direction, bytes) in [
                (Direction::Download, self.downloadBytesPerProvider),
                (Direction::Upload, self.uploadBytesPerProvider),
            ] {
                TransferPlan {
                    provider: provider.clone(),
                    direction,
                    bytes,
                    streams: self.streams,
                    timeoutMs: self.phaseTimeoutMs,
                }
                .validate()?;
            }
        }
        let count = self.providers.len() as u64;
        if self
            .downloadBytesPerProvider
            .checked_mul(count)
            .is_none_or(|bytes| bytes > config.maxDownloadBytes)
            || self
                .uploadBytesPerProvider
                .checked_mul(count)
                .is_none_or(|bytes| bytes > config.maxUploadBytes)
        {
            return Err(
                "Requested transfer payload exceeds the configured session download/upload budget"
                    .into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBindings {
    pub transfers: Vec<super::SourceBinding>,
    pub latency: Vec<crate::benchmark::SourceBinding>,
}

impl SourceBindings {
    pub fn validate(&self, plan: &SessionPlan) -> AppResult<()> {
        if self.transfers.len() != plan.providers.len() {
            return Err("Every load provider needs one complete ordered transfer binding".into());
        }
        for (binding, provider) in self.transfers.iter().zip(&plan.providers) {
            binding.validate(provider)?;
        }
        crate::benchmark::validateSourceBindings(&plan.latencyEndpoints, &self.latency)
    }
}

pub trait BoundTransferRunner: Sync {
    fn measureFrom(
        &self,
        plan: TransferPlan,
        binding: super::SourceBinding,
        cancelled: &AtomicBool,
        progress: &TransferProgress,
    ) -> AppResult<TransferResult>;
}

struct DirectBoundTransfer;

impl BoundTransferRunner for DirectBoundTransfer {
    fn measureFrom(
        &self,
        plan: TransferPlan,
        binding: super::SourceBinding,
        cancelled: &AtomicBool,
        progress: &TransferProgress,
    ) -> AppResult<TransferResult> {
        super::measureFrom(plan, binding, cancelled, progress)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Idle,
    Download,
    Upload,
    Recovery,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencySample {
    pub providerIndex: usize,
    pub phase: Phase,
    pub sample: Sample,
    pub inFlightRequestsAtStart: u64,
    pub inFlightRequestsAtEnd: u64,
    pub payloadProgressDuringProbe: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhaseResult {
    pub providerIndex: usize,
    pub phase: Phase,
    pub result: Option<TransferResult>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRun {
    pub id: i64,
    pub startedAt: String,
    pub finishedAt: String,
    pub appVersion: String,
    pub status: String,
    pub config: Config,
    pub plan: SessionPlan,
    pub transfers: Vec<PhaseResult>,
    pub latencySamples: Vec<LatencySample>,
    pub latencySummaries: Vec<LatencySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sourceBindings: Option<SourceBindings>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencySummary {
    pub providerIndex: usize,
    pub phase: Phase,
    pub results: Vec<EndpointResult>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionProgress {
    pub providerIndex: usize,
    pub providerCount: usize,
    pub phase: Phase,
    pub downloadBytesRead: u64,
    pub uploadBodyBytesProvided: u64,
    pub sample: Option<LatencySample>,
}

struct Completion(Arc<AtomicBool>);
impl Drop for Completion {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct Observer<'a, F: FnMut(SessionProgress)> {
    plan: &'a SessionPlan,
    sourceBindings: Option<&'a SourceBindings>,
    transferRunner: &'a dyn BoundTransferRunner,
    cancelled: &'a AtomicBool,
    deadline: Instant,
    echoProbe: EchoProbe,
    samples: Vec<LatencySample>,
    onProgress: F,
}

impl<F: FnMut(SessionProgress)> Observer<'_, F> {
    fn stopped(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst) || Instant::now() >= self.deadline
    }

    fn notify(
        &mut self,
        providerIndex: usize,
        phase: Phase,
        progress: &TransferProgress,
        sample: Option<LatencySample>,
    ) {
        (self.onProgress)(SessionProgress {
            providerIndex,
            providerCount: self.plan.providers.len(),
            phase,
            downloadBytesRead: progress.downloadBytesRead.load(Ordering::SeqCst),
            uploadBodyBytesProvided: progress.uploadBodyBytesProvided.load(Ordering::SeqCst),
            sample,
        });
    }

    fn pace(&self) {
        let until =
            (Instant::now() + Duration::from_millis(self.plan.intervalMs)).min(self.deadline);
        while !self.stopped() && Instant::now() < until {
            thread::sleep(
                Duration::from_millis(25).min(until.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn sample(
        &mut self,
        providerIndex: usize,
        phase: Phase,
        endpointIndex: usize,
        progress: &TransferProgress,
    ) -> AppResult<()> {
        if self.stopped() {
            return Ok(());
        }
        let timeout = Duration::from_millis(self.plan.probeTimeoutMs)
            .min(self.deadline.saturating_duration_since(Instant::now()));
        if timeout.as_millis() == 0 {
            return Ok(());
        }
        let inFlightRequestsAtStart = progress.activeRequests.load(Ordering::SeqCst);
        let before = progress.downloadBytesRead.load(Ordering::SeqCst)
            + progress.uploadBodyBytesProvided.load(Ordering::SeqCst);
        if let Some(sample) = measureOnce(
            &self.plan.latencyEndpoints[endpointIndex],
            timeout,
            self.cancelled,
            &mut self.echoProbe,
            self.sourceBindings
                .map(|bindings| &bindings.latency[endpointIndex].source),
        )? {
            let after = progress.downloadBytesRead.load(Ordering::SeqCst)
                + progress.uploadBodyBytesProvided.load(Ordering::SeqCst);
            let sample = LatencySample {
                providerIndex,
                phase,
                sample,
                inFlightRequestsAtStart,
                inFlightRequestsAtEnd: progress.activeRequests.load(Ordering::SeqCst),
                payloadProgressDuringProbe: after.saturating_sub(before),
            };
            self.samples.push(sample.clone());
            self.notify(providerIndex, phase, progress, Some(sample));
        }
        Ok(())
    }

    fn quiet(&mut self, providerIndex: usize, phase: Phase) -> AppResult<()> {
        let progress = TransferProgress::default();
        self.notify(providerIndex, phase, &progress, None);
        for _ in 0..self.plan.idleRounds {
            for endpointIndex in 0..self.plan.latencyEndpoints.len() {
                if self.stopped() {
                    return Ok(());
                }
                self.sample(providerIndex, phase, endpointIndex, &progress)?;
                self.pace();
            }
        }
        Ok(())
    }

    fn loaded(&mut self, providerIndex: usize, direction: Direction) -> AppResult<PhaseResult> {
        let phase = if direction == Direction::Download {
            Phase::Download
        } else {
            Phase::Upload
        };
        let plan = TransferPlan {
            provider: self.plan.providers[providerIndex].clone(),
            direction,
            bytes: if direction == Direction::Download {
                self.plan.downloadBytesPerProvider
            } else {
                self.plan.uploadBytesPerProvider
            },
            streams: self.plan.streams,
            timeoutMs: self.plan.phaseTimeoutMs.min(
                self.deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis() as u64,
            ),
        };
        let progress = TransferProgress::default();
        self.notify(providerIndex, phase, &progress, None);
        let done = Arc::new(AtomicBool::new(false));
        let phaseCancelled = AtomicBool::new(self.stopped());
        let binding = self
            .sourceBindings
            .map(|bindings| bindings.transfers[providerIndex]);
        let transferRunner = self.transferRunner;
        let result = thread::scope(|scope| {
            let completion = Completion(done.clone());
            let progress = &progress;
            let cancelled = &phaseCancelled;
            let worker = scope.spawn(move || {
                let _completion = completion;
                if let Some(binding) = binding {
                    let result = transferRunner.measureFrom(plan.clone(), binding, cancelled, progress)?;
                    if serde_json::to_value(&result.plan)? != serde_json::to_value(&plan)?
                        || result.sourceBinding != Some(binding)
                        || serde_json::to_value(&result.provider)? != serde_json::to_value(plan.provider.info()?)?
                    {
                        return Err("Bound transfer runner returned a different plan, provider, source, or peer".into());
                    }
                    Ok(result)
                } else {
                    measure(plan, cancelled, progress)
                }
            });
            let mut observationError = None;
            let mut endpointIndex = 0;
            while !done.load(Ordering::SeqCst) && !self.stopped() {
                if let Err(error) = self.sample(providerIndex, phase, endpointIndex, progress) {
                    observationError = Some(error);
                    break;
                }
                endpointIndex = (endpointIndex + 1) % self.plan.latencyEndpoints.len();
                self.pace();
            }
            if self.stopped() || observationError.is_some() {
                phaseCancelled.store(true, Ordering::SeqCst);
            }
            let result = worker.join().map_err(|_| "Transfer worker failed")?;
            if let Some(error) = observationError {
                return Err(error);
            }
            result
        });
        self.notify(providerIndex, phase, &progress, None);
        Ok(match result {
            Ok(result) => PhaseResult {
                providerIndex,
                phase,
                result: Some(result),
                error: None,
            },
            Err(error) => PhaseResult {
                providerIndex,
                phase,
                result: None,
                error: Some(error.to_string()),
            },
        })
    }
}

pub fn runSession(
    config: Config,
    plan: SessionPlan,
    cancelled: &AtomicBool,
    onProgress: impl FnMut(SessionProgress),
) -> AppResult<SessionRun> {
    runSessionInternal(
        config,
        plan,
        None,
        cancelled,
        onProgress,
        &DirectBoundTransfer,
    )
}

pub fn runSourceBoundSession(
    config: Config,
    plan: SessionPlan,
    bindings: SourceBindings,
    cancelled: &AtomicBool,
    onProgress: impl FnMut(SessionProgress),
) -> AppResult<SessionRun> {
    runSourceBoundSessionWithRunner(
        config,
        plan,
        bindings,
        cancelled,
        onProgress,
        &DirectBoundTransfer,
    )
}

pub fn runSourceBoundSessionWithRunner(
    config: Config,
    plan: SessionPlan,
    bindings: SourceBindings,
    cancelled: &AtomicBool,
    onProgress: impl FnMut(SessionProgress),
    transferRunner: &dyn BoundTransferRunner,
) -> AppResult<SessionRun> {
    runSessionInternal(
        config,
        plan,
        Some(bindings),
        cancelled,
        onProgress,
        transferRunner,
    )
}

fn runSessionInternal(
    config: Config,
    plan: SessionPlan,
    sourceBindings: Option<SourceBindings>,
    cancelled: &AtomicBool,
    onProgress: impl FnMut(SessionProgress),
    transferRunner: &dyn BoundTransferRunner,
) -> AppResult<SessionRun> {
    plan.validate(&config)?;
    if let Some(bindings) = &sourceBindings {
        bindings.validate(&plan)?;
    }
    let startedAt = chrono::Utc::now().to_rfc3339();
    let mut observer = Observer {
        plan: &plan,
        sourceBindings: sourceBindings.as_ref(),
        transferRunner,
        cancelled,
        deadline: Instant::now() + Duration::from_secs(u64::from(config.sessionMinutes) * 60),
        echoProbe: EchoProbe::default(),
        samples: Vec::new(),
        onProgress,
    };
    let mut transfers = Vec::new();
    for providerIndex in 0..plan.providers.len() {
        observer.quiet(providerIndex, Phase::Idle)?;
        for direction in [Direction::Download, Direction::Upload] {
            if observer.stopped() {
                break;
            }
            let phase = observer.loaded(providerIndex, direction)?;
            let failed = phase
                .result
                .as_ref()
                .is_none_or(|result| result.status != TransferStatus::Completed);
            transfers.push(phase);
            if failed {
                break;
            }
        }
        observer.quiet(providerIndex, Phase::Recovery)?;
        if observer.stopped() {
            break;
        }
    }
    let status = if cancelled.load(Ordering::SeqCst) {
        "cancelled"
    } else if Instant::now() >= observer.deadline {
        "timeLimit"
    } else if transfers.len() != plan.providers.len() * 2
        || transfers.iter().any(|phase| {
            phase
                .result
                .as_ref()
                .is_none_or(|result| result.status != TransferStatus::Completed)
        })
    {
        "partialFailure"
    } else {
        "completed"
    };
    let latencySamples = observer.samples;
    let mut latencySummaries = Vec::new();
    for providerIndex in 0..plan.providers.len() {
        for phase in [Phase::Idle, Phase::Download, Phase::Upload, Phase::Recovery] {
            let samples: Vec<_> = latencySamples
                .iter()
                .filter(|sample| {
                    sample.providerIndex == providerIndex
                        && sample.phase == phase
                        && (matches!(phase, Phase::Idle | Phase::Recovery)
                            || (sample.inFlightRequestsAtStart > 0
                                && sample.inFlightRequestsAtEnd > 0)
                            || sample.payloadProgressDuringProbe > 0)
                })
                .map(|sample| sample.sample.clone())
                .collect();
            let results = plan
                .latencyEndpoints
                .iter()
                .cloned()
                .map(|endpoint| {
                    let mut result = summarizeEndpoint(endpoint, &samples);
                    if result.summary.attempted == 0 {
                        result.summary.connectionFailurePercent = None;
                    }
                    result
                })
                .collect();
            latencySummaries.push(LatencySummary {
                providerIndex,
                phase,
                results,
            });
        }
    }
    Ok(SessionRun {
        id: 0,
        startedAt,
        finishedAt: chrono::Utc::now().to_rfc3339(),
        appVersion: env!("CARGO_PKG_VERSION").into(),
        status: status.into(),
        config,
        plan,
        transfers,
        latencySamples,
        latencySummaries,
        sourceBindings,
    })
}
