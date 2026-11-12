use super::{
    Direction, Plan, Role, Session, Unit,
    baseline::{Context, timestamp, validateSample},
    digest, identifier,
};
use crate::{
    AppResult,
    benchmark::summarizeEndpoint,
    transfer::{
        self, TransferStatus,
        session::{LatencySample, Phase, SessionRun},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum Statistic {
    GoodputMbps { direction: transfer::Direction },
    P95Ms { phase: Phase, endpointId: String },
    IqrMs { phase: Phase, endpointId: String },
    SuccessiveVariationMs { phase: Phase, endpointId: String },
    FailurePercent { phase: Phase, endpointId: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selection {
    pub metricId: String,
    pub providerIndex: usize,
    pub statistic: Statistic,
}

pub fn cohortSha256(run: &SessionRun, selections: &[Selection]) -> AppResult<String> {
    run.plan.validate(&run.config)?;
    run.sourceBindings
        .as_ref()
        .ok_or("Load comparisons require complete source and peer bindings")?
        .validate(&run.plan)?;
    if !identifier(&run.appVersion) || !(1..=super::MAX_METRICS).contains(&selections.len()) {
        return Err("Load comparison version or metric count is invalid".into());
    }
    let mut ids = BTreeSet::new();
    for selection in selections {
        if !identifier(&selection.metricId)
            || !ids.insert(&selection.metricId)
            || selection.providerIndex >= run.plan.providers.len()
        {
            return Err(
                "Load metric identities must be unique and refer to the frozen provider cohort"
                    .into(),
            );
        }
        if let Statistic::P95Ms { endpointId, .. }
        | Statistic::IqrMs { endpointId, .. }
        | Statistic::SuccessiveVariationMs { endpointId, .. }
        | Statistic::FailurePercent { endpointId, .. } = &selection.statistic
            && !run
                .plan
                .latencyEndpoints
                .iter()
                .any(|endpoint| &endpoint.id == endpointId)
        {
            return Err("Load comparison metric refers to an unknown latency endpoint".into());
        }
    }
    let original = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            "source-bound-load-cohort-v1",
            &run.appVersion,
            &run.config,
            &run.plan,
            &run.sourceBindings,
            selections
        ))?)
    );
    Ok(if let Some(execution) = run.transferExecution {
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(
                "source-bound-load-cohort-v2",
                execution,
                original
            ))?)
        )
    } else {
        original
    })
}

fn phaseOrdinal(phase: Phase) -> usize {
    match phase {
        Phase::Idle => 0,
        Phase::Download => 1,
        Phase::Upload => 2,
        Phase::Recovery => 3,
    }
}

fn validateTransfers(run: &SessionRun, start: u64, finish: u64) -> AppResult<Vec<(u64, u64)>> {
    if run.transfers.len() != run.plan.providers.len() * 2 {
        return Err(
            "Load comparison requires both completed transfer directions for every provider".into(),
        );
    }
    let mut previous = start;
    let mut windows = Vec::with_capacity(run.transfers.len());
    for (index, phase) in run.transfers.iter().enumerate() {
        let direction = if index % 2 == 0 {
            transfer::Direction::Download
        } else {
            transfer::Direction::Upload
        };
        let expectedPhase = if index % 2 == 0 {
            Phase::Download
        } else {
            Phase::Upload
        };
        let providerIndex = index / 2;
        let result = phase
            .result
            .as_ref()
            .ok_or("Missing completed transfer evidence")?;
        let expectedBytes = if index % 2 == 0 {
            run.plan.downloadBytesPerProvider
        } else {
            run.plan.uploadBytesPerProvider
        };
        let binding = run.sourceBindings.as_ref().unwrap().transfers[providerIndex];
        let first = timestamp(&result.startedAt)?;
        let last = timestamp(&result.finishedAt)?;
        if phase.providerIndex != providerIndex
            || phase.phase != expectedPhase
            || phase.error.is_some()
            || result.status != TransferStatus::Completed
            || first < previous
            || last < first
            || last > finish
            || result.plan.direction != direction
            || result.plan.bytes != expectedBytes
            || result.plan.streams != run.plan.streams
            || result.plan.timeoutMs != run.plan.phaseTimeoutMs
            || result.acceptedPayloadBytes != expectedBytes
            || result.sourceBinding != Some(binding)
            || result.streams.len() != usize::from(run.plan.streams)
            || !result.elapsedMs.is_finite()
            || result.elapsedMs <= 0.0
            || result.elapsedMs > run.plan.phaseTimeoutMs as f64 + 250.0
            || ((last - first) as f64 - result.elapsedMs).abs() > 250.0
            || serde_json::to_value(&result.plan.provider)?
                != serde_json::to_value(&run.plan.providers[providerIndex])?
            || serde_json::to_value(&result.provider)?
                != serde_json::to_value(run.plan.providers[providerIndex].info()?)?
        {
            return Err("Load transfer order, binding, duration, provider, payload, or completion evidence is inconsistent".into());
        }
        for (ordinal, stream) in result.streams.iter().enumerate() {
            let requested = expectedBytes / u64::from(run.plan.streams)
                + u64::from((ordinal as u64) < expectedBytes % u64::from(run.plan.streams));
            if stream.ordinal as usize != ordinal
                || stream.requestedBytes != requested
                || stream.acceptedPayloadBytes != requested
                || stream.status != TransferStatus::Completed
                || stream.error.is_some()
                || !stream.elapsedMs.is_finite()
                || stream.elapsedMs < 0.0
                || stream.elapsedMs > result.elapsedMs
                || stream
                    .remoteAddress
                    .as_ref()
                    .and_then(|value| value.parse::<std::net::SocketAddr>().ok())
                    != Some(binding.peer)
                || if direction == transfer::Direction::Download {
                    stream.httpStatus != Some(200)
                        || stream.downloadBytesRead != requested
                        || stream.uploadBodyBytesProvided != 0
                } else {
                    !stream
                        .httpStatus
                        .is_some_and(|status| (200..300).contains(&status))
                        || stream.uploadBodyBytesProvided != requested
                        || stream.downloadBytesRead != 0
                }
            {
                return Err("Load stream identity, peer, timing, status, or exact byte counts are inconsistent".into());
            }
        }
        previous = last;
        windows.push((first, last));
    }
    Ok(windows)
}

fn validateLatency(
    run: &SessionRun,
    start: u64,
    finish: u64,
    windows: &[(u64, u64)],
) -> AppResult<()> {
    if run.latencySamples.len() > 4096 {
        return Err("Load comparison raw probe count exceeds its bounded allowance".into());
    }
    let mut previousTime = start;
    let mut previousPhase = 0;
    for sample in &run.latencySamples {
        if sample.providerIndex >= run.plan.providers.len() {
            return Err("Load probe refers to an unknown provider".into());
        }
        let endpoint = run
            .plan
            .latencyEndpoints
            .iter()
            .find(|endpoint| endpoint.id == sample.sample.endpointId)
            .ok_or("Load probe refers to an unknown endpoint")?;
        let currentPhase = sample.providerIndex * 4 + phaseOrdinal(sample.phase);
        let time = validateSample(&sample.sample, endpoint, start, finish)?;
        let quiet = matches!(sample.phase, Phase::Idle | Phase::Recovery);
        if !quiet && qualifies(sample) {
            let index = sample.providerIndex * 2 + usize::from(sample.phase == Phase::Upload);
            let (first, last) = windows[index];
            if time < first || time > last.saturating_add(run.plan.probeTimeoutMs + 250) {
                return Err(
                    "Qualified loaded probe falls outside its recorded transfer window".into(),
                );
            }
        }
        let bytes = if sample.phase == Phase::Download {
            run.plan.downloadBytesPerProvider
        } else {
            run.plan.uploadBytesPerProvider
        };
        if currentPhase < previousPhase
            || time < previousTime
            || sample.inFlightRequestsAtStart > u64::from(run.plan.streams)
            || sample.inFlightRequestsAtEnd > u64::from(run.plan.streams)
            || sample.payloadProgressDuringProbe > bytes
            || (quiet
                && (sample.inFlightRequestsAtStart != 0
                    || sample.inFlightRequestsAtEnd != 0
                    || sample.payloadProgressDuringProbe != 0))
        {
            return Err(
                "Load probe order, phase, timestamp, or overlap evidence is inconsistent".into(),
            );
        }
        previousTime = time;
        previousPhase = currentPhase;
    }
    for provider in 0..run.plan.providers.len() {
        for phase in [Phase::Download, Phase::Upload] {
            let observed: u64 = run
                .latencySamples
                .iter()
                .filter(|sample| sample.providerIndex == provider && sample.phase == phase)
                .map(|sample| sample.payloadProgressDuringProbe)
                .sum();
            let limit = if phase == Phase::Download {
                run.plan.downloadBytesPerProvider
            } else {
                run.plan.uploadBytesPerProvider
            };
            if observed > limit {
                return Err("Load probe overlap progress exceeds the entire phase payload".into());
            }
        }
        for phase in [Phase::Idle, Phase::Recovery] {
            for endpoint in &run.plan.latencyEndpoints {
                if run
                    .latencySamples
                    .iter()
                    .filter(|sample| {
                        sample.providerIndex == provider
                            && sample.phase == phase
                            && sample.sample.endpointId == endpoint.id
                    })
                    .count()
                    != usize::from(run.plan.idleRounds)
                {
                    return Err("Load quiet phases are incomplete or unbalanced".into());
                }
            }
        }
    }
    Ok(())
}

fn qualifies(sample: &LatencySample) -> bool {
    matches!(sample.phase, Phase::Idle | Phase::Recovery)
        || (sample.inFlightRequestsAtStart > 0 && sample.inFlightRequestsAtEnd > 0)
}

fn successiveVariation(
    samples: &[LatencySample],
    providerIndex: usize,
    phase: Phase,
    endpointId: &str,
) -> AppResult<Option<f64>> {
    let replyTimes: Vec<_> = samples
        .iter()
        .filter(|sample| {
            sample.providerIndex == providerIndex
                && sample.phase == phase
                && sample.sample.endpointId == endpointId
        })
        .map(|sample| {
            if qualifies(sample) {
                sample
                    .sample
                    .echo
                    .as_ref()
                    .and_then(|echo| echo.rttMs)
                    .map(f64::from)
            } else {
                None
            }
        })
        .collect();
    let pairs = replyTimes
        .windows(2)
        .filter(|pair| pair[0].is_some() && pair[1].is_some())
        .count();
    if pairs < 11 {
        return Err("Successive load RTT variation requires eleven adjacent qualifying reply pairs without bridging timeouts or unqualified probes".into());
    }
    Ok(crate::statistics::summarize(&replyTimes).successiveVariationMs)
}

pub fn fromRun(
    run: &SessionRun,
    selections: &[Selection],
    plan: &Plan,
    context: Context<'_>,
) -> AppResult<Session> {
    plan.validate()?;
    let cohort = cohortSha256(run, selections)?;
    let start = timestamp(&run.startedAt)?;
    let finish = timestamp(&run.finishedAt)?;
    if run.id <= 0
        || run.status != "completed"
        || start == 0
        || finish <= start
        || cohort != plan.cohortSha256
        || context.environmentSha256 != plan.environmentSha256
        || !digest(context.configurationSha256)
        || (context.configurationSha256 != plan.originalConfigurationSha256
            && context.configurationSha256 != plan.candidateConfigurationSha256)
        || selections.len() != plan.metrics.len()
    {
        return Err("Only complete saved source-bound load sessions with matching plan, environment, and configuration can be compared".into());
    }
    let windows = validateTransfers(run, start, finish)?;
    validateLatency(run, start, finish, &windows)?;
    let mut values = Vec::with_capacity(selections.len());
    for (selection, rule) in selections.iter().zip(&plan.metrics) {
        let (value, unit, direction, resolution, guard) = match &selection.statistic {
            Statistic::GoodputMbps { direction } => {
                let offset = usize::from(*direction == transfer::Direction::Upload);
                let transfer = run.transfers[selection.providerIndex * 2 + offset]
                    .result
                    .as_ref()
                    .unwrap();
                (
                    transfer
                        .streams
                        .iter()
                        .map(|stream| stream.acceptedPayloadBytes)
                        .sum::<u64>() as f64
                        * 8.0
                        / (transfer.elapsedMs * 1000.0),
                    Unit::MegabitsPerSecond,
                    Direction::HigherIsBetter,
                    0.0,
                    false,
                )
            }
            Statistic::P95Ms { phase, endpointId }
            | Statistic::IqrMs { phase, endpointId }
            | Statistic::SuccessiveVariationMs { phase, endpointId }
            | Statistic::FailurePercent { phase, endpointId } => {
                let endpoint = run
                    .plan
                    .latencyEndpoints
                    .iter()
                    .find(|endpoint| &endpoint.id == endpointId)
                    .unwrap();
                let samples: Vec<_> = run
                    .latencySamples
                    .iter()
                    .filter(|sample| {
                        sample.providerIndex == selection.providerIndex
                            && sample.phase == *phase
                            && sample.sample.endpointId == *endpointId
                            && qualifies(sample)
                    })
                    .map(|sample| sample.sample.clone())
                    .collect();
                if samples.len() < 12 {
                    return Err("Load comparison needs at least twelve qualifying probes for each selected latency metric".into());
                }
                let failure = matches!(selection.statistic, Statistic::FailurePercent { .. });
                let summary = summarizeEndpoint(endpoint.clone(), &samples).summary;
                if !failure && summary.successful < 12 {
                    return Err(
                        "Load latency statistics need at least twelve qualifying successful replies"
                            .into(),
                    );
                }
                let value = match selection.statistic {
                    Statistic::FailurePercent { .. } => summary.echoTimeoutPercent,
                    Statistic::P95Ms { .. } => summary.p95Ms,
                    Statistic::IqrMs { .. } => summary.iqrMs,
                    Statistic::SuccessiveVariationMs { .. } => successiveVariation(
                        &run.latencySamples,
                        selection.providerIndex,
                        *phase,
                        endpointId,
                    )?,
                    Statistic::GoodputMbps { .. } => unreachable!(),
                }
                .ok_or("Required load latency or failure metric is unavailable")?;
                (
                    value,
                    if failure {
                        Unit::Percent
                    } else {
                        Unit::Milliseconds
                    },
                    Direction::LowerIsBetter,
                    if failure {
                        100.0 / samples.len() as f64
                    } else {
                        1.0
                    },
                    failure,
                )
            }
        };
        if rule.id != selection.metricId
            || rule.unit != unit
            || rule.direction != direction
            || rule.resolution < resolution
            || (guard && rule.role != Role::Guard)
            || !(0.0..=1e12).contains(&value)
        {
            return Err("Load metric order, unit, direction, role, or measurement resolution differs from the reviewed rules".into());
        }
        values.push(value);
    }
    Ok(Session {
        id: format!("load:{}", run.id),
        startedAtUnixMs: start,
        finishedAtUnixMs: finish,
        completed: true,
        cohortSha256: cohort,
        environmentSha256: context.environmentSha256.into(),
        configurationSha256: context.configurationSha256.into(),
        values,
    })
}

#[cfg(test)]
mod tests;
