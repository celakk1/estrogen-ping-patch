use super::{Direction, Plan, Session, Unit, digest, identifier};
use crate::{
    AppResult,
    benchmark::{
        BenchmarkRun, Endpoint, ProbeProtocol, RoutingStatus, Sample, summarizeEndpoint,
        validateEndpoints,
    },
    dns::DnsStatus,
    icmp::{EchoStatus, EchoTarget},
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Statistic {
    MedianMs,
    P95Ms,
    P99Ms,
    IqrMs,
    SuccessiveVariationMs,
    FailurePercent,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Selection {
    pub metricId: String,
    pub endpointId: String,
    pub statistic: Statistic,
}

pub struct Context<'a> {
    pub environmentSha256: &'a str,
    pub configurationSha256: &'a str,
}

pub fn cohortSha256(run: &BenchmarkRun, selections: &[Selection]) -> AppResult<String> {
    run.config.validate()?;
    if !(2..=8).contains(&run.results.len()) {
        return Err("Baseline comparison requires two to eight endpoint results".into());
    }
    let endpoints: Vec<_> = run
        .results
        .iter()
        .map(|result| result.endpoint.clone())
        .collect();
    validateEndpoints(&endpoints)?;
    if !identifier(&run.appVersion)
        || !(1..=super::MAX_METRICS).contains(&selections.len())
        || selections
            .iter()
            .any(|selection| !identifier(&selection.metricId) || !identifier(&selection.endpointId))
    {
        return Err(
            "Baseline comparison requires a bounded application version and metric selection"
                .into(),
        );
    }
    let bytes = serde_json::to_vec(&(
        "baseline-cohort-v1",
        &run.appVersion,
        &endpoints,
        run.config.sampleCount,
        run.config.intervalMs,
        run.config.timeoutMs,
        run.config.sessionMinutes,
        selections,
    ))?;
    let legacy = format!("{:x}", Sha256::digest(bytes));
    if let Some(bindings) = &run.sourceBindings {
        crate::benchmark::validateSourceBindings(&endpoints, bindings)?;
        let bytes = serde_json::to_vec(&("source-bound-baseline-cohort-v1", legacy, bindings))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    } else {
        Ok(legacy)
    }
}

pub(super) fn timestamp(value: &str) -> AppResult<u64> {
    if value.len() > 64 {
        return Err("Baseline timestamp exceeds its supported size".into());
    }
    Ok(DateTime::parse_from_rfc3339(value)?
        .timestamp_millis()
        .try_into()?)
}

pub(super) fn validateSample(
    sample: &Sample,
    endpoint: &Endpoint,
    start: u64,
    finish: u64,
) -> AppResult<u64> {
    let time = timestamp(&sample.timestamp)?;
    if sample.address != endpoint.address || !(start..=finish).contains(&time) {
        return Err("Baseline sample target or timestamp does not match its session".into());
    }
    let timing = |value: f64| value.is_finite() && (0.0..=1e12).contains(&value);
    let valid = match endpoint.protocol {
        ProbeProtocol::TcpConnect => {
            sample.echo.is_none()
                && sample.dns.is_none()
                && sample.connectMs.is_none_or(timing)
                && sample.connectMs.is_some() == sample.error.is_none()
        }
        ProbeProtocol::IcmpEcho => {
            if let Some(echo) = &sample.echo {
                let target = EchoTarget::parse(&endpoint.address)?;
                sample.connectMs.is_none()
                    && sample.dns.is_none()
                    && echo.rttUnitMs == 1
                    && timing(echo.callDurationMs)
                    && echo.status != EchoStatus::Cancelled
                    && echo.rttMs.is_some() == (echo.status == EchoStatus::Reply)
                    && sample.error.is_none() == (echo.status == EchoStatus::Reply)
                    && (echo.status != EchoStatus::Reply || echo.responder == Some(target.address))
                    && (echo.status != EchoStatus::Reply
                        || target.scopeId == 0
                        || echo.responderScopeId == Some(target.scopeId))
            } else {
                false
            }
        }
        ProbeProtocol::DnsLookup => {
            if let Some(dns) = &sample.dns {
                sample.connectMs.is_none()
                    && sample.echo.is_none()
                    && dns.status != DnsStatus::Cancelled
                    && dns.lookupMs.is_none_or(timing)
                    && dns.responseMs.is_none_or(timing)
                    && dns.query.normalized()?
                        == endpoint
                            .dnsQuery
                            .as_ref()
                            .ok_or("DNS query missing")?
                            .normalized()?
                    && dns.lookupMs.is_some() == (dns.status == DnsStatus::Resolved)
                    && sample.error.is_none() == (dns.status == DnsStatus::Resolved)
                    && (dns.status != DnsStatus::Resolved || !dns.answers.is_empty())
            } else {
                false
            }
        }
    };
    if !valid {
        return Err(
            "Baseline sample has inconsistent protocol, outcome, or timing evidence".into(),
        );
    }
    Ok(time)
}

pub fn fromRun(
    run: &BenchmarkRun,
    selections: &[Selection],
    plan: &Plan,
    context: Context<'_>,
) -> AppResult<Session> {
    plan.validate()?;
    if let Some(routing) = &run.routing
        && (routing.schemaVersion != 1
            || !matches!(routing.status, RoutingStatus::Unchanged)
            || !routing.beforeFingerprint.as_deref().is_some_and(digest)
            || routing.beforeFingerprint != routing.afterFingerprint)
    {
        return Err("Recorded route choices changed or could not be verified; repeat this session before comparison".into());
    }
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
        || run.samples.len() != run.config.sampleCount as usize * run.results.len()
    {
        return Err("Only complete saved baselines with matching cohort, context, configuration, and sample counts can be compared".into());
    }
    let protocol = match run.results[0].endpoint.protocol {
        ProbeProtocol::TcpConnect => "tcpConnect",
        ProbeProtocol::IcmpEcho => "icmpEcho",
        ProbeProtocol::DnsLookup => "dnsLookup",
    };
    if run.protocol != protocol {
        return Err("Baseline protocol metadata does not match its endpoints".into());
    }
    let mut previousTime = start;
    for sample in &run.samples {
        let endpoint = run
            .results
            .iter()
            .find(|result| result.endpoint.id == sample.endpointId)
            .ok_or("Baseline sample refers to an unknown endpoint")?;
        let time = validateSample(sample, &endpoint.endpoint, start, finish)?;
        if time < previousTime {
            return Err(
                "Baseline samples must remain in their measured chronological order".into(),
            );
        }
        previousTime = time;
    }
    if run.results.iter().any(|result| {
        run.samples
            .iter()
            .filter(|sample| sample.endpointId == result.endpoint.id)
            .count()
            != run.config.sampleCount as usize
    }) {
        return Err("Baseline endpoint sample counts are incomplete or unbalanced".into());
    }
    let mut identifiers = BTreeSet::new();
    let mut values = Vec::new();
    for (selection, rule) in selections.iter().zip(&plan.metrics) {
        let endpoint = &run
            .results
            .iter()
            .find(|result| result.endpoint.id == selection.endpointId)
            .ok_or("Selected comparison endpoint is absent from the baseline")?
            .endpoint;
        if !identifier(&selection.metricId)
            || !identifiers.insert(&selection.metricId)
            || rule.id != selection.metricId
            || rule.direction != Direction::LowerIsBetter
            || rule.unit
                != if matches!(selection.statistic, Statistic::FailurePercent) {
                    Unit::Percent
                } else {
                    Unit::Milliseconds
                }
            || (endpoint.protocol == ProbeProtocol::IcmpEcho
                && rule.unit == Unit::Milliseconds
                && rule.resolution < 1.0)
        {
            return Err(
                "Baseline metric order, unit, direction, or measurement resolution is inconsistent"
                    .into(),
            );
        }
        let result = summarizeEndpoint(endpoint.clone(), &run.samples);
        if result.summary.attempted != run.config.sampleCount as usize {
            return Err("Baseline endpoint sample counts are incomplete or unbalanced".into());
        }
        let summary = result.summary;
        let value = match selection.statistic {
            Statistic::MedianMs => summary.medianMs,
            Statistic::P95Ms => summary.p95Ms,
            Statistic::P99Ms => summary.p99Ms,
            Statistic::IqrMs => summary.iqrMs,
            Statistic::SuccessiveVariationMs => summary.successiveVariationMs,
            Statistic::FailurePercent => match endpoint.protocol {
                ProbeProtocol::TcpConnect => summary.connectionFailurePercent,
                ProbeProtocol::IcmpEcho => summary.echoTimeoutPercent,
                ProbeProtocol::DnsLookup => summary.dnsFailurePercent,
            },
        }.ok_or("A required baseline metric is unavailable; preserve the failed session instead of treating it as zero")?;
        values.push(value);
    }
    Ok(Session {
        id: format!("baseline:{}", run.id),
        startedAtUnixMs: start,
        finishedAtUnixMs: finish,
        completed: true,
        cohortSha256: cohort,
        environmentSha256: context.environmentSha256.into(),
        configurationSha256: context.configurationSha256.into(),
        values,
    })
}
