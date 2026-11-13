use super::*;
use epp_core::packet_size::{self, Limits, Sample};
use std::sync::atomic::{AtomicBool, Ordering};

const FINAL_HEADROOM_MS: u64 = 19_000;

pub mod recording;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Plan {
    pub adapterGuid: Uuid,
    pub targets: Vec<routing::Address>,
    pub maximumDurationMs: u64,
    pub maximumProbes: usize,
    pub maximumRequestedIpv4Bytes: u64,
}

impl Plan {
    pub fn validate(&self) -> ServiceResult<()> {
        if self.adapterGuid.is_nil()
            || !(2..=8).contains(&self.targets.len())
            || !(35_000..=300_000).contains(&self.maximumDurationMs)
            || !(self.targets.len() * 10..=self.targets.len() * 144).contains(&self.maximumProbes)
            || self.maximumRequestedIpv4Bytes == 0
            || self.maximumRequestedIpv4Bytes > self.maximumProbes as u64 * 9000
        {
            return Err("MTU diagnosis requires an adapter, two to eight destinations, 35..300 seconds, and fixed probe/IPv4-byte allowances".into());
        }
        for (index, target) in self.targets.iter().enumerate() {
            target.validateDestination()?;
            if !target.ip.is_ipv4()
                || target.ip.is_loopback()
                || self.targets[..index].contains(target)
            {
                return Err(
                    "MTU diagnosis requires distinct non-loopback IPv4 destinations".into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum StopReason {
    Cancelled,
    TimeLimit,
    TrafficLimit,
    TargetLimit,
    Failed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Partial {
    pub before: Option<policy::Capture>,
    pub routesBefore: Vec<routing::Capture>,
    pub reports: Vec<Report>,
    pub after: Option<policy::Capture>,
    pub routesAfter: Vec<routing::Capture>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Collection {
    Completed {
        plan: Plan,
        evidence: Box<Evidence>,
        proposal: Option<Box<MtuProposal>>,
    },
    Stopped {
        plan: Plan,
        reason: StopReason,
        detail: String,
        evidence: Box<Partial>,
    },
}

trait Backend {
    fn diagnose(
        &mut self,
        plan: packet_size::Plan,
        limits: Limits,
        cancelled: &AtomicBool,
        progress: &mut dyn FnMut(&Sample) -> ServiceResult<()>,
    ) -> ServiceResult<Report>;
    fn policy(
        &mut self,
        adapterGuid: Uuid,
        cancelled: &AtomicBool,
    ) -> ServiceResult<policy::Capture>;
    fn routes(
        &mut self,
        targets: &[routing::Address],
        cancelled: &AtomicBool,
    ) -> ServiceResult<Vec<routing::Capture>>;
}

#[derive(Default)]
struct Native;

impl Backend for Native {
    fn diagnose(
        &mut self,
        plan: packet_size::Plan,
        limits: Limits,
        cancelled: &AtomicBool,
        progress: &mut dyn FnMut(&Sample) -> ServiceResult<()>,
    ) -> ServiceResult<Report> {
        crate::read_worker::diagnose(plan, limits, cancelled, progress)
    }
    fn policy(
        &mut self,
        adapterGuid: Uuid,
        cancelled: &AtomicBool,
    ) -> ServiceResult<policy::Capture> {
        policy::inspect(adapterGuid, AddressFamily::Ipv4, cancelled)
    }
    fn routes(
        &mut self,
        targets: &[routing::Address],
        cancelled: &AtomicBool,
    ) -> ServiceResult<Vec<routing::Capture>> {
        crate::read_worker::routes(targets, cancelled)
    }
}

struct Guard<'a> {
    cancelled: &'a AtomicBool,
    deadline: Instant,
    expiresAtUnixMs: u64,
    highWaterUnixMs: u64,
}

type Stop = (StopReason, String);

impl Guard<'_> {
    fn check(&mut self) -> Result<Duration, Stop> {
        let now = crate::watchdog::nowUnixMs()
            .map_err(|error| (StopReason::Failed, error.to_string()))?;
        if now < self.highWaterUnixMs {
            return Err((
                StopReason::Failed,
                "The clock moved backward during MTU diagnosis".into(),
            ));
        }
        self.highWaterUnixMs = now;
        if self.cancelled.load(Ordering::SeqCst) {
            return Err((StopReason::Cancelled, "MTU diagnosis was cancelled".into()));
        }
        let remaining =
            self.deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(
                    self.expiresAtUnixMs.saturating_sub(now),
                ));
        if remaining.is_zero() {
            return Err((
                StopReason::TimeLimit,
                "MTU diagnosis reached its shared time allowance".into(),
            ));
        }
        Ok(remaining)
    }
}

pub fn collect(
    plan: Plan,
    cancelled: &AtomicBool,
    progress: impl FnMut(usize, &Sample) -> ServiceResult<()>,
) -> ServiceResult<Collection> {
    collectWithBackend(plan, cancelled, progress, &mut Native)
}

fn collectWithBackend<B: Backend>(
    plan: Plan,
    cancelled: &AtomicBool,
    mut progress: impl FnMut(usize, &Sample) -> ServiceResult<()>,
    backend: &mut B,
) -> ServiceResult<Collection> {
    plan.validate()?;
    let now = crate::watchdog::nowUnixMs()?;
    let mut guard = Guard {
        cancelled,
        deadline: Instant::now()
            .checked_add(Duration::from_millis(plan.maximumDurationMs))
            .ok_or("MTU diagnosis deadline overflow")?,
        expiresAtUnixMs: now
            .checked_add(plan.maximumDurationMs)
            .ok_or("MTU diagnosis expiry overflow")?,
        highWaterUnixMs: now,
    };
    let mut partial = Partial {
        before: None,
        routesBefore: Vec::new(),
        reports: Vec::new(),
        after: None,
        routesAfter: Vec::new(),
    };
    let failed =
        |error: Box<dyn std::error::Error + Send + Sync>| (StopReason::Failed, error.to_string());
    let result = (|| -> Result<(), Stop> {
        guard.check()?;
        partial.before = Some(
            backend
                .policy(plan.adapterGuid, cancelled)
                .map_err(failed)?,
        );
        guard.check()?;
        let before = partial.before.as_ref().unwrap();
        if before.native.adapterGuid != plan.adapterGuid {
            return Err((
                StopReason::Failed,
                "MTU diagnosis capture returned a different adapter".into(),
            ));
        }
        partial.routesBefore = backend.routes(&plan.targets, cancelled).map_err(failed)?;
        guard.check()?;
        routesMatch(&plan.targets, &partial.routesBefore, before).map_err(failed)?;
        if before.native.capturedAtUnixMs > guard.highWaterUnixMs
            || guard.highWaterUnixMs - before.native.capturedAtUnixMs > 5000
            || !routeTimes(&partial.routesBefore, |time| {
                time >= before.native.capturedAtUnixMs && time <= guard.highWaterUnixMs
            })
        {
            return Err((
                StopReason::Failed,
                "MTU diagnosis needs fresh native and selected-route evidence before traffic"
                    .into(),
            ));
        }
        let mut usedProbes = 0;
        let mut usedBytes = 0;
        for (index, target) in plan.targets.iter().enumerate() {
            let remaining = guard.check()?;
            let budgetMs = remaining
                .as_millis()
                .saturating_sub(u128::from(FINAL_HEADROOM_MS))
                .min(120_000) as u32;
            if budgetMs < 1000 {
                return Err((
                    StopReason::TimeLimit,
                    "Insufficient time remains for diagnosis and final native verification".into(),
                ));
            }
            if usedProbes >= plan.maximumProbes || usedBytes >= plan.maximumRequestedIpv4Bytes {
                return Err((
                    StopReason::TrafficLimit,
                    "MTU diagnosis reached its shared traffic allowance".into(),
                ));
            }
            let routing::Capture::Captured { snapshot: route } = &partial.routesBefore[index]
            else {
                unreachable!()
            };
            let (std::net::IpAddr::V4(source), std::net::IpAddr::V4(destination)) =
                (route.source.ip, target.ip)
            else {
                unreachable!()
            };
            let mut callbackError = None;
            let report = backend
                .diagnose(
                    packet_size::Plan {
                        source,
                        destination,
                        interfaceMtu: before.native.settings.nlMtu,
                        timeoutMs: 750,
                        intervalMs: 75,
                        budgetMs,
                    },
                    Limits {
                        maximumProbes: (plan.maximumProbes - usedProbes).min(144),
                        maximumRequestedIpv4Bytes: (plan.maximumRequestedIpv4Bytes - usedBytes)
                            .min(Limits::default().maximumRequestedIpv4Bytes),
                    },
                    cancelled,
                    &mut |sample| {
                        if callbackError.is_none() {
                            let result = guard
                                .check()
                                .and_then(|_| progress(index, sample).map_err(failed));
                            if let Err(error) = result {
                                callbackError = Some(error);
                                cancelled.store(true, Ordering::SeqCst);
                            }
                        }
                        Ok(())
                    },
                )
                .map_err(failed)?;
            usedProbes += report.samples.len();
            usedBytes += report.requestedIpv4Bytes;
            let outcome = report.outcome;
            partial.reports.push(report);
            if let Some(error) = callbackError {
                return Err(error);
            }
            guard.check()?;
            if !matches!(
                outcome,
                Outcome::TestedLimitReached | Outcome::SizeBoundaryObserved
            ) {
                return Err((
                    if outcome == Outcome::BudgetExpired {
                        if usedProbes >= plan.maximumProbes
                            || usedBytes >= plan.maximumRequestedIpv4Bytes
                        {
                            StopReason::TrafficLimit
                        } else {
                            StopReason::TargetLimit
                        }
                    } else {
                        StopReason::Failed
                    },
                    format!("MTU diagnosis target {index} did not complete: {outcome:?}"),
                ));
            }
        }
        if guard.check()?.as_millis() < u128::from(FINAL_HEADROOM_MS) {
            return Err((
                StopReason::TimeLimit,
                "Insufficient time remains for final native verification".into(),
            ));
        }
        partial.routesAfter = backend.routes(&plan.targets, cancelled).map_err(failed)?;
        if guard.check()?.as_millis() < 15_000 {
            return Err((
                StopReason::TimeLimit,
                "Insufficient time remains for final policy capture".into(),
            ));
        }
        partial.after = Some(
            backend
                .policy(plan.adapterGuid, cancelled)
                .map_err(failed)?,
        );
        guard.check()?;
        Ok(())
    })();
    let stop = |reason, detail: String, evidence| Collection::Stopped {
        plan: plan.clone(),
        reason,
        detail: detail
            .chars()
            .take(512)
            .map(|value| if value.is_control() { ' ' } else { value })
            .collect(),
        evidence: Box::new(evidence),
    };
    if let Err((reason, detail)) = result {
        return Ok(stop(reason, detail, partial));
    }
    let evidence = Evidence {
        before: partial.before.take().unwrap(),
        routesBefore: partial.routesBefore,
        reports: partial.reports,
        after: partial.after.take().unwrap(),
        routesAfter: partial.routesAfter,
    };
    match crate::watchdog::nowUnixMs().and_then(|now| proposeMtu(&plan.targets, &evidence, now)) {
        Ok(proposal) => Ok(Collection::Completed {
            plan,
            evidence: Box::new(evidence),
            proposal: proposal.map(Box::new),
        }),
        Err(error) => Ok(stop(
            StopReason::Failed,
            error.to_string(),
            Partial {
                before: Some(evidence.before),
                routesBefore: evidence.routesBefore,
                reports: evidence.reports,
                after: Some(evidence.after),
                routesAfter: evidence.routesAfter,
            },
        )),
    }
}

#[cfg(test)]
mod tests;
