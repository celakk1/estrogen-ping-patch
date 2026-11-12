use super::measurement::hash;
use crate::{
    ServiceResult,
    journal::{AddressFamily, MtuCheckpoint},
    mtu::policy,
    routing,
};
use epp_core::packet_size::{Outcome, Report};
use serde::Serialize;
use std::time::{Duration, Instant};
use uuid::Uuid;

const MAX_AGE_MS: u64 = 300_000;

pub mod diagnosis;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub before: policy::Capture,
    pub routesBefore: Vec<routing::Capture>,
    pub reports: Vec<Report>,
    pub after: policy::Capture,
    pub routesAfter: Vec<routing::Capture>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub candidateId: String,
    pub adapterGuid: Uuid,
    pub addressFamily: AddressFamily,
    pub originalMtu: u32,
    pub proposedMtu: u32,
    pub targets: Vec<routing::Address>,
    pub boundaryTargets: Vec<routing::Address>,
    pub evidenceSha256: String,
    pub diagnosedAtUnixMs: u64,
    pub expiresAtUnixMs: u64,
}

#[derive(Serialize)]
#[serde(transparent)]
pub struct MtuProposal {
    summary: Summary,
    #[serde(skip)]
    original: policy::Capture,
    #[serde(skip)]
    routeSha256: String,
    #[serde(skip)]
    deadline: Instant,
    #[serde(skip)]
    highWaterUnixMs: u64,
    #[serde(skip)]
    stopped: bool,
}

fn routesMatch(
    targets: &[routing::Address],
    routes: &[routing::Capture],
    policy: &policy::Capture,
) -> ServiceResult<String> {
    policy.validate()?;
    if policy.native.addressFamily != AddressFamily::Ipv4
        || policy.native.operationalStatus != 1
        || policy.native.mediaConnectState != 1
        || routes.len() != targets.len()
    {
        return Err(
            "MTU diagnosis requires the same connected IPv4 adapter for every target".into(),
        );
    }
    for (target, route) in targets.iter().zip(routes) {
        target.validateDestination()?;
        let routing::Capture::Captured { snapshot } = route else {
            return Err("MTU diagnosis has an unavailable selected route".into());
        };
        snapshot.matchesInterface(&policy.native)?;
        if target != &snapshot.destination || snapshot.loopback || target.ip.is_loopback() {
            return Err(
                "MTU diagnosis targets must match their non-loopback selected routes".into(),
            );
        }
    }
    routing::fingerprint(routes)?.ok_or_else(|| "MTU diagnosis routes are unavailable".into())
}

fn unchanged(original: &policy::Capture, current: &policy::Capture) -> ServiceResult<()> {
    original
        .evidence()
        .validateMtuObservation(&original.native, current)?;
    if original.native.settings.nlMtu != current.native.settings.nlMtu {
        return Err("MTU changed during candidate diagnosis".into());
    }
    Ok(())
}

fn routeTimes(routes: &[routing::Capture], check: impl Fn(u64) -> bool) -> bool {
    routes.iter().all(|route| {
        matches!(route, routing::Capture::Captured {snapshot} if check(snapshot.capturedAtUnixMs))
    })
}

pub fn proposeMtu(
    targets: &[routing::Address],
    evidence: &Evidence,
    nowUnixMs: u64,
) -> ServiceResult<Option<MtuProposal>> {
    if !(2..=8).contains(&targets.len())
        || targets
            .iter()
            .enumerate()
            .any(|(index, target)| !target.ip.is_ipv4() || targets[..index].contains(target))
        || evidence.reports.len() != targets.len()
        || nowUnixMs > i64::MAX as u64
    {
        return Err("MTU candidate diagnosis requires the complete frozen cohort of two to eight distinct IPv4 targets".into());
    }
    let routeSha256 = routesMatch(targets, &evidence.routesBefore, &evidence.before)?;
    if routesMatch(targets, &evidence.routesAfter, &evidence.after)? != routeSha256 {
        return Err("Selected routes changed during MTU candidate diagnosis".into());
    }
    unchanged(&evidence.before, &evidence.after)?;
    let before = evidence.before.native.capturedAtUnixMs;
    let after = evidence.after.native.capturedAtUnixMs;
    let expiresAtUnixMs = before
        .checked_add(MAX_AGE_MS)
        .ok_or("MTU diagnosis expiry overflow")?;
    if before == 0 || after < before || after > nowUnixMs || nowUnixMs >= expiresAtUnixMs {
        return Err("MTU candidate diagnosis is stale or has invalid capture times".into());
    }
    let mut previous = before;
    let mut proposedMtu = evidence.before.native.settings.nlMtu;
    let mut boundaryTargets = Vec::new();
    for (index, (target, report)) in targets.iter().zip(&evidence.reports).enumerate() {
        report.validate()?;
        let routing::Capture::Captured { snapshot: route } = &evidence.routesBefore[index] else {
            return Err("MTU diagnosis route is unavailable".into());
        };
        if report.plan.source != route.source.ip
            || report.plan.destination != target.ip
            || report.plan.interfaceMtu != evidence.before.native.settings.nlMtu
            || report.startedAtUnixMs < previous
            || report.finishedAtUnixMs > after
            || report
                .finishedAtUnixMs
                .checked_sub(report.startedAtUnixMs)
                .is_none_or(|duration| duration > u64::from(report.plan.budgetMs) + 1000)
            || !matches!(
                report.outcome,
                Outcome::TestedLimitReached | Outcome::SizeBoundaryObserved
            )
        {
            return Err("MTU candidate diagnosis requires complete source-bound reports bracketed by unchanged native evidence".into());
        }
        previous = report.finishedAtUnixMs;
        if let Some(boundary) = report.confirmedBoundaryBytes {
            proposedMtu = proposedMtu.min(boundary);
            boundaryTargets.push(target.clone());
        }
    }
    let first = evidence.reports[0].startedAtUnixMs;
    if !routeTimes(&evidence.routesBefore, |time| {
        time >= before && time <= first
    }) || !routeTimes(&evidence.routesAfter, |time| {
        time >= previous && time <= after
    }) {
        return Err("Selected route captures do not bracket MTU diagnosis".into());
    }
    if boundaryTargets.is_empty() {
        return Ok(None);
    }
    if !(1280..evidence.before.native.settings.nlMtu).contains(&proposedMtu) {
        return Err("The diagnosed MTU is outside the supported temporary-trial range; no candidate was proposed".into());
    }
    Ok(Some(MtuProposal {
        summary: Summary {
            candidateId: "ip.pathMtu".into(),
            adapterGuid: evidence.before.native.adapterGuid,
            addressFamily: AddressFamily::Ipv4,
            originalMtu: evidence.before.native.settings.nlMtu,
            proposedMtu,
            targets: targets.to_vec(),
            boundaryTargets,
            evidenceSha256: hash(&("controlled-mtu-proposal-v1", targets, evidence))?,
            diagnosedAtUnixMs: after,
            expiresAtUnixMs,
        },
        original: evidence.before.clone(),
        routeSha256,
        deadline: Instant::now()
            .checked_add(Duration::from_millis(expiresAtUnixMs - nowUnixMs))
            .ok_or("MTU proposal monotonic deadline overflow")?,
        highWaterUnixMs: nowUnixMs,
        stopped: false,
    }))
}

impl MtuProposal {
    pub fn summary(&self) -> &Summary {
        &self.summary
    }

    pub fn checkpoint(
        &mut self,
        current: &policy::Capture,
        routes: &[routing::Capture],
        ownerSid: &str,
        trialDurationMs: u64,
        nowUnixMs: u64,
    ) -> ServiceResult<MtuCheckpoint> {
        if self.stopped
            || nowUnixMs < self.highWaterUnixMs
            || nowUnixMs >= self.summary.expiresAtUnixMs
            || Instant::now() >= self.deadline
        {
            self.stopped = true;
            return Err(
                "MTU proposal expired or its clock moved backward; collect a fresh diagnosis"
                    .into(),
            );
        }
        self.highWaterUnixMs = nowUnixMs;
        if !(5000..=300_000).contains(&trialDurationMs)
            || !routeTimes(routes, |time| time <= nowUnixMs && nowUnixMs - time <= 5000)
            || current.native.capturedAtUnixMs > nowUnixMs
            || nowUnixMs - current.native.capturedAtUnixMs > 5000
        {
            return Err("MTU proposal expired or needs fresh native and route evidence with a bounded trial lease".into());
        }
        unchanged(&self.original, current)?;
        if routesMatch(&self.summary.targets, routes, current)? != self.routeSha256 {
            return Err(
                "MTU proposal selected routes changed before checkpoint preparation".into(),
            );
        }
        let document = MtuCheckpoint {
            schemaVersion: 4,
            id: Uuid::new_v4(),
            createdAtUnixMs: nowUnixMs,
            leaseExpiresAtUnixMs: nowUnixMs
                .checked_add(trialDurationMs)
                .ok_or("MTU trial deadline overflow")?,
            authorizedUserSid: ownerSid.into(),
            context: current.native.journalContext()?,
            addressFamily: AddressFamily::Ipv4,
            originalMtu: current.native.settings.nlMtu,
            proposedMtu: self.summary.proposedMtu,
            nativeOriginal: Some(current.native.clone()),
            policyOriginal: Some(current.evidence()),
        };
        document.validate()?;
        Ok(document)
    }
}

#[cfg(test)]
mod tests;
