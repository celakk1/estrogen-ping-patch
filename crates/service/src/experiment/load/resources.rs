use super::*;
use epp_core::comparison::{Direction, Role, Unit};
use serde::Serialize;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AdapterContext {
    adapterGuid: uuid::Uuid,
    interfaceLuid: String,
    interfaceIndex: u32,
    interfaceType: u32,
    operStatus: i32,
    adminStatus: i32,
    mediaConnectState: i32,
    receiveLinkSpeedBps: String,
    transmitLinkSpeedBps: String,
}

impl AdapterContext {
    fn fromSnapshot(snapshot: &routing::Snapshot) -> ServiceResult<Self> {
        snapshot.validate()?;
        let stats = snapshot
            .linkStatistics
            .as_deref()
            .ok_or("Load guards require reported adapter statistics")?;
        if stats.operStatus != 1
            || stats.adminStatus != 1
            || stats.mediaConnectState != 1
            || matches!(stats.receiveLinkSpeedBps.parse::<u64>()?, 0 | u64::MAX)
            || matches!(stats.transmitLinkSpeedBps.parse::<u64>()?, 0 | u64::MAX)
        {
            return Err("Reported adapter guards require an active connected interface with qualified positive link speeds".into());
        }
        Ok(Self {
            adapterGuid: snapshot.adapterGuid,
            interfaceLuid: snapshot.interfaceLuid.clone(),
            interfaceIndex: snapshot.interfaceIndex,
            interfaceType: stats.interfaceType,
            operStatus: stats.operStatus,
            adminStatus: stats.adminStatus,
            mediaConnectState: stats.mediaConnectState,
            receiveLinkSpeedBps: stats.receiveLinkSpeedBps.clone(),
            transmitLinkSpeedBps: stats.transmitLinkSpeedBps.clone(),
        })
    }

    pub(super) fn fromRoutes(routes: &[routing::Capture]) -> ServiceResult<Self> {
        Self::fromSnapshot(boundary(routes, true)?)
    }
}

pub const ADAPTER_GUARD_IDS: [&str; 5] = [
    "adapter.receivedErrors",
    "adapter.receivedDiscards",
    "adapter.receivedUnknownProtocols",
    "adapter.sentErrors",
    "adapter.sentDiscards",
];

pub(super) fn cohort(transferCohort: &str, context: &AdapterContext) -> ServiceResult<String> {
    hash(&(
        "adapter-load-reported-counters-v1",
        transferCohort,
        ADAPTER_GUARD_IDS,
        context,
    ))
}

pub(super) fn transferPlan(
    plan: &comparison::Plan,
    selections: usize,
    transferCohort: String,
) -> ServiceResult<comparison::Plan> {
    plan.validate()?;
    if plan.metrics.len() != selections + ADAPTER_GUARD_IDS.len() {
        return Err(
            "Load trials require all transfer metrics and five reported adapter counter guards"
                .into(),
        );
    }
    for (rule, id) in plan.metrics[selections..].iter().zip(ADAPTER_GUARD_IDS) {
        if rule.id != id
            || rule.unit != Unit::Count
            || rule.direction != Direction::LowerIsBetter
            || rule.role != Role::Guard
            || rule.resolution < 1.0
        {
            return Err("Reported adapter counters require the exact reviewed guard order, count units, lower-is-better direction, and integer resolution".into());
        }
    }
    let mut transfer = plan.clone();
    transfer.metrics.truncate(selections);
    transfer.cohortSha256 = transferCohort;
    transfer.validate()?;
    Ok(transfer)
}

fn counters(stats: &routing::LinkStatistics) -> ServiceResult<[u64; 11]> {
    Ok([
        stats.receivedErrors.parse()?,
        stats.receivedDiscards.parse()?,
        stats.receivedUnknownProtocols.parse()?,
        stats.sentErrors.parse()?,
        stats.sentDiscards.parse()?,
        stats.receivedOctets.parse()?,
        stats.sentOctets.parse()?,
        stats.receivedUnicastPackets.parse()?,
        stats.receivedNonUnicastPackets.parse()?,
        stats.sentUnicastPackets.parse()?,
        stats.sentNonUnicastPackets.parse()?,
    ])
}

fn compatible(before: &routing::LinkStatistics, after: &routing::LinkStatistics) -> bool {
    before.interfaceType == after.interfaceType
        && before.operStatus == after.operStatus
        && before.adminStatus == after.adminStatus
        && before.mediaConnectState == after.mediaConnectState
        && before.receiveLinkSpeedBps == after.receiveLinkSpeedBps
        && before.transmitLinkSpeedBps == after.transmitLinkSpeedBps
}

fn boundary(captures: &[routing::Capture], first: bool) -> ServiceResult<&routing::Snapshot> {
    if !(1..=routing::MAX_DESTINATIONS).contains(&captures.len()) {
        return Err("Adapter guard route boundary exceeds its bounded destination scope".into());
    }
    let mut previous: Option<&routing::Snapshot> = None;
    let mut selected = None;
    for capture in captures {
        let routing::Capture::Captured { snapshot } = capture else {
            return Err("Adapter guards require every selected route to be captured".into());
        };
        snapshot.validate()?;
        let stats = snapshot
            .linkStatistics
            .as_deref()
            .ok_or("Adapter guards require reported native counters; legacy absence is not zero")?;
        if let Some(previous) = previous {
            let prior = previous.linkStatistics.as_deref().unwrap();
            if snapshot.adapterGuid != previous.adapterGuid
                || snapshot.interfaceLuid != previous.interfaceLuid
                || snapshot.interfaceIndex != previous.interfaceIndex
                || !compatible(prior, stats)
                || prior.queryFinishedAtUnixMs > stats.queryStartedAtUnixMs
                || counters(prior)?
                    .iter()
                    .zip(counters(stats)?)
                    .any(|(left, right)| right < *left)
            {
                return Err("Adapter identity, reported state, query order, or counters changed within a boundary capture".into());
            }
        }
        if !first || selected.is_none() {
            selected = Some(snapshot);
        }
        previous = Some(snapshot);
    }
    selected.ok_or_else(|| "Adapter guard capture is empty".into())
}

pub(super) fn values(
    before: &[routing::Capture],
    after: &[routing::Capture],
    run: &SessionRun,
    context: &AdapterContext,
) -> ServiceResult<Vec<f64>> {
    let before = boundary(before, false)?;
    let after = boundary(after, true)?;
    if &AdapterContext::fromSnapshot(before)? != context
        || &AdapterContext::fromSnapshot(after)? != context
    {
        return Err(
            "Reported adapter resource context differs from its frozen review scope".into(),
        );
    }
    let first = before.linkStatistics.as_deref().unwrap();
    let last = after.linkStatistics.as_deref().unwrap();
    let started = chrono::DateTime::parse_from_rfc3339(&run.startedAt)?.timestamp_millis();
    let finished = chrono::DateTime::parse_from_rfc3339(&run.finishedAt)?.timestamp_millis();
    if before.adapterGuid != after.adapterGuid
        || before.interfaceLuid != after.interfaceLuid
        || before.interfaceIndex != after.interfaceIndex
        || !compatible(first, last)
        || first.operStatus != 1
        || first.adminStatus != 1
        || i64::try_from(first.queryFinishedAtUnixMs)? > started
        || i64::try_from(last.queryStartedAtUnixMs)? < finished
    {
        return Err("Reported adapter counter windows must bracket the complete run on the same active interface and unchanged link state/speed".into());
    }
    let before = counters(first)?;
    let after = counters(last)?;
    let mut deltas = [0u64; 11];
    for ((delta, before), after) in deltas.iter_mut().zip(before).zip(after) {
        *delta = after
            .checked_sub(before)
            .ok_or("Reported adapter counters reset, wrapped, or regressed")?;
    }
    let mut payload = [0u64; 2];
    for phase in &run.transfers {
        let result = phase
            .result
            .as_ref()
            .ok_or("Adapter guards require completed transfer payloads")?;
        let index = usize::from(result.plan.direction == transfer::Direction::Upload);
        payload[index] = payload[index]
            .checked_add(result.acceptedPayloadBytes)
            .ok_or("Adapter payload allowance overflowed")?;
    }
    if payload.contains(&0) || deltas[5] < payload[0] || deltas[6] < payload[1] {
        return Err("Reported adapter octet advances cannot account for the completed download and upload payloads".into());
    }
    deltas[..ADAPTER_GUARD_IDS.len()]
        .iter()
        .map(|value| {
            if *value > 1_000_000_000_000 {
                return Err(
                    "Reported adapter count delta exceeds the comparison value bound".into(),
                );
            }
            Ok(*value as f64)
        })
        .collect()
}
