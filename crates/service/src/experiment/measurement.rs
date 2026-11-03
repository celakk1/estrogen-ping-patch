use super::*;
use crate::{mtu::policy, recovery::policyObservationMatches, routing};
use epp_core::experiment::budget::Resources;
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) fn hash(value: &impl Serialize) -> ServiceResult<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeHashes {
    pub cohortSha256: String,
    pub environmentSha256: String,
    pub originalConfigurationSha256: String,
    pub candidateConfigurationSha256: String,
}

pub(super) struct AdapterScope {
    pub template: MtuCheckpoint,
    pub targets: Vec<routing::Address>,
    pub sources: Vec<routing::Address>,
    pub environmentSha256: String,
    pub originalConfigurationSha256: String,
    pub candidateConfigurationSha256: String,
}

fn sources(
    targets: &[routing::Address],
    captures: &[routing::Capture],
    native: &Snapshot,
) -> ServiceResult<Vec<routing::Address>> {
    if targets.len() != captures.len() {
        return Err("Every measurement target requires its own native route".into());
    }
    targets.iter().zip(captures).map(|(target,capture)| {
        let routing::Capture::Captured {snapshot} = capture else {return Err("A selected measurement route is unavailable".into());};
        snapshot.matchesInterface(native)?;
        if snapshot.destination != *target || snapshot.loopback || target.ip.is_loopback() {
            return Err("Optimization measurements require non-loopback routes through the exact changed adapter".into());
        }
        Ok(snapshot.source.clone())
    }).collect()
}

fn environment(template: &MtuCheckpoint, captures: &[routing::Capture]) -> ServiceResult<String> {
    let native = template
        .nativeOriginal
        .as_ref()
        .ok_or("Missing native original")?;
    let policy = template
        .policyOriginal
        .as_ref()
        .ok_or("Missing policy original")?;
    let fingerprint =
        routing::fingerprint(captures)?.ok_or("Measurement routes could not be verified")?;
    hash(&(
        "source-bound-adapter-baseline-v1",
        native.adapterGuid,
        native.addressFamily,
        &native.os,
        &native.driver,
        &native.registryOrigins,
        &policy.active,
        &policy.persistent,
        fingerprint,
    ))
}

impl AdapterScope {
    pub fn validateInput(
        template: &MtuCheckpoint,
        targets: &[routing::Address],
    ) -> ServiceResult<()> {
        template.validate()?;
        if template.schemaVersion != 4
            || !(1280..template.originalMtu).contains(&template.proposedMtu)
            || !(1..=8).contains(&targets.len())
        {
            return Err("Measurement scope requires a policy-backed MTU reduction and one to eight selected route targets".into());
        }
        for (index, target) in targets.iter().enumerate() {
            target.validateDestination()?;
            if target.ip.is_loopback() || targets[..index].contains(target) {
                return Err("Measurement route targets must be distinct and non-loopback".into());
            }
        }
        Ok(())
    }

    pub fn capture(
        template: MtuCheckpoint,
        targets: Vec<routing::Address>,
        cancelled: &AtomicBool,
    ) -> ServiceResult<Self> {
        Self::validateInput(&template, &targets)?;
        let current = policy::inspect(
            template.context.adapterGuid,
            template.addressFamily,
            cancelled,
        )?;
        let routes = routing::capture(&targets, cancelled)?;
        Self::fromEvidence(template, targets, current, routes)
    }

    pub fn fromEvidence(
        template: MtuCheckpoint,
        targets: Vec<routing::Address>,
        current: policy::Capture,
        routes: Vec<routing::Capture>,
    ) -> ServiceResult<Self> {
        Self::validateInput(&template, &targets)?;
        policyObservationMatches(&template, &current, template.originalMtu, nowUnixMs()?)?;
        let sources = sources(&targets, &routes, &current.native)?;
        let mut candidate = current.native.settings.clone();
        candidate.nlMtu = template.proposedMtu;
        let environmentSha256 = environment(&template, &routes)?;
        let originalConfigurationSha256 = hash(&current.native.settings)?;
        let candidateConfigurationSha256 = hash(&candidate)?;
        Ok(Self {
            template,
            targets,
            sources,
            environmentSha256,
            originalConfigurationSha256,
            candidateConfigurationSha256,
        })
    }

    pub fn hashes(&self, cohortSha256: String) -> ScopeHashes {
        ScopeHashes {
            cohortSha256,
            environmentSha256: self.environmentSha256.clone(),
            originalConfigurationSha256: self.originalConfigurationSha256.clone(),
            candidateConfigurationSha256: self.candidateConfigurationSha256.clone(),
        }
    }

    pub fn observe(
        &self,
        configuration: Configuration,
    ) -> ServiceResult<(policy::Capture, Vec<routing::Capture>)> {
        let cancelled = AtomicBool::new(false);
        let current = policy::inspect(
            self.template.context.adapterGuid,
            self.template.addressFamily,
            &cancelled,
        )?;
        let routes = routing::capture(&self.targets, &cancelled)?;
        self.verify(&current, &routes, configuration)?;
        Ok((current, routes))
    }

    pub fn verify(
        &self,
        current: &policy::Capture,
        routes: &[routing::Capture],
        configuration: Configuration,
    ) -> ServiceResult<()> {
        self.verifyAt(current, routes, configuration, nowUnixMs()?)
    }

    pub fn verifyRecorded(
        &self,
        current: &policy::Capture,
        routes: &[routing::Capture],
        configuration: Configuration,
    ) -> ServiceResult<()> {
        self.verifyAt(
            current,
            routes,
            configuration,
            current.native.capturedAtUnixMs,
        )
    }

    fn verifyAt(
        &self,
        current: &policy::Capture,
        routes: &[routing::Capture],
        configuration: Configuration,
        atUnixMs: u64,
    ) -> ServiceResult<()> {
        let expected = if configuration == Configuration::Original {
            self.template.originalMtu
        } else {
            self.template.proposedMtu
        };
        policyObservationMatches(&self.template, current, expected, atUnixMs)?;
        if current.native.operationalStatus != 1
            || current.native.mediaConnectState != 1
            || sources(&self.targets, routes, &current.native)? != self.sources
            || environment(&self.template, routes)? != self.environmentSha256
        {
            return Err("Native link, selected source, adapter route, or environment changed during collection".into());
        }
        Ok(())
    }

    pub fn verifyCheckpoint(
        &self,
        document: &MtuCheckpoint,
        expiresAtUnixMs: u64,
    ) -> ServiceResult<()> {
        document.validate()?;
        let original = &self.template;
        if document.schemaVersion != 4
            || document.context != original.context
            || document.addressFamily != original.addressFamily
            || document.authorizedUserSid != original.authorizedUserSid
            || document.originalMtu != original.originalMtu
            || document.proposedMtu != original.proposedMtu
            || document.leaseExpiresAtUnixMs > expiresAtUnixMs
        {
            return Err("Measurement checkpoint differs from its captured experiment scope".into());
        }
        document
            .nativeOriginal
            .as_ref()
            .ok_or("Missing checkpoint native original")?
            .validateMtuObservation(original.nativeOriginal.as_ref().unwrap())?;
        let first = document
            .policyOriginal
            .as_ref()
            .ok_or("Missing checkpoint policy")?;
        let expected = original.policyOriginal.as_ref().unwrap();
        if first.active != expected.active || first.persistent != expected.persistent {
            return Err("Measurement checkpoint policy changed".into());
        }
        Ok(())
    }
}

pub(super) fn validatePlan(
    plan: &Plan,
    hashes: &ScopeHashes,
    costs: &BTreeMap<String, Resources>,
) -> ServiceResult<()> {
    plan.validate()?;
    if plan.comparison.cohortSha256 != hashes.cohortSha256
        || plan.comparison.environmentSha256 != hashes.environmentSha256
        || plan.comparison.originalConfigurationSha256 != hashes.originalConfigurationSha256
        || plan.comparison.candidateConfigurationSha256 != hashes.candidateConfigurationSha256
    {
        return Err(
            "Experiment plan differs from the captured source-bound measurement scope".into(),
        );
    }
    let budget = plan
        .trafficBudget
        .as_ref()
        .ok_or("Collection requires explicit traffic limits")?;
    budget.bind(costs)?;
    if !budget.allows(plan.blockCount as u32)? {
        return Err("Traffic limits cannot cover every approved bracket".into());
    }
    Ok(())
}

pub(super) fn validateSessionWindow(
    session: &Session,
    plan: &Plan,
    configuration: Configuration,
    checkpoint: Option<&MtuCheckpoint>,
    beforeUnixMs: u64,
    afterUnixMs: u64,
) -> ServiceResult<()> {
    if session.startedAtUnixMs < plan.createdAtUnixMs
        || session.finishedAtUnixMs > plan.expiresAtUnixMs
        || beforeUnixMs > session.startedAtUnixMs.saturating_add(250)
        || afterUnixMs.saturating_add(250) < session.finishedAtUnixMs
        || beforeUnixMs > afterUnixMs
        || afterUnixMs > nowUnixMs()?.saturating_add(250)
    {
        return Err("Native measurement evidence must bracket a session within its frozen experiment window".into());
    }
    match (configuration, checkpoint) {
        (Configuration::Original, None) => Ok(()),
        (Configuration::Candidate, Some(document))
            if session.startedAtUnixMs.min(beforeUnixMs) >= document.createdAtUnixMs
                && session.finishedAtUnixMs.max(afterUnixMs) < document.leaseExpiresAtUnixMs => Ok(()),
        _ => Err("Candidate measurements and native evidence require their exact checkpoint's active lease; original measurements require no candidate binding".into()),
    }
}

pub(super) fn validateStorage(database: &Connection) -> ServiceResult<()> {
    let durable: u32 = database.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let foreignKeys: bool = database.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let mode: String = database.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let version: u32 = database.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if durable != 2 || !foreignKeys || !mode.eq_ignore_ascii_case("wal") || version != 6 {
        return Err("Measurement storage must be the validated application database with FULL durability, foreign keys, and WAL".into());
    }
    Ok(())
}
