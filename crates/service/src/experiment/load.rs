pub use super::measurement::ScopeHashes;
use super::measurement::{self, AdapterScope, hash};
use super::*;
use crate::{mtu::policy, routing};
use epp_core::{
    benchmark::{Endpoint, ProbeProtocol, SourceBinding as EchoBinding},
    comparison::{self, load as comparisonLoad},
    config::Config,
    experiment::budget::Resources,
    icmp::EchoTarget,
    transfer::{
        self,
        session::{self, SessionPlan, SessionRun, SourceBindings},
    },
};
use rusqlite::Connection;
use std::{collections::BTreeMap, net::SocketAddr};

pub mod recording;

pub struct Scope {
    adapter: AdapterScope,
    config: Config,
    sessionPlan: SessionPlan,
    bindings: SourceBindings,
    selections: Vec<comparisonLoad::Selection>,
    hashes: ScopeHashes,
    costs: BTreeMap<String, Resources>,
}

fn address(peer: SocketAddr) -> routing::Address {
    routing::Address {
        ip: peer.ip(),
        scopeId: match peer {
            SocketAddr::V4(_) => 0,
            SocketAddr::V6(peer) => peer.scope_id(),
        },
    }
}

fn targets(endpoints: &[Endpoint], peers: &[SocketAddr]) -> ServiceResult<Vec<routing::Address>> {
    let mut targets = Vec::new();
    for endpoint in endpoints {
        let (ip, scopeId) = endpoint.destinationAddress()?;
        let target = routing::Address { ip, scopeId };
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    for peer in peers {
        let target = address(*peer);
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    Ok(targets)
}

impl Scope {
    fn validateInput(
        template: &MtuCheckpoint,
        config: &Config,
        plan: &SessionPlan,
        peers: &[SocketAddr],
    ) -> ServiceResult<()> {
        template.validate()?;
        plan.validate(config)?;
        let lease = template.leaseExpiresAtUnixMs - template.createdAtUnixMs;
        if peers.len() != plan.providers.len()
            || plan.idleRounds < 12
            || plan.probeTimeoutMs + plan.intervalMs > 1500
            || lease > 300_000
            || u64::from(config.sessionMinutes) * 60_000 + 30_000 > lease
            || plan
                .latencyEndpoints
                .iter()
                .any(|endpoint| endpoint.protocol != ProbeProtocol::IcmpEcho)
        {
            return Err("Bound load collection requires complete provider peers, echo-only latency, twelve idle rounds, bounded heartbeat gaps, a five-minute maximum trial, and thirty seconds of native-verification headroom".into());
        }
        let roundMs = plan.latencyEndpoints.len() as u64 * plan.intervalMs;
        let loadedPhaseMs = 12 * roundMs;
        let minimumSessionMs = plan.providers.len() as u64
            * (2 * u64::from(plan.idleRounds) * roundMs + 2 * loadedPhaseMs);
        if plan.phaseTimeoutMs < loadedPhaseMs {
            return Err(format!("Each transfer phase needs at least {:.1} seconds for twelve paced probes per destination; its limit is {:.1} seconds. Increase the phase timeout or use fewer destinations", loadedPhaseMs as f64/1000.0, plan.phaseTimeoutMs as f64/1000.0).into());
        }
        if minimumSessionMs >= u64::from(config.sessionMinutes) * 60_000 {
            return Err(format!("This load plan needs more than {:.1} seconds of sampling across all providers and phases; the session limit is {} seconds. Allow more time or use fewer providers and destinations",minimumSessionMs as f64/1000.0,u64::from(config.sessionMinutes)*60).into());
        }
        AdapterScope::validateInput(template, &targets(&plan.latencyEndpoints, peers)?)
    }

    pub fn capture(
        template: MtuCheckpoint,
        config: Config,
        plan: SessionPlan,
        peers: Vec<SocketAddr>,
        selections: Vec<comparisonLoad::Selection>,
        cancelled: &AtomicBool,
    ) -> ServiceResult<Self> {
        Self::validateInput(&template, &config, &plan, &peers)?;
        let adapter = AdapterScope::capture(
            template,
            targets(&plan.latencyEndpoints, &peers)?,
            cancelled,
        )?;
        Self::fromAdapter(adapter, config, plan, peers, selections)
    }

    fn fromAdapter(
        adapter: AdapterScope,
        config: Config,
        sessionPlan: SessionPlan,
        peers: Vec<SocketAddr>,
        selections: Vec<comparisonLoad::Selection>,
    ) -> ServiceResult<Self> {
        Self::validateInput(&adapter.template, &config, &sessionPlan, &peers)?;
        if adapter.targets != targets(&sessionPlan.latencyEndpoints, &peers)? {
            return Err("Load targets differ from the captured adapter scope".into());
        }
        let sourceFor = |target: &routing::Address| -> ServiceResult<routing::Address> {
            let index = adapter
                .targets
                .iter()
                .position(|candidate| candidate == target)
                .ok_or("Missing selected load route")?;
            Ok(adapter.sources[index].clone())
        };
        let latency = sessionPlan
            .latencyEndpoints
            .iter()
            .map(|endpoint| {
                let (ip, scopeId) = endpoint.destinationAddress()?;
                let source = sourceFor(&routing::Address { ip, scopeId })?;
                Ok(EchoBinding {
                    endpointId: endpoint.id.clone(),
                    source: EchoTarget {
                        address: source.ip,
                        scopeId: source.scopeId,
                    },
                })
            })
            .collect::<ServiceResult<Vec<_>>>()?;
        let transfers = peers
            .iter()
            .map(|peer| {
                let source = sourceFor(&address(*peer))?;
                if source.scopeId != 0 {
                    return Err("Scoped transfer sources are unsupported".into());
                }
                Ok(transfer::SourceBinding {
                    source: source.ip,
                    peer: *peer,
                })
            })
            .collect::<ServiceResult<Vec<_>>>()?;
        let bindings = SourceBindings { transfers, latency };
        bindings.validate(&sessionPlan)?;
        let blueprint = session::runSourceBoundSessionWithRunner(
            config.clone(),
            sessionPlan.clone(),
            bindings.clone(),
            &AtomicBool::new(true),
            |_| {},
            &recording::Runner,
        )?;
        let hashes = adapter.hashes(comparisonLoad::cohortSha256(&blueprint, &selections)?);
        let attempts =
            (u64::from(config.sessionMinutes) * 60_000).div_ceil(sessionPlan.intervalMs) + 1;
        let mut costs = BTreeMap::new();
        for index in 0..sessionPlan.latencyEndpoints.len() {
            costs.insert(
                format!("echo-{index}"),
                Resources {
                    probeAttempts: attempts,
                    ..Default::default()
                },
            );
        }
        for index in 0..sessionPlan.providers.len() {
            costs.insert(
                format!("load-{index}"),
                Resources {
                    providerRequests: 2 * u64::from(sessionPlan.streams),
                    downloadBytes: sessionPlan.downloadBytesPerProvider,
                    uploadBytes: sessionPlan.uploadBytesPerProvider,
                    ..Default::default()
                },
            );
        }
        Ok(Self {
            adapter,
            config,
            sessionPlan,
            bindings,
            selections,
            hashes,
            costs,
        })
    }

    pub fn hashes(&self) -> &ScopeHashes {
        &self.hashes
    }
    pub fn maximumTraffic(&self) -> &BTreeMap<String, Resources> {
        &self.costs
    }

    pub fn bind(self, database: &mut Connection, plan: Plan) -> ServiceResult<Collector<'_>> {
        measurement::validatePlan(&plan, &self.hashes, &self.costs)?;
        comparisonLoad::validateProfileObjectives(
            self.config.profile,
            &self.selections,
            &plan.comparison,
        )?;
        for (rule, selection) in plan.comparison.metrics.iter().zip(&self.selections) {
            let (unit, direction, resolution, guard) = match selection.statistic {
                comparisonLoad::Statistic::GoodputMbps { .. } => (
                    comparison::Unit::MegabitsPerSecond,
                    comparison::Direction::HigherIsBetter,
                    0.0,
                    false,
                ),
                comparisonLoad::Statistic::MedianMs { .. }
                | comparisonLoad::Statistic::P95Ms { .. }
                | comparisonLoad::Statistic::P99Ms { .. }
                | comparisonLoad::Statistic::IqrMs { .. }
                | comparisonLoad::Statistic::SuccessiveVariationMs { .. } => (
                    comparison::Unit::Milliseconds,
                    comparison::Direction::LowerIsBetter,
                    1.0,
                    false,
                ),
                comparisonLoad::Statistic::FailurePercent { .. } => (
                    comparison::Unit::Percent,
                    comparison::Direction::LowerIsBetter,
                    100.0 / 12.0,
                    true,
                ),
            };
            if rule.id != selection.metricId
                || rule.unit != unit
                || rule.direction != direction
                || rule.resolution < resolution
                || (guard && rule.role != comparison::Role::Guard)
            {
                return Err("Load metric rules differ from their units, directions, guards, or conservative resolution".into());
            }
        }
        measurement::validateStorage(database)?;
        recording::initialize(database)?;
        database.execute_batch("CREATE TABLE IF NOT EXISTS adapter_load_measurements(run_id INTEGER PRIMARY KEY REFERENCES load_sessions(id), experiment_id TEXT NOT NULL, payload_json TEXT NOT NULL, sha256 TEXT NOT NULL)")?;
        Ok(Collector {
            scope: self,
            database,
            plan,
            checkpoint: None,
        })
    }
}

pub struct Collector<'a> {
    scope: Scope,
    database: &'a mut Connection,
    plan: Plan,
    checkpoint: Option<MtuCheckpoint>,
}

impl Collector<'_> {
    fn verifySaved(
        database: &Connection,
        run: &SessionRun,
        payload: &str,
        checksum: &str,
    ) -> ServiceResult<()> {
        let saved: (String, String) = database.query_row(
            "SELECT payload_json,sha256 FROM adapter_load_measurements WHERE run_id=?1",
            [run.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let raw: String = database.query_row(
            "SELECT report_json FROM load_sessions WHERE id=?1",
            [run.id],
            |row| row.get(0),
        )?;
        if saved.0 != payload || saved.1 != checksum || raw != serde_json::to_string(run)? {
            return Err(
                "Committed load report or native receipt differs from captured evidence".into(),
            );
        }
        Ok(())
    }

    fn acceptRaw(
        &mut self,
        run: &SessionRun,
        before: &(policy::Capture, Vec<routing::Capture>),
        after: &(policy::Capture, Vec<routing::Capture>),
        configuration: Configuration,
    ) -> ServiceResult<Session> {
        if run.transferExecution != Some(session::TransferExecution::RecordedRestrictedWorkerV1) {
            return Err("Bound load collection requires isolated-worker execution evidence".into());
        }
        if (configuration == Configuration::Candidate) != self.checkpoint.is_some() {
            return Err("Candidate load measurements require their exact issued checkpoint".into());
        }
        let measured = comparisonLoad::fromRun(
            run,
            &self.scope.selections,
            &self.plan.comparison,
            comparison::baseline::Context {
                environmentSha256: &self.scope.hashes.environmentSha256,
                configurationSha256: if configuration == Configuration::Candidate {
                    &self.scope.hashes.candidateConfigurationSha256
                } else {
                    &self.scope.hashes.originalConfigurationSha256
                },
            },
        )?;
        self.scope
            .adapter
            .verifyRecorded(&before.0, &before.1, configuration)?;
        self.scope
            .adapter
            .verifyRecorded(&after.0, &after.1, configuration)?;
        measurement::validateSessionWindow(
            &measured,
            &self.plan,
            configuration,
            self.checkpoint.as_ref(),
            before.0.native.capturedAtUnixMs,
            after.0.native.capturedAtUnixMs,
        )?;
        if before.0.native.capturedAtUnixMs
            < self
                .scope
                .adapter
                .template
                .createdAtUnixMs
                .saturating_sub(250)
        {
            return Err("Native load evidence does not bracket its raw session".into());
        }
        let receipt = serde_json::json!({"schemaVersion":1,"benchmarkScope":"sourceBoundAdapterLoad","experimentId":self.plan.id,"checkpointId":self.checkpoint.as_ref().map(|document|document.id),"checkpointSha256":self.checkpoint.as_ref().map(crate::authorization::checkpointChecksum).transpose()?,"configuration":if configuration==Configuration::Candidate {"candidate"} else {"original"},"rawRunId":run.id,"rawRunSha256":hash(run)?,"nativeBefore":before.0,"nativeAfter":after.0,"routesBefore":before.1,"routesAfter":after.1});
        let payload = serde_json::to_string(&receipt)?;
        if payload.len() > 131_072 {
            return Err("Native load receipt exceeds 128 KiB".into());
        }
        let checksum = epp_core::backups::checksum(&payload);
        let transaction = self
            .database
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        transaction.execute("INSERT INTO adapter_load_measurements(run_id,experiment_id,payload_json,sha256) VALUES(?1,?2,?3,?4)",(run.id,&self.plan.id,&payload,&checksum))?;
        Self::verifySaved(&transaction, run, &payload, &checksum)?;
        transaction.commit()?;
        Self::verifySaved(self.database, run, &payload, &checksum)?;
        Ok(measured)
    }
}

impl Measurements for Collector<'_> {
    fn maximumTraffic(&self) -> ServiceResult<BTreeMap<String, Resources>> {
        Ok(self.scope.costs.clone())
    }
    fn bindCheckpoint(&mut self, document: Option<&MtuCheckpoint>) -> ServiceResult<()> {
        if let Some(document) = document {
            self.scope
                .adapter
                .verifyCheckpoint(document, self.plan.expiresAtUnixMs)?;
        }
        self.checkpoint = document.cloned();
        Ok(())
    }
    fn verifyEnvironment(&mut self, plan: &Plan, original: &Snapshot) -> ServiceResult<()> {
        if hash(plan)? != hash(&self.plan)?
            || hash(&original.settings)? != self.scope.hashes.originalConfigurationSha256
        {
            return Err("Load plan or original configuration changed".into());
        }
        self.scope
            .adapter
            .observe(Configuration::Original)
            .map(|_| ())
    }
    fn collect(
        &mut self,
        configuration: Configuration,
        progress: &Progress<'_, '_>,
    ) -> ServiceResult<Session> {
        progress.check()?;
        if (configuration == Configuration::Candidate) != self.checkpoint.is_some() {
            return Err("Candidate load measurements require their exact issued checkpoint".into());
        }
        let before = self.scope.adapter.observe(configuration)?;
        progress.check()?;
        let header = recording::Header::capture(
            &self.scope,
            &self.plan,
            configuration,
            self.checkpoint.as_ref(),
            &before,
        )?;
        let mut recorder = recording::Recorder::start(self.database, header)?;
        let cancelled = AtomicBool::new(false);
        let mut progressError = None;
        let run = session::runSourceBoundSessionWithRunner(
            self.scope.config.clone(),
            self.scope.sessionPlan.clone(),
            self.scope.bindings.clone(),
            &cancelled,
            |update| {
                if progressError.is_some() {
                    return;
                }
                let result = progress
                    .check()
                    .and_then(|()| recorder.append(self.database, update, nowUnixMs()?));
                if let Err(error) = result {
                    progressError = Some(error.to_string());
                    cancelled.store(true, Ordering::SeqCst);
                }
            },
            &recording::Runner,
        );
        let mut run = match run {
            Ok(run) => run,
            Err(error) => {
                let reason = error.to_string();
                recorder
                    .abort(self.database, &reason)
                    .map_err(|recordingError| {
                        format!("{reason}; recording could not be closed: {recordingError}")
                    })?;
                return Err(error);
            }
        };
        if let Err(error) = progress.check() {
            progressError.get_or_insert_with(|| error.to_string());
        }
        let after = if progressError.is_none() {
            self.scope.adapter.observe(configuration)
        } else {
            Err("Load collection stopped before final native verification".into())
        };
        recorder.finish(self.database, &mut run, progressError.as_deref())?;
        if let Some(error) = progressError {
            return Err(error.into());
        }
        let after = after?;
        progress.check()?;
        self.acceptRaw(&run, &before, &after, configuration)
    }
}

#[cfg(test)]
mod tests;
