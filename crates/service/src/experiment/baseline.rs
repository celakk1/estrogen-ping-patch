use super::*;
use crate::{mtu::policy, recovery::policyObservationMatches, routing};
use epp_core::{
    benchmark::{
        self, BenchmarkRun, Endpoint, ProbeProtocol, RoutingEvidence, RoutingStatus, SourceBinding,
    },
    comparison::baseline::{self, Selection, Statistic},
    config::Config,
    experiment::budget::Resources,
};
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn hash(value: &impl Serialize) -> ServiceResult<String> {
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

pub struct Scope {
    template: MtuCheckpoint,
    config: Config,
    endpoints: Vec<Endpoint>,
    selections: Vec<Selection>,
    sources: Vec<SourceBinding>,
    hashes: ScopeHashes,
    costs: BTreeMap<String, Resources>,
}

fn destinations(endpoints: &[Endpoint]) -> ServiceResult<Vec<routing::Address>> {
    endpoints
        .iter()
        .map(|endpoint| {
            let (ip, scopeId) = endpoint.destinationAddress()?;
            Ok(routing::Address { ip, scopeId })
        })
        .collect()
}

fn routeSources(
    endpoints: &[Endpoint],
    captures: &[routing::Capture],
    native: &Snapshot,
) -> ServiceResult<Vec<SourceBinding>> {
    if endpoints.len() != captures.len() {
        return Err("Every benchmark endpoint requires its own native route".into());
    }
    endpoints.iter().zip(captures).map(|(endpoint, capture)| {
        let routing::Capture::Captured { snapshot } = capture else { return Err("A selected benchmark route is unavailable".into()); };
        snapshot.matchesInterface(native)?;
        let (ip, scopeId) = endpoint.destinationAddress()?;
        if endpoint.protocol != ProbeProtocol::IcmpEcho || snapshot.destination != (routing::Address { ip, scopeId }) || snapshot.loopback || ip.is_loopback() {
            return Err("Optimization measurements require non-loopback echo routes through the exact changed adapter".into());
        }
        Ok(SourceBinding { endpointId: endpoint.id.clone(), source: epp_core::icmp::EchoTarget { address: snapshot.source.ip, scopeId: snapshot.source.scopeId } })
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
        routing::fingerprint(captures)?.ok_or("Benchmark routes could not be verified")?;
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

impl Scope {
    pub fn capture(
        template: MtuCheckpoint,
        config: Config,
        endpoints: Vec<Endpoint>,
        selections: Vec<Selection>,
        cancelled: &AtomicBool,
    ) -> ServiceResult<Self> {
        Self::validateInput(&template, &config, &endpoints, &selections)?;
        let current = policy::inspect(
            template.context.adapterGuid,
            template.addressFamily,
            cancelled,
        )?;
        let routes = routing::capture(&destinations(&endpoints)?, cancelled)?;
        Self::fromEvidence(template, config, endpoints, selections, current, routes)
    }

    fn validateInput(
        template: &MtuCheckpoint,
        config: &Config,
        endpoints: &[Endpoint],
        selections: &[Selection],
    ) -> ServiceResult<()> {
        template.validate()?;
        config.validate()?;
        benchmark::validateEndpoints(endpoints)?;
        let lease = template.leaseExpiresAtUnixMs - template.createdAtUnixMs;
        let worstCase = u64::from(config.sampleCount)
            .checked_mul(endpoints.len() as u64)
            .and_then(|count| count.checked_mul(config.timeoutMs + config.intervalMs))
            .ok_or("Collection duration overflow")?;
        if template.schemaVersion != 4
            || !(1280..template.originalMtu).contains(&template.proposedMtu)
            || config.timeoutMs > 1000
            || config.intervalMs > 500
            || config.sampleCount < 12
            || worstCase > lease.saturating_sub(10_000)
            || selections.len() != endpoints.len() * 2
        {
            return Err("Bound echo collection requires policy-backed MTU reduction, at least twelve samples, bounded heartbeat gaps, latency/failure guards, and ten seconds of lease headroom".into());
        }
        for endpoint in endpoints {
            if endpoint.protocol != ProbeProtocol::IcmpEcho
                || selections
                    .iter()
                    .filter(|selection| {
                        selection.endpointId == endpoint.id
                            && matches!(selection.statistic, Statistic::P95Ms)
                    })
                    .count()
                    != 1
                || selections
                    .iter()
                    .filter(|selection| {
                        selection.endpointId == endpoint.id
                            && matches!(selection.statistic, Statistic::FailurePercent)
                    })
                    .count()
                    != 1
            {
                return Err(
                    "Every echo endpoint needs one p95 latency and one failure-rate selection"
                        .into(),
                );
            }
        }
        Ok(())
    }

    fn fromEvidence(
        template: MtuCheckpoint,
        config: Config,
        endpoints: Vec<Endpoint>,
        selections: Vec<Selection>,
        current: policy::Capture,
        routes: Vec<routing::Capture>,
    ) -> ServiceResult<Self> {
        Self::validateInput(&template, &config, &endpoints, &selections)?;
        policyObservationMatches(&template, &current, template.originalMtu, nowUnixMs()?)?;
        let sources = routeSources(&endpoints, &routes, &current.native)?;
        let blueprint = benchmark::runSourceBoundEchoBenchmark(
            config.clone(),
            endpoints.clone(),
            sources.clone(),
            &AtomicBool::new(true),
            |_, _, _| {},
        )?;
        let mut candidate = current.native.settings.clone();
        candidate.nlMtu = template.proposedMtu;
        let hashes = ScopeHashes {
            cohortSha256: baseline::cohortSha256(&blueprint, &selections)?,
            environmentSha256: environment(&template, &routes)?,
            originalConfigurationSha256: hash(&current.native.settings)?,
            candidateConfigurationSha256: hash(&candidate)?,
        };
        let costs = endpoints
            .iter()
            .map(|endpoint| {
                (
                    endpoint.id.clone(),
                    Resources {
                        probeAttempts: u64::from(config.sampleCount),
                        ..Default::default()
                    },
                )
            })
            .collect();
        Ok(Self {
            template,
            config,
            endpoints,
            selections,
            sources,
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
        plan.validate()?;
        if plan.comparison.cohortSha256 != self.hashes.cohortSha256
            || plan.comparison.environmentSha256 != self.hashes.environmentSha256
            || plan.comparison.originalConfigurationSha256
                != self.hashes.originalConfigurationSha256
            || plan.comparison.candidateConfigurationSha256
                != self.hashes.candidateConfigurationSha256
        {
            return Err(
                "Experiment plan differs from the captured source-bound measurement scope".into(),
            );
        }
        let budget = plan
            .trafficBudget
            .as_ref()
            .ok_or("Collection requires explicit traffic limits")?;
        budget.bind(&self.costs)?;
        if !budget.allows(plan.blockCount as u32)? {
            return Err("Traffic limits cannot cover every approved bracket".into());
        }
        if plan.comparison.metrics.len() != self.selections.len()
            || plan
                .comparison
                .metrics
                .iter()
                .zip(&self.selections)
                .any(|(rule, selection)| {
                    rule.id != selection.metricId
                        || rule.direction != epp_core::comparison::Direction::LowerIsBetter
                        || if matches!(selection.statistic, Statistic::FailurePercent) {
                            rule.unit != epp_core::comparison::Unit::Percent
                                || rule.resolution < 100.0 / f64::from(self.config.sampleCount)
                                || rule.role != epp_core::comparison::Role::Guard
                        } else {
                            rule.unit != epp_core::comparison::Unit::Milliseconds
                                || rule.resolution < 1.0
                        }
                })
        {
            return Err("Measurement rules differ from the captured p95/failure selections or native resolution".into());
        }
        let durable: u32 = database.pragma_query_value(None, "synchronous", |row| row.get(0))?;
        let foreignKeys: bool =
            database.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
        let mode: String = database.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        let version: u32 = database.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if durable != 2 || !foreignKeys || !mode.eq_ignore_ascii_case("wal") || version != 6 {
            return Err("Measurement storage must be the validated application database with FULL durability, foreign keys, and WAL".into());
        }
        database.execute_batch("CREATE TABLE IF NOT EXISTS adapter_measurements(run_id INTEGER PRIMARY KEY REFERENCES benchmark_runs(id), experiment_id TEXT NOT NULL, payload_json TEXT NOT NULL, sha256 TEXT NOT NULL)")?;
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
    fn capture(
        &self,
        configuration: Configuration,
    ) -> ServiceResult<(policy::Capture, Vec<routing::Capture>)> {
        let template = &self.scope.template;
        let cancelled = AtomicBool::new(false);
        let current = policy::inspect(
            template.context.adapterGuid,
            template.addressFamily,
            &cancelled,
        )?;
        let routes = routing::capture(&destinations(&self.scope.endpoints)?, &cancelled)?;
        self.verify(&current, &routes, configuration)?;
        Ok((current, routes))
    }

    fn verify(
        &self,
        current: &policy::Capture,
        routes: &[routing::Capture],
        configuration: Configuration,
    ) -> ServiceResult<()> {
        let expectedMtu = if configuration == Configuration::Original {
            self.scope.template.originalMtu
        } else {
            self.scope.template.proposedMtu
        };
        policyObservationMatches(&self.scope.template, current, expectedMtu, nowUnixMs()?)?;
        if current.native.operationalStatus != 1
            || current.native.mediaConnectState != 1
            || routeSources(&self.scope.endpoints, routes, &current.native)? != self.scope.sources
            || environment(&self.scope.template, routes)? != self.scope.hashes.environmentSha256
        {
            return Err("Native link, selected source, adapter route, or environment changed during collection".into());
        }
        Ok(())
    }
    fn acceptRaw(
        &mut self,
        run: &BenchmarkRun,
        before: &policy::Capture,
        after: &policy::Capture,
        configuration: Configuration,
    ) -> ServiceResult<Session> {
        let session = baseline::fromRun(
            run,
            &self.scope.selections,
            &self.plan.comparison,
            baseline::Context {
                environmentSha256: &self.scope.hashes.environmentSha256,
                configurationSha256: if configuration == Configuration::Candidate {
                    &self.scope.hashes.candidateConfigurationSha256
                } else {
                    &self.scope.hashes.originalConfigurationSha256
                },
            },
        )?;

        if before.native.capturedAtUnixMs > session.startedAtUnixMs.saturating_add(250)
            || after.native.capturedAtUnixMs.saturating_add(250) < session.finishedAtUnixMs
        {
            return Err("Native measurement evidence does not bracket the raw session".into());
        }
        let receipt = serde_json::json!({"schemaVersion":1,"benchmarkScope":"sourceBoundAdapterBaseline","experimentId":self.plan.id,"checkpointId":self.checkpoint.as_ref().map(|checkpoint| checkpoint.id),"checkpointSha256":self.checkpoint.as_ref().map(crate::authorization::checkpointChecksum).transpose()?,"configuration":if configuration == Configuration::Candidate {"candidate"} else {"original"},"rawRunId":run.id,"rawRunSha256":hash(run)?,"nativeBefore":before,"nativeAfter":after});
        let payload = serde_json::to_string(&receipt)?;
        if payload.len() > 131_072 {
            return Err("Native measurement receipt exceeds 128 KiB".into());
        }
        let checksum = epp_core::backups::checksum(&payload);
        let transaction = self
            .database
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        transaction.execute("INSERT INTO adapter_measurements(run_id,experiment_id,payload_json,sha256) VALUES(?1,?2,?3,?4)", (run.id, &self.plan.id, &payload, &checksum))?;
        Self::verifySaved(&transaction, run, &payload, &checksum)?;
        transaction.commit()?;
        Self::verifySaved(self.database, run, &payload, &checksum)?;
        Ok(session)
    }

    fn verifySaved(
        database: &Connection,
        run: &BenchmarkRun,
        payload: &str,
        checksum: &str,
    ) -> ServiceResult<()> {
        let saved: (String, String) = database.query_row(
            "SELECT payload_json,sha256 FROM adapter_measurements WHERE run_id=?1",
            [run.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let raw: String = database.query_row(
            "SELECT report_json FROM benchmark_runs WHERE id=?1",
            [run.id],
            |row| row.get(0),
        )?;
        if saved.0 != payload
            || saved.1 != checksum
            || hash(&serde_json::from_str::<BenchmarkRun>(&raw)?)? != hash(run)?
        {
            return Err("Measurement durable readback differs from the captured raw session or native receipt".into());
        }

        let mut statement = database.prepare(
            "SELECT sample_json FROM benchmark_samples WHERE run_id=?1 ORDER BY ordinal",
        )?;
        let samples = statement
            .query_map([run.id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if samples.len() != run.samples.len()
            || samples.iter().zip(&run.samples).any(|(saved, sample)| {
                !serde_json::to_string(sample).is_ok_and(|expected| expected == *saved)
            })
        {
            return Err("Durable raw sample rows differ from the accepted report".into());
        }
        Ok(())
    }
}

impl Measurements for Collector<'_> {
    fn maximumTraffic(&self) -> ServiceResult<BTreeMap<String, Resources>> {
        Ok(self.scope.costs.clone())
    }

    fn bindCheckpoint(&mut self, checkpoint: Option<&MtuCheckpoint>) -> ServiceResult<()> {
        if let Some(document) = checkpoint {
            document.validate()?;
            let original = &self.scope.template;
            if document.schemaVersion != 4
                || document.context != original.context
                || document.addressFamily != original.addressFamily
                || document.authorizedUserSid != original.authorizedUserSid
                || document.originalMtu != original.originalMtu
                || document.proposedMtu != original.proposedMtu
                || document.leaseExpiresAtUnixMs > self.plan.expiresAtUnixMs
            {
                return Err(
                    "Measurement checkpoint differs from its captured experiment scope".into(),
                );
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
        }
        self.checkpoint = checkpoint.cloned();
        Ok(())
    }

    fn verifyEnvironment(&mut self, plan: &Plan, original: &Snapshot) -> ServiceResult<()> {
        if hash(plan)? != hash(&self.plan)?
            || hash(&original.settings)? != self.scope.hashes.originalConfigurationSha256
        {
            return Err("Measurement plan or original configuration changed".into());
        }
        self.capture(Configuration::Original).map(|_| ())
    }

    fn collect(
        &mut self,
        configuration: Configuration,
        progress: &Progress<'_, '_>,
    ) -> ServiceResult<Session> {
        progress.check()?;
        if (configuration == Configuration::Candidate) != self.checkpoint.is_some() {
            return Err("Candidate measurements require their exact issued checkpoint".into());
        }
        let (before, routeBefore) = self.capture(configuration)?;
        progress.check()?;
        let cancelled = AtomicBool::new(false);
        let mut progressError = None;
        let mut run = benchmark::runSourceBoundEchoBenchmark(
            self.scope.config.clone(),
            self.scope.endpoints.clone(),
            self.scope.sources.clone(),
            &cancelled,
            |_, _, _| {
                if let Err(error) = progress.check() {
                    progressError = Some(error.to_string());
                    cancelled.store(true, Ordering::SeqCst);
                }
            },
        )?;
        if let Err(error) = progress.check() {
            progressError.get_or_insert_with(|| error.to_string());
        }
        let after = if progressError.is_none() {
            self.capture(configuration)
        } else {
            Err("Collection stopped before final native verification".into())
        };
        run.routing = Some(RoutingEvidence {
            schemaVersion: 1,
            status: if after.is_ok() {
                RoutingStatus::Unchanged
            } else {
                RoutingStatus::Unavailable
            },
            beforeFingerprint: routing::fingerprint(&routeBefore)?,
            afterFingerprint: after
                .as_ref()
                .ok()
                .map(|(_, routes)| routing::fingerprint(routes))
                .transpose()?
                .flatten(),
            before: serde_json::to_value(&routeBefore)?,
            after: after
                .as_ref()
                .ok()
                .map(|(_, routes)| serde_json::to_value(routes))
                .transpose()?
                .unwrap_or(serde_json::Value::Null),
        });
        epp_core::storage::saveRun(self.database, &mut run)?;
        if let Some(error) = progressError {
            return Err(error.into());
        }
        let (after, _) = after?;
        progress.check()?;
        self.acceptRaw(&run, &before, &after, configuration)
    }
}

#[cfg(test)]
mod tests;
