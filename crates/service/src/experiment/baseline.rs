pub use super::measurement::ScopeHashes;
use super::measurement::{self, AdapterScope, hash};
use super::*;
use crate::{mtu::policy, routing};
use epp_core::{
    benchmark::{
        self, BenchmarkRun, Endpoint, ProbeProtocol, RoutingEvidence, RoutingStatus, SourceBinding,
    },
    comparison::baseline::{self, Selection, Statistic},
    config::Config,
    experiment::budget::Resources,
};
use rusqlite::Connection;
use std::collections::BTreeMap;

pub struct Scope {
    adapter: AdapterScope,
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

impl Scope {
    pub fn capture(
        template: MtuCheckpoint,
        config: Config,
        endpoints: Vec<Endpoint>,
        selections: Vec<Selection>,
        cancelled: &AtomicBool,
    ) -> ServiceResult<Self> {
        Self::validateInput(&template, &config, &endpoints, &selections)?;
        let adapter = AdapterScope::capture(template, destinations(&endpoints)?, cancelled)?;
        Self::fromAdapter(adapter, config, endpoints, selections)
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
        if config.profile == epp_core::config::Profile::Download {
            return Err("The Download profile requires throughput collection; echo-only trials cannot measure its objective".into());
        }
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

    #[cfg(test)]
    fn fromEvidence(
        template: MtuCheckpoint,
        config: Config,
        endpoints: Vec<Endpoint>,
        selections: Vec<Selection>,
        current: policy::Capture,
        routes: Vec<routing::Capture>,
    ) -> ServiceResult<Self> {
        Self::validateInput(&template, &config, &endpoints, &selections)?;
        let adapter =
            AdapterScope::fromEvidence(template, destinations(&endpoints)?, current, routes)?;
        Self::fromAdapter(adapter, config, endpoints, selections)
    }

    fn fromAdapter(
        adapter: AdapterScope,
        config: Config,
        endpoints: Vec<Endpoint>,
        selections: Vec<Selection>,
    ) -> ServiceResult<Self> {
        Self::validateInput(&adapter.template, &config, &endpoints, &selections)?;
        if adapter.targets != destinations(&endpoints)? {
            return Err("Echo targets differ from the captured adapter scope".into());
        }
        let sources: Vec<_> = endpoints
            .iter()
            .zip(&adapter.sources)
            .map(|(endpoint, source)| SourceBinding {
                endpointId: endpoint.id.clone(),
                source: epp_core::icmp::EchoTarget {
                    address: source.ip,
                    scopeId: source.scopeId,
                },
            })
            .collect();
        let blueprint = benchmark::runSourceBoundEchoBenchmark(
            config.clone(),
            endpoints.clone(),
            sources.clone(),
            &AtomicBool::new(true),
            |_, _, _| {},
        )?;
        let hashes = adapter.hashes(baseline::cohortSha256(&blueprint, &selections)?);
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
            adapter,
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
        measurement::validatePlan(&plan, &self.hashes, &self.costs)?;
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
        measurement::validateStorage(database)?;
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
        self.scope.adapter.observe(configuration)
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
        if self.scope.endpoints.iter().any(|endpoint| {
            run.samples
                .iter()
                .filter(|sample| {
                    sample.endpointId == endpoint.id
                        && sample
                            .echo
                            .as_ref()
                            .is_some_and(|echo| echo.status == epp_core::icmp::EchoStatus::Reply)
                })
                .count()
                < 12
        }) {
            return Err("Trusted latency evidence requires at least twelve successful echo replies per endpoint".into());
        }

        measurement::validateSessionWindow(
            &session,
            &self.plan,
            configuration,
            self.checkpoint.as_ref(),
            before.native.capturedAtUnixMs,
            after.native.capturedAtUnixMs,
        )?;
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
            self.scope
                .adapter
                .verifyCheckpoint(document, self.plan.expiresAtUnixMs)?;
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
pub(super) mod tests;
