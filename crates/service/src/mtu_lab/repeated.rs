use super::*;
use crate::{
    consent::session::SessionConsent,
    experiment::{Configuration, Measurements, MtuHost, Progress},
    journal::{Journal, State},
    routing,
};
use epp_core::{
    benchmark::{self, BenchmarkRun, Endpoint, ProbeProtocol, RoutingEvidence, RoutingStatus},
    comparison::{
        self, Session,
        baseline::{self, Selection, Statistic},
    },
    config::Config as BenchmarkConfig,
    experiment,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    net::{SocketAddr, TcpListener},
    sync::{Mutex, atomic::AtomicU32},
};

pub(super) fn checkpointId(parent: Uuid, index: u8) -> Uuid {
    // derive restart-stable child ids; protected grants remain the write authority.
    let mut digest = Sha256::new();
    digest.update(b"epp-native-repeated-checkpoint-v1");
    digest.update(parent.as_bytes());
    digest.update([index]);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn hash(value: &impl Serialize) -> ServiceResult<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

pub(super) fn recover(journal: &mut Journal, backend: &mut Backend<'_>) -> ServiceResult<()> {
    let mut pending = journal.pendingRecovery()?;
    pending.extend(journal.pendingPolicyVerification()?);
    for checkpoint in &pending {
        let document = checkpoint.document();
        if !backend.checkpointIds.contains(&document.id)
            || !matches!(document.schemaVersion, 3 | 4)
            || document.authorizedUserSid != backend.config.ownerSid
            || document.context.adapterGuid != backend.config.guid
            || document.addressFamily != backend.config.family
        {
            return Err("Repeated native lab refuses unrelated pending recovery work".into());
        }
    }
    if !pending.is_empty() {
        let results = {
            let mut recovery = crate::recovery::only::RecoveryOnly::capture(journal, backend)?;
            MtuCoordinator::new(journal, &mut recovery, nowUnixMs).restoreAllPending()?
        };
        if results.iter().any(|result| {
            !result.originalMtuVerified
                || !result.journalFinalized
                || result.unrelatedSettingsDrifted
                || result.error.is_some()
        }) {
            return Err("Repeated native lab could not verify interrupted recovery".into());
        }
    }
    Ok(())
}

struct Listeners {
    endpoints: Vec<Endpoint>,
    accepted: Arc<AtomicU32>,
    stopped: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<ServiceResult<()>>>,
}

impl Listeners {
    fn new() -> ServiceResult<Self> {
        let listeners = [
            TcpListener::bind("127.0.0.1:0")?,
            TcpListener::bind("[::1]:0")?,
        ];
        let endpoints = listeners
            .iter()
            .enumerate()
            .map(|(index, listener)| {
                Ok(Endpoint {
                    id: format!("loopback-{}", index + 1),
                    address: listener.local_addr()?.to_string(),
                    protocol: ProbeProtocol::TcpConnect,
                    dnsQuery: None,
                })
            })
            .collect::<ServiceResult<Vec<_>>>()?;
        for listener in &listeners {
            listener.set_nonblocking(true)?;
        }
        let accepted = Arc::new(AtomicU32::new(0));
        let stopped = Arc::new(AtomicBool::new(false));
        let count = accepted.clone();
        let stop = stopped.clone();
        let worker = std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                for listener in &listeners {
                    loop {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                drop(stream);
                                count.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(error) => return Err(error.into()),
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        });
        Ok(Self {
            endpoints,
            accepted,
            stopped,
            worker: Some(worker),
        })
    }

    fn finish(&mut self, expected: u32) -> ServiceResult<()> {
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.accepted.load(Ordering::SeqCst) < expected && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        self.stopped.store(true, Ordering::SeqCst);
        self.worker
            .take()
            .ok_or("Missing loopback listener worker")?
            .join()
            .map_err(|_| "Loopback listener worker panicked")??;
        if self.accepted.load(Ordering::SeqCst) != expected {
            return Err("Loopback listener did not accept every recorded connection".into());
        }
        Ok(())
    }
}

impl Drop for Listeners {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn routes(endpoints: &[Endpoint]) -> ServiceResult<(Vec<routing::Capture>, String)> {
    let destinations = endpoints
        .iter()
        .map(|endpoint| {
            let address: SocketAddr = endpoint.address.parse()?;
            Ok(routing::Address {
                ip: address.ip(),
                scopeId: match address {
                    SocketAddr::V6(address) => address.scope_id(),
                    _ => 0,
                },
            })
        })
        .collect::<ServiceResult<Vec<_>>>()?;
    let values = routing::capture(&destinations, &AtomicBool::new(false))?;
    let fingerprint =
        routing::fingerprint(&values)?.ok_or("Native loopback route evidence is unavailable")?;
    Ok((values, fingerprint))
}

fn environment(native: &Snapshot, fingerprint: &str) -> ServiceResult<String> {
    hash(&(
        "native-lab-loopback-environment-v2",
        native.adapterGuid,
        native.addressFamily,
        &native.os,
        &native.driver,
        &native.registryOrigins,
        fingerprint,
    ))
}

fn selections() -> Vec<Selection> {
    ["loopback-1", "loopback-2"]
        .into_iter()
        .flat_map(|endpoint| {
            [
                Selection {
                    metricId: format!("{endpoint}-median"),
                    endpointId: endpoint.into(),
                    statistic: Statistic::MedianMs,
                },
                Selection {
                    metricId: format!("{endpoint}-failure"),
                    endpointId: endpoint.into(),
                    statistic: Statistic::FailurePercent,
                },
            ]
        })
        .collect()
}

fn plan(
    config: &Config,
    original: &Snapshot,
    seed: &BenchmarkRun,
    fingerprint: &str,
) -> ServiceResult<experiment::Plan> {
    let mut candidate = original.settings.clone();
    candidate.nlMtu = 1400;
    let metric = |id: &str, failure| comparison::MetricRule {
        id: id.into(),
        unit: if failure {
            comparison::Unit::Percent
        } else {
            comparison::Unit::Milliseconds
        },
        direction: comparison::Direction::LowerIsBetter,
        role: if failure {
            comparison::Role::Guard
        } else {
            comparison::Role::Objective
        },
        resolution: 0.1,
        minimumImprovement: comparison::Threshold {
            absolute: if failure { 0.1 } else { 1000.0 },
            relativeFraction: 0.0,
        },
        maximumRegression: comparison::Threshold {
            absolute: if failure { 0.0 } else { 1000.0 },
            relativeFraction: 0.0,
        },
        maximumBaselineDrift: comparison::Threshold {
            absolute: if failure { 0.0 } else { 1000.0 },
            relativeFraction: 0.0,
        },
    };
    let now = nowUnixMs()?;
    let plan = experiment::Plan {
        id: config.trialId.to_string(),
        createdAtUnixMs: now,
        expiresAtUnixMs: now
            .checked_add(300_000)
            .ok_or("Repeated lab deadline overflow")?,
        blockCount: 12,
        trafficBudget: Some(experiment::budget::TrafficBudget {
            schemaVersion: 1,
            limits: experiment::budget::Resources {
                probeAttempts: 216,
                ..Default::default()
            },
            providers: seed
                .results
                .iter()
                .map(|result| experiment::budget::Provider {
                    id: result.endpoint.id.clone(),
                    perCollection: experiment::budget::Resources {
                        probeAttempts: 3,
                        ..Default::default()
                    },
                    limits: experiment::budget::Resources {
                        probeAttempts: 108,
                        ..Default::default()
                    },
                })
                .collect(),
        }),
        comparison: comparison::Plan {
            maximumBlockDurationMs: 30_000,
            cohortSha256: baseline::cohortSha256(seed, &selections())?,
            environmentSha256: environment(original, fingerprint)?,
            originalConfigurationSha256: hash(&original.settings)?,
            candidateConfigurationSha256: hash(&candidate)?,
            metrics: selections()
                .iter()
                .map(|selection| {
                    metric(
                        &selection.metricId,
                        matches!(selection.statistic, Statistic::FailurePercent),
                    )
                })
                .collect(),
        },
    };
    plan.validate()?;
    Ok(plan)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Receipt<'a> {
    schemaVersion: u32,
    benchmarkScope: &'static str,
    experimentId: Uuid,
    checkpointId: Option<Uuid>,
    configuration: &'static str,
    rawRunId: i64,
    rawRunSha256: String,
    nativeBefore: &'a Snapshot,
    nativeAfter: &'a Snapshot,
}

struct Collector<'a> {
    config: BenchmarkConfig,
    endpoints: Vec<Endpoint>,
    original: Snapshot,
    plan: experiment::Plan,
    database: &'a mut rusqlite::Connection,
    receipts: Arc<Mutex<Vec<i64>>>,
    activeCheckpoint: Arc<Mutex<Option<Uuid>>>,
}

impl Collector<'_> {
    fn verify(
        &self,
        native: &Snapshot,
        fingerprint: &str,
        configuration: Configuration,
    ) -> ServiceResult<()> {
        native.validateMtuObservation(&self.original)?;
        let expected = match configuration {
            Configuration::Original => &self.plan.comparison.originalConfigurationSha256,
            Configuration::Candidate => &self.plan.comparison.candidateConfigurationSha256,
        };
        if native.operationalStatus != 1
            || native.mediaConnectState != 1
            || hash(&native.settings)? != *expected
            || environment(native, fingerprint)? != self.plan.comparison.environmentSha256
        {
            return Err("Repeated native measurement context or setting changed".into());
        }
        Ok(())
    }
}

impl Measurements for Collector<'_> {
    fn maximumTraffic(
        &self,
    ) -> ServiceResult<std::collections::BTreeMap<String, experiment::budget::Resources>> {
        Ok(self
            .endpoints
            .iter()
            .map(|endpoint| {
                (
                    endpoint.id.clone(),
                    experiment::budget::Resources {
                        probeAttempts: u64::from(self.config.sampleCount),
                        ..Default::default()
                    },
                )
            })
            .collect())
    }

    fn verifyEnvironment(
        &mut self,
        plan: &experiment::Plan,
        original: &Snapshot,
    ) -> ServiceResult<()> {
        let (_, fingerprint) = routes(&self.endpoints)?;
        self.verify(original, &fingerprint, Configuration::Original)?;
        if serde_json::to_vec(plan)? != serde_json::to_vec(&self.plan)? {
            return Err("Repeated native measurement plan changed".into());
        }
        Ok(())
    }

    fn collect(
        &mut self,
        configuration: Configuration,
        progress: &Progress<'_, '_>,
    ) -> ServiceResult<Session> {
        progress.check()?;
        let before = mtu::capture(
            self.original.adapterGuid,
            self.original.addressFamily,
            &AtomicBool::new(false),
        )?;
        let (routeBefore, fingerprintBefore) = routes(&self.endpoints)?;
        self.verify(&before, &fingerprintBefore, configuration)?;
        let cancelled = AtomicBool::new(false);
        let mut progressError = None;
        let mut run = benchmark::runBenchmark(
            self.config.clone(),
            self.endpoints.clone(),
            &cancelled,
            |_, _, _| {
                if let Err(error) = progress.check() {
                    progressError = Some(error.to_string());
                    cancelled.store(true, Ordering::SeqCst);
                }
            },
        )?;
        let after = mtu::capture(
            self.original.adapterGuid,
            self.original.addressFamily,
            &AtomicBool::new(false),
        )?;
        let (routeAfter, fingerprintAfter) = routes(&self.endpoints)?;
        run.routing = Some(RoutingEvidence {
            schemaVersion: 1,
            status: if fingerprintBefore == fingerprintAfter {
                RoutingStatus::Unchanged
            } else {
                RoutingStatus::Changed
            },
            beforeFingerprint: Some(fingerprintBefore),
            afterFingerprint: Some(fingerprintAfter.clone()),
            before: serde_json::to_value(routeBefore)?,
            after: serde_json::to_value(routeAfter)?,
        });
        epp_core::storage::saveRun(self.database, &mut run)?;
        if let Some(error) = progressError {
            return Err(error.into());
        }
        progress.check()?;
        self.verify(&after, &fingerprintAfter, configuration)?;
        if run.status != "completed"
            || run.samples.len() != 6
            || run
                .samples
                .iter()
                .any(|sample| sample.connectMs.is_none() || sample.error.is_some())
        {
            return Err("Repeated native lab requires six successful bounded loopback connections per session".into());
        }
        let checkpointId = if configuration == Configuration::Candidate {
            Some(
                self.activeCheckpoint
                    .lock()
                    .map_err(|_| "Repeated checkpoint state poisoned")?
                    .ok_or("Candidate measurement has no checkpoint")?,
            )
        } else {
            None
        };
        let receipt = Receipt {
            schemaVersion: 1,
            benchmarkScope: "softwareLoopbackLifecycleControl",
            experimentId: self.originalRunId()?,
            checkpointId,
            configuration: if configuration == Configuration::Candidate {
                "candidate"
            } else {
                "original"
            },
            rawRunId: run.id,
            rawRunSha256: hash(&run)?,
            nativeBefore: &before,
            nativeAfter: &after,
        };
        let payload = serde_json::to_string(&receipt)?;
        let checksum = epp_core::backups::checksum(&payload);
        self.database.execute("INSERT INTO native_measurements(run_id,experiment_id,payload_json,sha256) VALUES(?1,?2,?3,?4)", (run.id, &self.plan.id, &payload, &checksum))?;
        let (saved, savedHash): (String, String) = self.database.query_row(
            "SELECT payload_json,sha256 FROM native_measurements WHERE run_id=?1",
            [run.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let raw: String = self.database.query_row(
            "SELECT report_json FROM benchmark_runs WHERE id=?1",
            [run.id],
            |row| row.get(0),
        )?;
        if saved != payload
            || savedHash != checksum
            || hash(&serde_json::from_str::<BenchmarkRun>(&raw)?)? != receipt.rawRunSha256
        {
            return Err("Repeated native measurement durable readback failed".into());
        }
        self.receipts
            .lock()
            .map_err(|_| "Repeated receipt state poisoned")?
            .push(run.id);
        baseline::fromRun(
            &run,
            &selections(),
            &self.plan.comparison,
            baseline::Context {
                environmentSha256: &self.plan.comparison.environmentSha256,
                configurationSha256: if configuration == Configuration::Candidate {
                    &self.plan.comparison.candidateConfigurationSha256
                } else {
                    &self.plan.comparison.originalConfigurationSha256
                },
            },
        )
    }
}

impl Collector<'_> {
    fn originalRunId(&self) -> ServiceResult<Uuid> {
        Ok(Uuid::parse_str(&self.plan.id)?)
    }
}

pub(super) fn run(
    journal: &mut Journal,
    backend: &mut Backend<'_>,
    owned: &mut storage::OwnedExperiments,
) -> ServiceResult<()> {
    match owned.store.load(&backend.config.trialId.to_string()) {
        Ok(_) => return Err("Repeated native experiment already exists; interrupted work must not replay automatically".into()),
        Err(error) if matches!(error.downcast_ref::<rusqlite::Error>(), Some(rusqlite::Error::QueryReturnedNoRows)) => {},
        Err(error) => return Err(error),
    }
    if !owned.store.pending()?.is_empty() {
        return Err("Unfinished repeated native experiment blocks new work".into());
    }
    let original = mtu::capture(
        backend.config.guid,
        backend.config.family,
        &AtomicBool::new(false),
    )?;
    backend.permit.validateTarget(&original)?;
    if original.settings.nlMtu != 1500 {
        return Err("Repeated native lab requires its unchanged original MTU 1500".into());
    }
    let mut listeners = Listeners::new()?;
    let config = BenchmarkConfig {
        sampleCount: 3,
        intervalMs: 250,
        timeoutMs: 100,
        sessionMinutes: 1,
        ..Default::default()
    };
    let seed = benchmark::runBenchmark(
        config.clone(),
        listeners.endpoints.clone(),
        &AtomicBool::new(true),
        |_, _, _| {},
    )?;
    let (_, fingerprint) = routes(&listeners.endpoints)?;
    let plan = plan(backend.config, &original, &seed, &fingerprint)?;
    let policyOriginal = backend.policyOriginal(&original)?;
    let now = nowUnixMs()?;
    let template = MtuCheckpoint {
        schemaVersion: 4,
        id: backend.config.trialId,
        createdAtUnixMs: now,
        leaseExpiresAtUnixMs: now + backend.config.leaseMs(),
        authorizedUserSid: backend.config.ownerSid.clone(),
        context: original.journalContext()?,
        addressFamily: original.addressFamily,
        originalMtu: 1500,
        proposedMtu: 1400,
        nativeOriginal: Some(original.clone()),
        policyOriginal: Some(policyOriginal),
    };
    let receipts = Arc::new(Mutex::new(Vec::new()));
    let activeCheckpoint = Arc::new(Mutex::new(None));
    let collector = Collector {
        config,
        endpoints: listeners.endpoints.clone(),
        original: original.clone(),
        plan: plan.clone(),
        database: &mut owned.measurements,
        receipts: receipts.clone(),
        activeCheckpoint: activeCheckpoint.clone(),
    };
    let mut issued = 0usize;
    let stop = backend.stop.clone();
    let parentId = backend.config.trialId;
    let mut consent = SessionConsent::new(&backend.config.ownerSid)?;
    let now = nowUnixMs()?;
    let preview = consent.preview(
        template.clone(),
        plan.clone(),
        &collector.maximumTraffic()?,
        &backend.config.ownerSid,
        now,
    )?;
    let mut approvedSession = consent.approve(
        preview.mtu.previewId,
        &preview.scopeSha256,
        &backend.config.ownerSid,
        nowUnixMs()?,
    )?;
    event(
        json!({"phase":"repeatedSessionApproved","trialId":parentId,"previewId":preview.mtu.previewId,"scopeSha256":preview.scopeSha256,"blockCount":plan.blockCount,"allowRetention":false}),
    )?;
    let mut issuedGrants = Vec::new();
    let mut host = MtuHost::new(
        journal,
        backend,
        template.clone(),
        crate::watchdog::Policy::default(),
        &stop,
        collector,
        |backend: &mut Backend<'_>, fresh: &Snapshot, plan: &experiment::Plan| {
            let policyOriginal = backend.policyOriginal(fresh)?;
            if template.policyOriginal.as_ref() != Some(&policyOriginal) {
                return Err(
                    "IP policy drifted from the repeated experiment's original cohort".into(),
                );
            }
            let id = *backend
                .checkpointIds
                .get(issued)
                .ok_or("Repeated native checkpoint allowance exhausted")?;
            let now = nowUnixMs()?;
            let expires = now
                .checked_add(backend.config.leaseMs())
                .ok_or("Repeated native lease overflow")?;
            if expires > plan.expiresAtUnixMs {
                return Err("Insufficient remaining time for another bounded native trial".into());
            }
            let mut document = template.clone();
            document.id = id;
            document.createdAtUnixMs = now;
            document.leaseExpiresAtUnixMs = expires;
            document.nativeOriginal = Some(fresh.clone());
            document.policyOriginal = Some(policyOriginal);
            let grant = approvedSession.issue(
                &document,
                plan,
                &backend.config.ownerSid,
                backend
                    .authorization
                    .as_deref_mut()
                    .ok_or("Repeated native trial has no protected authorization store")?,
                now,
            )?;
            issuedGrants.push(grant.id);
            backend.grantId = Some(grant.id);
            *activeCheckpoint
                .lock()
                .map_err(|_| "Repeated checkpoint state poisoned")? = Some(id);
            issued += 1;
            event(
                json!({"phase":"repeatedCheckpointIssued","trialId":parentId,"checkpointId":id,"grantId":grant.id}),
            )?;
            Ok(document)
        },
    )?;
    let execution = experiment::execute(&mut owned.store, plan, &mut host, &stop);
    drop(host);
    let authorization = backend
        .authorization
        .as_deref_mut()
        .ok_or("Repeated native session lost its authorization store")?;
    let revocation = approvedSession.cancel(&backend.config.ownerSid, authorization, nowUnixMs()?);
    let report = match (execution, revocation) {
        (Ok(report), Ok(())) => report,
        (Err(primary), Err(revocation)) => {
            return Err(
                format!("{primary}; session grant revocation also failed: {revocation}").into(),
            );
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
    };
    for id in &issuedGrants {
        if !authorization.read(*id)?.revoked {
            return Err("Repeated session did not durably revoke every issued trial grant".into());
        }
    }
    let ids = receipts
        .lock()
        .map_err(|_| "Repeated receipt state poisoned")?
        .clone();
    if report.snapshot.state != experiment::State::Completed
        || report.snapshot.blocks.len() != 12
        || report.snapshot.checkpoints.len() != 12
        || ids.len() != 36
        || issued != 12
        || backend.writes != 24
        || !journal.pendingRecovery()?.is_empty()
    {
        event(
            json!({"phase":"repeatedExperimentFailed","trialId":parentId,"state":report.snapshot.state,"error":report.snapshot.error,"blocks":report.snapshot.blocks.len(),"writes":backend.writes}),
        )?;
        return Err("Repeated native experiment did not complete every verified bracket".into());
    }
    listeners.finish(216)?;
    let mut mutators = Vec::new();
    let mut policyVerifications = 0;
    let checkpointIds = backend.checkpointIds.clone();
    for id in checkpointIds {
        let checkpoint = journal.load(id)?;
        if checkpoint.state() != State::Restored
            || checkpoint.policyVerifications().len() != 1
            || checkpoint
                .policyVerifications()
                .last()
                .is_none_or(|record| !record.matchesOriginal)
        {
            return Err("Repeated native checkpoint is not restored".into());
        }
        policyVerifications += checkpoint.policyVerifications().len();
        let records = journal.mutators(id)?;
        if records.len() != 2 {
            return Err("Repeated native checkpoint has unexpected mutator records".into());
        }
        for record in &records {
            backend.waitForMutator(record)?;
        }
        let observed = backend.observe(checkpoint.document())?;
        let native = observed
            .native
            .as_ref()
            .ok_or("Repeated native final observation missing")?;
        native.validateMtuObservation(&original)?;
        if native.settings != original.settings {
            return Err("Repeated native final settings differ from the exact original".into());
        }
        mutators.extend(records);
        event(
            json!({"phase":"repeatedTrialVerified","trialId":parentId,"checkpointId":id,"state":checkpoint.state(),"originalMtu":checkpoint.document().originalMtu,"finalMtu":observed.mtu}),
        )?;
    }
    let after = mtu::capture(
        backend.config.guid,
        backend.config.family,
        &AtomicBool::new(false),
    )?;
    let comparison = report
        .comparison
        .as_ref()
        .ok_or("Repeated native comparison missing")?;
    let traffic = report
        .traffic
        .as_ref()
        .ok_or("Repeated native traffic reservations missing")?;
    if traffic.reservedBlocks != 12
        || traffic.reservedCollections != 36
        || traffic.totals.probeAttempts != 216
        || traffic.totals.providerRequests != 0
        || traffic.totals.downloadBytes != 0
        || traffic.totals.uploadBytes != 0
    {
        return Err(
            "Repeated native traffic reservations do not match its fixed loopback workload".into(),
        );
    }
    if !comparison.exploratory || comparison.outcome != comparison::Outcome::Inconclusive {
        return Err("Lifecycle fixture must not claim a retained optimization".into());
    }
    event(
        json!({"phase":"repeatedExperimentComplete","trialId":parentId,"state":report.snapshot.state,"blockCount":12,"measurementCount":36,"rawRunIds":ids,"checkpoints":report.snapshot.checkpoints,"comparisonOutcome":comparison.outcome,"exploratory":comparison.exploratory,"acceptedConnections":listeners.accepted.load(Ordering::SeqCst),"reservedProbeAttempts":traffic.totals.probeAttempts,"sessionApprovalCount":1,"revokedTrialGrants":issuedGrants.len()}),
    )?;
    event(
        json!({"phase":"complete","trialId":parentId,"state":"restored","checkpointSchemaVersion":template.schemaVersion,"policyOriginal":template.policyOriginal,"policyVerificationCount":policyVerifications,"policyOriginalVerified":true,"pendingPolicyVerificationCount":journal.pendingPolicyVerification()?.len(),"original":original,"after":after,"writesThisProcess":backend.writes,"pendingRecoveryCount":0,"mutators":mutators,"processId":std::process::id()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn originChangesAlterTheEnvironmentFingerprintWhileCandidateMtuDoesNot() {
        use crate::mtu::origins::{OriginCapture, RawValue, tests::fixture};
        let mut native = crate::recovery::tests::nativeFixture();
        native.schemaVersion = 2;
        native.registryOrigins = Some(OriginCapture::Captured {
            evidence: fixture(native.adapterGuid),
        });
        let original = environment(&native, "route-fixture").unwrap();
        native.settings.nlMtu = 1400;
        assert_eq!(environment(&native, "route-fixture").unwrap(), original);
        let Some(OriginCapture::Captured { evidence }) = &mut native.registryOrigins else {
            unreachable!()
        };
        evidence.stacks[0].values[5].value = Some(RawValue {
            valueType: 1,
            dataHex: "0000".into(),
        });
        assert_ne!(environment(&native, "route-fixture").unwrap(), original);
    }

    #[test]
    fn repeatedCheckpointScopeIsDeterministicBoundedAndSeparateFromItsParent() {
        let parent = Uuid::new_v4();
        let config = Config {
            ownerSid: "S-1-5-21-1-2-3-1000".into(),
            guid: Uuid::new_v4(),
            family: AddressFamily::Ipv4,
            phase: Phase::Repeated,
            trialId: parent,
        };
        let ids = config.checkpointIds();
        assert_eq!(ids.len(), 12);
        assert_eq!(
            ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
            12
        );
        assert!(!ids.contains(&parent));
        assert!(!ids.contains(&checkpointId(parent, 12)));
        assert_eq!(ids, config.checkpointIds());
        assert_ne!(ids[0], checkpointId(Uuid::new_v4(), 0));
        assert_eq!(config.leaseMs(), 30_000);
        assert_eq!(config.deadline(), Duration::from_secs(300));
    }

    #[test]
    fn repeatedPlanUsesValidUnitsAndConservativeLifecycleThresholds() {
        let original = crate::recovery::tests::nativeFixture();
        let config = Config {
            ownerSid: "S-1-5-21-1-2-3-1000".into(),
            guid: original.adapterGuid,
            family: original.addressFamily,
            phase: Phase::Repeated,
            trialId: Uuid::new_v4(),
        };
        let listeners = Listeners::new().unwrap();
        let benchmarkConfig = BenchmarkConfig {
            sampleCount: 3,
            intervalMs: 250,
            timeoutMs: 100,
            sessionMinutes: 1,
            ..Default::default()
        };
        let seed = benchmark::runBenchmark(
            benchmarkConfig,
            listeners.endpoints.clone(),
            &AtomicBool::new(true),
            |_, _, _| {},
        )
        .unwrap();
        let plan = plan(&config, &original, &seed, &"a".repeat(64)).unwrap();
        plan.validate().unwrap();
        assert_eq!(plan.blockCount, 12);
        assert_eq!(plan.comparison.metrics.len(), 4);
        for metric in plan.comparison.metrics {
            if metric.unit == comparison::Unit::Percent {
                assert_eq!(metric.minimumImprovement.absolute, 0.1);
                assert_eq!(metric.maximumRegression.absolute, 0.0);
            } else {
                assert_eq!(metric.minimumImprovement.absolute, 1000.0);
            }
        }
    }

    #[test]
    fn repeatedScopeRejectsParentForeignAndExhaustedCheckpointIdsAndRetention() {
        let mut original = crate::recovery::tests::nativeFixture();
        original.alias = format!("epp-mtu-lab-{}", original.adapterGuid);
        let DriverContext::Captured { identity } = &mut original.driver else {
            panic!("fixture driver missing")
        };
        identity.infPath = "netloop.inf".into();
        identity.deviceInstanceId = "ROOT\\NET\\0000".into();
        let config = Config {
            ownerSid: "S-1-5-21-1-2-3-1000".into(),
            guid: original.adapterGuid,
            family: original.addressFamily,
            phase: Phase::Repeated,
            trialId: Uuid::new_v4(),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let backend = Backend {
            config: &config,
            permit: ServicePermit {
                guid: config.guid,
                family: config.family,
            },
            stop: stop.clone(),
            started: Instant::now(),
            pause: None,
            writes: 0,
            authorization: None,
            grantId: None,
            checkpointIds: config.checkpointIds(),
        };
        let document = MtuCheckpoint {
            schemaVersion: 3,
            id: checkpointId(config.trialId, 0),
            createdAtUnixMs: original.capturedAtUnixMs,
            leaseExpiresAtUnixMs: original.capturedAtUnixMs + 30_000,
            authorizedUserSid: config.ownerSid.clone(),
            context: original.journalContext().unwrap(),
            addressFamily: original.addressFamily,
            originalMtu: original.settings.nlMtu,
            proposedMtu: 1400,
            nativeOriginal: Some(original),
            policyOriginal: None,
        };
        let now = document.createdAtUnixMs + 1;
        backend
            .validateAuthorizationScope(&document, AuthorizationAction::Prepare, now)
            .unwrap();
        for id in [
            config.trialId,
            Uuid::new_v4(),
            checkpointId(config.trialId, 12),
        ] {
            let mut changed = document.clone();
            changed.id = id;
            assert!(
                backend
                    .validateAuthorizationScope(&changed, AuthorizationAction::Prepare, now)
                    .is_err()
            );
        }
        assert!(
            backend
                .validateAuthorizationScope(&document, AuthorizationAction::Retain, now)
                .is_err()
        );
        let mut changed = document.clone();
        changed.leaseExpiresAtUnixMs += 1;
        assert!(
            backend
                .validateAuthorizationScope(&changed, AuthorizationAction::Prepare, now)
                .is_err()
        );
        stop.store(true, Ordering::SeqCst);
        assert!(
            backend
                .validateAuthorizationScope(&document, AuthorizationAction::Prepare, now)
                .is_err()
        );
    }
}
