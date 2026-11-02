use super::*;
use crate::watchdog::tests::fixture;
use epp_core::{
    comparison::{self, Direction, MetricRule, Role, Threshold, Unit},
    experiment::{self, State},
};
use sha2::{Digest, Sha256};
use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{Arc, atomic::AtomicU32},
    time::{Duration, Instant},
};

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "epp-service-experiment-{}.sqlite3",
            uuid::Uuid::new_v4()
        )))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut path = self.0.clone().into_os_string();
            path.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(path));
        }
    }
}

fn hash(value: &impl serde::Serialize) -> String {
    format!("{:x}", Sha256::digest(serde_json::to_vec(value).unwrap()))
}

fn plan(original: &Snapshot, endpoints: &[SocketAddr]) -> Plan {
    let mut candidate = original.settings.clone();
    candidate.nlMtu = 1400;
    let now = nowUnixMs().unwrap();
    let threshold = |absolute| Threshold {
        absolute,
        relativeFraction: 0.0,
    };
    let metric = |id: &str, role, unit| MetricRule {
        id: id.into(),
        unit,
        direction: Direction::LowerIsBetter,
        role,
        resolution: 0.1,
        minimumImprovement: threshold(100.0),
        maximumRegression: threshold(100.0),
        maximumBaselineDrift: threshold(100.0),
    };
    Plan {
        id: uuid::Uuid::new_v4().to_string(),
        createdAtUnixMs: now,
        expiresAtUnixMs: now + 30_000,
        blockCount: 12,
        trafficBudget: Some(epp_core::experiment::budget::TrafficBudget {
            schemaVersion: 1,
            limits: epp_core::experiment::budget::Resources {
                probeAttempts: 72,
                ..Default::default()
            },
            providers: endpoints
                .iter()
                .map(|endpoint| epp_core::experiment::budget::Provider {
                    id: endpoint.to_string(),
                    perCollection: epp_core::experiment::budget::Resources {
                        probeAttempts: 1,
                        ..Default::default()
                    },
                    limits: epp_core::experiment::budget::Resources {
                        probeAttempts: 36,
                        ..Default::default()
                    },
                })
                .collect(),
        }),
        comparison: comparison::Plan {
            maximumBlockDurationMs: 5000,
            cohortSha256: hash(&endpoints),
            environmentSha256: hash(&(&original.os, &original.driver)),
            originalConfigurationSha256: hash(&original.settings),
            candidateConfigurationSha256: hash(&candidate),
            metrics: vec![
                metric("loopback-median", Role::Objective, Unit::Milliseconds),
                metric("connection-failure", Role::Guard, Unit::Percent),
            ],
        },
    }
}

struct Collector {
    plan: Plan,
    endpoints: Vec<SocketAddr>,
    observed: Arc<AtomicU32>,
    count: usize,
    cancel: Option<Arc<AtomicBool>>,
    restoredDuringStall: Arc<AtomicBool>,
}

impl Measurements for Collector {
    fn maximumTraffic(
        &self,
    ) -> ServiceResult<std::collections::BTreeMap<String, epp_core::experiment::budget::Resources>>
    {
        Ok(self
            .endpoints
            .iter()
            .map(|endpoint| {
                (
                    endpoint.to_string(),
                    epp_core::experiment::budget::Resources {
                        probeAttempts: 1,
                        ..Default::default()
                    },
                )
            })
            .collect())
    }

    fn verifyEnvironment(&mut self, plan: &Plan, original: &Snapshot) -> ServiceResult<()> {
        if plan.comparison.environmentSha256 != hash(&(&original.os, &original.driver))
            || plan.comparison.originalConfigurationSha256 != hash(&original.settings)
            || plan.comparison.cohortSha256 != hash(&self.endpoints)
        {
            return Err("fixture evidence binding changed".into());
        }
        Ok(())
    }
    fn collect(
        &mut self,
        configuration: Configuration,
        progress: &Progress<'_, '_>,
    ) -> ServiceResult<Session> {
        self.count += 1;
        let candidate = configuration == Configuration::Candidate;
        assert_eq!(
            self.observed.load(Ordering::SeqCst),
            if candidate { 1400 } else { 1500 }
        );
        let start = nowUnixMs()?;
        let mut timings = Vec::new();
        for address in &self.endpoints {
            progress.check()?;
            let before = Instant::now();
            let _stream = TcpStream::connect_timeout(address, Duration::from_millis(100))?;
            timings.push(before.elapsed().as_secs_f64() * 1000.0);
        }
        if candidate && let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(2);
            while self.observed.load(Ordering::SeqCst) != 1500 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            self.restoredDuringStall.store(
                self.observed.load(Ordering::SeqCst) == 1500,
                Ordering::SeqCst,
            );
            return Err("fixture stopped collection after session cancellation".into());
        }
        std::thread::sleep(Duration::from_millis(2));
        progress.check()?;
        assert_eq!(
            self.observed.load(Ordering::SeqCst),
            if candidate { 1400 } else { 1500 }
        );
        let summary =
            epp_core::statistics::summarize(&timings.into_iter().map(Some).collect::<Vec<_>>());
        Ok(Session {
            id: uuid::Uuid::new_v4().to_string(),
            startedAtUnixMs: start,
            finishedAtUnixMs: nowUnixMs()?,
            completed: true,
            cohortSha256: self.plan.comparison.cohortSha256.clone(),
            environmentSha256: self.plan.comparison.environmentSha256.clone(),
            configurationSha256: if candidate {
                &self.plan.comparison.candidateConfigurationSha256
            } else {
                &self.plan.comparison.originalConfigurationSha256
            }
            .clone(),
            values: vec![
                summary.medianMs.ok_or("Missing TCP median")?,
                summary
                    .connectionFailurePercent
                    .ok_or("Missing TCP outcomes")?,
            ],
        })
    }
}

fn issue(template: &MtuCheckpoint, original: &Snapshot, plan: &Plan) -> MtuCheckpoint {
    let mut document = template.clone();
    document.id = uuid::Uuid::new_v4();
    document.createdAtUnixMs = nowUnixMs().unwrap();
    document.leaseExpiresAtUnixMs = plan.expiresAtUnixMs;
    document.nativeOriginal = Some(original.clone());
    document
}

struct RefusingBinding(Collector);

impl Measurements for RefusingBinding {
    fn bindCheckpoint(&mut self, checkpoint: Option<&MtuCheckpoint>) -> ServiceResult<()> {
        if checkpoint.is_some() {
            return Err("fixture collector refuses issued checkpoint".into());
        }
        Ok(())
    }
    fn maximumTraffic(
        &self,
    ) -> ServiceResult<std::collections::BTreeMap<String, epp_core::experiment::budget::Resources>>
    {
        self.0.maximumTraffic()
    }
    fn verifyEnvironment(&mut self, plan: &Plan, original: &Snapshot) -> ServiceResult<()> {
        self.0.verifyEnvironment(plan, original)
    }
    fn collect(
        &mut self,
        configuration: Configuration,
        progress: &Progress<'_, '_>,
    ) -> ServiceResult<Session> {
        self.0.collect(configuration, progress)
    }
}

#[test]
fn collectorCheckpointRefusalBlocksPreparationAndEverySettingWrite() {
    let mut fixture = fixture();
    let first = TcpListener::bind("127.0.0.1:0").unwrap();
    let second = TcpListener::bind("[::1]:0").unwrap();
    let endpoints = vec![first.local_addr().unwrap(), second.local_addr().unwrap()];
    let plan = plan(
        fixture.document.nativeOriginal.as_ref().unwrap(),
        &endpoints,
    );
    let temporary = Temporary::new();
    let mut store = experiment::Store::open(&temporary.0).unwrap();
    let observed = Arc::new(AtomicU32::new(1500));
    fixture.backend.observedMtu = Some(observed.clone());
    let collector = RefusingBinding(Collector {
        plan: plan.clone(),
        endpoints,
        observed: observed.clone(),
        count: 0,
        cancel: None,
        restoredDuringStall: Arc::new(AtomicBool::new(false)),
    });
    let checkpointId = uuid::Uuid::new_v4();
    let template = fixture.document.clone();
    let stop = AtomicBool::new(false);
    let mut host = MtuHost::new(
        &mut fixture.journal,
        &mut fixture.backend,
        template.clone(),
        watchdog::Policy::default(),
        &stop,
        collector,
        |_, original, plan| {
            let mut document = issue(&template, original, plan);
            document.id = checkpointId;
            Ok(document)
        },
    )
    .unwrap();
    let report = experiment::execute(&mut store, plan, &mut host, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.snapshot.state, State::Failed);
    assert_eq!(host.measurements.0.count, 1);
    drop(host);
    assert!(fixture.backend.writes.is_empty());
    assert!(fixture.journal.load(checkpointId).is_err());
    assert_eq!(observed.load(Ordering::SeqCst), 1500);
}

#[test]
fn repeatedServiceTrialsMeasureActualLoopbackAndVerifyEveryOriginalBetweenCandidates() {
    for allowedBlocks in [0, 1, 12] {
        let mut fixture = fixture();
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("[::1]:0").unwrap();
        let endpoints = vec![first.local_addr().unwrap(), second.local_addr().unwrap()];
        let native = fixture.document.nativeOriginal.as_ref().unwrap();
        let mut plan = plan(native, &endpoints);
        plan.trafficBudget.as_mut().unwrap().limits.probeAttempts = allowedBlocks * 6;
        let temporary = Temporary::new();
        let mut store = experiment::Store::open(&temporary.0).unwrap();
        let observed = Arc::new(AtomicU32::new(1500));
        fixture.backend.observedMtu = Some(observed.clone());
        let collector = Collector {
            plan: plan.clone(),
            endpoints,
            observed: observed.clone(),
            count: 0,
            cancel: None,
            restoredDuringStall: Arc::new(AtomicBool::new(false)),
        };
        let template = fixture.document.clone();
        let stop = AtomicBool::new(false);
        let mut host = MtuHost::new(
            &mut fixture.journal,
            &mut fixture.backend,
            template.clone(),
            watchdog::Policy::default(),
            &stop,
            collector,
            |_, original, plan| Ok(issue(&template, original, plan)),
        )
        .unwrap();
        let report =
            experiment::execute(&mut store, plan, &mut host, &AtomicBool::new(false)).unwrap();
        assert_eq!(
            report.snapshot.state,
            if allowedBlocks == 12 {
                State::Completed
            } else {
                State::BudgetExhausted
            }
        );
        assert_eq!(report.snapshot.blocks.len(), allowedBlocks as usize);
        assert_eq!(report.snapshot.checkpoints.len(), allowedBlocks as usize);
        if let Some(comparison) = report.comparison {
            assert!(comparison.exploratory);
            assert_eq!(comparison.outcome, comparison::Outcome::Inconclusive);
        } else {
            assert_eq!(allowedBlocks, 0);
        }
        assert_eq!(host.measurements.count, allowedBlocks as usize * 3);
        assert_eq!(
            report.traffic.unwrap().totals.probeAttempts,
            allowedBlocks * 6
        );
        drop(host);
        assert_eq!(observed.load(Ordering::SeqCst), 1500);
        assert_eq!(fixture.backend.writes.len(), allowedBlocks as usize * 2);
        assert!(fixture.journal.pendingRecovery().unwrap().is_empty());
        for id in report.snapshot.checkpoints {
            let checkpoint = fixture.journal.load(id.parse().unwrap()).unwrap();
            assert_eq!(checkpoint.state(), crate::journal::State::Restored);
            assert_eq!(
                fixture
                    .journal
                    .mutators(checkpoint.document().id)
                    .unwrap()
                    .len(),
                2
            );
        }
    }
}

#[test]
fn sessionCancellationRestoresEvenWhileTheCollectorStopsReportingProgress() {
    let mut fixture = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoints = vec![listener.local_addr().unwrap()];
    let plan = plan(
        fixture.document.nativeOriginal.as_ref().unwrap(),
        &endpoints,
    );
    let temporary = Temporary::new();
    let mut store = experiment::Store::open(&temporary.0).unwrap();
    let observed = Arc::new(AtomicU32::new(1500));
    fixture.backend.observedMtu = Some(observed.clone());
    let cancelled = Arc::new(AtomicBool::new(false));
    let restored = Arc::new(AtomicBool::new(false));
    let collector = Collector {
        plan: plan.clone(),
        endpoints,
        observed: observed.clone(),
        count: 0,
        cancel: Some(cancelled.clone()),
        restoredDuringStall: restored.clone(),
    };
    let template = fixture.document.clone();
    let stop = AtomicBool::new(false);
    let policy = watchdog::Policy {
        pollInterval: Duration::from_millis(10),
        ..Default::default()
    };
    let mut host = MtuHost::new(
        &mut fixture.journal,
        &mut fixture.backend,
        template.clone(),
        policy,
        &stop,
        collector,
        |_, original, plan| Ok(issue(&template, original, plan)),
    )
    .unwrap();
    let report = experiment::execute(&mut store, plan, &mut host, &cancelled).unwrap();
    assert_eq!(report.snapshot.state, State::Cancelled);
    assert!(report.snapshot.blocks.is_empty());
    assert_eq!(host.measurements.count, 2);
    assert!(restored.load(Ordering::SeqCst));
    drop(host);
    assert_eq!(fixture.backend.writes.len(), 2);
    assert!(fixture.journal.pendingRecovery().unwrap().is_empty());
}

#[test]
fn anIssuedCheckpointOutsideThePlanIsRejectedBeforeAnySettingWrite() {
    let mut fixture = fixture();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoints = vec![listener.local_addr().unwrap()];
    let plan = plan(
        fixture.document.nativeOriginal.as_ref().unwrap(),
        &endpoints,
    );
    let temporary = Temporary::new();
    let mut store = experiment::Store::open(&temporary.0).unwrap();
    let observed = Arc::new(AtomicU32::new(1500));
    let collector = Collector {
        plan: plan.clone(),
        endpoints,
        observed,
        count: 0,
        cancel: None,
        restoredDuringStall: Arc::new(AtomicBool::new(false)),
    };
    let template = fixture.document.clone();
    let stop = AtomicBool::new(false);
    let mut host = MtuHost::new(
        &mut fixture.journal,
        &mut fixture.backend,
        template.clone(),
        watchdog::Policy::default(),
        &stop,
        collector,
        |_, original, plan| {
            let mut document = issue(&template, original, plan);
            document.proposedMtu = 1300;
            Ok(document)
        },
    )
    .unwrap();
    let report = experiment::execute(&mut store, plan, &mut host, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.snapshot.state, State::Failed);
    assert_eq!(host.measurements.count, 1);
    drop(host);
    assert!(fixture.backend.writes.is_empty());
}

#[test]
fn failedNativeRestorationBlocksMoreTrialsUntilServiceRecoveryIsVerified() {
    let mut fixture = fixture();
    fixture.backend.failRestore = true;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoints = vec![listener.local_addr().unwrap()];
    let plan = plan(
        fixture.document.nativeOriginal.as_ref().unwrap(),
        &endpoints,
    );
    let temporary = Temporary::new();
    let mut store = experiment::Store::open(&temporary.0).unwrap();
    let observed = Arc::new(AtomicU32::new(1500));
    fixture.backend.observedMtu = Some(observed.clone());
    let collector = Collector {
        plan: plan.clone(),
        endpoints: endpoints.clone(),
        observed: observed.clone(),
        count: 0,
        cancel: None,
        restoredDuringStall: Arc::new(AtomicBool::new(false)),
    };
    let template = fixture.document.clone();
    let stop = AtomicBool::new(false);
    let mut host = MtuHost::new(
        &mut fixture.journal,
        &mut fixture.backend,
        template.clone(),
        watchdog::Policy::default(),
        &stop,
        collector,
        |_, original, plan| Ok(issue(&template, original, plan)),
    )
    .unwrap();
    let report =
        experiment::execute(&mut store, plan.clone(), &mut host, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.snapshot.state, State::RecoveryRequired);
    assert!(
        report
            .snapshot
            .error
            .as_deref()
            .is_some_and(|error| error.contains("fixture restoration failed"))
    );
    assert!(
        report
            .snapshot
            .pendingCandidate
            .as_ref()
            .unwrap()
            .error
            .as_deref()
            .is_some_and(|error| error.contains("fixture restoration failed"))
    );
    assert!(report.snapshot.blocks.is_empty());
    assert_eq!(host.measurements.count, 2);
    assert!(experiment::acknowledgeRecovery(&mut store, &plan.id, &mut host).is_err());
    assert_eq!(store.pending().unwrap().len(), 1);
    drop(host);
    assert_eq!(observed.load(Ordering::SeqCst), 1400);
    let checkpointId = fixture.journal.pendingRecovery().unwrap()[0].document().id;
    fixture.backend.failRestore = false;
    let recovery =
        crate::recovery::MtuCoordinator::new(&mut fixture.journal, &mut fixture.backend, nowUnixMs)
            .restore(checkpointId)
            .unwrap();
    assert!(recovery.originalMtuVerified);
    assert!(recovery.journalFinalized);
    let collector = Collector {
        plan: plan.clone(),
        endpoints,
        observed: observed.clone(),
        count: 0,
        cancel: None,
        restoredDuringStall: Arc::new(AtomicBool::new(false)),
    };
    let mut host = MtuHost::new(
        &mut fixture.journal,
        &mut fixture.backend,
        template.clone(),
        watchdog::Policy::default(),
        &stop,
        collector,
        |_, original, plan| Ok(issue(&template, original, plan)),
    )
    .unwrap();
    assert_eq!(
        experiment::acknowledgeRecovery(&mut store, &plan.id, &mut host)
            .unwrap()
            .state,
        State::Interrupted
    );
    assert_eq!(host.measurements.count, 0);
    assert_eq!(observed.load(Ordering::SeqCst), 1500);
    assert!(store.pending().unwrap().is_empty());
}
