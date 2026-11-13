use super::*;
use comparison::{Direction, MetricRule, Role, Threshold, Unit};
use std::{path::PathBuf, sync::Arc};

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Self {
        let mut bytes = [0u8; 16];
        getrandom::fill(&mut bytes).unwrap();
        let id: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        Self(std::env::temp_dir().join(format!("epp-repeated-trials-{id}.sqlite3")))
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

fn plan() -> Plan {
    let now = nowUnixMs().unwrap();
    let threshold = |absolute| Threshold {
        absolute,
        relativeFraction: 0.0,
    };
    let metric = |id: &str, role, direction| MetricRule {
        id: id.into(),
        unit: Unit::Milliseconds,
        direction,
        role,
        resolution: 0.1,
        minimumImprovement: threshold(2.0),
        maximumRegression: threshold(3.0),
        maximumBaselineDrift: threshold(4.0),
    };
    Plan {
        id: "repeated-test".into(),
        createdAtUnixMs: now,
        expiresAtUnixMs: now + 30_000,
        blockCount: 12,
        trafficBudget: Some(budget::TrafficBudget {
            schemaVersion: 1,
            limits: budget::Resources {
                probeAttempts: 96,
                ..Default::default()
            },
            providers: vec![budget::Provider {
                id: "fixture".into(),
                perCollection: budget::Resources {
                    probeAttempts: 1,
                    ..Default::default()
                },
                limits: budget::Resources {
                    probeAttempts: 96,
                    ..Default::default()
                },
            }],
        }),
        comparison: comparison::Plan {
            maximumBlockDurationMs: 1000,
            cohortSha256: "a".repeat(64),
            environmentSha256: "b".repeat(64),
            originalConfigurationSha256: "c".repeat(64),
            candidateConfigurationSha256: "d".repeat(64),
            metrics: vec![
                metric("latency", Role::Objective, Direction::LowerIsBetter),
                metric("guard", Role::Guard, Direction::LowerIsBetter),
            ],
        },
    }
}

#[derive(Default)]
struct HostFixture {
    plan: Option<Plan>,
    originals: usize,
    candidates: usize,
    verifications: usize,
    changed: bool,
    reject: bool,
    drift: bool,
    badOriginal: bool,
    badCandidate: bool,
    reusedCheckpoint: bool,
    panicCandidate: bool,
    candidateOutcome: Option<TrialOutcome>,
    cancel: Option<Arc<AtomicBool>>,
    cancelOnFinalVerification: Option<Arc<AtomicBool>>,
    cancelAtVerification: Option<(usize, Arc<AtomicBool>)>,
    expireDuringCandidate: bool,
    initialVerificationDelay: Duration,
    traffic: Option<std::collections::BTreeMap<String, budget::Resources>>,
    inspectReservations: Option<PathBuf>,
    trafficDelay: Duration,
}

impl HostFixture {
    fn measurement(&self, candidate: bool, id: String) -> Session {
        let plan = self.plan.as_ref().unwrap();
        if let Some(path) = &self.inspectReservations {
            let stored = Store::open(path).unwrap().load(&plan.id).unwrap();
            assert_eq!(stored.reservedBlocks as usize, stored.blocks.len() + 1);
            assert_eq!(stored.schemaVersion, 2);
            assert!(
                stored
                    .plan
                    .trafficBudget
                    .as_ref()
                    .unwrap()
                    .allows(stored.reservedBlocks)
                    .unwrap()
            );
            if candidate {
                assert_eq!(stored.state, State::Candidate);
            }
        }
        let start = nowUnixMs().unwrap();
        std::thread::sleep(Duration::from_millis(2));
        let variation = if self.candidates.is_multiple_of(2) {
            -0.5
        } else {
            0.5
        };
        Session {
            id,
            startedAtUnixMs: start,
            finishedAtUnixMs: nowUnixMs().unwrap(),
            completed: true,
            cohortSha256: plan.comparison.cohortSha256.clone(),
            environmentSha256: plan.comparison.environmentSha256.clone(),
            configurationSha256: if candidate {
                &plan.comparison.candidateConfigurationSha256
            } else {
                &plan.comparison.originalConfigurationSha256
            }
            .clone(),
            values: if candidate {
                vec![
                    if self.reject { 80.0 } else { 25.0 + variation },
                    100.0 + variation,
                ]
            } else {
                vec![
                    if self.drift && self.originals.is_multiple_of(2) {
                        45.0
                    } else {
                        30.0
                    },
                    100.0,
                ]
            },
        }
    }
}

impl Host for HostFixture {
    fn maximumTraffic(&self) -> AppResult<std::collections::BTreeMap<String, budget::Resources>> {
        std::thread::sleep(self.trafficDelay);
        Ok(self.traffic.clone().unwrap_or_else(|| {
            [(
                "fixture".into(),
                budget::Resources {
                    probeAttempts: 1,
                    ..Default::default()
                },
            )]
            .into()
        }))
    }

    fn verifyOriginal(&mut self, plan: &Plan) -> AppResult<()> {
        if self.verifications == 0 {
            std::thread::sleep(self.initialVerificationDelay);
        }
        self.verifications += 1;
        if let Some((verification, cancel)) = &self.cancelAtVerification
            && self.verifications == *verification
        {
            cancel.store(true, Ordering::SeqCst);
        }
        self.plan = Some(plan.clone());
        if self.candidates == 12
            && self.originals == 24
            && let Some(cancel) = &self.cancelOnFinalVerification
        {
            cancel.store(true, Ordering::SeqCst);
        }
        if self.changed {
            return Err("fixture original not restored".into());
        }
        Ok(())
    }
    fn measureOriginal(&mut self, _: &Control<'_>) -> AppResult<Session> {
        self.originals += 1;
        let mut session = self.measurement(false, format!("original-{}", self.originals));
        if self.badOriginal {
            session.completed = false;
        }
        Ok(session)
    }
    fn measureCandidate(&mut self, control: &Control<'_>) -> AppResult<CandidateResult> {
        self.candidates += 1;
        self.changed = true;
        assert!(self.candidates <= 32);
        if self.panicCandidate {
            panic!("fixture candidate interrupted before restoration");
        }
        if self.expireDuringCandidate {
            std::thread::sleep(
                control.deadline.saturating_duration_since(Instant::now())
                    + Duration::from_millis(10),
            );
        }
        let mut measurement = self.measurement(true, format!("candidate-{}", self.candidates));
        if self.badCandidate {
            measurement.environmentSha256 = "e".repeat(64);
        }
        self.changed = false;
        if let Some(cancel) = &self.cancel {
            cancel.store(true, Ordering::SeqCst);
        }
        Ok(CandidateResult {
            checkpointId: format!(
                "checkpoint-{}",
                if self.reusedCheckpoint {
                    1
                } else {
                    self.candidates
                }
            ),
            outcome: self.candidateOutcome.unwrap_or(TrialOutcome::Completed),
            measurement: Some(measurement),
            error: self
                .candidateOutcome
                .map(|_| "fixture candidate failure detail".into()),
        })
    }
}

#[test]
fn widestRepeatedPlanPreservesAllThirtyTwoBracketsWithinTheDurableLimit() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let now = nowUnixMs().unwrap();
    let mut plan = plan();
    plan.createdAtUnixMs = now - 1000;
    plan.blockCount = 32;
    let mut guard = plan.comparison.metrics[1].clone();
    guard.role = Role::Guard;
    plan.comparison.metrics.resize(64, guard);
    for (index, rule) in plan.comparison.metrics.iter_mut().enumerate() {
        rule.id = format!("metric-{index}-{}", "x".repeat(88));
    }
    let mut snapshot = store.begin(plan, now).unwrap();
    for index in 0..32 {
        let start = snapshot.plan.createdAtUnixMs + index * 20;
        let session = |offset: u64, configuration: &str| Session {
            id: format!("session-{index}-{offset}-{}", "x".repeat(82)),
            startedAtUnixMs: start + offset,
            finishedAtUnixMs: start + offset + 1,
            completed: true,
            cohortSha256: snapshot.plan.comparison.cohortSha256.clone(),
            environmentSha256: snapshot.plan.comparison.environmentSha256.clone(),
            configurationSha256: configuration.into(),
            values: vec![999_999_999_999.999_9; 64],
        };
        snapshot.blocks.push(MatchedBlock {
            originalBefore: session(0, &snapshot.plan.comparison.originalConfigurationSha256),
            candidate: session(5, &snapshot.plan.comparison.candidateConfigurationSha256),
            originalAfter: session(10, &snapshot.plan.comparison.originalConfigurationSha256),
        });
        snapshot.checkpoints.push(format!("checkpoint-{index}"));
    }
    snapshot.state = State::Completed;
    snapshot.reservedBlocks = 32;
    snapshot.revision = 1;
    store.save(&snapshot).unwrap();
    let expected = serde_json::to_value(&snapshot).unwrap();
    assert!(serde_json::to_vec(&snapshot).unwrap().len() <= 262_144);
    drop(store);
    let store = Store::open(&temporary.0).unwrap();
    assert_eq!(
        serde_json::to_value(store.load(&snapshot.plan.id).unwrap()).unwrap(),
        expected
    );
    assert!(store.pending().unwrap().is_empty());
}

#[test]
fn repeatedTrialsPersistAllBracketsAndNeverAuthorizeRetention() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let mut host = HostFixture::default();
    let report = execute(&mut store, plan(), &mut host, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.snapshot.state, State::Completed);
    assert_eq!(host.candidates, 12);
    assert_eq!(host.originals, 24);
    assert!(!host.changed);
    let exported = serde_json::to_value(&report).unwrap();
    assert_eq!(exported["snapshot"]["state"], "completed");
    assert_eq!(exported["comparison"]["exploratory"], true);
    let comparison = report.comparison.unwrap();
    assert_eq!(comparison.outcome, comparison::Outcome::Promising);
    assert!(comparison.exploratory);
    assert_eq!(comparison.blockCount, 12);
    assert!(store.pending().unwrap().is_empty());
    let saved = serde_json::to_value(&report.snapshot).unwrap();
    drop(store);
    let store = Store::open(&temporary.0).unwrap();
    assert_eq!(
        serde_json::to_value(store.load("repeated-test").unwrap()).unwrap(),
        saved
    );
}

#[test]
fn hardRegressionAndBaselineDriftStopAfterTheFirstCompleteBracket() {
    for drift in [false, true] {
        let temporary = Temporary::new();
        let mut store = Store::open(&temporary.0).unwrap();
        let mut host = HostFixture {
            reject: !drift,
            drift,
            ..Default::default()
        };
        let report = execute(&mut store, plan(), &mut host, &AtomicBool::new(false)).unwrap();
        assert_eq!(
            report.snapshot.state,
            if drift {
                State::Invalid
            } else {
                State::Rejected
            }
        );
        assert_eq!(report.snapshot.blocks.len(), 1);
        assert_eq!(host.candidates, 1);
        assert_eq!(host.originals, 2);
        assert!(!host.changed);
    }
}

#[test]
fn invalidBaselinePreventsAnyCandidateAndChangedCandidateContextCannotEnterAComparison() {
    for badOriginal in [true, false] {
        let temporary = Temporary::new();
        let mut store = Store::open(&temporary.0).unwrap();
        let mut host = HostFixture {
            badOriginal,
            badCandidate: !badOriginal,
            ..Default::default()
        };
        let report = execute(&mut store, plan(), &mut host, &AtomicBool::new(false)).unwrap();
        assert_eq!(report.snapshot.state, State::Failed);
        assert!(report.comparison.is_none());
        assert_eq!(host.candidates, usize::from(!badOriginal));
        assert_eq!(host.originals, 1);
        assert!(!host.changed);
    }
}

#[test]
fn cancellationAndDeadlineAfterCandidateCannotStartAnotherMeasurement() {
    for cancelled in [true, false] {
        let temporary = Temporary::new();
        let mut store = Store::open(&temporary.0).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut plan = plan();
        let mut host = HostFixture {
            initialVerificationDelay: Duration::from_millis(100),
            ..Default::default()
        };
        if cancelled {
            host.cancel = Some(cancel.clone());
        } else {
            plan.expiresAtUnixMs = nowUnixMs().unwrap() + 5_000;
            host.expireDuringCandidate = true;
        }
        let report = execute(&mut store, plan, &mut host, &cancel).unwrap();
        assert_eq!(
            report.snapshot.state,
            if cancelled {
                State::Cancelled
            } else {
                State::Expired
            }
        );
        assert_eq!(host.candidates, 1);
        assert_eq!(host.originals, 1);
        assert!(report.snapshot.blocks.is_empty());
        assert!(!host.changed);
    }
}

#[test]
fn cancellationDuringOriginalVerificationCannotEnterAnotherMeasurement() {
    for verification in [1, 2] {
        let temporary = Temporary::new();
        let mut store = Store::open(&temporary.0).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut host = HostFixture {
            cancelAtVerification: Some((verification, cancel.clone())),
            ..Default::default()
        };
        let report = execute(&mut store, plan(), &mut host, &cancel).unwrap();
        assert_eq!(report.snapshot.state, State::Cancelled);
        assert_eq!(host.originals, verification - 1);
        assert_eq!(host.candidates, 0);
        assert_eq!(report.snapshot.reservedBlocks as usize, verification - 1);
        assert!(report.snapshot.blocks.is_empty());
        assert!(store.pending().unwrap().is_empty());
        assert!(!host.changed);
    }
}

#[test]
fn cancellationDuringFinalOriginalVerificationCannotBeReportedAsCompleted() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let mut host = HostFixture {
        cancelOnFinalVerification: Some(cancel.clone()),
        ..Default::default()
    };
    let report = execute(&mut store, plan(), &mut host, &cancel).unwrap();
    assert_eq!(report.snapshot.state, State::Cancelled);
    assert_eq!(report.snapshot.blocks.len(), 12);
    assert!(!host.changed);
}

#[test]
fn hostPanicRequiresRecoveryAndBlocksNewWorkUntilExactOriginalVerification() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let mut host = HostFixture {
        panicCandidate: true,
        ..Default::default()
    };
    let report = execute(&mut store, plan(), &mut host, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.snapshot.state, State::RecoveryRequired);
    assert!(host.changed);
    assert_eq!(store.pending().unwrap().len(), 1);
    assert!(acknowledgeRecovery(&mut store, "repeated-test", &mut host).is_err());
    let mut next = plan();
    next.id = "another-experiment".into();
    assert!(execute(&mut store, next, &mut host, &AtomicBool::new(false)).is_err());
    assert_eq!(host.candidates, 1);
    host.changed = false;
    assert_eq!(
        acknowledgeRecovery(&mut store, "repeated-test", &mut host)
            .unwrap()
            .state,
        State::Interrupted
    );
    assert!(store.pending().unwrap().is_empty());
    assert!(acknowledgeRecovery(&mut store, "repeated-test", &mut host).is_err());
}

#[test]
fn restartPreservesIntentAndNeverAutomaticallyRepeatsTheCandidate() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let plan = plan();
    let mut snapshot = store.begin(plan.clone(), nowUnixMs().unwrap()).unwrap();
    let mut host = HostFixture::default();
    host.verifyOriginal(&plan).unwrap();
    snapshot.reservedBlocks = 1;
    persist(&mut store, &mut snapshot, State::BaselineBefore).unwrap();
    let cancel = AtomicBool::new(false);
    let control = Control {
        cancelled: &cancel,
        expiresAtUnixMs: plan.expiresAtUnixMs,
        deadline: Instant::now() + Duration::from_secs(30),
        startedAtUnixMs: plan.createdAtUnixMs,
    };
    snapshot.pendingBefore = Some(host.measureOriginal(&control).unwrap());
    persist(&mut store, &mut snapshot, State::Candidate).unwrap();
    drop(store);
    let mut store = Store::open(&temporary.0).unwrap();
    assert_eq!(store.pending().unwrap()[0].state, State::Candidate);
    assert_eq!(host.candidates, 0);
    assert!(execute(&mut store, plan, &mut host, &cancel).is_err());
    assert_eq!(host.candidates, 0);
    acknowledgeRecovery(&mut store, "repeated-test", &mut host).unwrap();
    assert!(store.pending().unwrap().is_empty());
}

#[test]
fn failedPhaseWriteStopsTrialsAndCanFinalizeOnlyAfterOriginalVerification() {
    for phase in ["candidate", "baselineAfter"] {
        let temporary = Temporary::new();
        let mut store = Store::open(&temporary.0).unwrap();
        let connection = rusqlite::Connection::open(&temporary.0).unwrap();
        connection.execute_batch(&format!("CREATE TRIGGER refuse_progress BEFORE UPDATE ON experiments WHEN json_extract(NEW.payload_json,'$.state')='{phase}' BEGIN SELECT RAISE(FAIL,'fixture progress storage unavailable'); END;")).unwrap();
        let mut host = HostFixture::default();
        let report = execute(&mut store, plan(), &mut host, &AtomicBool::new(false)).unwrap();
        assert_eq!(report.snapshot.state, State::Failed);
        assert!(
            report
                .snapshot
                .error
                .unwrap()
                .contains("fixture progress storage unavailable")
        );
        assert_eq!(host.candidates, usize::from(phase == "baselineAfter"));
        assert_eq!(host.originals, 1);
        assert!(!host.changed);
        assert!(store.pending().unwrap().is_empty());
        connection
            .execute_batch("DROP TRIGGER refuse_progress")
            .unwrap();
    }
}

#[test]
fn unavailableProgressAndFinalizationStoragePreserveIntentAndBothErrors() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let connection = rusqlite::Connection::open(&temporary.0).unwrap();
    connection.execute_batch("CREATE TRIGGER refuse_progress BEFORE UPDATE ON experiments BEGIN SELECT RAISE(FAIL,'fixture storage unavailable'); END;").unwrap();
    let mut host = HostFixture::default();
    let error = execute(&mut store, plan(), &mut host, &AtomicBool::new(false))
        .err()
        .unwrap()
        .to_string();
    assert!(error.starts_with("fixture storage unavailable"), "{error}");
    assert!(
        error.contains("durable finalization failed: fixture storage unavailable"),
        "{error}"
    );
    assert_eq!(host.candidates, 0);
    assert_eq!(host.originals, 0);
    assert!(!host.changed);
    assert_eq!(store.pending().unwrap()[0].state, State::Ready);
    connection
        .execute_batch("DROP TRIGGER refuse_progress")
        .unwrap();
    acknowledgeRecovery(&mut store, "repeated-test", &mut host).unwrap();
    assert!(store.pending().unwrap().is_empty());
}

#[test]
fn aReusedCheckpointAndInterruptedCandidateCannotSupplyCompletedBrackets() {
    for interrupted in [false, true] {
        let temporary = Temporary::new();
        let mut store = Store::open(&temporary.0).unwrap();
        let mut host = HostFixture {
            reusedCheckpoint: !interrupted,
            candidateOutcome: interrupted.then_some(TrialOutcome::Interrupted),
            ..Default::default()
        };
        let report = execute(&mut store, plan(), &mut host, &AtomicBool::new(false)).unwrap();
        assert_eq!(
            report.snapshot.state,
            if interrupted {
                State::Interrupted
            } else {
                State::Failed
            }
        );
        if interrupted {
            assert_eq!(
                report.snapshot.error.as_deref(),
                Some("fixture candidate failure detail")
            );
            assert_eq!(
                report
                    .snapshot
                    .pendingCandidate
                    .as_ref()
                    .unwrap()
                    .error
                    .as_deref(),
                Some("fixture candidate failure detail")
            );
        }
        assert_eq!(report.snapshot.blocks.len(), usize::from(!interrupted));
        assert!(!host.changed);
        assert!(store.pending().unwrap().is_empty());
    }
}

#[test]
fn aCompletedCandidateWithAnUnresolvedErrorCannotSupplyComparisonEvidence() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let mut host = HostFixture {
        candidateOutcome: Some(TrialOutcome::Completed),
        ..Default::default()
    };
    let report = execute(&mut store, plan(), &mut host, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.snapshot.state, State::Failed);
    assert!(report.snapshot.blocks.is_empty());
    assert!(report.comparison.is_none());
    assert_eq!(host.candidates, 1);
    assert!(!host.changed);
}

#[test]
fn invalidPlansAndAlreadyCancelledWorkAreRefusedBeforeHostExecution() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let mut host = HostFixture::default();
    let mut invalid = plan();
    invalid.blockCount = 1;
    assert!(execute(&mut store, invalid, &mut host, &AtomicBool::new(false)).is_err());
    assert!(execute(&mut store, plan(), &mut host, &AtomicBool::new(true)).is_err());
    assert_eq!(host.verifications, 0);
    assert!(store.pending().unwrap().is_empty());
}

#[test]
fn aggregateLimitsStopOnlyBeforeWholeBracketsAndNeverLeaveACandidateActive() {
    for (limit, blocks) in [(2, 0), (3, 1), (6, 2)] {
        let temporary = Temporary::new();
        let mut store = Store::open(&temporary.0).unwrap();
        let mut plan = plan();
        plan.trafficBudget.as_mut().unwrap().limits.probeAttempts = limit;
        let mut host = HostFixture::default();
        let report = execute(&mut store, plan, &mut host, &AtomicBool::new(false)).unwrap();
        assert_eq!(report.snapshot.state, State::BudgetExhausted);
        assert_eq!(report.snapshot.blocks.len(), blocks);
        assert_eq!(report.snapshot.reservedBlocks as usize, blocks);
        assert_eq!(host.candidates, blocks);
        assert_eq!(host.originals, blocks * 2);
        assert!(!host.changed);
        let usage = report.traffic.unwrap();
        assert_eq!(usage.totals.probeAttempts, (blocks * 3) as u64);
        assert!(store.pending().unwrap().is_empty());
        assert_eq!(
            store.load("repeated-test").unwrap().reservedBlocks as usize,
            blocks
        );
    }
}

#[test]
fn everyMeasurementSeesItsWholeBracketReservationAlreadyCommitted() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let mut host = HostFixture {
        inspectReservations: Some(temporary.0.clone()),
        ..Default::default()
    };
    let report = execute(&mut store, plan(), &mut host, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.snapshot.state, State::Completed);
    assert_eq!(report.snapshot.reservedBlocks, 12);
    assert_eq!(report.traffic.unwrap().reservedCollections, 36);
}

#[test]
fn underdeclaredOrUnknownCollectorTrafficIsRejectedBeforeAnyExperimentIntent() {
    for unknown in [false, true] {
        let temporary = Temporary::new();
        let mut store = Store::open(&temporary.0).unwrap();
        let mut plan = plan();
        let budget = plan.trafficBudget.as_mut().unwrap();
        if unknown {
            budget.providers[0].id = "untrusted-substitute".into();
        } else {
            budget.providers[0].perCollection.probeAttempts = 0;
            budget.providers[0].perCollection.providerRequests = 1;
        }
        let mut host = HostFixture::default();
        let error = execute(&mut store, plan, &mut host, &AtomicBool::new(false)).unwrap_err();
        assert!(error.to_string().contains("trusted collector"));
        assert_eq!(host.verifications, 0);
        assert_eq!(host.originals, 0);
        assert_eq!(host.candidates, 0);
        assert!(store.load("repeated-test").is_err());
    }
}

#[test]
fn timeSpentDeclaringTrafficCannotExtendTheExperimentOrCreateExpiredIntent() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let mut plan = plan();
    plan.expiresAtUnixMs = nowUnixMs().unwrap() + 50;
    let mut host = HostFixture {
        trafficDelay: Duration::from_millis(100),
        ..Default::default()
    };
    assert!(execute(&mut store, plan, &mut host, &AtomicBool::new(false)).is_err());
    assert_eq!(host.verifications, 0);
    assert!(store.load("repeated-test").is_err());
}

#[test]
fn providerPayloadLimitsApplyEvenWhenTheGlobalBudgetHasRoom() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let mut plan = plan();
    let budget = plan.trafficBudget.as_mut().unwrap();
    budget.limits.downloadBytes = 1_000_000;
    budget.limits.uploadBytes = 1_000_000;
    let first = &mut budget.providers[0];
    first.perCollection.downloadBytes = 100;
    first.perCollection.uploadBytes = 50;
    first.limits.downloadBytes = 300;
    first.limits.uploadBytes = 150;
    budget.providers.push(budget::Provider {
        id: "second".into(),
        perCollection: budget::Resources {
            providerRequests: 2,
            ..Default::default()
        },
        limits: budget::Resources {
            providerRequests: 1000,
            ..Default::default()
        },
    });
    budget.limits.providerRequests = 1000;
    let mut host = HostFixture {
        traffic: Some(
            budget
                .providers
                .iter()
                .map(|provider| (provider.id.clone(), provider.perCollection))
                .collect(),
        ),
        ..Default::default()
    };
    let report = execute(&mut store, plan, &mut host, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.snapshot.state, State::BudgetExhausted);
    assert_eq!(host.candidates, 1);
    let usage = report.traffic.unwrap();
    assert_eq!(usage.totals.downloadBytes, 300);
    assert_eq!(usage.totals.uploadBytes, 150);
    assert_eq!(usage.totals.providerRequests, 6);
    assert_eq!(usage.providers[0].reserved.downloadBytes, 300);
    assert_eq!(usage.providers[1].reserved.providerRequests, 6);
}

#[test]
fn failedReservationCommitCannotStartMeasurementsOrRefundItsConservativeAllowance() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let connection = rusqlite::Connection::open(&temporary.0).unwrap();
    connection.execute_batch("CREATE TRIGGER refuse_reservation BEFORE UPDATE ON experiments WHEN json_extract(NEW.payload_json,'$.state')='baselineBefore' BEGIN SELECT RAISE(FAIL,'fixture reservation write failed'); END;").unwrap();
    let mut host = HostFixture::default();
    let report = execute(&mut store, plan(), &mut host, &AtomicBool::new(false)).unwrap();
    assert_eq!(report.snapshot.state, State::Failed);
    assert_eq!(host.originals, 0);
    assert_eq!(host.candidates, 0);
    assert_eq!(report.snapshot.reservedBlocks, 1);
    assert_eq!(report.traffic.unwrap().totals.probeAttempts, 3);
    assert_eq!(store.load("repeated-test").unwrap().reservedBlocks, 1);
}

#[test]
fn committedReservationsCannotBeReducedBeforeAnotherCallerContinues() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let mut snapshot = store.begin(plan(), nowUnixMs().unwrap()).unwrap();
    snapshot.reservedBlocks = 1;
    persist(&mut store, &mut snapshot, State::BaselineBefore).unwrap();
    snapshot.reservedBlocks = 0;
    assert!(persist(&mut store, &mut snapshot, State::RecoveryRequired).is_err());
    assert_eq!(store.load("repeated-test").unwrap().reservedBlocks, 1);
}

#[test]
fn legacyUnbudgetedIntentRemainsRecoverableButCannotStartNewMeasurements() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let snapshot = store.begin(plan(), nowUnixMs().unwrap()).unwrap();
    let mut legacy = serde_json::to_value(&snapshot).unwrap();
    legacy["schemaVersion"] = serde_json::json!(1);
    legacy["plan"]
        .as_object_mut()
        .unwrap()
        .remove("trafficBudget");
    legacy.as_object_mut().unwrap().remove("reservedBlocks");
    let payload = serde_json::to_string(&legacy).unwrap();
    let connection = rusqlite::Connection::open(&temporary.0).unwrap();
    connection
        .execute(
            "UPDATE experiments SET payload_json=?1,sha256=?2",
            (&payload, crate::backups::checksum(&payload)),
        )
        .unwrap();
    drop(store);
    let mut store = Store::open(&temporary.0).unwrap();
    let loaded = store.load("repeated-test").unwrap();
    assert_eq!(loaded.schemaVersion, 1);
    assert!(loaded.plan.trafficBudget.is_none());
    let mut host = HostFixture::default();
    assert!(execute(&mut store, loaded.plan, &mut host, &AtomicBool::new(false)).is_err());
    assert_eq!(host.verifications, 0);
    let recovered = acknowledgeRecovery(&mut store, "repeated-test", &mut host).unwrap();
    assert_eq!(recovered.state, State::Interrupted);
    assert_eq!(recovered.schemaVersion, 1);
    assert!(store.pending().unwrap().is_empty());
    assert_eq!(host.originals, 0);
    assert_eq!(host.candidates, 0);
}

#[test]
fn legacyCompletedBracketsRemainReadableWithoutInventedTrafficAccounting() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let report = execute(
        &mut store,
        plan(),
        &mut HostFixture::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    let mut legacy = serde_json::to_value(&report.snapshot).unwrap();
    legacy["schemaVersion"] = serde_json::json!(1);
    legacy["plan"]
        .as_object_mut()
        .unwrap()
        .remove("trafficBudget");
    legacy.as_object_mut().unwrap().remove("reservedBlocks");
    let payload = serde_json::to_string(&legacy).unwrap();
    let connection = rusqlite::Connection::open(&temporary.0).unwrap();
    connection
        .execute(
            "UPDATE experiments SET payload_json=?1,sha256=?2",
            (&payload, crate::backups::checksum(&payload)),
        )
        .unwrap();
    drop(store);
    let reopened = Store::open(&temporary.0)
        .unwrap()
        .load("repeated-test")
        .unwrap();
    assert_eq!(reopened.state, State::Completed);
    assert_eq!(reopened.blocks.len(), 12);
    assert_eq!(reopened.reservedBlocks, 0);
    assert!(reopened.plan.trafficBudget.is_none());
    assert_eq!(serde_json::to_value(reopened).unwrap(), legacy);
}

#[test]
fn storeRejectsStaleWritersCorruptionAndForeignSchemas() {
    let temporary = Temporary::new();
    let mut store = Store::open(&temporary.0).unwrap();
    let mut first = store.begin(plan(), nowUnixMs().unwrap()).unwrap();
    let mut other = Store::open(&temporary.0).unwrap();
    let mut stale = other.load("repeated-test").unwrap();
    first.reservedBlocks = 1;
    stale.reservedBlocks = 1;
    persist(&mut store, &mut first, State::BaselineBefore).unwrap();
    persist(&mut store, &mut first, State::RecoveryRequired).unwrap();
    assert!(persist(&mut other, &mut stale, State::BaselineBefore).is_err());
    drop(other);
    drop(store);
    let connection = rusqlite::Connection::open(&temporary.0).unwrap();
    connection
        .execute("UPDATE experiments SET payload_json='{}'", [])
        .unwrap();
    drop(connection);
    assert!(Store::open(&temporary.0).is_err());
    let foreign = Temporary::new();
    let connection = rusqlite::Connection::open(&foreign.0).unwrap();
    connection
        .pragma_update(None, "application_id", 12345)
        .unwrap();
    connection.pragma_update(None, "user_version", 999).unwrap();
    assert!(Store::open(&foreign.0).is_err());
    assert_eq!(
        connection
            .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        999
    );
}
