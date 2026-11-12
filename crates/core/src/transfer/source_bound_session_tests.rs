use super::*;
use crate::{
    benchmark,
    config::Config,
    icmp::{EchoStatus, EchoTarget},
};
use session::{Phase, SessionPlan, SourceBindings, runSourceBoundSession};

struct RefusingRunner(std::sync::atomic::AtomicUsize);

#[cfg(windows)]
#[test]
fn invalidProgressPreparationOrSnapshotsPreserveRawFailureWithoutHttpFallback() {
    struct FaultRunner {
        preparation: bool,
        calls: std::sync::atomic::AtomicUsize,
    }
    impl session::BoundTransferRunner for FaultRunner {
        fn execution(&self) -> Option<session::TransferExecution> {
            Some(session::TransferExecution::RestrictedWorkerV2)
        }
        fn createProgress(&self) -> crate::AppResult<TransferProgress> {
            if self.preparation {
                Err("fixture progress preparation refused".into())
            } else {
                Ok(TransferProgress::default())
            }
        }
        fn snapshot(&self, _: &TransferProgress) -> crate::AppResult<session::ProgressSnapshot> {
            Ok(session::ProgressSnapshot {
                downloadBytesRead: u64::MAX,
                uploadBodyBytesProvided: 0,
                activeRequests: 1,
            })
        }
        fn measureFrom(
            &self,
            _: TransferPlan,
            _: SourceBinding,
            cancelled: &AtomicBool,
            _: &TransferProgress,
        ) -> crate::AppResult<TransferResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(2);
            while !cancelled.load(Ordering::SeqCst) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(1));
            }
            assert!(cancelled.load(Ordering::SeqCst));
            Err("fixture cancelled after invalid progress".into())
        }
    }
    for preparation in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let (plan, bindings) = scopedPlan(Provider::UserOwnedHttp {
            origin: format!("http://{}/", listener.local_addr().unwrap()),
        });
        let runner = FaultRunner {
            preparation,
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let run = session::runSourceBoundSessionWithRunner(
            Config::default(),
            plan,
            bindings,
            &AtomicBool::new(false),
            |_| {},
            &runner,
        )
        .unwrap();
        assert_eq!(run.status, "partialFailure");
        assert_eq!(run.transfers.len(), 1);
        assert!(matches!(
            run.transfers[0].interruptedProgress,
            Some(session::InterruptedProgress::Unavailable { .. })
        ));
        assert!(
            run.transfers[0]
                .error
                .as_ref()
                .unwrap()
                .contains(if preparation {
                    "preparation refused"
                } else {
                    "phase allowance"
                })
        );
        assert!(
            run.latencySamples
                .iter()
                .any(|sample| sample.phase == Phase::Idle)
        );
        assert!(
            run.latencySamples
                .iter()
                .any(|sample| sample.phase == Phase::Recovery)
        );
        assert_eq!(
            runner.calls.load(Ordering::SeqCst),
            usize::from(!preparation)
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

impl session::BoundTransferRunner for RefusingRunner {
    fn measureFrom(
        &self,
        _: TransferPlan,
        _: SourceBinding,
        _: &AtomicBool,
        _: &TransferProgress,
    ) -> crate::AppResult<TransferResult> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err("test delegated transfer refusal".into())
    }
}

#[test]
fn stoppedOrInvalidSessionsNeverInvokeTheDelegatedTransferRunner() {
    let runner = RefusingRunner(std::sync::atomic::AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let provider = Provider::UserOwnedHttp {
        origin: format!("http://{}/", listener.local_addr().unwrap()),
    };
    let (plan, bindings) = scopedPlan(provider);
    let run = session::runSourceBoundSessionWithRunner(
        Config::default(),
        plan.clone(),
        bindings.clone(),
        &AtomicBool::new(true),
        |_| {},
        &runner,
    )
    .unwrap();
    assert_eq!(run.status, "cancelled");
    assert!(run.transfers.is_empty() && run.latencySamples.is_empty());
    let mut invalid = bindings;
    invalid.transfers.clear();
    assert!(
        session::runSourceBoundSessionWithRunner(
            Config::default(),
            plan,
            invalid,
            &AtomicBool::new(false),
            |_| panic!("invalid scope produced progress"),
            &runner
        )
        .is_err()
    );
    assert_eq!(runner.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(windows)]
#[test]
fn aDelegatedTransferRefusalCannotFallBackToInProcessHttp() {
    let runner = RefusingRunner(std::sync::atomic::AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let provider = Provider::UserOwnedHttp {
        origin: format!("http://{}/", listener.local_addr().unwrap()),
    };
    let (plan, bindings) = scopedPlan(provider);
    let run = session::runSourceBoundSessionWithRunner(
        Config::default(),
        plan,
        bindings.clone(),
        &AtomicBool::new(false),
        |_| {},
        &runner,
    )
    .unwrap();
    assert_eq!(runner.0.load(Ordering::SeqCst), 1);
    assert_eq!(run.status, "partialFailure");
    assert!(run.transfers[0].interruptedProgress.is_none());
    assert!(
        serde_json::to_value(&run).unwrap()["transfers"][0]
            .get("interruptedProgress")
            .is_none()
    );
    assert_eq!(run.sourceBindings, Some(bindings));
    assert_eq!(run.transfers.len(), 1);
    assert!(run.transfers[0].result.is_none());
    assert!(
        run.transfers[0]
            .error
            .as_ref()
            .unwrap()
            .contains("delegated transfer refusal")
    );
    for phase in [Phase::Idle, Phase::Recovery] {
        assert!(
            run.latencySamples
                .iter()
                .any(|sample| sample.phase == phase)
        );
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(windows)]
struct RecordingRunner {
    mutation: u8,
    calls: std::sync::Mutex<Vec<(Direction, SourceBinding, u64)>>,
}

#[cfg(windows)]
impl session::BoundTransferRunner for RecordingRunner {
    fn measureFrom(
        &self,
        plan: TransferPlan,
        binding: SourceBinding,
        cancelled: &AtomicBool,
        progress: &TransferProgress,
    ) -> crate::AppResult<TransferResult> {
        self.calls
            .lock()
            .unwrap()
            .push((plan.direction, binding, plan.bytes));
        let mut result = crate::transfer::measureFrom(plan, binding, cancelled, progress)?;
        match self.mutation {
            1 => result.plan.bytes += 1,
            2 => result.sourceBinding.as_mut().unwrap().peer.set_port(
                if binding.peer.port() == u16::MAX {
                    u16::MAX - 1
                } else {
                    binding.peer.port() + 1
                },
            ),
            3 => result.provider.protocol = "unexpected protocol".into(),
            _ => {}
        }
        Ok(result)
    }
}

#[cfg(windows)]
#[test]
fn delegatedTransfersKeepBothDirectionsAndRejectChangedResultIdentities() {
    for mutation in 0..4 {
        let (provider, worker) = fixture(Behavior::Normal, if mutation == 0 { 2 } else { 1 });
        let (plan, bindings) = scopedPlan(provider);
        let runner = RecordingRunner {
            mutation,
            calls: std::sync::Mutex::new(Vec::new()),
        };
        let run = session::runSourceBoundSessionWithRunner(
            Config::default(),
            plan,
            bindings.clone(),
            &AtomicBool::new(false),
            |_| {},
            &runner,
        )
        .unwrap();
        worker.join().unwrap();
        let calls = runner.calls.lock().unwrap();
        if mutation == 0 {
            assert_eq!(
                *calls,
                vec![
                    (Direction::Download, bindings.transfers[0], 4096),
                    (Direction::Upload, bindings.transfers[0], 4096)
                ]
            );
            assert_eq!(run.status, "completed");
            assert!(
                run.transfers
                    .iter()
                    .all(|phase| phase.result.as_ref().unwrap().sourceBinding
                        == Some(bindings.transfers[0]))
            );
        } else {
            assert_eq!(calls.len(), 1);
            assert_eq!(run.status, "partialFailure");
            assert_eq!(run.transfers.len(), 1);
            assert!(run.transfers[0].result.is_none());
            assert!(
                run.transfers[0]
                    .error
                    .as_ref()
                    .unwrap()
                    .contains("different plan, provider, source, or peer")
            );
        }
        assert_eq!(run.sourceBindings, Some(bindings));
    }
}

fn scopedPlan(provider: Provider) -> (SessionPlan, SourceBindings) {
    let origin = reqwest::Url::parse(&provider.info().unwrap().origin).unwrap();
    let peer = format!("{}:{}", origin.host_str().unwrap(), origin.port().unwrap())
        .parse::<std::net::SocketAddr>()
        .unwrap();
    let endpoints: Vec<_> = ["127.0.0.1", "::1"]
        .into_iter()
        .enumerate()
        .map(|(index, address)| benchmark::Endpoint {
            id: format!("echo-{index}"),
            address: address.into(),
            protocol: benchmark::ProbeProtocol::IcmpEcho,
            dnsQuery: None,
        })
        .collect();
    let bindings = SourceBindings {
        transfers: vec![SourceBinding {
            source: peer.ip(),
            peer,
        }],
        latency: endpoints
            .iter()
            .map(|endpoint| benchmark::SourceBinding {
                endpointId: endpoint.id.clone(),
                source: EchoTarget::parse(&endpoint.address).unwrap(),
            })
            .collect(),
    };
    (
        SessionPlan {
            providers: vec![provider],
            downloadBytesPerProvider: 4096,
            uploadBytesPerProvider: 4096,
            streams: 1,
            phaseTimeoutMs: 2000,
            idleRounds: 3,
            intervalMs: 250,
            probeTimeoutMs: 100,
            latencyEndpoints: endpoints,
        },
        bindings,
    )
}

#[cfg(windows)]
#[test]
fn completeLoadSessionsBindTransfersAndEveryLatencyPhaseAndPersistTheirCohort() {
    let (provider, worker) = fixture(Behavior::Slow, 2);
    let (plan, bindings) = scopedPlan(provider);
    let mut run = runSourceBoundSession(
        Config::default(),
        plan,
        bindings.clone(),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    worker.join().unwrap();
    assert_eq!(run.status, "completed");
    assert_eq!(run.sourceBindings, Some(bindings.clone()));
    assert_eq!(run.transfers.len(), 2);
    for phase in &run.transfers {
        let transfer = phase.result.as_ref().unwrap();
        assert_eq!(transfer.sourceBinding, Some(bindings.transfers[0]));
        assert_eq!(transfer.status, TransferStatus::Completed);
        assert_eq!(transfer.acceptedPayloadBytes, 4096);
    }
    for phase in [Phase::Idle, Phase::Download, Phase::Upload, Phase::Recovery] {
        let samples: Vec<_> = run
            .latencySamples
            .iter()
            .filter(|sample| sample.phase == phase)
            .collect();
        assert!(!samples.is_empty(), "missing {phase:?} probes");
        assert!(
            samples
                .iter()
                .all(|sample| sample.sample.echo.as_ref().unwrap().status == EchoStatus::Reply)
        );
    }
    assert!(run.latencySamples.iter().any(|sample| matches!(
        sample.phase,
        Phase::Download | Phase::Upload
    ) && sample.inFlightRequestsAtStart > 0
        && sample.inFlightRequestsAtEnd > 0));
    let mut database = crate::storage::openDatabase(std::path::Path::new(":memory:")).unwrap();
    crate::storage::saveLoadSession(&mut database, &mut run).unwrap();
    let saved = crate::storage::loadSessionHistory(&database, 1)
        .unwrap()
        .remove(0);
    assert_eq!(saved.sourceBindings, Some(bindings));
    assert_eq!(
        serde_json::to_value(saved).unwrap(),
        serde_json::to_value(run).unwrap()
    );
}

#[cfg(windows)]
#[test]
fn unavailableLatencySourceNeverTurnsIntoSuccessfulDefaultRouteProbes() {
    let (provider, worker) = fixture(Behavior::Normal, 2);
    let (plan, mut bindings) = scopedPlan(provider);
    bindings.latency[0].source = EchoTarget::parse("192.0.2.254").unwrap();
    let run = runSourceBoundSession(
        Config::default(),
        plan,
        bindings,
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    worker.join().unwrap();
    assert_eq!(run.status, "completed");
    let samples: Vec<_> = run
        .latencySamples
        .iter()
        .filter(|sample| sample.sample.endpointId == "echo-0")
        .collect();
    assert!(!samples.is_empty());
    assert!(samples.iter().all(|sample| {
        let echo = sample.sample.echo.as_ref().unwrap();
        echo.status != EchoStatus::Reply && echo.rttMs.is_none() && sample.sample.error.is_some()
    }));
    assert!(
        run.latencySamples
            .iter()
            .any(|sample| sample.sample.endpointId == "echo-1"
                && sample.sample.echo.as_ref().unwrap().status == EchoStatus::Reply)
    );
    for summary in run
        .latencySummaries
        .iter()
        .filter(|summary| matches!(summary.phase, Phase::Idle | Phase::Recovery))
    {
        assert!(summary.results[0].summary.p95Ms.is_none());
        assert!(summary.results[0].summary.echoTimeoutPercent.is_none());
    }
}

#[test]
fn incompleteReorderedAndNonEchoLoadBindingsAreRejectedBeforeProgressOrTraffic() {
    let provider = Provider::UserOwnedHttp {
        origin: "http://127.0.0.1:43210/".into(),
    };
    let (plan, bindings) = scopedPlan(provider);
    for failure in 0..6 {
        let mut plan = plan.clone();
        let mut bindings = bindings.clone();
        match failure {
            0 => bindings.transfers.clear(),
            1 => {
                bindings.latency.pop();
            }
            2 => bindings.latency.reverse(),
            3 => bindings.latency[0].endpointId = "different".into(),
            4 => bindings.latency[0].source = EchoTarget::parse("::1").unwrap(),
            _ => {
                for endpoint in &mut plan.latencyEndpoints {
                    endpoint.protocol = benchmark::ProbeProtocol::TcpConnect;
                    endpoint.address = if endpoint.id == "echo-0" {
                        "127.0.0.1:43210"
                    } else {
                        "[::1]:43210"
                    }
                    .into();
                }
            }
        }
        assert!(
            runSourceBoundSession(
                Config::default(),
                plan,
                bindings,
                &AtomicBool::new(true),
                |_| panic!("invalid scope reported progress")
            )
            .is_err(),
            "failure {failure}"
        );
    }
    let mut two = plan;
    two.providers.push(Provider::UserOwnedHttp {
        origin: "http://127.0.0.1:43211/".into(),
    });
    let mut bindings = bindings;
    bindings.transfers.push(SourceBinding {
        source: "127.0.0.1".parse().unwrap(),
        peer: "127.0.0.1:43211".parse().unwrap(),
    });
    bindings.validate(&two).unwrap();
    bindings.transfers.reverse();
    assert!(bindings.validate(&two).is_err());
}

#[test]
fn cancelledBoundSessionsPreserveScopeWithoutStartingAnyRequest() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let provider = Provider::UserOwnedHttp {
        origin: format!("http://{}/", listener.local_addr().unwrap()),
    };
    let (plan, bindings) = scopedPlan(provider);
    let run = runSourceBoundSession(
        Config::default(),
        plan,
        bindings.clone(),
        &AtomicBool::new(true),
        |_| {},
    )
    .unwrap();
    assert_eq!(run.status, "cancelled");
    assert!(run.transfers.is_empty());
    assert!(run.latencySamples.is_empty());
    assert_eq!(run.sourceBindings, Some(bindings));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[cfg(windows)]
#[test]
fn actualSavedBoundSessionsAdmitQuietMetricsAndRefuseInsufficientLoadedSamples() {
    use crate::comparison::{
        self,
        load::{Selection, Statistic},
    };
    let (provider, worker) = fixture(Behavior::Slow, 2);
    let (mut plan, bindings) = scopedPlan(provider);
    plan.idleRounds = 12;
    let mut run = runSourceBoundSession(
        Config::default(),
        plan,
        bindings,
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap();
    worker.join().unwrap();
    assert_eq!(run.status, "completed");
    let mut database = crate::storage::openDatabase(std::path::Path::new(":memory:")).unwrap();
    crate::storage::saveLoadSession(&mut database, &mut run).unwrap();
    let mut selections = vec![
        Selection {
            metricId: "download".into(),
            providerIndex: 0,
            statistic: Statistic::GoodputMbps {
                direction: Direction::Download,
            },
        },
        Selection {
            metricId: "upload".into(),
            providerIndex: 0,
            statistic: Statistic::GoodputMbps {
                direction: Direction::Upload,
            },
        },
        Selection {
            metricId: "idle-p95".into(),
            providerIndex: 0,
            statistic: Statistic::P95Ms {
                phase: Phase::Idle,
                endpointId: "echo-0".into(),
            },
        },
        Selection {
            metricId: "recovery-failures".into(),
            providerIndex: 0,
            statistic: Statistic::FailurePercent {
                phase: Phase::Recovery,
                endpointId: "echo-0".into(),
            },
        },
    ];
    let threshold = |absolute| comparison::Threshold {
        absolute,
        relativeFraction: 0.0,
    };
    let mut comparison = comparison::Plan {
        maximumBlockDurationMs: 120_000,
        cohortSha256: comparison::load::cohortSha256(&run, &selections).unwrap(),
        environmentSha256: "b".repeat(64),
        originalConfigurationSha256: "c".repeat(64),
        candidateConfigurationSha256: "d".repeat(64),
        metrics: selections
            .iter()
            .enumerate()
            .map(|(index, selection)| comparison::MetricRule {
                id: selection.metricId.clone(),
                unit: if index < 2 {
                    comparison::Unit::MegabitsPerSecond
                } else if index == 2 {
                    comparison::Unit::Milliseconds
                } else {
                    comparison::Unit::Percent
                },
                direction: if index < 2 {
                    comparison::Direction::HigherIsBetter
                } else {
                    comparison::Direction::LowerIsBetter
                },
                role: if index == 2 {
                    comparison::Role::Objective
                } else {
                    comparison::Role::Guard
                },
                resolution: if index == 3 { 100.0 / 12.0 } else { 1.0 },
                minimumImprovement: threshold(10.0),
                maximumRegression: threshold(1.0),
                maximumBaselineDrift: threshold(5.0),
            })
            .collect(),
    };
    let context = || comparison::baseline::Context {
        environmentSha256: &comparison.environmentSha256,
        configurationSha256: &comparison.originalConfigurationSha256,
    };
    let measured = comparison::load::fromRun(&run, &selections, &comparison, context()).unwrap();
    assert_eq!(
        measured.values[0],
        run.transfers[0]
            .result
            .as_ref()
            .unwrap()
            .applicationGoodputMbps
            .unwrap()
    );
    assert_eq!(
        measured.values[1],
        run.transfers[1]
            .result
            .as_ref()
            .unwrap()
            .applicationGoodputMbps
            .unwrap()
    );
    assert_eq!(measured.values[3], 0.0);
    selections[2].statistic = Statistic::P95Ms {
        phase: Phase::Download,
        endpointId: "echo-0".into(),
    };
    comparison.cohortSha256 = comparison::load::cohortSha256(&run, &selections).unwrap();
    let error = comparison::load::fromRun(
        &run,
        &selections,
        &comparison,
        comparison::baseline::Context {
            environmentSha256: &comparison.environmentSha256,
            configurationSha256: &comparison.originalConfigurationSha256,
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("twelve qualifying"));
}
