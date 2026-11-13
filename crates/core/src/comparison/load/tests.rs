use super::*;
use crate::{
    benchmark::{self, ProbeProtocol},
    config::Config,
    icmp::{EchoOutcome, EchoStatus, EchoTarget},
    transfer::{
        Provider, StreamResult, TransferPlan, TransferResult,
        session::{PhaseResult, SessionPlan, SourceBindings},
    },
};

fn time(offset: u64) -> String {
    chrono::DateTime::from_timestamp_millis(1_793_600_000_000 + offset as i64)
        .unwrap()
        .to_rfc3339()
}

fn fixture() -> (SessionRun, Vec<Selection>, Plan) {
    let provider = Provider::UserOwnedHttp {
        origin: "https://owned-benchmark.example/".into(),
    };
    let binding = transfer::SourceBinding {
        source: "192.0.2.2".parse().unwrap(),
        peer: "192.0.2.10:443".parse().unwrap(),
    };
    let endpoints: Vec<_> = ["192.0.2.20", "198.51.100.20"]
        .into_iter()
        .enumerate()
        .map(|(index, address)| benchmark::Endpoint {
            id: format!("endpoint-{index}"),
            address: address.into(),
            protocol: ProbeProtocol::IcmpEcho,
            dnsQuery: None,
        })
        .collect();
    let plan = SessionPlan {
        providers: vec![provider.clone()],
        downloadBytesPerProvider: 8192,
        uploadBytesPerProvider: 8192,
        streams: 2,
        phaseTimeoutMs: 10_000,
        idleRounds: 12,
        intervalMs: 250,
        probeTimeoutMs: 100,
        latencyEndpoints: endpoints.clone(),
    };
    let bindings = SourceBindings {
        transfers: vec![binding],
        latency: endpoints
            .iter()
            .map(|endpoint| benchmark::SourceBinding {
                endpointId: endpoint.id.clone(),
                source: EchoTarget::parse("192.0.2.2").unwrap(),
            })
            .collect(),
    };
    let transfers = [
        (Phase::Download, transfer::Direction::Download, 7000),
        (Phase::Upload, transfer::Direction::Upload, 14500),
    ]
    .into_iter()
    .map(|(phase, direction, start)| PhaseResult {
        interruptedProgress: None,
        providerIndex: 0,
        phase,
        error: None,
        result: Some(TransferResult {
            plan: TransferPlan {
                provider: provider.clone(),
                direction,
                bytes: 8192,
                streams: 2,
                timeoutMs: 10_000,
            },
            provider: provider.info().unwrap(),
            startedAt: time(start),
            finishedAt: time(start + 7000),
            elapsedMs: 7000.0,
            status: TransferStatus::Completed,
            acceptedPayloadBytes: 8192,
            applicationGoodputMbps: Some(999_999.0),
            sourceBinding: Some(binding),
            streams: (0..2)
                .map(|ordinal| StreamResult {
                    ordinal,
                    requestedBytes: 4096,
                    downloadBytesRead: if direction == transfer::Direction::Download {
                        4096
                    } else {
                        0
                    },
                    uploadBodyBytesProvided: if direction == transfer::Direction::Upload {
                        4096
                    } else {
                        0
                    },
                    acceptedPayloadBytes: 4096,
                    elapsedMs: 6800.0,
                    status: TransferStatus::Completed,
                    httpStatus: Some(200),
                    remoteAddress: Some(binding.peer.to_string()),
                    retryAfter: None,
                    error: None,
                })
                .collect(),
        }),
    })
    .collect();
    let mut latencySamples = Vec::new();
    for (phase, start, rtt) in [
        (Phase::Idle, 1000, 10),
        (Phase::Download, 7250, 20),
        (Phase::Upload, 14750, 30),
        (Phase::Recovery, 22000, 12),
    ] {
        let loaded = matches!(phase, Phase::Download | Phase::Upload);
        for round in 0..12 {
            for (index, endpoint) in endpoints.iter().enumerate() {
                latencySamples.push(LatencySample {
                    providerIndex: 0,
                    phase,
                    sample: benchmark::Sample {
                        endpointId: endpoint.id.clone(),
                        address: endpoint.address.clone(),
                        timestamp: time(start + (round * 2 + index as u64) * 250),
                        connectMs: None,
                        error: None,
                        dns: None,
                        echo: Some(EchoOutcome {
                            status: EchoStatus::Reply,
                            rttMs: Some(rtt + index as u32),
                            rttUnitMs: 1,
                            callDurationMs: f64::from(rtt + index as u32),
                            responder: Some(endpoint.address.parse().unwrap()),
                            responderScopeId: None,
                            nativeCode: Some(0),
                        }),
                    },
                    inFlightRequestsAtStart: u64::from(loaded),
                    inFlightRequestsAtEnd: u64::from(loaded),
                    payloadProgressDuringProbe: if loaded { 256 } else { 0 },
                });
            }
        }
    }
    let run = SessionRun {
        transferExecution: None,
        id: 42,
        startedAt: time(0),
        finishedAt: time(28000),
        appVersion: "0.1.0".into(),
        status: "completed".into(),
        config: Config {
            sessionMinutes: 2,
            ..Config::default()
        },
        plan,
        transfers,
        latencySamples,
        latencySummaries: Vec::new(),
        sourceBindings: Some(bindings),
    };
    let selections = vec![
        Selection {
            metricId: "download".into(),
            providerIndex: 0,
            statistic: Statistic::GoodputMbps {
                direction: transfer::Direction::Download,
            },
        },
        Selection {
            metricId: "upload".into(),
            providerIndex: 0,
            statistic: Statistic::GoodputMbps {
                direction: transfer::Direction::Upload,
            },
        },
        Selection {
            metricId: "loaded-p95".into(),
            providerIndex: 0,
            statistic: Statistic::P95Ms {
                phase: Phase::Download,
                endpointId: "endpoint-0".into(),
            },
        },
        Selection {
            metricId: "loaded-failures".into(),
            providerIndex: 0,
            statistic: Statistic::FailurePercent {
                phase: Phase::Download,
                endpointId: "endpoint-0".into(),
            },
        },
    ];
    let mut plan = super::super::tests::plan();
    plan.maximumBlockDurationMs = 120_000;
    plan.cohortSha256 = cohortSha256(&run, &selections).unwrap();
    plan.metrics = selections
        .iter()
        .enumerate()
        .map(|(index, selection)| {
            let mut rule = super::super::tests::plan().metrics[0].clone();
            rule.id = selection.metricId.clone();
            rule.role = if index == 2 {
                Role::Objective
            } else {
                Role::Guard
            };
            rule.unit = if index < 2 {
                Unit::MegabitsPerSecond
            } else if index == 2 {
                Unit::Milliseconds
            } else {
                Unit::Percent
            };
            rule.direction = if index < 2 {
                Direction::HigherIsBetter
            } else {
                Direction::LowerIsBetter
            };
            rule.resolution = if index == 3 { 100.0 / 12.0 } else { 1.0 };
            rule.minimumImprovement.absolute =
                rule.minimumImprovement.absolute.max(rule.resolution);
            rule
        })
        .collect();
    plan.validate().unwrap();
    convert(&run, &selections, &plan).unwrap();
    (run, selections, plan)
}

fn convert(run: &SessionRun, selections: &[Selection], plan: &Plan) -> AppResult<Session> {
    fromRun(
        run,
        selections,
        plan,
        Context {
            environmentSha256: &plan.environmentSha256,
            configurationSha256: &plan.originalConfigurationSha256,
        },
    )
}

#[test]
fn fourPhaseSafetySelectionsCoverEveryEndpointAndProduceRawValues() {
    let (run, _, mut plan) = fixture();
    let selections = requiredSafetySelections(&run.config, &run.plan).unwrap();
    assert_eq!(selections.len(), 50);
    validateSafetyCoverage(&run.config, &run.plan, &selections).unwrap();
    let original = plan.metrics.clone();
    plan.metrics = selections.iter().map(|selection| {
        let source = match selection.statistic {
            Statistic::GoodputMbps { .. } => 0,
            Statistic::FailurePercent { .. } => 3,
            _ => 2,
        };
        let mut rule = original[source].clone();
        rule.id = selection.metricId.clone();
        rule.role = if matches!(&selection.statistic, Statistic::P95Ms { phase: Phase::Download, endpointId } if endpointId == "endpoint-0") { Role::Objective } else { Role::Guard };
        rule
    }).collect();
    plan.cohortSha256 = cohortSha256(&run, &selections).unwrap();
    let values = convert(&run, &selections, &plan).unwrap().values;
    assert_eq!(values.len(), 50);
    for (selection, value) in selections.iter().zip(values) {
        if matches!(
            selection.statistic,
            Statistic::FailurePercent { .. }
                | Statistic::IqrMs { .. }
                | Statistic::SuccessiveVariationMs { .. }
        ) {
            assert_eq!(value, 0.0);
        } else {
            assert!(value > 0.0);
        }
    }
    for failure in 0..6 {
        let mut changed = selections.clone();
        match failure {
            0 => {
                changed.pop();
            }
            1 => changed[49].statistic = changed[48].statistic.clone(),
            2 => changed[49].providerIndex = 1,
            3 => {
                changed[49].statistic = Statistic::FailurePercent {
                    phase: Phase::Download,
                    endpointId: "endpoint-1".into(),
                }
            }
            4 => {
                changed[49].statistic = Statistic::FailurePercent {
                    phase: Phase::Recovery,
                    endpointId: "endpoint-0".into(),
                }
            }
            _ => changed.push(changed[49].clone()),
        }
        assert!(
            validateSafetyCoverage(&run.config, &run.plan, &changed).is_err(),
            "{failure}"
        );
    }
    let mut renamed = selections;
    for (index, selection) in renamed.iter_mut().enumerate() {
        selection.metricId = format!("reviewed-{index}");
    }
    validateSafetyCoverage(&run.config, &run.plan, &renamed).unwrap();
    assert_ne!(cohortSha256(&run, &renamed).unwrap(), plan.cohortSha256);
}

#[test]
fn oversizedSafetyCohortsAreRefusedWithoutDroppingServers() {
    let (mut run, _, _) = fixture();
    run.plan.providers.push(Provider::UserOwnedHttp {
        origin: "https://second-owned.example/".into(),
    });
    let error = requiredSafetySelections(&run.config, &run.plan).unwrap_err();
    assert!(error.to_string().contains("100 metrics"));
    assert_eq!(run.plan.providers.len(), 2);
    assert_eq!(run.plan.latencyEndpoints.len(), 2);
    run.plan.providers.pop();
    let selections = requiredSafetySelections(&run.config, &run.plan).unwrap();
    assert_eq!(selections.len(), 50);
    assert_eq!(run.plan.latencyEndpoints.len(), 2);
    run.plan.latencyEndpoints.truncate(1);
    assert!(requiredSafetySelections(&run.config, &run.plan).is_err());
}

#[test]
fn primaryObjectivesFollowTheFrozenProfileWithoutRemovingSafetyRules() {
    for profile in [Profile::Latency, Profile::Balanced, Profile::Download] {
        for objective in 0..4 {
            let (mut run, selections, mut plan) = fixture();
            run.config.profile = profile;
            plan.cohortSha256 = cohortSha256(&run, &selections).unwrap();
            for rule in &mut plan.metrics {
                rule.role = Role::Guard;
            }
            match objective {
                0 => plan.metrics[2].role = Role::Objective,
                1 => plan.metrics[0].role = Role::Objective,
                2 => {
                    plan.metrics[0].role = Role::Objective;
                    plan.metrics[2].role = Role::Objective;
                }
                _ => plan.metrics[3].role = Role::Objective,
            }
            let expected = match profile {
                Profile::Latency => objective == 0,
                Profile::Balanced => objective != 3,
                Profile::Download => objective == 1,
            };
            assert_eq!(
                validateProfileObjectives(profile, &selections, &plan).is_ok(),
                expected,
                "{profile:?}, {objective}"
            );
            assert_eq!(
                convert(&run, &selections, &plan).is_ok(),
                expected,
                "{profile:?}, {objective}"
            );
        }
    }
}

#[test]
fn latencyObjectiveKindsAreAcceptedForLatencyAndGuardedForDownload() {
    for statistic in [
        Statistic::MedianMs {
            phase: Phase::Download,
            endpointId: "endpoint-0".into(),
        },
        Statistic::P95Ms {
            phase: Phase::Download,
            endpointId: "endpoint-0".into(),
        },
        Statistic::P99Ms {
            phase: Phase::Download,
            endpointId: "endpoint-0".into(),
        },
        Statistic::IqrMs {
            phase: Phase::Download,
            endpointId: "endpoint-0".into(),
        },
        Statistic::SuccessiveVariationMs {
            phase: Phase::Download,
            endpointId: "endpoint-0".into(),
        },
    ] {
        let (run, mut selections, mut plan) = fixture();
        selections[2].statistic = statistic;
        plan.cohortSha256 = cohortSha256(&run, &selections).unwrap();
        assert!(validateProfileObjectives(Profile::Latency, &selections, &plan).is_ok());
        assert!(validateProfileObjectives(Profile::Balanced, &selections, &plan).is_ok());
        assert!(validateProfileObjectives(Profile::Download, &selections, &plan).is_err());
        plan.metrics[2].role = Role::Guard;
        plan.metrics[0].role = Role::Objective;
        assert!(validateProfileObjectives(Profile::Download, &selections, &plan).is_ok());
        plan.metrics[0].role = Role::Guard;
        assert!(validateProfileObjectives(Profile::Download, &selections, &plan).is_err());
    }
    let (_, selections, mut plan) = fixture();
    assert!(validateProfileObjectives(Profile::Balanced, &selections[..3], &plan).is_err());
    plan.metrics[2].id = "changed-order".into();
    assert!(validateProfileObjectives(Profile::Balanced, &selections, &plan).is_err());
}

#[test]
fn loadValuesAreRecomputedFromRawStreamsAndQualifyingEchoes() {
    let (run, selections, plan) = fixture();
    let session = convert(&run, &selections, &plan).unwrap();
    assert_eq!(session.id, "load:42");
    assert_eq!(
        session.values,
        vec![
            8192.0 * 8.0 / 7_000_000.0,
            8192.0 * 8.0 / 7_000_000.0,
            20.0,
            0.0
        ]
    );
    assert_eq!(session.cohortSha256, plan.cohortSha256);
    assert!(session.completed);
}

fn quantileFixture(phase: Phase, tail: bool) -> (SessionRun, Vec<Selection>, Plan) {
    let (mut run, mut selections, mut plan) = fixture();
    for (round, sample) in run
        .latencySamples
        .iter_mut()
        .filter(|sample| sample.phase == phase && sample.sample.endpointId == "endpoint-0")
        .enumerate()
    {
        let rtt = if round == 11 { 100 } else { round as u32 };
        let echo = sample.sample.echo.as_mut().unwrap();
        echo.rttMs = Some(rtt);
        echo.callDurationMs = f64::from(rtt);
    }
    selections[2].statistic = if tail {
        Statistic::P99Ms {
            phase,
            endpointId: "endpoint-0".into(),
        }
    } else {
        Statistic::MedianMs {
            phase,
            endpointId: "endpoint-0".into(),
        }
    };
    plan.cohortSha256 = cohortSha256(&run, &selections).unwrap();
    (run, selections, plan)
}

#[test]
fn medianAndP99UseRawRepliesInEveryPhaseAndHaveSeparateCohorts() {
    for phase in [Phase::Idle, Phase::Download, Phase::Upload, Phase::Recovery] {
        let (run, median, medianPlan) = quantileFixture(phase, false);
        let (_, tail, tailPlan) = quantileFixture(phase, true);
        assert!((convert(&run, &median, &medianPlan).unwrap().values[2] - 5.5).abs() < 1e-9);
        assert!((convert(&run, &tail, &tailPlan).unwrap().values[2] - 90.1).abs() < 1e-9);
        assert_ne!(medianPlan.cohortSha256, tailPlan.cohortSha256);
        assert!(convert(&run, &median, &tailPlan).is_err());
        assert!(convert(&run, &tail, &medianPlan).is_err());
        for (selections, plan) in [(median, medianPlan), (tail, tailPlan)] {
            let restored: Vec<Selection> =
                serde_json::from_str(&serde_json::to_string(&selections).unwrap()).unwrap();
            assert_eq!(cohortSha256(&run, &restored).unwrap(), plan.cohortSha256);
            assert!(convert(&run, &restored, &plan).is_ok());
            let mut changed = selections;
            let endpointId = match &mut changed[2].statistic {
                Statistic::MedianMs { endpointId, .. } | Statistic::P99Ms { endpointId, .. } => {
                    endpointId
                }
                _ => unreachable!(),
            };
            *endpointId = "unknown-endpoint".into();
            assert!(cohortSha256(&run, &changed).is_err());
        }
    }
}

#[test]
fn quantilesRefuseTooFewRepliesPartialOverlapAndIncompatibleRules() {
    for tail in [false, true] {
        for failure in 0..7 {
            let (mut run, selections, mut plan) = quantileFixture(Phase::Download, tail);
            match failure {
                0 => plan.metrics[2].resolution = 0.1,
                1 => plan.metrics[2].unit = Unit::Count,
                2 => plan.metrics[2].direction = Direction::HigherIsBetter,
                3 => {
                    let sample = run
                        .latencySamples
                        .iter_mut()
                        .find(|sample| {
                            sample.phase == Phase::Download
                                && sample.sample.endpointId == "endpoint-0"
                        })
                        .unwrap();
                    let echo = sample.sample.echo.as_mut().unwrap();
                    echo.status = EchoStatus::TimedOut;
                    echo.rttMs = None;
                    echo.nativeCode = Some(11010);
                    echo.responder = None;
                    sample.sample.error = Some("timeout".into());
                }
                4 => {
                    let sample = run
                        .latencySamples
                        .iter_mut()
                        .find(|sample| {
                            sample.phase == Phase::Download
                                && sample.sample.endpointId == "endpoint-0"
                        })
                        .unwrap();
                    sample.inFlightRequestsAtEnd = 0;
                }
                5 => {
                    let sample = run
                        .latencySamples
                        .iter_mut()
                        .find(|sample| {
                            sample.phase == Phase::Download
                                && sample.sample.endpointId == "endpoint-0"
                        })
                        .unwrap();
                    sample.sample.echo.as_mut().unwrap().rttUnitMs = 0;
                }
                _ => plan.metrics[2].id = "different-metric".into(),
            }
            assert!(
                convert(&run, &selections, &plan).is_err(),
                "tail={tail}, failure={failure}"
            );
        }
    }
}

fn variationFixture(phase: Phase, successive: bool) -> (SessionRun, Vec<Selection>, Plan) {
    let (mut run, mut selections, mut plan) = fixture();
    for (round, sample) in run
        .latencySamples
        .iter_mut()
        .filter(|sample| sample.phase == phase && sample.sample.endpointId == "endpoint-0")
        .enumerate()
    {
        let value = if round % 2 == 0 { 10 } else { 20 };
        sample.sample.echo.as_mut().unwrap().rttMs = Some(value);
        sample.sample.echo.as_mut().unwrap().callDurationMs = f64::from(value);
    }
    selections[2].statistic = if successive {
        Statistic::SuccessiveVariationMs {
            phase,
            endpointId: "endpoint-0".into(),
        }
    } else {
        Statistic::IqrMs {
            phase,
            endpointId: "endpoint-0".into(),
        }
    };
    plan.cohortSha256 = cohortSha256(&run, &selections).unwrap();
    plan.validate().unwrap();
    (run, selections, plan)
}

#[test]
fn rawRttSpreadAndSuccessiveVariationWorkAcrossAllFourPhases() {
    for phase in [Phase::Idle, Phase::Download, Phase::Upload, Phase::Recovery] {
        for successive in [false, true] {
            let (run, selections, plan) = variationFixture(phase, successive);
            assert_eq!(convert(&run, &selections, &plan).unwrap().values[2], 10.0);
            let roundTrip: Vec<Selection> =
                serde_json::from_str(&serde_json::to_string(&selections).unwrap()).unwrap();
            assert_eq!(cohortSha256(&run, &roundTrip).unwrap(), plan.cohortSha256);
            let mut tooPrecise = plan.clone();
            tooPrecise.metrics[2].resolution = 0.1;
            assert!(convert(&run, &selections, &tooPrecise).is_err());
        }
    }
    let (run, iqr, iqrPlan) = variationFixture(Phase::Download, false);
    let (_, successive, successivePlan) = variationFixture(Phase::Download, true);
    assert_ne!(iqrPlan.cohortSha256, successivePlan.cohortSha256);
    assert!(convert(&run, &iqr, &successivePlan).is_err());
    assert!(convert(&run, &successive, &iqrPlan).is_err());
}

#[test]
fn responseVariationNeverInventsValuesFromInsufficientSuccessfulReplies() {
    for successive in [false, true] {
        let (mut run, selections, plan) = variationFixture(Phase::Download, successive);
        let sample = run
            .latencySamples
            .iter_mut()
            .find(|sample| {
                sample.phase == Phase::Download && sample.sample.endpointId == "endpoint-0"
            })
            .unwrap();
        let echo = sample.sample.echo.as_mut().unwrap();
        echo.status = EchoStatus::TimedOut;
        echo.rttMs = None;
        echo.nativeCode = Some(11010);
        echo.responder = None;
        sample.sample.error = Some("timeout".into());
        assert!(convert(&run, &selections, &plan).is_err());
    }
}

fn insertUnqualifiedGap(run: &mut SessionRun) {
    let index = run
        .latencySamples
        .iter()
        .position(|sample| {
            sample.phase == Phase::Download && sample.sample.timestamp == time(10250)
        })
        .unwrap();
    let mut gap = run.latencySamples[index].clone();
    gap.sample.timestamp = time(10125);
    gap.inFlightRequestsAtStart = 0;
    gap.inFlightRequestsAtEnd = 0;
    gap.payloadProgressDuringProbe = 0;
    gap.sample.echo.as_mut().unwrap().rttMs = Some(90);
    gap.sample.echo.as_mut().unwrap().callDurationMs = 90.0;
    run.latencySamples.insert(index, gap);
}

#[test]
fn unqualifiedLoadedProbesBreakSuccessiveReplyPairsInsteadOfDisappearing() {
    let (mut run, selections, plan) = variationFixture(Phase::Download, true);
    insertUnqualifiedGap(&mut run);
    let error = convert(&run, &selections, &plan).unwrap_err().to_string();
    assert!(error.contains("eleven adjacent"), "{error}");
    let (mut iqrRun, iqrSelections, iqrPlan) = variationFixture(Phase::Download, false);
    insertUnqualifiedGap(&mut iqrRun);
    assert_eq!(
        convert(&iqrRun, &iqrSelections, &iqrPlan).unwrap().values[2],
        10.0
    );
}

#[test]
fn sufficientlySampledVariationExcludesUnqualifiedGapsAndTimeoutPairs() {
    for timedOut in [false, true] {
        let (mut run, selections, plan) = variationFixture(Phase::Download, true);
        insertUnqualifiedGap(&mut run);
        let gap = run
            .latencySamples
            .iter_mut()
            .find(|sample| sample.sample.timestamp == time(10125))
            .unwrap();
        if timedOut {
            gap.inFlightRequestsAtStart = 1;
            gap.inFlightRequestsAtEnd = 1;
            let echo = gap.sample.echo.as_mut().unwrap();
            echo.status = EchoStatus::TimedOut;
            echo.rttMs = None;
            echo.nativeCode = Some(11010);
            echo.responder = None;
            gap.sample.error = Some("timeout".into());
        }
        let firstUpload = run
            .latencySamples
            .iter()
            .position(|sample| sample.phase == Phase::Upload)
            .unwrap();
        let mut added = run.latencySamples[firstUpload - 2].clone();
        for (index, at) in [13250, 13750].into_iter().enumerate() {
            added.sample.timestamp = time(at);
            added.sample.echo.as_mut().unwrap().rttMs = Some(100);
            added.sample.echo.as_mut().unwrap().callDurationMs = 100.0;
            run.latencySamples
                .insert(firstUpload + index, added.clone());
        }
        assert_eq!(convert(&run, &selections, &plan).unwrap().values[2], 15.0);
    }
}

#[test]
fn changedSourcesPeersPayloadsAndMetricSelectionsCannotShareACohort() {
    let (run, selections, plan) = fixture();
    for failure in 0..5 {
        let mut run = run.clone();
        let mut selections = selections.clone();
        match failure {
            0 => {
                run.sourceBindings.as_mut().unwrap().transfers[0].source =
                    "192.0.2.3".parse().unwrap()
            }
            1 => {
                run.sourceBindings.as_mut().unwrap().transfers[0].peer =
                    "192.0.2.11:443".parse().unwrap()
            }
            2 => run.plan.downloadBytesPerProvider += 1,
            3 => run.appVersion = "0.1.1".into(),
            _ => selections.swap(0, 1),
        }
        assert_ne!(cohortSha256(&run, &selections).unwrap(), plan.cohortSha256);
        assert!(convert(&run, &selections, &plan).is_err());
    }
}

#[test]
fn partialMismatchedAndCorruptStreamEvidenceIsNeverAccepted() {
    for failure in 0..12 {
        let (mut run, selections, plan) = fixture();
        let result = run.transfers[0].result.as_mut().unwrap();
        match failure {
            0 => result.streams[0].acceptedPayloadBytes -= 1,
            1 => result.streams[0].downloadBytesRead -= 1,
            2 => result.streams[0].remoteAddress = Some("192.0.2.11:443".into()),
            3 => result.streams[0].ordinal = 1,
            4 => result.streams[0].elapsedMs = f64::NAN,
            5 => result.elapsedMs = 0.0,
            6 => result.sourceBinding = None,
            7 => result.status = TransferStatus::Cancelled,
            8 => result.finishedAt = time(6000),
            9 => result.plan.timeoutMs -= 1,
            10 => {
                run.transfers.swap(0, 1);
            }
            _ => run.status = "partialFailure".into(),
        }
        assert!(
            convert(&run, &selections, &plan).is_err(),
            "failure {failure}"
        );
    }
}

#[test]
fn isolatedExecutionCannotShareALegacyCohortAndSurvivesRawRoundTrip() {
    let (mut run, selections, plan) = fixture();
    let legacy = serde_json::to_value(&run).unwrap();
    assert!(legacy.get("transferExecution").is_none());
    assert_eq!(cohortSha256(&run, &selections).unwrap(), plan.cohortSha256);
    run.transferExecution = Some(crate::transfer::session::TransferExecution::RestrictedWorkerV1);
    let isolated = cohortSha256(&run, &selections).unwrap();
    assert_ne!(isolated, plan.cohortSha256);
    assert!(convert(&run, &selections, &plan).is_err());
    let roundTrip: SessionRun =
        serde_json::from_str(&serde_json::to_string(&run).unwrap()).unwrap();
    assert_eq!(roundTrip.transferExecution, run.transferExecution);
    assert_eq!(cohortSha256(&roundTrip, &selections).unwrap(), isolated);
    run.transferExecution = Some(crate::transfer::session::TransferExecution::RestrictedWorkerV2);
    let second = cohortSha256(&run, &selections).unwrap();
    assert_ne!(second, isolated);
    run.transferExecution =
        Some(crate::transfer::session::TransferExecution::RecordedRestrictedWorkerV1);
    assert_ne!(cohortSha256(&run, &selections).unwrap(), second);
    let legacy: SessionRun = serde_json::from_value(legacy).unwrap();
    assert_eq!(legacy.transferExecution, None);
    assert_eq!(
        cohortSha256(&legacy, &selections).unwrap(),
        plan.cohortSha256
    );
}

#[test]
fn interruptedProgressCannotPromoteAnIncompleteOrContradictoryTransfer() {
    use crate::transfer::session::{InterruptedProgress, ProgressSnapshot};
    for evidence in [
        InterruptedProgress::Observed {
            capturedAt: time(10000),
            counters: ProgressSnapshot {
                downloadBytesRead: 1024,
                uploadBodyBytesProvided: 0,
                activeRequests: 1,
            },
        },
        InterruptedProgress::Unavailable {
            detail: "fixture counters unavailable".into(),
        },
    ] {
        let (mut run, selections, plan) = fixture();
        assert!(convert(&run, &selections, &plan).is_ok());
        run.transfers[0].interruptedProgress = Some(evidence);
        assert!(convert(&run, &selections, &plan).is_err());
        run.transfers[0].result = None;
        run.transfers[0].error = Some("fixture interrupted worker".into());
        assert!(convert(&run, &selections, &plan).is_err());
    }
}

#[test]
fn invalidProbeOrderOverlapIdentityAndQuietCountsAreRefused() {
    for failure in 0..8 {
        let (mut run, selections, plan) = fixture();
        match failure {
            0 => run.latencySamples[0].providerIndex = usize::MAX,
            1 => run.latencySamples.swap(0, 1),
            2 => run.latencySamples[0].payloadProgressDuringProbe = 1,
            3 => run.latencySamples[0].sample.address = "203.0.113.1".into(),
            4 => {
                run.latencySamples.remove(0);
            }
            5 => {
                run.latencySamples[0]
                    .sample
                    .echo
                    .as_mut()
                    .unwrap()
                    .responder = Some("203.0.113.1".parse().unwrap())
            }
            6 => run.latencySamples[24].inFlightRequestsAtStart = 3,
            _ => {
                for sample in run
                    .latencySamples
                    .iter_mut()
                    .filter(|sample| sample.phase == Phase::Download)
                {
                    sample.payloadProgressDuringProbe = 8192;
                }
            }
        }
        assert!(
            convert(&run, &selections, &plan).is_err(),
            "failure {failure}"
        );
    }
}

#[test]
fn insufficientConcurrentSamplesAndUnavailableMetricsCannotBecomeComparisonValues() {
    for failure in 0..4 {
        let (mut run, selections, plan) = fixture();
        let samples: Vec<_> = run
            .latencySamples
            .iter_mut()
            .filter(|sample| {
                sample.phase == Phase::Download && sample.sample.endpointId == "endpoint-0"
            })
            .collect();
        for sample in samples {
            match failure {
                0 => {
                    sample.inFlightRequestsAtStart = 0;
                    sample.inFlightRequestsAtEnd = 0;
                    sample.payloadProgressDuringProbe = 0;
                }
                1 => {
                    let echo = sample.sample.echo.as_mut().unwrap();
                    echo.status = crate::icmp::EchoStatus::OsError;
                    echo.rttMs = None;
                    sample.sample.error = Some("source unavailable".into());
                }
                2 => {
                    sample.inFlightRequestsAtEnd = 0;
                    sample.payloadProgressDuringProbe = 0;
                }
                _ => sample.inFlightRequestsAtEnd = 0,
            }
        }
        assert!(convert(&run, &selections, &plan).is_err());
    }
}

#[test]
fn wrongMetricRulesAndMissingBindingsCannotAdmitAComparison() {
    for failure in 0..6 {
        let (mut run, selections, mut plan) = fixture();
        match failure {
            0 => plan.metrics[0].direction = Direction::LowerIsBetter,
            1 => plan.metrics[2].resolution = 0.1,
            2 => plan.metrics[3].resolution = 0.1,
            3 => plan.metrics[3].role = Role::Objective,
            4 => run.sourceBindings = None,
            _ => run.id = 0,
        }
        assert!(convert(&run, &selections, &plan).is_err());
    }
    let (run, selections, plan) = fixture();
    assert!(
        fromRun(
            &run,
            &selections,
            &plan,
            Context {
                environmentSha256: &"a".repeat(64),
                configurationSha256: &plan.originalConfigurationSha256
            }
        )
        .is_err()
    );
}

#[test]
fn twelveAttemptsWithTooFewRepliesCannotDefineTheSelectedLatencyQuantile() {
    let (mut run, selections, plan) = fixture();
    let sample = run
        .latencySamples
        .iter_mut()
        .find(|sample| sample.phase == Phase::Download && sample.sample.endpointId == "endpoint-0")
        .unwrap();
    sample.sample.error = Some("timeout".into());
    let echo = sample.sample.echo.as_mut().unwrap();
    echo.status = EchoStatus::TimedOut;
    echo.rttMs = None;
    echo.responder = None;
    echo.nativeCode = Some(11010);
    assert!(convert(&run, &selections, &plan).is_err());
}

#[test]
fn qualifiedProbesOutsideTheirRecordedTransferWindowCannotBecomeLoadedMetrics() {
    for (index, offset) in [(24, 6950), (47, 14351)] {
        let (mut run, selections, plan) = fixture();
        run.latencySamples[index].sample.timestamp = time(offset);
        assert!(convert(&run, &selections, &plan).is_err());
    }
}
