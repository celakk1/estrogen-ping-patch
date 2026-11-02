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
