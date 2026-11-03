use super::*;
use crate::experiment::baseline::tests::{Database, evidence};
use epp_core::{
    comparison::{Direction, MetricRule, Role, Threshold, Unit},
    experiment::budget::{Provider as BudgetProvider, TrafficBudget},
    icmp::{EchoOutcome, EchoStatus},
    transfer::{
        Provider, StreamResult, TransferPlan, TransferResult, TransferStatus,
        session::{LatencySample, Phase, PhaseResult},
    },
};
use uuid::Uuid;

type NativeEvidence = (policy::Capture, Vec<routing::Capture>);

fn fixture() -> (Scope, policy::Capture, Vec<routing::Capture>) {
    let (mut template, config, endpoints, _, current, mut routes) = evidence();
    template.createdAtUnixMs -= 30_000;
    template.leaseExpiresAtUnixMs -= 30_000;
    template.nativeOriginal.as_mut().unwrap().capturedAtUnixMs = template.createdAtUnixMs;
    let peer = "203.0.113.10:443".parse::<SocketAddr>().unwrap();
    let mut providerRoute = routes[0].clone();
    if let routing::Capture::Captured { snapshot } = &mut providerRoute {
        snapshot.destination = address(peer);
    }
    routes.push(providerRoute);
    let plan = SessionPlan {
        providers: vec![Provider::UserOwnedHttp {
            origin: "https://owned-benchmark.example/".into(),
        }],
        downloadBytesPerProvider: 8192,
        uploadBytesPerProvider: 8192,
        streams: 2,
        phaseTimeoutMs: 10_000,
        idleRounds: 12,
        intervalMs: 250,
        probeTimeoutMs: 100,
        latencyEndpoints: endpoints,
    };
    let selections = vec![
        comparisonLoad::Selection {
            metricId: "download".into(),
            providerIndex: 0,
            statistic: comparisonLoad::Statistic::GoodputMbps {
                direction: transfer::Direction::Download,
            },
        },
        comparisonLoad::Selection {
            metricId: "upload".into(),
            providerIndex: 0,
            statistic: comparisonLoad::Statistic::GoodputMbps {
                direction: transfer::Direction::Upload,
            },
        },
        comparisonLoad::Selection {
            metricId: "loaded-p95".into(),
            providerIndex: 0,
            statistic: comparisonLoad::Statistic::P95Ms {
                phase: Phase::Download,
                endpointId: "server-0".into(),
            },
        },
        comparisonLoad::Selection {
            metricId: "loaded-failures".into(),
            providerIndex: 0,
            statistic: comparisonLoad::Statistic::FailurePercent {
                phase: Phase::Download,
                endpointId: "server-0".into(),
            },
        },
    ];
    let adapter = AdapterScope::fromEvidence(
        template,
        targets(&plan.latencyEndpoints, &[peer]).unwrap(),
        current.clone(),
        routes.clone(),
    )
    .unwrap();
    (
        Scope::fromAdapter(adapter, config, plan, vec![peer], selections).unwrap(),
        current,
        routes,
    )
}

fn plan(scope: &Scope) -> Plan {
    let threshold = |absolute| Threshold {
        absolute,
        relativeFraction: 0.0,
    };
    let metrics = scope
        .selections
        .iter()
        .enumerate()
        .map(|(index, selection)| MetricRule {
            id: selection.metricId.clone(),
            unit: if index < 2 {
                Unit::MegabitsPerSecond
            } else if index == 2 {
                Unit::Milliseconds
            } else {
                Unit::Percent
            },
            direction: if index < 2 {
                Direction::HigherIsBetter
            } else {
                Direction::LowerIsBetter
            },
            role: if index == 2 {
                Role::Objective
            } else {
                Role::Guard
            },
            resolution: if index == 3 { 100.0 / 12.0 } else { 1.0 },
            minimumImprovement: threshold(10.0),
            maximumRegression: threshold(0.0),
            maximumBaselineDrift: threshold(5.0),
        })
        .collect();
    let add = |left: Resources, right: &Resources| Resources {
        probeAttempts: left.probeAttempts + right.probeAttempts,
        providerRequests: left.providerRequests + right.providerRequests,
        downloadBytes: left.downloadBytes + right.downloadBytes,
        uploadBytes: left.uploadBytes + right.uploadBytes,
    };
    let multiply = |cost: &Resources| Resources {
        probeAttempts: cost.probeAttempts * 36,
        providerRequests: cost.providerRequests * 36,
        downloadBytes: cost.downloadBytes * 36,
        uploadBytes: cost.uploadBytes * 36,
    };
    let providers = scope
        .costs
        .iter()
        .map(|(id, cost)| BudgetProvider {
            id: id.clone(),
            perCollection: *cost,
            limits: multiply(cost),
        })
        .collect();
    let total = scope.costs.values().fold(Resources::default(), add);
    Plan {
        id: Uuid::new_v4().to_string(),
        createdAtUnixMs: scope.adapter.template.createdAtUnixMs,
        expiresAtUnixMs: nowUnixMs().unwrap() + 600_000,
        blockCount: 12,
        comparison: comparison::Plan {
            maximumBlockDurationMs: 120_000,
            cohortSha256: scope.hashes.cohortSha256.clone(),
            environmentSha256: scope.hashes.environmentSha256.clone(),
            originalConfigurationSha256: scope.hashes.originalConfigurationSha256.clone(),
            candidateConfigurationSha256: scope.hashes.candidateConfigurationSha256.clone(),
            metrics,
        },
        trafficBudget: Some(TrafficBudget {
            schemaVersion: 1,
            limits: multiply(&total),
            providers,
        }),
    }
}

fn time(value: u64) -> String {
    chrono::DateTime::from_timestamp_millis(value as i64)
        .unwrap()
        .to_rfc3339()
}

fn savedRaw(
    collector: &mut Collector<'_>,
    current: &policy::Capture,
    routes: &[routing::Capture],
) -> (SessionRun, NativeEvidence, NativeEvidence) {
    let start = nowUnixMs().unwrap() - 28_000;
    let mut run = session::runSourceBoundSession(
        collector.scope.config.clone(),
        collector.scope.sessionPlan.clone(),
        collector.scope.bindings.clone(),
        &AtomicBool::new(true),
        |_| {},
    )
    .unwrap();
    run.startedAt = time(start);
    run.finishedAt = time(start + 28_000);
    run.status = "completed".into();
    for (phase, offset, rtt) in [
        (Phase::Idle, 1000, 10),
        (Phase::Download, 7250, 20),
        (Phase::Upload, 14750, 30),
        (Phase::Recovery, 22000, 12),
    ] {
        let loaded = matches!(phase, Phase::Download | Phase::Upload);
        for round in 0..12 {
            for (index, endpoint) in run.plan.latencyEndpoints.iter().enumerate() {
                run.latencySamples.push(LatencySample {
                    providerIndex: 0,
                    phase,
                    sample: epp_core::benchmark::Sample {
                        endpointId: endpoint.id.clone(),
                        address: endpoint.address.clone(),
                        timestamp: time(start + offset + (round * 2 + index as u64) * 250),
                        connectMs: None,
                        error: None,
                        dns: None,
                        echo: Some(EchoOutcome {
                            status: EchoStatus::Reply,
                            rttMs: Some(rtt),
                            rttUnitMs: 1,
                            callDurationMs: f64::from(rtt),
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
    for (phase, direction, offset) in [
        (Phase::Download, transfer::Direction::Download, 7000),
        (Phase::Upload, transfer::Direction::Upload, 14500),
    ] {
        let provider = run.plan.providers[0].clone();
        let binding = collector.scope.bindings.transfers[0];
        run.transfers.push(PhaseResult {
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
                startedAt: time(start + offset),
                finishedAt: time(start + offset + 7000),
                elapsedMs: 7000.0,
                status: TransferStatus::Completed,
                acceptedPayloadBytes: 8192,
                applicationGoodputMbps: None,
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
        });
    }
    let observation = |at| {
        let mut current = current.clone();
        current.native.capturedAtUnixMs = at;
        let mut routes = routes.to_vec();
        for route in &mut routes {
            if let routing::Capture::Captured { snapshot } = route {
                snapshot.capturedAtUnixMs = at;
            }
        }
        (current, routes)
    };
    let before = observation(start);
    let after = observation(start + 28_000);
    epp_core::storage::saveLoadSession(collector.database, &mut run).unwrap();
    (run, before, after)
}

#[test]
fn loadScopeDerivesEverySourceAndConservativelyCoversAllRequestsPayloadAndProbes() {
    let (scope, _, _) = fixture();
    assert_eq!(scope.bindings.latency.len(), 2);
    assert_eq!(scope.bindings.transfers.len(), 1);
    assert_eq!(scope.bindings.transfers[0].source.to_string(), "192.0.2.2");
    assert_eq!(
        scope.maximumTraffic()["load-0"],
        Resources {
            providerRequests: 4,
            downloadBytes: 8192,
            uploadBytes: 8192,
            ..Default::default()
        }
    );
    assert_eq!(scope.maximumTraffic()["echo-0"].probeAttempts, 241);
    let plan = plan(&scope);
    let storage = Database::new();
    let mut database = storage.open();
    let collector = scope.bind(&mut database, plan).unwrap();
    assert_eq!(collector.maximumTraffic().unwrap().len(), 3);
}

#[test]
fn nativeReceiptBindsTheSavedLoadRunAndEveryTransferAndEchoRoute() {
    let (scope, current, routes) = fixture();
    let plan = plan(&scope);
    let storage = Database::new();
    let mut database = storage.open();
    let mut collector = scope.bind(&mut database, plan).unwrap();
    let (run, before, after) = savedRaw(&mut collector, &current, &routes);
    let measured = collector
        .acceptRaw(&run, &before, &after, Configuration::Original)
        .unwrap();
    assert_eq!(measured.values[2..], [20.0, 0.0]);
    let (payload, checksum): (String, String) = collector
        .database
        .query_row(
            "SELECT payload_json,sha256 FROM adapter_load_measurements WHERE run_id=?1",
            [run.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(checksum, epp_core::backups::checksum(&payload));
    let receipt: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(receipt["rawRunSha256"], hash(&run).unwrap());
    assert_eq!(receipt["routesBefore"].as_array().unwrap().len(), 3);
    assert_eq!(receipt["experimentId"], collector.plan.id);
    assert!(receipt["checkpointId"].is_null());
}

#[test]
fn driftedNativePolicyRoutesAndMismatchedCandidateStateCannotProduceReceipts() {
    for failure in 0..7 {
        let (scope, current, routes) = fixture();
        let plan = plan(&scope);
        let storage = Database::new();
        let mut database = storage.open();
        let mut collector = scope.bind(&mut database, plan).unwrap();
        let (run, mut before, mut after) = savedRaw(&mut collector, &current, &routes);
        match failure {
            0 => after.0.native.adapterGuid = Uuid::new_v4(),
            1 => {
                if let routing::Capture::Captured { snapshot } = &mut after.1[2] {
                    snapshot.source.ip = "192.0.2.3".parse().unwrap();
                }
            }
            2 => {
                after
                    .0
                    .active
                    .values
                    .get_mut("InterfaceMetric")
                    .unwrap()
                    .value = Some(999)
            }
            3 => before.0.native.capturedAtUnixMs += 1000,
            4 => after.0.native.capturedAtUnixMs -= 1000,
            5 => after.0.native.settings.nlMtu = 1427,
            _ => {}
        }
        assert!(
            collector
                .acceptRaw(
                    &run,
                    &before,
                    &after,
                    if failure == 6 {
                        Configuration::Candidate
                    } else {
                        Configuration::Original
                    }
                )
                .is_err(),
            "failure {failure}"
        );
        assert_eq!(
            collector
                .database
                .query_row(
                    "SELECT count(*) FROM adapter_load_measurements",
                    [],
                    |row| row.get::<_, u32>(0)
                )
                .unwrap(),
            0
        );
    }
}

#[test]
fn loadReceiptAndRawStorageFaultsRollBackAdmissionWhilePreservingRawRuns() {
    for failure in 0..4 {
        let (scope, current, routes) = fixture();
        let plan = plan(&scope);
        let storage = Database::new();
        let mut database = storage.open();
        let mut collector = scope.bind(&mut database, plan).unwrap();
        let (run, before, after) = savedRaw(&mut collector, &current, &routes);
        collector.database.execute_batch(match failure {
            0=>"CREATE TRIGGER refuse_load_receipt BEFORE INSERT ON adapter_load_measurements BEGIN SELECT RAISE(ABORT,'receipt unavailable'); END",
            1=>"CREATE TRIGGER change_load_receipt AFTER INSERT ON adapter_load_measurements BEGIN UPDATE adapter_load_measurements SET sha256='different' WHERE run_id=NEW.run_id; END",
            2=>"UPDATE load_sessions SET report_json='{}'",
            _=>"CREATE TRIGGER change_load_raw AFTER INSERT ON adapter_load_measurements BEGIN UPDATE load_sessions SET report_json='{}' WHERE id=NEW.run_id; END",
        }).unwrap();
        assert!(
            collector
                .acceptRaw(&run, &before, &after, Configuration::Original)
                .is_err(),
            "fault {failure}"
        );
        assert_eq!(
            collector
                .database
                .query_row(
                    "SELECT count(*) FROM adapter_load_measurements",
                    [],
                    |row| row.get::<_, u32>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            collector
                .database
                .query_row("SELECT count(*) FROM load_sessions", [], |row| row
                    .get::<_, u32>(0))
                .unwrap(),
            1
        );
        if failure != 2 {
            let raw: String = collector
                .database
                .query_row(
                    "SELECT report_json FROM load_sessions WHERE id=?1",
                    [run.id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(raw, serde_json::to_string(&run).unwrap());
        }
    }
}

#[test]
fn changedPlansRulesBudgetsAndNonDurableStorageCannotAdmitLoadCollectors() {
    for failure in 0..5 {
        let (scope, _, _) = fixture();
        let mut plan = plan(&scope);
        let storage = Database::new();
        let mut database = storage.open();
        match failure {
            0 => plan.comparison.cohortSha256 = "a".repeat(64),
            1 => plan.comparison.metrics[2].resolution = 0.1,
            2 => plan.trafficBudget.as_mut().unwrap().limits.providerRequests = 1,
            3 => plan.comparison.metrics[3].role = Role::Objective,
            _ => database
                .pragma_update(None, "synchronous", "NORMAL")
                .unwrap(),
        }
        assert!(scope.bind(&mut database, plan).is_err());
    }
}

#[test]
fn loadCheckpointBindingRejectsChangesWithoutLosingTheLastValidBinding() {
    let (scope, _, _) = fixture();
    let plan = plan(&scope);
    let storage = Database::new();
    let mut database = storage.open();
    let mut collector = scope.bind(&mut database, plan).unwrap();
    let mut document = collector.scope.adapter.template.clone();
    document.id = Uuid::new_v4();
    collector.bindCheckpoint(Some(&document)).unwrap();
    let id = collector.checkpoint.as_ref().unwrap().id;
    document.proposedMtu = 1400;
    assert!(collector.bindCheckpoint(Some(&document)).is_err());
    assert_eq!(collector.checkpoint.as_ref().unwrap().id, id);
    collector.bindCheckpoint(None).unwrap();
    assert!(collector.checkpoint.is_none());
}

#[test]
fn unsupportedDurationRoundsAndPeerCountsFailBeforeNativeInspection() {
    let (scope, _, _) = fixture();
    for failure in 0..4 {
        let mut config = scope.config.clone();
        let mut plan = scope.sessionPlan.clone();
        let mut peers = vec![scope.bindings.transfers[0].peer];
        match failure {
            0 => config.sessionMinutes = 2,
            1 => plan.idleRounds = 3,
            2 => peers.clear(),
            _ => {
                plan.intervalMs = 1000;
                plan.probeTimeoutMs = 1000;
            }
        }
        assert!(Scope::validateInput(&scope.adapter.template, &config, &plan, &peers).is_err());
    }
}

#[test]
fn candidateLoadReceiptsRequireMatchingNativeMtuAndTheExactBoundCheckpoint() {
    let (scope, current, routes) = fixture();
    let plan = plan(&scope);
    let storage = Database::new();
    let mut database = storage.open();
    let mut collector = scope.bind(&mut database, plan).unwrap();
    let mut document = collector.scope.adapter.template.clone();
    document.id = Uuid::new_v4();
    collector.bindCheckpoint(Some(&document)).unwrap();
    let (run, mut before, mut after) = savedRaw(&mut collector, &current, &routes);
    assert!(
        collector
            .acceptRaw(&run, &before, &after, Configuration::Candidate)
            .is_err()
    );
    for observation in [&mut before.0, &mut after.0] {
        observation.native.settings.nlMtu = document.proposedMtu;
        observation.active.values.get_mut("NlMtu").unwrap().value = Some(document.proposedMtu);
    }
    let measured = collector
        .acceptRaw(&run, &before, &after, Configuration::Candidate)
        .unwrap();
    assert_eq!(
        measured.configurationSha256,
        collector.scope.hashes.candidateConfigurationSha256
    );
    let payload: String = collector
        .database
        .query_row(
            "SELECT payload_json FROM adapter_load_measurements WHERE run_id=?1",
            [run.id],
            |row| row.get(0),
        )
        .unwrap();
    let receipt: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(receipt["checkpointId"], document.id.to_string());
    assert_eq!(
        receipt["checkpointSha256"],
        crate::authorization::checkpointChecksum(&document).unwrap()
    );
    assert_eq!(receipt["configuration"], "candidate");
}

#[test]
fn loadEvidenceOutsideItsIssuedCheckpointLeaseCannotProduceACandidateReceipt() {
    let mut outcomes = Vec::new();
    for failure in 0..4 {
        let (scope, current, routes) = fixture();
        let plan = plan(&scope);
        let storage = Database::new();
        let mut database = storage.open();
        let mut collector = scope.bind(&mut database, plan).unwrap();
        let (run, mut before, mut after) = savedRaw(&mut collector, &current, &routes);
        let mut document = collector.scope.adapter.template.clone();
        document.id = Uuid::new_v4();
        match failure {
            0 => {
                document.createdAtUnixMs = nowUnixMs().unwrap();
                document.nativeOriginal.as_mut().unwrap().capturedAtUnixMs =
                    document.createdAtUnixMs;
            }
            1 => document.leaseExpiresAtUnixMs = after.0.native.capturedAtUnixMs - 1000,
            2 => {
                document.createdAtUnixMs = before.0.native.capturedAtUnixMs - 500;
                before.0.native.capturedAtUnixMs -= 1000;
            }
            _ => {
                document.leaseExpiresAtUnixMs = after.0.native.capturedAtUnixMs + 1;
                after.0.native.capturedAtUnixMs += 2;
            }
        }
        document.validate().unwrap();
        collector.bindCheckpoint(Some(&document)).unwrap();
        for observation in [&mut before.0, &mut after.0] {
            observation.native.settings.nlMtu = document.proposedMtu;
            observation.active.values.get_mut("NlMtu").unwrap().value = Some(document.proposedMtu);
        }
        let refused = collector
            .acceptRaw(&run, &before, &after, Configuration::Candidate)
            .is_err();
        let receipts = collector
            .database
            .query_row(
                "SELECT count(*) FROM adapter_load_measurements",
                [],
                |row| row.get::<_, u32>(0),
            )
            .unwrap();
        outcomes.push((failure, refused, receipts));
        assert_eq!(
            collector
                .database
                .query_row("SELECT count(*) FROM load_sessions", [], |row| row
                    .get::<_, u32>(0))
                .unwrap(),
            1
        );
    }
    assert_eq!(
        outcomes,
        vec![(0, true, 0), (1, true, 0), (2, true, 0), (3, true, 0)]
    );
}

#[test]
fn variationReceiptsUseRawRttValuesAndRefuseSubMillisecondRules() {
    for successive in [false, true] {
        for tooPrecise in [false, true] {
            let (mut scope, current, routes) = fixture();
            scope.selections[2].statistic = if successive {
                comparisonLoad::Statistic::SuccessiveVariationMs {
                    phase: session::Phase::Download,
                    endpointId: "server-0".into(),
                }
            } else {
                comparisonLoad::Statistic::IqrMs {
                    phase: session::Phase::Download,
                    endpointId: "server-0".into(),
                }
            };
            let peers = scope
                .bindings
                .transfers
                .iter()
                .map(|binding| binding.peer)
                .collect();
            let scope = Scope::fromAdapter(
                scope.adapter,
                scope.config,
                scope.sessionPlan,
                peers,
                scope.selections,
            )
            .unwrap();
            let mut plan = plan(&scope);
            if tooPrecise {
                plan.comparison.metrics[2].resolution = 0.1;
            }
            let storage = Database::new();
            let mut database = storage.open();
            let result = scope.bind(&mut database, plan);
            if tooPrecise {
                assert!(result.is_err());
            } else {
                let mut collector = result.unwrap();
                let (run, before, after) = savedRaw(&mut collector, &current, &routes);
                assert_eq!(
                    collector
                        .acceptRaw(&run, &before, &after, Configuration::Original)
                        .unwrap()
                        .values[2],
                    0.0
                );
            }
        }
    }
}
