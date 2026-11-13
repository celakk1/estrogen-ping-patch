use super::*;
use epp_core::{
    comparison::{Direction, MetricRule, Role, Threshold, Unit},
    experiment::budget::{Provider, TrafficBudget},
};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

pub(crate) struct Database {
    directory: PathBuf,
}

impl Database {
    pub(crate) fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("epp-bound-baseline-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        Self { directory }
    }
    pub(crate) fn open(&self) -> Connection {
        epp_core::storage::openDatabase(&self.directory.join("measurements.sqlite3")).unwrap()
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        for name in [
            "measurements.sqlite3",
            "measurements.sqlite3-wal",
            "measurements.sqlite3-shm",
        ] {
            let path = self.directory.join(name);
            if path.is_file() {
                std::fs::remove_file(path).unwrap();
            }
        }
        std::fs::remove_dir(&self.directory).unwrap();
    }
}

pub(crate) fn evidence() -> (
    MtuCheckpoint,
    Config,
    Vec<Endpoint>,
    Vec<Selection>,
    policy::Capture,
    Vec<routing::Capture>,
) {
    let now = nowUnixMs().unwrap();
    let mut current = policy::tests::fixture();
    current.native.capturedAtUnixMs = now;
    current.native.operationalStatus = 1;
    current.native.mediaConnectState = 1;
    let template = MtuCheckpoint {
        schemaVersion: 4,
        id: Uuid::new_v4(),
        createdAtUnixMs: now,
        leaseExpiresAtUnixMs: now + 120_000,
        authorizedUserSid: "S-1-5-21-1-2-3-1000".into(),
        context: current.native.journalContext().unwrap(),
        addressFamily: current.native.addressFamily,
        originalMtu: 1500,
        proposedMtu: 1427,
        nativeOriginal: Some(current.native.clone()),
        policyOriginal: Some(current.evidence()),
    };
    let config = Config {
        sampleCount: 12,
        intervalMs: 250,
        timeoutMs: 100,
        sessionMinutes: 1,
        ..Config::default()
    };
    let endpoints: Vec<_> = ["192.0.2.10", "198.51.100.10"]
        .into_iter()
        .enumerate()
        .map(|(index, address)| Endpoint {
            id: format!("server-{index}"),
            address: address.into(),
            protocol: ProbeProtocol::IcmpEcho,
            dnsQuery: None,
        })
        .collect();
    let selections = endpoints
        .iter()
        .flat_map(|endpoint| {
            [
                Selection {
                    metricId: format!("{}-p95", endpoint.id),
                    endpointId: endpoint.id.clone(),
                    statistic: Statistic::P95Ms,
                },
                Selection {
                    metricId: format!("{}-failures", endpoint.id),
                    endpointId: endpoint.id.clone(),
                    statistic: Statistic::FailurePercent,
                },
            ]
        })
        .collect();
    let routes = endpoints
        .iter()
        .map(|endpoint| routing::Capture::Captured {
            snapshot: routing::Snapshot {
                schemaVersion: 1,
                capturedAtUnixMs: now,
                destination: routing::Address {
                    ip: endpoint.address.parse().unwrap(),
                    scopeId: 0,
                },
                adapterGuid: current.native.adapterGuid,
                interfaceLuid: current.native.interfaceLuid.clone(),
                interfaceIndex: current.native.interfaceIndex,
                source: routing::Address {
                    ip: "192.0.2.2".parse().unwrap(),
                    scopeId: 0,
                },
                destinationPrefix: routing::Address {
                    ip: "0.0.0.0".parse().unwrap(),
                    scopeId: 0,
                },
                prefixLength: 0,
                nextHop: routing::Address {
                    ip: "192.0.2.1".parse().unwrap(),
                    scopeId: 0,
                },
                routeMetric: 10,
                protocol: 2,
                origin: 0,
                sitePrefixLength: 0,
                loopback: false,
                autoconfigureAddress: false,
                publish: false,
                immortal: true,
                validLifetimeSeconds: u32::MAX,
                preferredLifetimeSeconds: u32::MAX,
                ageSeconds: 1,
                linkStatistics: None,
            },
        })
        .collect();
    (template, config, endpoints, selections, current, routes)
}

fn scope() -> Scope {
    let (template, config, endpoints, selections, current, routes) = evidence();
    Scope::fromEvidence(template, config, endpoints, selections, current, routes).unwrap()
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
        .map(|(index, selection)| {
            let failure = matches!(selection.statistic, Statistic::FailurePercent);
            MetricRule {
                id: selection.metricId.clone(),
                unit: if failure {
                    Unit::Percent
                } else {
                    Unit::Milliseconds
                },
                direction: Direction::LowerIsBetter,
                role: if index == 0 {
                    Role::Objective
                } else {
                    Role::Guard
                },
                resolution: if failure { 100.0 / 12.0 } else { 1.0 },
                minimumImprovement: threshold(if failure { 100.0 / 12.0 } else { 2.0 }),
                maximumRegression: threshold(0.0),
                maximumBaselineDrift: threshold(5.0),
            }
        })
        .collect();
    let providers = scope
        .costs
        .iter()
        .map(|(id, cost)| Provider {
            id: id.clone(),
            perCollection: *cost,
            limits: Resources {
                probeAttempts: cost.probeAttempts * 36,
                ..Default::default()
            },
        })
        .collect();
    let now = nowUnixMs().unwrap();
    Plan {
        id: Uuid::new_v4().to_string(),
        createdAtUnixMs: now,
        expiresAtUnixMs: now + 600_000,
        blockCount: 12,
        comparison: epp_core::comparison::Plan {
            maximumBlockDurationMs: 120_000,
            cohortSha256: scope.hashes.cohortSha256.clone(),
            environmentSha256: scope.hashes.environmentSha256.clone(),
            originalConfigurationSha256: scope.hashes.originalConfigurationSha256.clone(),
            candidateConfigurationSha256: scope.hashes.candidateConfigurationSha256.clone(),
            metrics,
        },
        trafficBudget: Some(TrafficBudget {
            schemaVersion: 1,
            limits: Resources {
                probeAttempts: 864,
                ..Default::default()
            },
            providers,
        }),
    }
}

#[test]
fn downloadProfileCannotStartEchoOnlyOptimizationCollection() {
    use epp_core::config::Profile;
    let (template, mut config, endpoints, selections, _, _) = evidence();
    for profile in [Profile::Latency, Profile::Balanced] {
        config.profile = profile;
        Scope::validateInput(&template, &config, &endpoints, &selections).unwrap();
    }
    config.profile = Profile::Download;
    let error = Scope::capture(
        template,
        config,
        endpoints,
        selections,
        &AtomicBool::new(false),
    )
    .err()
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("Download profile requires throughput collection")
    );
}

#[test]
fn scopeBindsEveryEndpointToTheExactAdapterSourceAndTrafficAllowance() {
    let scope = scope();
    assert_eq!(scope.sources.len(), 2);
    assert!(
        scope
            .sources
            .iter()
            .all(|binding| binding.source.address.to_string() == "192.0.2.2")
    );
    assert_eq!(
        scope
            .maximumTraffic()
            .values()
            .map(|cost| cost.probeAttempts)
            .sum::<u64>(),
        24
    );
    assert_ne!(
        scope.hashes.originalConfigurationSha256,
        scope.hashes.candidateConfigurationSha256
    );
    let storage = Database::new();
    let mut database = storage.open();
    let plan = plan(&scope);
    let collector = scope.bind(&mut database, plan).unwrap();
    assert_eq!(collector.maximumTraffic().unwrap().len(), 2);
}

#[test]
fn differentUnavailableLocalAndChangedRoutesCannotBecomeOptimizationEvidence() {
    for failure in 0..5 {
        let (template, config, endpoints, selections, current, mut routes) = evidence();
        match failure {
            0 => {
                if let routing::Capture::Captured { snapshot } = &mut routes[0] {
                    snapshot.adapterGuid = Uuid::new_v4();
                }
            }
            1 => {
                if let routing::Capture::Captured { snapshot } = &mut routes[0] {
                    snapshot.source.ip = "0.0.0.0".parse().unwrap();
                }
            }
            2 => {
                if let routing::Capture::Captured { snapshot } = &mut routes[0] {
                    snapshot.loopback = true;
                }
            }
            3 => {
                routes[0] = routing::Capture::Unavailable {
                    destination: destinations(&endpoints).unwrap().remove(0),
                    error: "test unavailable".into(),
                }
            }
            _ => {
                if let routing::Capture::Captured { snapshot } = &mut routes[0] {
                    snapshot.destination.ip = "203.0.113.2".parse().unwrap();
                }
            }
        }
        assert!(
            Scope::fromEvidence(template, config, endpoints, selections, current, routes).is_err()
        );
    }
}

#[test]
fn insufficientLeaseAndMissingFailureGuardsAreRejectedBeforeNativeInspection() {
    let (mut template, mut config, endpoints, mut selections, _, _) = evidence();
    template.leaseExpiresAtUnixMs = template.createdAtUnixMs + 15_000;
    assert!(Scope::validateInput(&template, &config, &endpoints, &selections).is_err());
    template.leaseExpiresAtUnixMs = template.createdAtUnixMs + 120_000;
    selections[1].statistic = Statistic::MedianMs;
    assert!(Scope::validateInput(&template, &config, &endpoints, &selections).is_err());
    selections[1].statistic = Statistic::FailurePercent;
    config.timeoutMs = 5000;
    assert!(Scope::validateInput(&template, &config, &endpoints, &selections).is_err());
}

#[test]
fn alteredPlanCostsRulesOrNonDurableStorageCannotAdmitACollector() {
    let storage = Database::new();
    let mut database = storage.open();
    for failure in 0..4 {
        let scope = scope();
        let mut plan = plan(&scope);
        match failure {
            0 => plan.comparison.cohortSha256 = "a".repeat(64),
            1 => plan.trafficBudget.as_mut().unwrap().limits.probeAttempts = 1,
            2 => plan.comparison.metrics[0].resolution = 0.1,
            _ => database
                .pragma_update(None, "synchronous", "NORMAL")
                .unwrap(),
        }
        assert!(scope.bind(&mut database, plan).is_err());
    }
}

#[test]
fn contextAndCheckpointDriftAreRefusedBeforeAnyCandidateMeasurement() {
    let storage = Database::new();
    let mut database = storage.open();
    let scope = scope();
    let plan = plan(&scope);
    let mut collector = scope.bind(&mut database, plan).unwrap();
    let mut document = collector.scope.adapter.template.clone();
    document.id = Uuid::new_v4();
    collector.bindCheckpoint(Some(&document)).unwrap();
    let saved = collector.checkpoint.as_ref().unwrap().id;
    document.proposedMtu = 1400;
    assert!(collector.bindCheckpoint(Some(&document)).is_err());
    assert_eq!(collector.checkpoint.as_ref().unwrap().id, saved);
    collector.bindCheckpoint(None).unwrap();
    assert!(collector.checkpoint.is_none());
    let (_, _, _, _, mut current, routes) = evidence();
    current.native.adapterGuid = Uuid::new_v4();
    assert!(
        collector
            .scope
            .adapter
            .verify(&current, &routes, Configuration::Original)
            .is_err()
    );
}

fn savedRaw(collector: &mut Collector<'_>) -> (BenchmarkRun, policy::Capture, policy::Capture) {
    let original = collector
        .scope
        .adapter
        .template
        .nativeOriginal
        .as_ref()
        .unwrap();
    let policy = collector
        .scope
        .adapter
        .template
        .policyOriginal
        .as_ref()
        .unwrap();
    let mut before = policy::Capture {
        schemaVersion: 1,
        native: original.clone(),
        active: policy.active.clone(),
        persistent: policy.persistent.clone(),
    };
    before.native.capturedAtUnixMs = nowUnixMs().unwrap();
    let blueprint = || {
        benchmark::runSourceBoundEchoBenchmark(
            collector.scope.config.clone(),
            collector.scope.endpoints.clone(),
            collector.scope.sources.clone(),
            &AtomicBool::new(true),
            |_, _, _| {},
        )
        .unwrap()
    };
    let mut run = blueprint();
    std::thread::sleep(Duration::from_millis(2));
    run.finishedAt = blueprint().finishedAt;
    run.status = "completed".into();
    run.samples = (0..run.config.sampleCount)
        .flat_map(|_| {
            collector
                .scope
                .endpoints
                .iter()
                .map(|endpoint| benchmark::Sample {
                    endpointId: endpoint.id.clone(),
                    address: endpoint.address.clone(),
                    timestamp: run.startedAt.clone(),
                    connectMs: None,
                    error: None,
                    dns: None,
                    echo: Some(epp_core::icmp::EchoOutcome {
                        status: epp_core::icmp::EchoStatus::Reply,
                        rttMs: Some(10),
                        rttUnitMs: 1,
                        callDurationMs: 10.0,
                        responder: Some(endpoint.address.parse().unwrap()),
                        responderScopeId: None,
                        nativeCode: Some(0),
                    }),
                })
        })
        .collect();
    for result in &mut run.results {
        result.summary =
            epp_core::statistics::summarize(&vec![Some(10.0); run.config.sampleCount as usize]);
        result.summary.echoTimeoutPercent = Some(0.0);
        result.echoCounts = Some(benchmark::EchoCounts {
            replies: run.config.sampleCount as usize,
            ..Default::default()
        });
    }
    let mut after = before.clone();
    after.native.capturedAtUnixMs = nowUnixMs().unwrap();
    epp_core::storage::saveRun(collector.database, &mut run).unwrap();
    (run, before, after)
}

#[test]
fn savedRawAndNativeReceiptMustReadBackExactlyBeforeReturningMeasurements() {
    let storage = Database::new();
    let mut database = storage.open();
    let scope = scope();
    let plan = plan(&scope);
    let mut collector = scope.bind(&mut database, plan).unwrap();
    let (run, before, after) = savedRaw(&mut collector);
    let session = collector
        .acceptRaw(&run, &before, &after, Configuration::Original)
        .unwrap();
    assert_eq!(session.values, vec![10.0, 0.0, 10.0, 0.0]);
    let (payload, checksum): (String, String) = collector
        .database
        .query_row(
            "SELECT payload_json,sha256 FROM adapter_measurements WHERE run_id=?1",
            [run.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(checksum, epp_core::backups::checksum(&payload));
    let receipt: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(receipt["experimentId"], collector.plan.id);
    assert_eq!(receipt["rawRunSha256"], hash(&run).unwrap());
    assert_eq!(
        receipt["nativeBefore"],
        serde_json::to_value(before).unwrap()
    );
    assert_eq!(receipt["nativeAfter"], serde_json::to_value(after).unwrap());
    assert!(receipt["checkpointId"].is_null());
}

#[test]
fn failedOrAlteredDurableEvidenceNeverReturnsAnAcceptedSession() {
    for failure in 0..4 {
        let storage = Database::new();
        let mut database = storage.open();
        let scope = scope();
        let plan = plan(&scope);
        let mut collector = scope.bind(&mut database, plan).unwrap();
        let (run, before, after) = savedRaw(&mut collector);
        let fault = match failure {
            0 => {
                "CREATE TRIGGER refuse_receipt BEFORE INSERT ON adapter_measurements BEGIN SELECT RAISE(ABORT,'receipt unavailable'); END"
            }
            1 => {
                "CREATE TRIGGER alter_receipt AFTER INSERT ON adapter_measurements BEGIN UPDATE adapter_measurements SET sha256='changed' WHERE run_id=NEW.run_id; END"
            }
            2 => "UPDATE benchmark_runs SET report_json='{}'",
            _ => "UPDATE benchmark_samples SET sample_json='{}' WHERE ordinal=0",
        };
        collector.database.execute_batch(fault).unwrap();
        assert!(
            collector
                .acceptRaw(&run, &before, &after, Configuration::Original)
                .is_err(),
            "fault {failure}"
        );
        assert_eq!(
            collector
                .database
                .query_row("SELECT count(*) FROM benchmark_runs", [], |row| row
                    .get::<_, u32>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            collector
                .database
                .query_row("SELECT count(*) FROM adapter_measurements", [], |row| row
                    .get::<_, u32>(
                    0
                ))
                .unwrap(),
            0,
            "fault {failure} left a receipt after failed admission"
        );
    }
}

#[test]
fn unbracketedNativeEvidenceAndIncompleteRunsCannotBecomeMeasurements() {
    for failure in 0..3 {
        let storage = Database::new();
        let mut database = storage.open();
        let scope = scope();
        let plan = plan(&scope);
        let mut collector = scope.bind(&mut database, plan).unwrap();
        let (mut run, mut before, mut after) = savedRaw(&mut collector);
        match failure {
            0 => before.native.capturedAtUnixMs += 1_000,
            1 => after.native.capturedAtUnixMs -= 1_000,
            _ => {
                run.samples.pop();
            }
        }
        assert!(
            collector
                .acceptRaw(&run, &before, &after, Configuration::Original)
                .is_err()
        );
        assert_eq!(
            collector
                .database
                .query_row("SELECT count(*) FROM adapter_measurements", [], |row| row
                    .get::<_, u32>(
                    0
                ))
                .unwrap(),
            0
        );
    }
}

#[test]
fn tooFewSuccessfulEchoesCannotProduceATrustedLatencyReceipt() {
    let storage = Database::new();
    let mut database = storage.open();
    let scope = scope();
    let plan = plan(&scope);
    let mut collector = scope.bind(&mut database, plan).unwrap();
    let (mut run, before, after) = savedRaw(&mut collector);
    let sample = &mut run.samples[0];
    sample.error = Some("timeout".into());
    let echo = sample.echo.as_mut().unwrap();
    echo.status = epp_core::icmp::EchoStatus::TimedOut;
    echo.rttMs = None;
    echo.responder = None;
    echo.nativeCode = Some(11010);
    epp_core::storage::saveRun(collector.database, &mut run).unwrap();
    let error = collector
        .acceptRaw(&run, &before, &after, Configuration::Original)
        .unwrap_err();
    assert!(error.to_string().contains("twelve successful"));
    assert_eq!(
        collector
            .database
            .query_row("SELECT count(*) FROM adapter_measurements", [], |row| row
                .get::<_, u32>(
                0
            ))
            .unwrap(),
        0
    );
}

#[test]
fn sharedAdapterScopePreservesThePublishedEchoHashPreimages() {
    let (template, config, endpoints, selections, current, routes) = evidence();
    let native = template.nativeOriginal.as_ref().unwrap();
    let policy = template.policyOriginal.as_ref().unwrap();
    let legacy = hash(&(
        "source-bound-adapter-baseline-v1",
        native.adapterGuid,
        native.addressFamily,
        &native.os,
        &native.driver,
        &native.registryOrigins,
        &policy.active,
        &policy.persistent,
        routing::fingerprint(&routes).unwrap().unwrap(),
    ))
    .unwrap();
    let original = hash(&current.native.settings).unwrap();
    let mut candidate = current.native.settings.clone();
    candidate.nlMtu = template.proposedMtu;
    let candidate = hash(&candidate).unwrap();
    let scope =
        Scope::fromEvidence(template, config, endpoints, selections, current, routes).unwrap();
    assert_eq!(scope.hashes.environmentSha256, legacy);
    assert_eq!(scope.hashes.originalConfigurationSha256, original);
    assert_eq!(scope.hashes.candidateConfigurationSha256, candidate);
}

#[test]
fn echoCandidateEvidenceRequiresTheIssuedCheckpointAndItsLease() {
    let mut outcomes = Vec::new();
    for failure in 0..4 {
        let storage = Database::new();
        let mut database = storage.open();
        let scope = scope();
        let plan = plan(&scope);
        let mut collector = scope.bind(&mut database, plan).unwrap();
        let (run, mut before, mut after) = savedRaw(&mut collector);
        let mut document = collector.scope.adapter.template.clone();
        document.id = Uuid::new_v4();
        if failure == 1 {
            document.createdAtUnixMs = nowUnixMs().unwrap() + 1000;
            document.nativeOriginal.as_mut().unwrap().capturedAtUnixMs = document.createdAtUnixMs;
        } else if failure == 2 {
            document.leaseExpiresAtUnixMs = after.native.capturedAtUnixMs - 1;
        }
        document.validate().unwrap();
        if failure != 0 {
            collector.bindCheckpoint(Some(&document)).unwrap();
        }
        for observation in [&mut before, &mut after] {
            observation.native.settings.nlMtu = document.proposedMtu;
            observation.active.values.get_mut("NlMtu").unwrap().value = Some(document.proposedMtu);
        }
        let refused = collector
            .acceptRaw(&run, &before, &after, Configuration::Candidate)
            .is_err();
        let receipts = collector
            .database
            .query_row("SELECT count(*) FROM adapter_measurements", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap();
        outcomes.push((failure, refused, receipts));
        assert_eq!(
            collector
                .database
                .query_row("SELECT count(*) FROM benchmark_runs", [], |row| row
                    .get::<_, u32>(0))
                .unwrap(),
            1
        );
    }
    assert_eq!(
        outcomes,
        vec![(0, true, 0), (1, true, 0), (2, true, 0), (3, false, 1)]
    );
}
