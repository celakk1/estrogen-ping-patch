use super::*;
use crate::{benchmark, config::Config, icmp::EchoOutcome};

fn fixture() -> (BenchmarkRun, Vec<Selection>, Plan) {
    let config = Config {
        sampleCount: 3,
        intervalMs: 250,
        timeoutMs: 100,
        ..Config::default()
    };
    let endpoints: Vec<_> = (0..2)
        .map(|index| Endpoint {
            id: format!("server{index}"),
            address: format!("127.0.0.1:{}", 9000 + index),
            protocol: ProbeProtocol::TcpConnect,
            dnsQuery: None,
        })
        .collect();
    let samples = (0..3)
        .flat_map(|round| {
            endpoints.iter().map(move |endpoint| Sample {
                endpointId: endpoint.id.clone(),
                address: endpoint.address.clone(),
                timestamp: "2026-11-01T01:00:01Z".into(),
                connectMs: Some(10.0 + round as f64),
                error: None,
                echo: None,
                dns: None,
            })
        })
        .collect::<Vec<_>>();
    let results = endpoints
        .into_iter()
        .map(|endpoint| summarizeEndpoint(endpoint, &samples))
        .collect();
    let run = BenchmarkRun {
        id: 1,
        startedAt: "2026-11-01T01:00:00Z".into(),
        finishedAt: "2026-11-01T01:00:02Z".into(),
        status: "completed".into(),
        protocol: "tcpConnect".into(),
        appVersion: "0.1.0".into(),
        config,
        results,
        samples,
    };
    let selections = vec![
        Selection {
            metricId: "server.median".into(),
            endpointId: "server0".into(),
            statistic: Statistic::MedianMs,
        },
        Selection {
            metricId: "server.failures".into(),
            endpointId: "server0".into(),
            statistic: Statistic::FailurePercent,
        },
    ];
    let mut plan = super::super::tests::plan();
    plan.cohortSha256 = cohortSha256(&run, &selections).unwrap();
    plan.metrics[1].id = "server.failures".into();
    plan.metrics[1].unit = Unit::Percent;
    plan.metrics[1].direction = Direction::LowerIsBetter;
    (run, selections, plan)
}

fn convert(run: &BenchmarkRun, selections: &[Selection], plan: &Plan) -> AppResult<Session> {
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
fn comparisonRecomputesMetricsFromRawSamplesInsteadOfTrustingSavedSummaries() {
    let (mut run, selections, plan) = fixture();
    run.results[0].summary.medianMs = Some(0.0);
    run.results[0].summary.connectionFailurePercent = Some(100.0);
    let session = convert(&run, &selections, &plan).unwrap();
    assert_eq!(session.id, "baseline:1");
    assert_eq!(session.values, vec![11.0, 0.0]);
    run.samples[0].connectMs = None;
    run.samples[0].error = Some("fixture timeout".into());
    let session = convert(&run, &selections, &plan).unwrap();
    assert_eq!(session.values[0], 11.5);
    assert!((session.values[1] - 100.0 / 3.0).abs() < 1e-12);
}

#[test]
fn savedLiveLoopbackMeasurementsEnterTheSameSessionAdapter() {
    let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let second = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (run, selections, mut plan) = fixture();
    let endpoints = [first.local_addr().unwrap(), second.local_addr().unwrap()]
        .into_iter()
        .enumerate()
        .map(|(index, address)| Endpoint {
            id: format!("server{index}"),
            address: address.to_string(),
            protocol: ProbeProtocol::TcpConnect,
            dnsQuery: None,
        })
        .collect();
    let mut run = benchmark::runBenchmark(
        run.config,
        endpoints,
        &std::sync::atomic::AtomicBool::new(false),
        |_, _, _| {},
    )
    .unwrap();
    let mut connection = crate::storage::openDatabase(std::path::Path::new(":memory:")).unwrap();
    crate::storage::saveRun(&mut connection, &mut run).unwrap();
    let saved = crate::storage::history(&connection, 1).unwrap().remove(0);
    plan.cohortSha256 = cohortSha256(&saved, &selections).unwrap();
    let session = convert(&saved, &selections, &plan).unwrap();
    assert!(session.values[0].is_finite() && session.values[0] >= 0.0);
    assert_eq!(session.values[1], 0.0);
}

#[test]
fn cohortBindsTargetsQueriesMeasurementPolicyAndMetricSelections() {
    let (original, selections, plan) = fixture();
    for change in [
        "target",
        "count",
        "interval",
        "timeout",
        "duration",
        "version",
        "selection",
    ] {
        let mut run = original.clone();
        let mut selections = selections.clone();
        match change {
            "target" => run.results[0].endpoint.address = "127.0.0.2:9000".into(),
            "count" => run.config.sampleCount = 4,
            "interval" => run.config.intervalMs = 500,
            "timeout" => run.config.timeoutMs = 200,
            "duration" => run.config.sessionMinutes = 30,
            "version" => run.appVersion = "0.1.1".into(),
            "selection" => selections[0].statistic = Statistic::P95Ms,
            _ => unreachable!(),
        }
        assert_ne!(
            cohortSha256(&run, &selections).unwrap(),
            plan.cohortSha256,
            "{change}"
        );
        assert!(convert(&run, &selections, &plan).is_err(), "{change}");
    }
}

#[test]
fn incompleteInconsistentOrNonfiniteRawEvidenceIsRefused() {
    let (original, selections, plan) = fixture();
    for change in [
        "unsaved",
        "unfinished",
        "protocol",
        "timestamp",
        "order",
        "target",
        "unknown",
        "missing",
        "unbalanced",
        "nan",
        "negative",
        "mixed",
        "error",
    ] {
        let mut run = original.clone();
        match change {
            "unsaved" => run.id = 0,
            "unfinished" => run.status = "cancelled".into(),
            "protocol" => run.protocol = "icmpEcho".into(),
            "timestamp" => run.samples[0].timestamp = "2026-11-01T02:00:00Z".into(),
            "order" => run.samples[0].timestamp = "2026-11-01T01:00:01.500Z".into(),
            "target" => run.samples[0].address = "127.0.0.2:9000".into(),
            "unknown" => run.samples[0].endpointId = "absent".into(),
            "missing" => {
                run.samples.pop();
            }
            "unbalanced" => {
                run.samples[0].endpointId = "server1".into();
                run.samples[0].address = run.results[1].endpoint.address.clone();
            }
            "nan" => run.samples[0].connectMs = Some(f64::NAN),
            "negative" => run.samples[0].connectMs = Some(-1.0),
            "mixed" => run.samples[0].echo = Some(echo(EchoStatus::Reply)),
            "error" => run.samples[0].error = Some("inconsistent error".into()),
            _ => unreachable!(),
        }
        assert!(convert(&run, &selections, &plan).is_err(), "{change}");
    }
}

fn echo(status: EchoStatus) -> EchoOutcome {
    EchoOutcome {
        status,
        rttMs: if status == EchoStatus::Reply {
            Some(2)
        } else {
            None
        },
        rttUnitMs: 1,
        callDurationMs: 3.0,
        responder: Some("127.0.0.1".parse().unwrap()),
        responderScopeId: None,
        nativeCode: Some(0),
    }
}

#[test]
fn icmpErrorsCannotTurnIntoZeroLossOrSubmillisecondEvidence() {
    let (mut run, selections, mut plan) = fixture();
    for (index, result) in run.results.iter_mut().enumerate() {
        result.endpoint.address = format!("127.0.0.{}", index + 1);
        result.endpoint.protocol = ProbeProtocol::IcmpEcho;
    }
    for sample in &mut run.samples {
        let endpoint = &run
            .results
            .iter()
            .find(|result| result.endpoint.id == sample.endpointId)
            .unwrap()
            .endpoint;
        sample.address = endpoint.address.clone();
        sample.connectMs = None;
        let mut outcome = echo(EchoStatus::Reply);
        outcome.responder = Some(sample.address.parse().unwrap());
        sample.echo = Some(outcome);
    }
    run.protocol = "icmpEcho".into();
    plan.cohortSha256 = cohortSha256(&run, &selections).unwrap();
    assert_eq!(
        convert(&run, &selections, &plan).unwrap().values,
        vec![2.0, 0.0]
    );
    plan.metrics[0].resolution = 0.1;
    assert!(convert(&run, &selections, &plan).is_err());
    plan.metrics[0].resolution = 1.0;
    run.samples[0].echo = Some(echo(EchoStatus::OsError));
    run.samples[0].error = Some("fixture OS error".into());
    assert!(
        convert(&run, &selections, &plan)
            .unwrap_err()
            .to_string()
            .contains("unavailable")
    );
    run.samples[0].echo = Some(echo(EchoStatus::TimedOut));
    assert!((convert(&run, &selections, &plan).unwrap().values[1] - 100.0 / 3.0).abs() < 1e-12);
}

#[test]
fn dnsLookupTimingAndNegativeAnswersRemainSeparate() {
    use crate::dns::{Answer, CacheMode, DnsOutcome, QueryPlan, RecordType, Transport};
    let (mut run, selections, mut plan) = fixture();
    let query = QueryPlan {
        name: "example.com".into(),
        recordType: RecordType::A,
    };
    for result in &mut run.results {
        result.endpoint.protocol = ProbeProtocol::DnsLookup;
        result.endpoint.dnsQuery = Some(query.clone());
    }
    for sample in &mut run.samples {
        let time = sample.connectMs.take();
        sample.dns = Some(DnsOutcome {
            query: query.clone(),
            cacheMode: CacheMode::DirectResolverCacheUnknown,
            status: DnsStatus::Resolved,
            transport: Transport::Udp,
            lookupMs: time,
            responseMs: time,
            responseCode: Some(0),
            authenticatedDataReported: Some(false),
            recursionAvailable: Some(true),
            answers: vec![Answer {
                owner: "example.com.".into(),
                address: "192.0.2.1".parse().unwrap(),
                ttlSeconds: 60,
            }],
            aliases: vec![],
            rejectedResponses: 0,
            requestBytes: 29,
            responseBytes: 45,
            error: None,
        });
    }
    run.protocol = "dnsLookup".into();
    plan.cohortSha256 = cohortSha256(&run, &selections).unwrap();
    assert_eq!(
        convert(&run, &selections, &plan).unwrap().values,
        vec![11.0, 0.0]
    );
    let dns = run.samples[0].dns.as_mut().unwrap();
    dns.status = DnsStatus::NxDomain;
    dns.lookupMs = None;
    dns.responseCode = Some(3);
    dns.answers.clear();
    dns.error = Some("fixture negative answer".into());
    run.samples[0].error = Some("fixture negative answer".into());
    let session = convert(&run, &selections, &plan).unwrap();
    assert_eq!(session.values[0], 11.5);
    assert!((session.values[1] - 100.0 / 3.0).abs() < 1e-12);
    run.samples[0].dns.as_mut().unwrap().lookupMs = Some(0.0);
    assert!(convert(&run, &selections, &plan).is_err());
    run.samples[0].dns.as_mut().unwrap().lookupMs = None;
    run.samples[0].dns.as_mut().unwrap().query.name = "different.example".into();
    assert!(convert(&run, &selections, &plan).is_err());
}
