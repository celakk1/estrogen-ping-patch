use super::*;

fn cohort() -> (Vec<Endpoint>, Vec<SourceBinding>) {
    let endpoints = vec![
        Endpoint {
            id: "local4".into(),
            address: "127.0.0.1".into(),
            protocol: ProbeProtocol::IcmpEcho,
            dnsQuery: None,
        },
        Endpoint {
            id: "local6".into(),
            address: "::1".into(),
            protocol: ProbeProtocol::IcmpEcho,
            dnsQuery: None,
        },
    ];
    let bindings = endpoints
        .iter()
        .map(|endpoint| SourceBinding {
            endpointId: endpoint.id.clone(),
            source: EchoTarget::parse(&endpoint.address).unwrap(),
        })
        .collect();
    (endpoints, bindings)
}

#[test]
fn bindingValidationRefusesMissingReorderedWrongFamilyAndNonEchoSourcesBeforeTraffic() {
    let (endpoints, bindings) = cohort();
    validateSourceBindings(&endpoints, &bindings).unwrap();
    assert!(validateSourceBindings(&endpoints, &bindings[..1]).is_err());
    let mut changed = bindings.clone();
    changed.reverse();
    assert!(validateSourceBindings(&endpoints, &changed).is_err());
    changed = bindings.clone();
    changed[0].source = bindings[1].source.clone();
    assert!(validateSourceBindings(&endpoints, &changed).is_err());
    changed = bindings.clone();
    changed[0].source.address = "0.0.0.0".parse().unwrap();
    assert!(validateSourceBindings(&endpoints, &changed).is_err());
    let mut tcp = endpoints;
    tcp[0].protocol = ProbeProtocol::TcpConnect;
    tcp[0].address = "127.0.0.1:9".into();
    assert!(validateSourceBindings(&tcp, &bindings).is_err());
}

#[test]
fn sourceBindingsArePartOfTheCohortAndLegacyRunsKeepTheirOriginalIdentity() {
    use crate::comparison::baseline::{Selection, Statistic, cohortSha256};
    let (endpoints, bindings) = cohort();
    let mut run = runSourceBoundEchoBenchmark(
        Config::default(),
        endpoints,
        bindings,
        &AtomicBool::new(true),
        |_, _, _| {},
    )
    .unwrap();
    let selections = vec![Selection {
        metricId: "local-median".into(),
        endpointId: "local4".into(),
        statistic: Statistic::MedianMs,
    }];
    let bound = cohortSha256(&run, &selections).unwrap();
    run.sourceBindings.as_mut().unwrap()[0].source = EchoTarget::parse("127.0.0.2").unwrap();
    assert_ne!(bound, cohortSha256(&run, &selections).unwrap());
    run.sourceBindings.as_mut().unwrap()[0].endpointId = "other".into();
    assert!(cohortSha256(&run, &selections).is_err());
    run.sourceBindings = None;
    let legacy = cohortSha256(&run, &selections).unwrap();
    assert_ne!(legacy, bound);
    let value = serde_json::to_value(&run).unwrap();
    assert!(value.get("sourceBindings").is_none());
    let restored: BenchmarkRun = serde_json::from_value(value).unwrap();
    assert!(restored.sourceBindings.is_none());
    assert_eq!(cohortSha256(&restored, &selections).unwrap(), legacy);
}

#[cfg(windows)]
#[test]
fn nativeSourceBoundEchoPersistsBothFamiliesAndHonorsCancellation() {
    let (endpoints, bindings) = cohort();
    let config = Config {
        sampleCount: 3,
        intervalMs: 250,
        timeoutMs: 500,
        ..Config::default()
    };
    let cancelled = AtomicBool::new(false);
    let mut run = runSourceBoundEchoBenchmark(
        config.clone(),
        endpoints.clone(),
        bindings.clone(),
        &cancelled,
        |_, _, _| {},
    )
    .unwrap();
    assert_eq!(run.status, "completed");
    assert_eq!(run.sourceBindings.as_ref(), Some(&bindings));
    assert_eq!(run.samples.len(), 6);
    assert!(run.samples.iter().all(|sample| {
        sample
            .echo
            .as_ref()
            .is_some_and(|echo| echo.status == EchoStatus::Reply)
            && sample.connectMs.is_none()
    }));
    let directory = std::env::temp_dir().join(format!(
        "epp-bound-echo-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap()
    ));
    std::fs::create_dir(&directory).unwrap();
    {
        let mut database =
            crate::storage::openDatabase(&directory.join("measurements.sqlite3")).unwrap();
        crate::storage::saveRun(&mut database, &mut run).unwrap();
        let saved = crate::storage::history(&database, 1).unwrap().remove(0);
        assert_eq!(saved.sourceBindings.as_ref(), Some(&bindings));
        assert_eq!(saved.samples.len(), 6);
    }
    for name in [
        "measurements.sqlite3",
        "measurements.sqlite3-wal",
        "measurements.sqlite3-shm",
    ] {
        let path = directory.join(name);
        if path.exists() {
            std::fs::remove_file(path).unwrap();
        }
    }
    std::fs::remove_dir(&directory).unwrap();
    let run =
        runSourceBoundEchoBenchmark(config, endpoints, bindings, &cancelled, |_, count, _| {
            if count == 1 {
                cancelled.store(true, Ordering::SeqCst);
            }
        })
        .unwrap();
    assert_eq!(run.status, "cancelled");
    assert_eq!(run.samples.len(), 1);
    assert!(run.sourceBindings.is_some());
}

#[cfg(windows)]
#[test]
fn unavailableLocalSourceCannotFallBackToAnUnboundProbe() {
    let target = EchoTarget::parse("127.0.0.1").unwrap();
    let source = EchoTarget::parse("192.0.2.254").unwrap();
    let outcome = EchoProbe::default()
        .measureFrom(
            &source,
            &target,
            Duration::from_millis(100),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_ne!(outcome.status, EchoStatus::Reply);
    assert!(outcome.rttMs.is_none());
}
