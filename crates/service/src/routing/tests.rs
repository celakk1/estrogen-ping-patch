use super::*;

pub(crate) fn statistics(capturedAtUnixMs: u64) -> LinkStatistics {
    LinkStatistics {
        schemaVersion: 1,
        queryStartedAtUnixMs: capturedAtUnixMs.saturating_sub(2).max(1),
        queryFinishedAtUnixMs: capturedAtUnixMs,
        queryElapsedNs: "1000".into(),
        interfaceType: 6,
        operStatus: 1,
        adminStatus: 1,
        mediaConnectState: 1,
        receiveLinkSpeedBps: "1000000000".into(),
        transmitLinkSpeedBps: "1000000000".into(),
        receivedOctets: "9007199254740993".into(),
        sentOctets: u64::MAX.to_string(),
        receivedUnicastPackets: "100".into(),
        receivedNonUnicastPackets: "20".into(),
        sentUnicastPackets: "90".into(),
        sentNonUnicastPackets: "10".into(),
        receivedDiscards: "0".into(),
        receivedErrors: "0".into(),
        receivedUnknownProtocols: "0".into(),
        sentDiscards: "0".into(),
        sentErrors: "0".into(),
    }
}

#[test]
fn nativeStatisticsRemainExactWhileVolatileCountersStayOutsideRouteIdentity() {
    let original = snapshot();
    assert!(
        serde_json::to_value(&original)
            .unwrap()
            .get("linkStatistics")
            .is_none()
    );
    let captures = |snapshot| vec![Capture::Captured { snapshot }];
    let legacyDigest = fingerprint(&captures(original.clone())).unwrap();
    let mut before = original;
    before.linkStatistics = Some(Box::new(statistics(before.capturedAtUnixMs)));
    assert_eq!(
        fingerprint(&captures(before.clone())).unwrap(),
        legacyDigest
    );
    let mut after = before.clone();
    after.capturedAtUnixMs += 1000;
    let stats = after.linkStatistics.as_mut().unwrap();
    stats.queryStartedAtUnixMs += 1000;
    stats.queryFinishedAtUnixMs += 1000;
    stats.queryElapsedNs = "2000".into();
    stats.receivedOctets = "9007199254741094".into();
    stats.sentErrors = "1".into();
    stats.receiveLinkSpeedBps = "0".into();
    stats.operStatus = 2;
    assert_eq!(fingerprint(&captures(after.clone())).unwrap(), legacyDigest);
    let restored: Snapshot = serde_json::from_slice(&serde_json::to_vec(&before).unwrap()).unwrap();
    assert_eq!(restored, before);
    assert_eq!(
        restored.linkStatistics.unwrap().sentOctets,
        u64::MAX.to_string()
    );
    assert_ne!(
        serde_json::to_value(before).unwrap(),
        serde_json::to_value(after).unwrap()
    );
}

#[test]
fn malformedStatisticsCannotBecomeTrustedRouteEvidence() {
    for failure in 0..8 {
        let mut route = snapshot();
        let mut stats = statistics(route.capturedAtUnixMs);
        match failure {
            0 => stats.schemaVersion = 2,
            1 => stats.queryStartedAtUnixMs = 0,
            2 => stats.queryStartedAtUnixMs = stats.queryFinishedAtUnixMs + 1,
            3 => stats.queryFinishedAtUnixMs = route.capturedAtUnixMs + 1,
            4 => stats.queryElapsedNs = "-1".into(),
            5 => stats.receivedOctets = "01".into(),
            6 => stats.sentOctets = "+1".into(),
            _ => stats.receiveLinkSpeedBps = "18446744073709551616".into(),
        }
        route.linkStatistics = Some(Box::new(stats));
        assert!(route.validate().is_err(), "accepted statistics {failure}");
        assert!(fingerprint(&[Capture::Captured { snapshot: route }]).is_err());
    }
    let mut extra = serde_json::to_value(statistics(1000)).unwrap();
    extra["extra"] = true.into();
    assert!(serde_json::from_value::<LinkStatistics>(extra).is_err());
}

fn snapshot() -> Snapshot {
    Snapshot {
        schemaVersion: 1,
        capturedAtUnixMs: 1000,
        destination: Address {
            ip: "127.0.0.1".parse().unwrap(),
            scopeId: 0,
        },
        adapterGuid: Uuid::from_u128(123),
        interfaceLuid: "18446744073709551615".into(),
        interfaceIndex: 1,
        source: Address {
            ip: "127.0.0.1".parse().unwrap(),
            scopeId: 0,
        },
        destinationPrefix: Address {
            ip: "127.0.0.0".parse().unwrap(),
            scopeId: 0,
        },
        prefixLength: 8,
        nextHop: Address {
            ip: "0.0.0.0".parse().unwrap(),
            scopeId: 0,
        },
        routeMetric: 256,
        protocol: 2,
        origin: 0,
        sitePrefixLength: 0,
        loopback: true,
        autoconfigureAddress: false,
        publish: false,
        immortal: true,
        validLifetimeSeconds: u32::MAX,
        preferredLifetimeSeconds: u32::MAX,
        ageSeconds: 12,
        linkStatistics: None,
    }
}

#[test]
fn exactRouteEvidenceRoundTripsWithoutRoundingNativeIdentities() {
    let original = snapshot();
    original.validate().unwrap();
    let decoded: Snapshot =
        serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.interfaceLuid, "18446744073709551615");
    for (prefix, length, valid) in [
        ("0.0.0.0", 0, true),
        ("127.0.0.1", 32, true),
        ("128.0.0.0", 8, false),
        ("127.0.0.0", 33, false),
    ] {
        let mut value = original.clone();
        value.destinationPrefix.ip = prefix.parse().unwrap();
        value.prefixLength = length;
        assert_eq!(value.validate().is_ok(), valid, "{prefix}/{length}");
    }
}

#[test]
fn routeIdentityPreservesChoicesWhileIgnoringOrdinaryCountdowns() {
    let mut original = snapshot();
    original.validLifetimeSeconds = 600;
    original.preferredLifetimeSeconds = 300;
    let captures = |snapshot| vec![Capture::Captured { snapshot }];
    let digest = fingerprint(&captures(original.clone())).unwrap().unwrap();
    let mut aged = original.clone();
    aged.capturedAtUnixMs += 1000;
    aged.ageSeconds += 1;
    aged.validLifetimeSeconds -= 1;
    aged.preferredLifetimeSeconds -= 1;
    assert_eq!(
        fingerprint(&captures(aged.clone())).unwrap(),
        Some(digest.clone())
    );
    assert_eq!(original.validLifetimeSeconds, 600);
    for change in [
        "metric",
        "gateway",
        "source",
        "guid",
        "luid",
        "index",
        "expired",
        "infinite",
        "preferred",
        "protocol",
    ] {
        let mut value = original.clone();
        match change {
            "metric" => value.routeMetric += 1,
            "gateway" => value.nextHop.ip = "127.0.0.2".parse().unwrap(),
            "source" => value.source.ip = "127.0.0.2".parse().unwrap(),
            "guid" => value.adapterGuid = Uuid::from_u128(124),
            "luid" => value.interfaceLuid = "100".into(),
            "index" => value.interfaceIndex += 1,
            "expired" => value.validLifetimeSeconds = 0,
            "infinite" => value.validLifetimeSeconds = u32::MAX,
            "preferred" => value.preferredLifetimeSeconds = 0,
            "protocol" => value.protocol += 1,
            _ => unreachable!(),
        }
        assert_ne!(
            fingerprint(&captures(value)).unwrap(),
            Some(digest.clone()),
            "{change}"
        );
    }
    let unavailable = Capture::Unavailable {
        destination: original.destination.clone(),
        error: "fixture unavailable".into(),
    };
    assert!(
        fingerprint(&[Capture::Captured { snapshot: original }, unavailable])
            .unwrap()
            .is_none()
    );
    assert!(fingerprint(&[]).is_err());
}

#[test]
fn routeDestinationsRejectUnsupportedAddressingAndPreserveScope() {
    for (ip, scope, valid) in [
        ("0.0.0.0", 0, false),
        ("255.255.255.255", 0, false),
        ("224.0.0.1", 0, false),
        ("127.0.0.1", 1, false),
        ("::", 0, false),
        ("ff02::1", 1, false),
        ("::ffff:127.0.0.1", 0, false),
        ("fe80::1", 0, false),
        ("fe80::1", 12, true),
        ("::1", 0, true),
    ] {
        let address = Address {
            ip: ip.parse().unwrap(),
            scopeId: scope,
        };
        assert_eq!(address.validateDestination().is_ok(), valid, "{ip}%{scope}");
    }
    let mut value = snapshot();
    value.destination = Address {
        ip: "fe80::1234".parse().unwrap(),
        scopeId: 12,
    };
    value.source = Address {
        ip: "fe80::5678".parse().unwrap(),
        scopeId: 12,
    };
    value.destinationPrefix = Address {
        ip: "fe80::".parse().unwrap(),
        scopeId: 0,
    };
    value.prefixLength = 64;
    value.nextHop = Address {
        ip: "::".parse().unwrap(),
        scopeId: 0,
    };
    value.interfaceIndex = 12;
    value.validate().unwrap();
    value.interfaceIndex = 13;
    assert!(value.validate().is_err());
}

#[test]
fn malformedIdentityFamilyOrInterfaceBindingCannotBecomeContextEvidence() {
    for change in [
        "guid", "luid", "index", "source", "family", "schema", "time",
    ] {
        let mut value = snapshot();
        match change {
            "guid" => value.adapterGuid = Uuid::nil(),
            "luid" => value.interfaceLuid = "01".into(),
            "index" => value.interfaceIndex = 0,
            "source" => value.source.ip = "0.0.0.0".parse().unwrap(),
            "family" => value.nextHop.ip = "::".parse().unwrap(),
            "schema" => value.schemaVersion = 2,
            "time" => value.capturedAtUnixMs = 0,
            _ => unreachable!(),
        }
        assert!(value.validate().is_err(), "{change}");
    }
    let interface = crate::recovery::tests::nativeFixture();
    let mut value = snapshot();
    value.adapterGuid = interface.adapterGuid;
    value.interfaceLuid = interface.interfaceLuid.clone();
    value.interfaceIndex = interface.interfaceIndex;
    value.matchesInterface(&interface).unwrap();
    value.interfaceIndex += 1;
    assert!(value.matchesInterface(&interface).is_err());
}

#[test]
fn invalidOrCancelledCaptureCannotReturnPartialSuccess() {
    let target = Address {
        ip: "127.0.0.1".parse().unwrap(),
        scopeId: 0,
    };
    assert!(capture(&[], &AtomicBool::new(false)).is_err());
    assert!(
        capture(
            &vec![target.clone(); MAX_DESTINATIONS + 1],
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert!(capture(&[target], &AtomicBool::new(true)).is_err());
}

#[test]
#[cfg(windows)]
fn realWindowsLoopbackRouteSelectionHasGuidBoundEvidenceWithoutTraffic() {
    let destinations = [
        Address {
            ip: "127.0.0.1".parse().unwrap(),
            scopeId: 0,
        },
        Address {
            ip: "::1".parse().unwrap(),
            scopeId: 0,
        },
    ];
    let results = capture(&destinations, &AtomicBool::new(false)).unwrap();
    for (result, destination) in results.iter().zip(destinations) {
        let Capture::Captured { snapshot } = result else {
            panic!("Route inspection failed: {result:?}")
        };
        snapshot.validate().unwrap();
        snapshot
            .linkStatistics
            .as_ref()
            .expect("native route omitted adapter statistics")
            .validate(snapshot.capturedAtUnixMs)
            .unwrap();
        assert_eq!(snapshot.destination, destination);
        assert_eq!(snapshot.source.ip, destination.ip);
        assert!(snapshot.loopback);
    }
}
