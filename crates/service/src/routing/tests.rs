use super::*;

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
        assert_eq!(snapshot.destination, destination);
        assert_eq!(snapshot.source.ip, destination.ip);
        assert!(snapshot.loopback);
    }
}
