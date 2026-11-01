use super::*;

fn fixture() -> Capture {
    let mut native = crate::recovery::tests::nativeFixture();
    native.schemaVersion = 2;
    native.registryOrigins = Some(crate::mtu::origins::OriginCapture::Captured {
        evidence: crate::mtu::origins::tests::fixture(native.adapterGuid),
    });
    let active = Row {
        interfaceIndex: native.interfaceIndex,
        addressFamily: 2,
        store: 1,
        compartmentId: Value {
            cimType: 19,
            value: Some(1),
        },
        values: FIELDS
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    Value {
                        cimType: 19,
                        value: Some(if name == "NlMtu" { 1500 } else { 0 }),
                    },
                )
            })
            .collect(),
    };
    Capture {
        schemaVersion: 1,
        native,
        active,
        persistent: None,
    }
}

#[test]
fn incompleteOrLegacyNativeEvidenceCannotBecomeAPolicyOriginal() {
    let mut capture = fixture();
    capture.schemaVersion = 2;
    assert!(capture.validate().is_err());
    let mut capture = fixture();
    capture.native.schemaVersion = 1;
    capture.native.registryOrigins = None;
    assert!(capture.validate().is_err());
    let mut capture = fixture();
    capture.native.registryOrigins = Some(crate::mtu::origins::OriginCapture::Unavailable {
        error: "fixture unavailable".into(),
    });
    assert!(capture.validate().is_err());
    let mut capture = fixture();
    capture.native.driver = crate::mtu::DriverContext::Unavailable {
        error: "fixture missing driver".into(),
    };
    assert!(capture.validate().is_err());
}

#[test]
fn missingPersistentRowsNullValuesAndStoredValuesRemainDistinct() {
    let missing = fixture();
    let mut null = missing.clone();
    let mut persistent = null.active.clone();
    persistent.store = 0;
    persistent.values.get_mut("NlMtu").unwrap().value = None;
    null.persistent = Some(persistent);
    let mut stored = null.clone();
    stored
        .persistent
        .as_mut()
        .unwrap()
        .values
        .get_mut("NlMtu")
        .unwrap()
        .value = Some(1400);
    for capture in [&missing, &null, &stored] {
        capture.validate().unwrap();
        let encoded = serde_json::to_vec(capture).unwrap();
        assert_eq!(
            serde_json::from_slice::<Capture>(&encoded).unwrap(),
            *capture
        );
    }
    assert_ne!(missing, null);
    assert_ne!(null, stored);
    assert_eq!(null.persistent.unwrap().values["NlMtu"].value, None);
}

#[test]
fn wrongStoresIdentityFieldsOrActiveMtuCannotBecomePolicyEvidence() {
    for fault in 0..8 {
        let mut capture = fixture();
        match fault {
            0 => capture.active.store = 0,
            1 => capture.active.interfaceIndex += 1,
            2 => capture.active.addressFamily = 23,
            3 => capture.active.compartmentId.value = None,
            4 => capture.active.compartmentId.value = Some(2),
            5 => capture.active.values.get_mut("NlMtu").unwrap().value = None,
            6 => capture.active.values.get_mut("NlMtu").unwrap().value = Some(1400),
            _ => {
                capture.active.values.remove("Dhcp");
            }
        }
        assert!(capture.validate().is_err(), "fault {fault}");
    }
    let mut capture = fixture();
    capture.active.values.insert(
        "UnsupportedField".into(),
        Value {
            cimType: 19,
            value: Some(1),
        },
    );
    assert!(capture.validate().is_err());
    let mut capture = fixture();
    capture.persistent = Some(capture.active.clone());
    assert!(capture.validate().is_err());
}

#[test]
fn unsupportedCimTypesAndTruncatedScalarRangesAreRefusedWithoutGuessingDefaults() {
    for (cimType, value) in [
        (0, None),
        (8, Some(1)),
        (17, Some(256)),
        (18, Some(65536)),
        (19 | 0x2000, None),
    ] {
        assert!(Value { cimType, value }.validate().is_err());
    }
    for (cimType, maximum) in [(17, 255), (18, 65535), (19, u32::MAX)] {
        Value {
            cimType,
            value: None,
        }
        .validate()
        .unwrap();
        Value {
            cimType,
            value: Some(0),
        }
        .validate()
        .unwrap();
        Value {
            cimType,
            value: Some(maximum),
        }
        .validate()
        .unwrap();
    }
}

#[cfg(windows)]
#[test]
fn isolatedResponseMustBeCompleteAndMatchTheRequestedTarget() {
    let capture = fixture();
    let bytes = serde_json::to_vec(&capture).unwrap();
    let guid = capture.native.adapterGuid;
    let family = capture.native.addressFamily;
    assert_eq!(decode(&bytes, guid, family).unwrap(), capture);
    assert!(decode(&bytes, uuid::Uuid::new_v4(), family).is_err());
    assert!(decode(&bytes, guid, crate::journal::AddressFamily::Ipv6).is_err());
    assert!(decode(&bytes[..bytes.len() - 1], guid, family).is_err());
    let mut unknown = serde_json::to_value(&capture).unwrap();
    unknown["unknownField"] = true.into();
    assert!(decode(&serde_json::to_vec(&unknown).unwrap(), guid, family).is_err());
    let mut extra = bytes;
    extra.extend_from_slice(b"{}");
    assert!(decode(&extra, guid, family).is_err());
    assert!(inspect(guid, family, &AtomicBool::new(true)).is_err());
    assert!(
        inspect(guid, family, &AtomicBool::new(false))
            .unwrap_err()
            .to_string()
            .contains("dedicated service executable")
    );
}
