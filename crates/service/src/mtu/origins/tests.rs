use super::*;

pub(crate) fn fixture(adapterGuid: Uuid) -> RegistryOrigins {
    RegistryOrigins {
        schemaVersion: 1,
        adapterGuid,
        stacks: ["Tcpip", "Tcpip6"]
            .into_iter()
            .map(|name| Stack {
                name: name.into(),
                keyPresent: true,
                values: VALUE_NAMES
                    .into_iter()
                    .map(|name| NamedValue {
                        name: name.into(),
                        value: None,
                    })
                    .collect(),
            })
            .collect(),
    }
}

#[test]
fn absentEmptyAndZeroOriginValuesRemainDistinctAndRoundTripLosslessly() {
    let absent = fixture(Uuid::from_u128(1));
    let mut empty = absent.clone();
    empty.stacks[0].values[5].value = Some(RawValue {
        valueType: 1,
        dataHex: String::new(),
    });
    let mut zero = empty.clone();
    zero.stacks[0].values[5].value.as_mut().unwrap().dataHex = "0000".into();
    let mut binary = zero.clone();
    binary.stacks[0].values[5].value.as_mut().unwrap().valueType = 3;
    for evidence in [&absent, &empty, &zero, &binary] {
        evidence.validate(evidence.adapterGuid).unwrap();
        let saved = serde_json::to_vec(evidence).unwrap();
        assert_eq!(
            serde_json::from_slice::<RegistryOrigins>(&saved).unwrap(),
            *evidence
        );
    }
    assert_ne!(absent, empty);
    assert_ne!(empty, zero);
    assert_ne!(zero, binary);
    let mut missingKey = absent.clone();
    missingKey.stacks[0].keyPresent = false;
    missingKey.validate(missingKey.adapterGuid).unwrap();
    assert_ne!(missingKey, absent);
}

#[test]
fn unknownMissingReorderedOrOversizedOriginEvidenceIsRefused() {
    let original = fixture(Uuid::from_u128(1));
    for fault in 0..9 {
        let mut evidence = original.clone();
        match fault {
            0 => evidence.adapterGuid = Uuid::from_u128(2),
            1 => evidence.schemaVersion = 2,
            2 => evidence.stacks.swap(0, 1),
            3 => {
                evidence.stacks.pop();
            }
            4 => evidence.stacks[0].values[0].name = "UnapprovedValue".into(),
            5 => {
                evidence.stacks[0].values.pop();
            }
            _ => {
                evidence.stacks[0].values[0].value = Some(RawValue {
                    valueType: 4,
                    dataHex: match fault {
                        6 => "AA".into(),
                        7 => "0".into(),
                        _ => "00".repeat(MAX_DATA_BYTES + 1),
                    },
                });
            }
        }
        assert!(
            evidence.validate(original.adapterGuid).is_err(),
            "fault {fault}"
        );
    }
    let mut evidence = original.clone();
    evidence.stacks[0].keyPresent = false;
    evidence.stacks[0].values[0].value = Some(RawValue {
        valueType: 4,
        dataHex: "00000000".into(),
    });
    assert!(evidence.validate(original.adapterGuid).is_err());
    let mut evidence = original.clone();
    for stack in &mut evidence.stacks {
        stack.values[0].value = Some(RawValue {
            valueType: 3,
            dataHex: "00".repeat(MAX_DATA_BYTES / 2 + 1),
        });
    }
    assert!(evidence.validate(original.adapterGuid).is_err());
}

#[test]
fn missingOriginalOriginsBlockPreparationButNotNativeMtuIdentityForRecovery() {
    let legacy = crate::recovery::tests::nativeFixture();
    let mut original = legacy.clone();
    original.schemaVersion = 2;
    original.registryOrigins = Some(OriginCapture::Captured {
        evidence: fixture(original.adapterGuid),
    });
    original.journalContext().unwrap();
    original.requireOriginalOrigins().unwrap();
    original.validateMtuObservation(&original).unwrap();
    let mut observed = original.clone();
    observed.settings.nlMtu = 1400;
    observed.registryOrigins = Some(OriginCapture::Unavailable {
        error: "fixture access denied".into(),
    });
    observed.journalContext().unwrap();
    observed.validateMtuIdentity(&original).unwrap();
    assert!(observed.requireOriginalOrigins().is_err());
    assert!(observed.validateMtuObservation(&original).is_err());
    observed.registryOrigins = None;
    assert!(observed.journalContext().is_err());
    observed.schemaVersion = 1;
    observed.validateMtuIdentity(&original).unwrap();
    assert!(observed.validateMtuObservation(&original).is_err());
    original.schemaVersion = 1;
    assert!(original.journalContext().is_err());
    legacy.journalContext().unwrap();
    assert!(
        serde_json::to_value(legacy)
            .unwrap()
            .get("registryOrigins")
            .is_none()
    );
}

#[test]
fn dnsAddressingAndPersistentMtuOriginDriftCannotEnterAStrictObservation() {
    let mut original = crate::recovery::tests::nativeFixture();
    original.schemaVersion = 2;
    original.registryOrigins = Some(OriginCapture::Captured {
        evidence: fixture(original.adapterGuid),
    });
    for stack in 0..2 {
        for field in 0..VALUE_NAMES.len() {
            let mut observed = original.clone();
            let Some(OriginCapture::Captured { evidence }) = &mut observed.registryOrigins else {
                unreachable!()
            };
            evidence.stacks[stack].values[field].value = Some(RawValue {
                valueType: 3,
                dataHex: "000102ff".into(),
            });
            observed.settings.nlMtu = 1400;
            observed.validateMtuIdentity(&original).unwrap();
            assert!(observed.validateMtuObservation(&original).is_err());
        }
    }
}
