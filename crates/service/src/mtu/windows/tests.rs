use super::*;
use crate::mtu::DriverContext;

#[test]
fn nativeGuidMappingAndReadOnlyRowsPreserveExactValues() {
    let expected = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
    let native = nativeGuid(expected);
    assert_eq!(native.data1, 0x00112233);
    assert_eq!(native.data2, 0x4455);
    assert_eq!(native.data3, 0x6677);
    assert_eq!(
        native.data4,
        [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    );
    assert_eq!(uuid(native), expected);
    let row = MIB_IPINTERFACE_ROW {
        NlMtu: u32::MAX,
        Metric: u32::MAX,
        UseAutomaticMetric: true,
        DisableDefaultRoutes: true,
        ZoneIndices: [u32::MAX; 16],
        ..Default::default()
    };
    let captured = settings(&row);
    assert_eq!(captured.nlMtu, u32::MAX);
    assert_eq!(captured.metric, u32::MAX);
    assert_eq!(captured.zoneIndices, [u32::MAX; 16]);
    assert!(captured.useAutomaticMetric && captured.disableDefaultRoutes);
    let encoded = serde_json::to_string(&captured).unwrap();
    let decoded: InterfaceSettings = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, captured);
}

#[test]
fn cancellationAndUnknownIdentitiesCannotProducePartialNativeCaptures() {
    assert!(inventory(&AtomicBool::new(true)).is_err());
    assert!(capture(Uuid::nil(), AddressFamily::Ipv4, &AtomicBool::new(false)).is_err());
    assert!(
        capture(
            Uuid::from_u128(0x123456789abc4def123456789abcdef0),
            AddressFamily::Ipv4,
            &AtomicBool::new(false)
        )
        .is_err()
    );
    assert!(fixedText(&[0xd800, 0]).is_err());
    assert!(fixedText(&[1, 2]).is_err());
    let guid = Uuid::from_u128(1);
    assert!(crate::mtu::captureMany(&[guid, guid], &AtomicBool::new(false)).is_err());
    assert!(crate::mtu::captureMany(&[Uuid::nil()], &AtomicBool::new(false)).is_err());
    assert!(crate::mtu::captureMany(&[guid], &AtomicBool::new(true)).is_err());
}

#[test]
fn realNativeMtuCaptureMatchesTheCurrentInterfaceWithoutWriting() {
    let entries = inventory(&AtomicBool::new(false)).unwrap();
    assert!(!entries.is_empty());
    let mut captured = 0;
    for entry in entries {
        if let Some(snapshot) = entry.snapshot {
            captured += 1;
            assert_eq!(entry.adapterGuid, Some(snapshot.adapterGuid));
            assert_eq!(entry.interfaceIndex, snapshot.interfaceIndex);
            assert!(
                snapshot.os.major >= 10 && snapshot.os.build > 0 && snapshot.capturedAtUnixMs > 0
            );
            let luid = snapshot.interfaceLuid.parse::<u64>().unwrap();
            let mut row = MIB_IPINTERFACE_ROW {
                Family: family(snapshot.addressFamily),
                InterfaceLuid: NET_LUID_LH { Value: luid },
                ..Default::default()
            };
            errorCode("Test GetIpInterfaceEntry", unsafe {
                GetIpInterfaceEntry(&mut row)
            })
            .unwrap();
            assert_eq!(row.NlMtu, snapshot.settings.nlMtu);
            let saved: Snapshot =
                serde_json::from_str(&serde_json::to_string(&snapshot).unwrap()).unwrap();
            assert_eq!(saved, snapshot);
            match snapshot.driver {
                DriverContext::Captured { identity } => {
                    assert!(!identity.version.is_empty() && !identity.deviceInstanceId.is_empty())
                }
                DriverContext::Unavailable { error } => assert!(!error.is_empty()),
            };
        } else {
            assert!(entry.error.as_ref().is_some_and(|error| !error.is_empty()));
        }
    }
    assert!(
        captured > 0,
        "Expected at least one GUID-bound native IP interface on the Windows test host"
    );
}
