use super::*;

struct RefuseTarget;

impl TargetGuard for RefuseTarget {
    fn validateTarget(&self, _: &Snapshot) -> ServiceResult<()> {
        Err("test target refused before native access".into())
    }
}

#[test]
fn dispatchRejectsCandidateWritesAndAuthorizationBeforeNativeAccess() {
    let capture = crate::mtu::policy::tests::fixture();
    let document = MtuCheckpoint {
        schemaVersion: 4,
        id: Uuid::new_v4(),
        createdAtUnixMs: 1000,
        leaseExpiresAtUnixMs: 2000,
        authorizedUserSid: "S-1-5-21-1-2-3-1000".into(),
        context: capture.native.journalContext().unwrap(),
        addressFamily: capture.native.addressFamily,
        originalMtu: 1500,
        proposedMtu: 1400,
        nativeOriginal: Some(capture.native.clone()),
        policyOriginal: Some(capture.evidence()),
    };
    let observed = Observation {
        context: document.context.clone(),
        addressFamily: document.addressFamily,
        mtu: 1400,
        native: Some(capture.native),
    };
    let mut dispatch = Dispatch::new(&RefuseTarget);
    for action in [
        AuthorizationAction::Prepare,
        AuthorizationAction::Apply,
        AuthorizationAction::Retain,
    ] {
        assert!(dispatch.authorize(&document, action, 1001).is_err());
    }
    assert!(dispatch.checkAuthorization(&document, 1001).is_err());
    let mut registered = false;
    for (purpose, value) in [
        (WritePurpose::Apply, 1400),
        (WritePurpose::Apply, 1500),
        (WritePurpose::Restore, 1400),
    ] {
        assert!(
            dispatch
                .writeMtu(&document, &observed, value, purpose, &mut |_| {
                    registered = true;
                    Ok(())
                })
                .unwrap_err()
                .to_string()
                .contains("exact original")
        );
    }
    assert!(!registered);
    assert!(
        dispatch
            .observe(&document)
            .unwrap_err()
            .to_string()
            .contains("test target refused")
    );
    assert!(
        dispatch
            .observePolicy(&document, PolicyPurpose::VerifyRestored)
            .unwrap_err()
            .to_string()
            .contains("test target refused")
    );
}

#[test]
fn eachCheckpointHasItsOwnGuidFamilyAndDriverGuard() {
    struct AcceptTarget;
    impl TargetGuard for AcceptTarget {
        fn validateTarget(&self, _: &Snapshot) -> ServiceResult<()> {
            Ok(())
        }
    }
    let original = crate::mtu::policy::tests::fixture().native;
    let target = ScopedTarget {
        original: &original,
        guard: &AcceptTarget,
    };
    target.validateTarget(&original).unwrap();
    let mut other = original.clone();
    other.adapterGuid = Uuid::new_v4();
    assert!(target.validateTarget(&other).is_err());
    other = original.clone();
    other.addressFamily = crate::journal::AddressFamily::Ipv6;
    assert!(target.validateTarget(&other).is_err());
    other = original.clone();
    other.os.build += 1;
    assert!(target.validateTarget(&other).is_err());
    other = original.clone();
    if let mtu::DriverContext::Captured { identity } = &mut other.driver {
        identity.version.push_str(".changed");
    }
    assert!(target.validateTarget(&other).is_err());
}

#[cfg(feature = "native-recovery")]
#[test]
#[ignore = "requires explicit disposable hosted service recovery lab acknowledgement"]
fn installedRecoveryJournalFixture() {
    assert_eq!(
        std::env::var("EPP_RECOVERY_LAB_ACK").unwrap(),
        "owned-loopback-recovery-only"
    );
    assert_eq!(std::env::var("GITHUB_ACTIONS").unwrap(), "true");
    assert_eq!(
        std::env::var("RUNNER_ENVIRONMENT").unwrap(),
        "github-hosted"
    );
    let guid: Uuid = std::env::var("EPP_RECOVERY_LAB_GUID")
        .unwrap()
        .parse()
        .unwrap();
    let path = std::path::PathBuf::from(std::env::var_os("EPP_RECOVERY_LAB_PATH").unwrap());
    let phase = std::env::var("EPP_RECOVERY_LAB_PHASE").unwrap();
    let mut journal = Journal::open(&path).unwrap();
    for (index, family) in [
        crate::journal::AddressFamily::Ipv4,
        crate::journal::AddressFamily::Ipv6,
    ]
    .into_iter()
    .enumerate()
    {
        let id = Uuid::from_u128(guid.as_u128() ^ (0x45505001 + index as u128));
        if phase == "seed" {
            let capture = mtu::policy::inspect(guid, family, &AtomicBool::new(false)).unwrap();
            assert_eq!(capture.native.alias, format!("epp-recovery-lab-{guid}"));
            let mtu::DriverContext::Captured { identity } = &capture.native.driver else {
                panic!("missing owned driver");
            };
            assert!(identity.infPath.eq_ignore_ascii_case("netloop.inf"));
            assert!(
                identity
                    .deviceInstanceId
                    .to_ascii_uppercase()
                    .starts_with("ROOT\\NET\\")
            );
            assert_eq!(capture.native.settings.nlMtu, 1500);
            let now = crate::transport::nowUnixMs().unwrap();
            let document = MtuCheckpoint {
                schemaVersion: 4,
                id,
                createdAtUnixMs: now,
                leaseExpiresAtUnixMs: now + 1000,
                authorizedUserSid: std::env::var("EPP_RECOVERY_LAB_OWNER").unwrap(),
                context: capture.native.journalContext().unwrap(),
                addressFamily: family,
                originalMtu: 1500,
                proposedMtu: 1372,
                nativeOriginal: Some(capture.native.clone()),
                policyOriginal: Some(capture.evidence()),
            };
            let observation = Observation {
                context: document.context.clone(),
                addressFamily: family,
                mtu: 1500,
                native: Some(capture.native),
            };
            journal.prepare(document, now).unwrap();
            journal
                .transition(id, State::Prepared, State::Applying, now, Some(observation))
                .unwrap();
        } else if phase == "verify" {
            let checkpoint = journal.load(id).unwrap();
            assert_eq!(checkpoint.state(), State::Restored);
            assert_eq!(journal.mutators(id).unwrap().len(), 1);
            assert_eq!(checkpoint.policyVerifications().len(), 1);
            assert!(checkpoint.policyVerifications()[0].matchesOriginal);
            assert_eq!(checkpoint.document().originalMtu, 1500);
            assert_eq!(
                mtu::capture(guid, family, &AtomicBool::new(false))
                    .unwrap()
                    .settings
                    .nlMtu,
                1500
            );
        } else {
            panic!("unsupported hosted recovery fixture phase");
        }
    }
    if phase == "verify" {
        assert!(journal.pendingRecovery().unwrap().is_empty());
        assert!(journal.pendingPolicyVerification().unwrap().is_empty());
    }
}
