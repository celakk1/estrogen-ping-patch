use super::*;
use crate::{authorization::tests::Fixture, mtu::Snapshot};
use std::sync::atomic::AtomicUsize;

const OWNER: &str = "S-1-5-21-1-2-3-1000";
const OTHER: &str = "S-1-5-21-1-2-3-1001";

struct RefuseTarget(AtomicUsize);
impl TargetGuard for RefuseTarget {
    fn validateTarget(&self, _: &Snapshot) -> ServiceResult<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err("test target refused before native access".into())
    }
}

fn document() -> MtuCheckpoint {
    let mut capture = crate::mtu::policy::tests::fixture();
    let now = nowUnixMs().unwrap();
    capture.native.capturedAtUnixMs = now;
    MtuCheckpoint {
        schemaVersion: 4,
        id: Uuid::new_v4(),
        createdAtUnixMs: now,
        leaseExpiresAtUnixMs: now + 120_000,
        authorizedUserSid: OWNER.into(),
        context: capture.native.journalContext().unwrap(),
        addressFamily: capture.native.addressFamily,
        originalMtu: capture.native.settings.nlMtu,
        proposedMtu: 1400,
        policyOriginal: Some(capture.evidence()),
        nativeOriginal: Some(capture.native),
    }
}

fn observation(document: &MtuCheckpoint) -> Observation {
    Observation {
        context: document.context.clone(),
        addressFamily: document.addressFamily,
        mtu: document.originalMtu,
        native: document.nativeOriginal.clone(),
    }
}

#[test]
fn foreignMutatorIdentityCannotReachTheProcessBarrier() {
    let document = document();
    let guard = RefuseTarget(AtomicUsize::new(0));
    let stop = AtomicBool::new(false);
    let mut backend = NativeBackend::new(&document, &guard, &stop, None, Instant::now()).unwrap();
    let mut record = MutatorRecord {
        schemaVersion: 1,
        checkpointId: Uuid::new_v4(),
        checkpointSha256: crate::authorization::checkpointChecksum(&document).unwrap(),
        sequence: 0,
        registeredAtUnixMs: document.createdAtUnixMs,
        purpose: WritePurpose::Apply,
        identity: crate::journal::MutatorIdentity {
            processId: u32::MAX,
            creationTime100ns: "1".into(),
        },
        previousSha256: "0".repeat(64),
    };
    assert!(
        backend
            .waitForMutator(&record)
            .unwrap_err()
            .to_string()
            .contains("bound checkpoint")
    );
    record.checkpointId = document.id;
    record.checkpointSha256 = "0".repeat(64);
    assert!(
        backend
            .waitForMutator(&record)
            .unwrap_err()
            .to_string()
            .contains("bound checkpoint")
    );
    assert_eq!(guard.0.load(Ordering::SeqCst), 0);
}

#[test]
fn differentCheckpointCannotReachNativeObservationPolicyOrWrite() {
    let document = document();
    let mut changed = document.clone();
    changed.leaseExpiresAtUnixMs += 1;
    let guard = RefuseTarget(AtomicUsize::new(0));
    let stop = AtomicBool::new(false);
    let mut backend = NativeBackend::new(
        &document,
        &guard,
        &stop,
        None,
        Instant::now() + Duration::from_secs(60),
    )
    .unwrap();
    assert!(backend.observe(&changed).is_err());
    assert!(
        backend
            .observePolicy(&changed, PolicyPurpose::VerifyRestored)
            .is_err()
    );
    assert!(
        backend
            .authorize(
                &changed,
                AuthorizationAction::Prepare,
                changed.createdAtUnixMs
            )
            .is_err()
    );
    let mut registered = false;
    assert!(
        backend
            .writeMtu(
                &changed,
                &observation(&document),
                document.originalMtu,
                WritePurpose::Restore,
                &mut |_| {
                    registered = true;
                    Ok(())
                }
            )
            .is_err()
    );
    assert!(!registered);
    assert_eq!(guard.0.load(Ordering::SeqCst), 0);
}

#[test]
fn missingGrantBlocksApplyBeforeTargetAccessOrProcessRegistration() {
    let document = document();
    let guard = RefuseTarget(AtomicUsize::new(0));
    let stop = AtomicBool::new(false);
    let mut backend = NativeBackend::new(
        &document,
        &guard,
        &stop,
        None,
        Instant::now() + Duration::from_secs(60),
    )
    .unwrap();
    assert!(
        backend
            .authorize(
                &document,
                AuthorizationAction::Prepare,
                document.createdAtUnixMs
            )
            .unwrap_err()
            .to_string()
            .contains("live grant")
    );
    let mut registered = false;
    assert!(
        backend
            .writeMtu(
                &document,
                &observation(&document),
                1400,
                WritePurpose::Apply,
                &mut |_| {
                    registered = true;
                    Ok(())
                }
            )
            .unwrap_err()
            .to_string()
            .contains("live grant")
    );
    assert!(!registered);
    assert_eq!(guard.0.load(Ordering::SeqCst), 0);
}

#[test]
fn exactRecoveryDoesNotDependOnGrantStopFlagOrExpiredTrialDeadline() {
    let mut document = document();
    document.createdAtUnixMs -= 130_000;
    document.leaseExpiresAtUnixMs = document.createdAtUnixMs + 120_000;
    document.nativeOriginal.as_mut().unwrap().capturedAtUnixMs = document.createdAtUnixMs;
    let guard = RefuseTarget(AtomicUsize::new(0));
    let stop = AtomicBool::new(true);
    let expired = Instant::now();
    let mut backend = NativeBackend::new(&document, &guard, &stop, None, expired).unwrap();
    assert!(backend.commandDeadline(WritePurpose::Apply).unwrap() <= expired);
    assert!(backend.commandDeadline(WritePurpose::Restore).unwrap() > expired);
    let mut registered = false;
    let error = backend
        .writeMtu(
            &document,
            &observation(&document),
            document.originalMtu,
            WritePurpose::Restore,
            &mut |_| {
                registered = true;
                Ok(())
            },
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("test target refused"), "{error}");
    assert_eq!(guard.0.load(Ordering::SeqCst), 1);
    assert!(!registered);
    backend.limitCommandDeadline(expired);
    backend.limitCommandDeadline(expired + Duration::from_secs(10));
    assert!(backend.commandDeadline(WritePurpose::Restore).unwrap() <= expired);
}

#[test]
fn authorizationUsesActualStoreOwnerClaimRevocationAndNoRetention() {
    fn requireSend<T: Send>() {}
    requireSend::<NativeBackend<'_>>();
    let document = document();
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let grant = store
        .issue(&document, OWNER, false, document.createdAtUnixMs)
        .unwrap();
    let guard = RefuseTarget(AtomicUsize::new(0));
    let stop = AtomicBool::new(false);
    assert!(
        NativeBackend::new(
            &document,
            &guard,
            &stop,
            Some(ApplyAuthorization {
                store: &mut store,
                grantId: grant.id,
                actorSid: OTHER
            }),
            Instant::now() + Duration::from_secs(60)
        )
        .is_err()
    );
    let mut backend = NativeBackend::new(
        &document,
        &guard,
        &stop,
        Some(ApplyAuthorization {
            store: &mut store,
            grantId: grant.id,
            actorSid: OWNER,
        }),
        Instant::now() + Duration::from_secs(60),
    )
    .unwrap();
    backend
        .authorize(
            &document,
            AuthorizationAction::Prepare,
            document.createdAtUnixMs + 1,
        )
        .unwrap();
    backend
        .authorize(
            &document,
            AuthorizationAction::Apply,
            document.createdAtUnixMs + 2,
        )
        .unwrap();
    backend
        .checkAuthorization(&document, document.createdAtUnixMs + 3)
        .unwrap();
    assert!(
        backend
            .authorize(
                &document,
                AuthorizationAction::Retain,
                document.createdAtUnixMs + 3
            )
            .is_err()
    );
    stop.store(true, Ordering::SeqCst);
    assert!(
        backend
            .checkAuthorization(&document, document.createdAtUnixMs + 3)
            .is_err()
    );
    stop.store(false, Ordering::SeqCst);
    backend
        .authorization
        .as_mut()
        .unwrap()
        .store
        .revoke(grant.id, OWNER, document.createdAtUnixMs + 4)
        .unwrap();
    assert!(
        backend
            .checkAuthorization(&document, document.createdAtUnixMs + 5)
            .is_err()
    );
    assert_eq!(guard.0.load(Ordering::SeqCst), 0);
}
