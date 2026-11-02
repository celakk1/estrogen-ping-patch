use super::*;
use crate::recovery::only::RecoveryOnly;

fn applied(id: u128, tracked: bool) -> (Fixture, Journal, Backend, Arc<AtomicU64>, MtuCheckpoint) {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let clock = Arc::new(AtomicU64::new(1000));
    let mut backend = fixture.backend(clock.clone());
    let mut document = document(id);
    if tracked {
        document.schemaVersion = 3;
    }
    let mut coordinator = MtuCoordinator::new(&mut journal, &mut backend, || {
        Ok(clock.load(Ordering::SeqCst))
    });
    coordinator.prepare(document.clone()).unwrap();
    assert!(matches!(
        coordinator.apply(document.id).unwrap(),
        ApplyResult::Applied { .. }
    ));
    (fixture, journal, backend, clock, document)
}

#[test]
fn pendingOriginalRestoresAfterPermissionRevocationAndLeaseExpiry() {
    let (_fixture, mut journal, mut backend, clock, document) = applied(910, false);
    backend.allow = false;
    clock.store(20_000, Ordering::SeqCst);
    let mut recovery = RecoveryOnly::capture(&journal, &mut backend).unwrap();
    let results = MtuCoordinator::new(&mut journal, &mut recovery, || {
        Ok(clock.load(Ordering::SeqCst))
    })
    .restoreAllPending()
    .unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].originalMtuVerified && results[0].journalFinalized);
    assert!(journal.pendingRecovery().unwrap().is_empty());
    drop(recovery);
    assert_eq!(
        backend.writes,
        vec![(1400, WritePurpose::Apply), (1500, WritePurpose::Restore)]
    );
    assert_eq!(journal.load(document.id).unwrap().state(), State::Restored);
}

#[test]
fn recoveryCannotAuthorizeOrWriteAnyCandidateEvenWhenInnerBackendAllowsIt() {
    let (_fixture, journal, mut backend, _clock, document) = applied(911, false);
    let mut recovery = RecoveryOnly::capture(&journal, &mut backend).unwrap();
    let observed = recovery.observe(&document).unwrap();
    for action in [
        AuthorizationAction::Prepare,
        AuthorizationAction::Apply,
        AuthorizationAction::Retain,
    ] {
        assert!(recovery.authorize(&document, action, 1001).is_err());
    }
    assert!(recovery.checkAuthorization(&document, 1001).is_err());
    let mut registered = false;
    for (purpose, value) in [
        (WritePurpose::Apply, 1400),
        (WritePurpose::Apply, 1500),
        (WritePurpose::Restore, 1400),
    ] {
        assert!(
            recovery
                .writeMtu(&document, &observed, value, purpose, &mut |_| {
                    registered = true;
                    Ok(())
                })
                .is_err()
        );
    }
    assert!(!registered);
    drop(recovery);
    assert_eq!(backend.writes, vec![(1400, WritePurpose::Apply)]);
}

#[test]
fn newChangedAndAlreadyCompletedCheckpointsAreOutsideRecoveryScope() {
    let (_fixture, mut journal, mut backend, clock, document) = applied(912, false);
    let mut recovery = RecoveryOnly::capture(&journal, &mut backend).unwrap();
    let mut changed = document.clone();
    changed.leaseExpiresAtUnixMs += 1;
    assert!(
        recovery
            .observe(&changed)
            .unwrap_err()
            .to_string()
            .contains("new or changed")
    );
    let mut unknown = document.clone();
    unknown.id = Uuid::from_u128(913);
    assert!(recovery.observe(&unknown).is_err());
    assert!(
        recovery
            .observePolicy(&changed, PolicyPurpose::VerifyRestored)
            .unwrap_err()
            .to_string()
            .contains("new or changed")
    );
    MtuCoordinator::new(&mut journal, &mut recovery, || {
        Ok(clock.load(Ordering::SeqCst))
    })
    .restoreAllPending()
    .unwrap();
    drop(recovery);
    let mut empty = RecoveryOnly::capture(&journal, &mut backend).unwrap();
    assert!(empty.observe(&document).is_err());
}

#[test]
fn mutatorMustMatchTheFrozenCheckpointBeforeItsExitCanBeAccepted() {
    let (_fixture, journal, mut backend, _clock, document) = applied(914, true);
    let record = journal.mutators(document.id).unwrap().remove(0);
    backend.mutatorLive = true;
    let mut recovery = RecoveryOnly::capture(&journal, &mut backend).unwrap();
    let mut foreign = record.clone();
    foreign.checkpointId = Uuid::new_v4();
    assert!(
        recovery
            .waitForMutator(&foreign)
            .unwrap_err()
            .to_string()
            .contains("outside")
    );
    foreign = record.clone();
    foreign.checkpointSha256 = "0".repeat(64);
    assert!(
        recovery
            .waitForMutator(&foreign)
            .unwrap_err()
            .to_string()
            .contains("frozen")
    );
    assert!(
        recovery
            .waitForMutator(&record)
            .unwrap_err()
            .to_string()
            .contains("predecessor")
    );
    drop(recovery);
    backend.mutatorLive = false;
    RecoveryOnly::capture(&journal, &mut backend)
        .unwrap()
        .waitForMutator(&record)
        .unwrap();
}
