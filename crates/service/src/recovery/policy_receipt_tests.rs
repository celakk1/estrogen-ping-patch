use super::*;
use sha2::{Digest, Sha256};

fn applied(fixture: &Fixture) -> (MtuCheckpoint, PolicyBackend, Journal) {
    let (document, mut backend) = setup(fixture);
    let mut journal = fixture.open();
    MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .prepare(document.clone())
        .unwrap();
    assert!(matches!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .apply(document.id)
            .unwrap(),
        ApplyResult::Applied { .. }
    ));
    (document, backend, journal)
}

fn restored(fixture: &Fixture) -> (MtuCheckpoint, PolicyBackend, Journal) {
    let (document, mut backend, mut journal) = applied(fixture);
    let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .restore(document.id)
        .unwrap();
    assert_eq!(result.policyOriginalVerified, Some(true));
    assert_eq!(result.policyVerificationRecorded, Some(true));
    (document, backend, journal)
}

#[test]
fn serviceStatusKeepsRestoredButUnverifiedCheckpointsVisibleAfterRestart() {
    for commitFailed in [false, true] {
        let fixture = Fixture::new();
        let (document, mut backend, mut journal) = applied(&fixture);
        let status = crate::protocol::CheckpointStoreStatus::fromJournal(&journal, 1000).unwrap();
        assert_eq!(status.pendingRecoveryCount, 1);
        if commitFailed {
            Connection::open(&fixture.journal).unwrap().execute_batch("CREATE TRIGGER refuse_policy_receipt BEFORE INSERT ON checkpoint_policy_checks BEGIN SELECT RAISE(FAIL,'test refused policy receipt'); END;").unwrap();
        } else {
            backend.unavailable = true;
        }
        let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .restore(document.id)
            .unwrap();
        assert!(result.originalMtuVerified && result.journalFinalized);
        drop(journal);
        let mut journal = fixture.open();
        assert!(journal.pendingRecovery().unwrap().is_empty());
        let status = crate::protocol::CheckpointStoreStatus::fromJournal(&journal, 2000).unwrap();
        assert_eq!(status.pendingRecoveryCount, 1);
        assert_eq!(status.verifiedAtUnixMs, 2000);
        if commitFailed {
            Connection::open(&fixture.journal)
                .unwrap()
                .execute_batch("DROP TRIGGER refuse_policy_receipt;")
                .unwrap();
        }
        backend.unavailable = false;
        let writes = backend.inner.writes.len();
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(2000))
            .verifyRestoredPolicy(document.id)
            .unwrap();
        assert_eq!(backend.inner.writes.len(), writes);
        let status = crate::protocol::CheckpointStoreStatus::fromJournal(&journal, 3000).unwrap();
        assert_eq!(status.pendingRecoveryCount, 0);
    }
}

#[test]
fn recoveryOnlyScopeCanFinishPendingPolicyAfterPermissionLossWithoutAnotherWrite() {
    let fixture = Fixture::new();
    let (document, mut backend, mut journal) = applied(&fixture);
    backend.unavailable = true;
    let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .restore(document.id)
        .unwrap();
    assert!(result.originalMtuVerified && result.journalFinalized);
    assert_eq!(result.policyOriginalVerified, Some(false));
    assert!(journal.pendingRecovery().unwrap().is_empty());
    drop(journal);
    let mut journal = fixture.open();
    backend.unavailable = false;
    backend.inner.allow = false;
    backend.inner.clock.store(20_000, Ordering::SeqCst);
    let writes = backend.inner.writes.clone();
    let mut recovery =
        crate::recovery::only::RecoveryOnly::capture(&journal, &mut backend).unwrap();
    let results = MtuCoordinator::new(&mut journal, &mut recovery, || Ok(20_000))
        .restoreAllPending()
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].policyOriginalVerified, Some(true));
    assert_eq!(results[0].policyVerificationRecorded, Some(true));
    drop(recovery);
    assert_eq!(backend.inner.writes, writes);
    assert!(journal.pendingPolicyVerification().unwrap().is_empty());
}

#[test]
#[ignore = "requires explicit disposable service lab acknowledgement"]
fn serviceLabPolicyCheckpoint() {
    assert_eq!(
        std::env::var("EPP_JOURNAL_LAB_ACK").unwrap(),
        "disposable-lab-no-network-setter"
    );
    let path = PathBuf::from(std::env::var_os("EPP_JOURNAL_LAB_PATH").unwrap());
    let fixture = Fixture::new();
    let (document, mut backend) = setup(&fixture);
    backend.inner.journal = path.clone();
    let mut journal = Journal::open(&path).unwrap();
    match std::env::var("EPP_JOURNAL_LAB_PHASE").unwrap().as_str() {
        "policy-pending" => {
            let mut coordinator = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000));
            coordinator.prepare(document.clone()).unwrap();
            assert!(matches!(
                coordinator.apply(document.id).unwrap(),
                ApplyResult::Applied { .. }
            ));
            backend.unavailable = true;
            let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
                .restore(document.id)
                .unwrap();
            assert!(result.originalMtuVerified && result.journalFinalized);
            assert_eq!(result.policyOriginalVerified, Some(false));
            assert!(journal.pendingRecovery().unwrap().is_empty());
            assert_eq!(journal.pendingPolicyVerification().unwrap().len(), 1);
        }
        "policy-verified" => {
            let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
                .verifyRestoredPolicy(document.id)
                .unwrap();
            assert_eq!(result.policyOriginalVerified, Some(true));
            assert!(backend.inner.writes.is_empty());
            assert!(journal.pendingPolicyVerification().unwrap().is_empty());
        }
        _ => panic!("Unknown service lab policy phase"),
    }
}

#[test]
fn matchedPolicyReceiptBindsTheOriginalAndCommittedRestoredEvent() {
    let fixture = Fixture::new();
    let (document, _, journal) = restored(&fixture);
    let checkpoint = journal.load(document.id).unwrap();
    let records = checkpoint.policyVerifications();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].checkpointSha256, checkpoint.documentSha256());
    assert_eq!(records[0].previousSha256, checkpoint.documentSha256());
    assert!(records[0].matchesOriginal);
    let connection = Connection::open(&fixture.journal).unwrap();
    let terminalHash: String = connection.query_row("SELECT sha256 FROM checkpoint_events WHERE checkpoint_id=?1 ORDER BY sequence DESC LIMIT 1", [document.id.to_string()], |row| row.get(0)).unwrap();
    assert_eq!(records[0].restoredEventSha256, terminalHash);
    let payload: String = connection
        .query_row(
            "SELECT document_json FROM checkpoint_policy_checks",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let head: String = connection
        .query_row(
            "SELECT sha256 FROM policy_heads WHERE checkpoint_id=?1",
            [document.id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(head, format!("{:x}", Sha256::digest(payload.as_bytes())));
    assert!(journal.pendingPolicyVerification().unwrap().is_empty());
}

#[test]
fn unavailablePolicySurvivesRestartBlocksNewWorkAndRetriesWithoutASettingWrite() {
    let fixture = Fixture::new();
    let (document, mut backend, mut journal) = applied(&fixture);
    backend.unavailable = true;
    let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .restore(document.id)
        .unwrap();
    assert!(result.originalMtuVerified && result.journalFinalized);
    assert_eq!(result.policyOriginalVerified, Some(false));
    assert_eq!(result.policyVerificationRecorded, Some(true));
    drop(journal);
    let mut journal = fixture.open();
    assert_eq!(journal.pendingPolicyVerification().unwrap().len(), 1);
    let checkpoint = journal.load(document.id).unwrap();
    assert!(
        matches!(&checkpoint.policyVerifications()[0].readback, PolicyReadback::Unavailable { error } if error.contains("provider unavailable"))
    );
    let mut another = document.clone();
    another.id = Uuid::new_v4();
    assert!(journal.prepare(another, 1000).is_err());
    let writes = backend.inner.writes.len();
    backend.inner.allow = false;
    backend.inner.clock.store(20000, Ordering::SeqCst);
    backend.unavailable = false;
    let results = MtuCoordinator::new(&mut journal, &mut backend, || Ok(20000))
        .restoreAllPending()
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].policyOriginalVerified, Some(true));
    assert_eq!(results[0].policyVerificationRecorded, Some(true));
    assert_eq!(backend.inner.writes.len(), writes);
    assert_eq!(journal.mutators(document.id).unwrap().len(), 2);
    assert_eq!(
        journal
            .load(document.id)
            .unwrap()
            .policyVerifications()
            .len(),
        2
    );
    assert!(journal.pendingPolicyVerification().unwrap().is_empty());
    assert!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(20000))
            .verifyRestoredPolicy(document.id)
            .is_err()
    );
}

#[test]
fn failedReceiptCommitLeavesRestoredMtuAndPendingVerificationWithoutFabricatedSuccess() {
    let fixture = Fixture::new();
    let (document, mut backend, mut journal) = applied(&fixture);
    Connection::open(&fixture.journal).unwrap().execute_batch("CREATE TRIGGER refuse_policy_receipt BEFORE INSERT ON checkpoint_policy_checks BEGIN SELECT RAISE(FAIL, 'simulated receipt commit failure'); END;").unwrap();
    let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .restore(document.id)
        .unwrap();
    assert!(result.originalMtuVerified && result.journalFinalized);
    assert_eq!(result.policyOriginalVerified, Some(true));
    assert_eq!(result.policyVerificationRecorded, Some(false));
    assert!(result.error.unwrap().contains("not durably recorded"));
    assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
    assert!(
        journal
            .load(document.id)
            .unwrap()
            .policyVerifications()
            .is_empty()
    );
    assert_eq!(journal.pendingPolicyVerification().unwrap().len(), 1);
    Connection::open(&fixture.journal)
        .unwrap()
        .execute_batch("DROP TRIGGER refuse_policy_receipt;")
        .unwrap();
    let writes = backend.inner.writes.len();
    let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .verifyRestoredPolicy(document.id)
        .unwrap();
    assert_eq!(result.policyVerificationRecorded, Some(true));
    assert_eq!(backend.inner.writes.len(), writes);
}

#[test]
fn missingCorruptOrSelfConsistentlyMisboundPolicyRecordsAreRefused() {
    for fault in 0..7 {
        let fixture = Fixture::new();
        let (_, _, journal) = restored(&fixture);
        drop(journal);
        let connection = Connection::open(&fixture.journal).unwrap();
        match fault {
            0 => {
                connection
                    .execute("UPDATE checkpoint_policy_checks SET document_json='{}'", [])
                    .unwrap();
            }
            1 => {
                connection
                    .execute("DELETE FROM checkpoint_policy_checks", [])
                    .unwrap();
            }
            2 => {
                connection
                    .pragma_update(None, "foreign_keys", "OFF")
                    .unwrap();
                connection.execute("DELETE FROM policy_heads", []).unwrap();
            }
            _ => {
                let payload: String = connection
                    .query_row(
                        "SELECT document_json FROM checkpoint_policy_checks",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let mut value: serde_json::Value = serde_json::from_str(&payload).unwrap();
                match fault {
                    3 => value["restoredEventSha256"] = "0".repeat(64).into(),
                    4 => value["matchesOriginal"] = false.into(),
                    5 => value["sequence"] = 99.into(),
                    _ => value["recordedAtUnixMs"] = 0.into(),
                }
                let payload = serde_json::to_string(&value).unwrap();
                let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
                connection
                    .execute(
                        "UPDATE checkpoint_policy_checks SET document_json=?1,sha256=?2",
                        rusqlite::params![payload, digest],
                    )
                    .unwrap();
                connection
                    .execute("UPDATE policy_heads SET sha256=?1", [digest])
                    .unwrap();
            }
        }
        drop(connection);
        assert!(Journal::open(&fixture.journal).is_err(), "fault {fault}");
    }
}

#[test]
fn versionThreeMigrationPreservesOriginalBytesAndRequiresFreshPolicyVerification() {
    let fixture = Fixture::new();
    let (document, mut backend, journal) = restored(&fixture);
    let checkpoint = journal.load(document.id).unwrap();
    drop(journal);
    let connection = Connection::open(&fixture.journal).unwrap();
    let originalBytes: String = connection
        .query_row("SELECT document_json FROM checkpoints", [], |row| {
            row.get(0)
        })
        .unwrap();
    connection
        .execute_batch(
            "DROP TABLE checkpoint_policy_checks; DROP TABLE policy_heads; PRAGMA user_version=3;",
        )
        .unwrap();
    drop(connection);
    let mut journal = fixture.open();
    let migrated = journal.load(document.id).unwrap();
    assert_eq!(migrated.documentSha256(), checkpoint.documentSha256());
    assert_eq!(migrated.events(), checkpoint.events());
    assert!(migrated.policyVerifications().is_empty());
    assert_eq!(journal.pendingPolicyVerification().unwrap().len(), 1);
    let connection = Connection::open(&fixture.journal).unwrap();
    let migratedBytes: String = connection
        .query_row("SELECT document_json FROM checkpoints", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(migratedBytes, originalBytes);
    assert_eq!(
        connection
            .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        4
    );
    backend.inner.allow = false;
    let writes = backend.inner.writes.len();
    MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .restoreAllPending()
        .unwrap();
    assert_eq!(backend.inner.writes.len(), writes);
}

#[test]
fn corruptVersionThreeMutatorsAreRejectedBeforeMigrationCanCommit() {
    let fixture = Fixture::new();
    let (_, _, journal) = applied(&fixture);
    drop(journal);
    let connection = Connection::open(&fixture.journal).unwrap();
    connection
        .execute_batch(
            "DROP TABLE checkpoint_policy_checks; DROP TABLE policy_heads; PRAGMA user_version=3;",
        )
        .unwrap();
    connection
        .execute("UPDATE checkpoint_mutators SET sha256=?1", ["0".repeat(64)])
        .unwrap();
    drop(connection);
    assert!(Journal::open(&fixture.journal).is_err());
    let connection = Connection::open(&fixture.journal).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        3
    );
    assert_eq!(
        connection
            .query_row::<u32, _, _>(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='policy_heads'",
                [],
                |row| row.get(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn policyRetryCapacityIsBoundedAndDoesNotClearUnverifiedWork() {
    let fixture = Fixture::new();
    let (document, mut backend, mut journal) = applied(&fixture);
    backend.unavailable = true;
    MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .restore(document.id)
        .unwrap();
    for _ in 1..16 {
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .verifyRestoredPolicy(document.id)
            .unwrap();
    }
    let writes = backend.inner.writes.len();
    let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .verifyRestoredPolicy(document.id)
        .unwrap();
    assert_eq!(result.policyVerificationRecorded, Some(false));
    assert_eq!(
        journal
            .load(document.id)
            .unwrap()
            .policyVerifications()
            .len(),
        16
    );
    assert_eq!(journal.pendingPolicyVerification().unwrap().len(), 1);
    assert_eq!(backend.inner.writes.len(), writes);
}

#[test]
fn policyReceiptCannotPrecedeTheDurableMtuRestorationEvent() {
    let fixture = Fixture::new();
    let (document, _, mut journal) = applied(&fixture);
    assert!(
        journal
            .recordPolicyVerification(
                document.id,
                PolicyReadback::Unavailable {
                    error: "fixture unavailable".into()
                },
                1000
            )
            .is_err()
    );
    assert_eq!(journal.load(document.id).unwrap().state(), State::Applied);
    assert!(
        journal
            .load(document.id)
            .unwrap()
            .policyVerifications()
            .is_empty()
    );
}

#[test]
#[ignore]
fn exitsAfterMtuRestoreBeforePolicyReceipt() {
    let directory = PathBuf::from(std::env::var_os("EPP_POLICY_CRASH_DIRECTORY").unwrap());
    let fixture = Fixture {
        journal: directory.join("recovery.sqlite3"),
        value: directory.join("simulated-interface.json"),
        directory,
    };
    let (document, mut backend, mut journal) = applied(&fixture);
    backend.exitOnVerification = true;
    let _ = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000)).restore(document.id);
    panic!("crash fixture did not exit before the policy receipt");
}

#[test]
fn processExitAfterMtuRestoreLeavesOnlyPolicyWorkAndNeverReplaysASettingCommand() {
    use std::os::windows::process::CommandExt;
    let fixture = Fixture::new();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "recovery::tests::policy_tests::receipt_tests::exitsAfterMtuRestoreBeforePolicyReceipt",
            "--nocapture",
        ])
        .env("EPP_POLICY_CRASH_DIRECTORY", &fixture.directory)
        .creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("MTU_RESTORED_BEFORE_POLICY_RECEIPT"));
    assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
    let mut journal = fixture.open();
    assert!(journal.pendingRecovery().unwrap().is_empty());
    assert_eq!(journal.pendingPolicyVerification().unwrap().len(), 1);
    let document = journal
        .pendingPolicyVerification()
        .unwrap()
        .pop()
        .unwrap()
        .document()
        .clone();
    let mut backend = PolicyBackend {
        inner: fixture.backend(Arc::new(AtomicU64::new(20000))),
        evidence: document.policyOriginal.clone().unwrap(),
        unavailable: false,
        failAt: None,
        expireAt: None,
        reads: 0,
        exitOnVerification: false,
    };
    backend.inner.allow = false;
    let results = MtuCoordinator::new(&mut journal, &mut backend, || Ok(20000))
        .restoreAllPending()
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].policyOriginalVerified, Some(true));
    assert_eq!(results[0].policyVerificationRecorded, Some(true));
    assert!(backend.inner.writes.is_empty());
    assert_eq!(journal.mutators(document.id).unwrap().len(), 2);
    assert!(journal.pendingPolicyVerification().unwrap().is_empty());
}
