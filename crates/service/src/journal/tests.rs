use super::*;
use rusqlite::Connection;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let folder = std::env::temp_dir().join(format!(
            "epp-journal-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&folder).unwrap();
        Self {
            path: folder.join("recovery.sqlite3"),
        }
    }
    fn open(&self) -> Journal {
        Journal::open(&self.path).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let folder = self.path.parent().unwrap();
        if let (Ok(resolved), Ok(temp)) =
            (folder.canonicalize(), std::env::temp_dir().canonicalize())
            && resolved.parent() == Some(temp.as_path())
            && resolved
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("epp-journal-")
        {
            let _ = std::fs::remove_dir_all(resolved);
        }
    }
}

fn document(id: u128) -> MtuCheckpoint {
    MtuCheckpoint {
        schemaVersion: 1,
        id: Uuid::from_u128(id),
        createdAtUnixMs: 1000,
        leaseExpiresAtUnixMs: 10_000,
        authorizedUserSid: "S-1-5-21-1-2-3-1000".into(),
        context: AdapterContext {
            adapterGuid: Uuid::from_u128(100),
            osBuild: "26100".into(),
            driverVersion: "1.2.3".into(),
        },
        addressFamily: AddressFamily::Ipv4,
        originalMtu: 1500,
        proposedMtu: 1400,
        nativeOriginal: None,
        policyOriginal: None,
    }
}

fn observed(document: &MtuCheckpoint, mtu: u32) -> Observation {
    Observation {
        context: document.context.clone(),
        addressFamily: document.addressFamily,
        mtu,
        native: None,
    }
}

#[test]
fn originalCheckpointIsDurableBeforeApplyIntentIsReturned() {
    let fixture = Fixture::new();
    let original = document(1);
    let mut journal = fixture.open();
    let prepared = journal.prepare(original.clone(), 1000).unwrap();
    let observer = fixture.open();
    assert_eq!(observer.load(original.id).unwrap().document, original);
    assert_eq!(prepared.state(), State::Prepared);
    journal
        .transition(
            original.id,
            State::Prepared,
            State::Applying,
            1100,
            Some(observed(&original, 1500)),
        )
        .unwrap();
    assert_eq!(observer.load(original.id).unwrap().state(), State::Applying);
}

#[test]
fn everyInterruptedStateSurvivesReopenUntilVerifiedRestoration() {
    let fixture = Fixture::new();
    let original = document(2);
    {
        let mut journal = fixture.open();
        journal.prepare(original.clone(), 1000).unwrap();
        journal
            .transition(
                original.id,
                State::Prepared,
                State::Applying,
                1100,
                Some(observed(&original, 1500)),
            )
            .unwrap();
    }
    {
        let mut journal = fixture.open();
        assert_eq!(
            journal.pendingRecovery().unwrap()[0].state(),
            State::Applying
        );
        journal
            .transition(
                original.id,
                State::Applying,
                State::Restoring,
                11_000,
                Some(observed(&original, 1400)),
            )
            .unwrap();
    }
    {
        let mut journal = fixture.open();
        assert_eq!(
            journal.pendingRecovery().unwrap()[0].state(),
            State::Restoring
        );
        journal
            .transition(
                original.id,
                State::Restoring,
                State::Restored,
                12_000,
                Some(observed(&original, 1500)),
            )
            .unwrap();
    }
    let journal = fixture.open();
    assert!(journal.pendingRecovery().unwrap().is_empty());
    assert_eq!(journal.load(original.id).unwrap().document, original);
}

#[test]
fn candidateReadbackAndOriginalReadbackCannotBeConfused() {
    let fixture = Fixture::new();
    let original = document(3);
    let mut journal = fixture.open();
    journal.prepare(original.clone(), 1000).unwrap();
    assert!(
        journal
            .transition(
                original.id,
                State::Prepared,
                State::Applying,
                1100,
                Some(observed(&original, 1400))
            )
            .is_err()
    );
    journal
        .transition(
            original.id,
            State::Prepared,
            State::Applying,
            1100,
            Some(observed(&original, 1500)),
        )
        .unwrap();
    assert!(
        journal
            .transition(original.id, State::Applying, State::Applied, 1200, None)
            .is_err()
    );
    journal
        .transition(
            original.id,
            State::Applying,
            State::Applied,
            1200,
            Some(observed(&original, 1400)),
        )
        .unwrap();
    assert!(
        journal
            .transition(
                original.id,
                State::Applied,
                State::Restored,
                1300,
                Some(observed(&original, 1400))
            )
            .is_err()
    );
    assert_eq!(journal.load(original.id).unwrap().state(), State::Applied);
}

#[test]
fn changedContextOrOutOfBandValueCannotAuthorizeRestoration() {
    let fixture = Fixture::new();
    let original = document(4);
    let mut journal = fixture.open();
    journal.prepare(original.clone(), 1000).unwrap();
    journal
        .transition(
            original.id,
            State::Prepared,
            State::Applying,
            1100,
            Some(observed(&original, 1500)),
        )
        .unwrap();
    let mut changed = observed(&original, 1400);
    changed.context.driverVersion = "2.0".into();
    assert!(
        journal
            .transition(
                original.id,
                State::Applying,
                State::Restoring,
                1200,
                Some(changed)
            )
            .is_err()
    );
    assert!(
        journal
            .transition(
                original.id,
                State::Applying,
                State::Restoring,
                1200,
                Some(observed(&original, 1450))
            )
            .is_err()
    );
    journal
        .transition(
            original.id,
            State::Applying,
            State::RecoveryRequired,
            1200,
            None,
        )
        .unwrap();
    assert_eq!(
        journal.pendingRecovery().unwrap()[0].state(),
        State::RecoveryRequired
    );
}

#[test]
fn expiredLeaseBlocksNewWritesAndRetentionButNeverBlocksRecovery() {
    let fixture = Fixture::new();
    let original = document(5);
    let mut journal = fixture.open();
    journal.prepare(original.clone(), 1000).unwrap();
    assert!(
        journal
            .transition(
                original.id,
                State::Prepared,
                State::Applying,
                10_000,
                Some(observed(&original, 1500))
            )
            .is_err()
    );
    journal
        .transition(
            original.id,
            State::Prepared,
            State::Applying,
            1100,
            Some(observed(&original, 1500)),
        )
        .unwrap();
    journal
        .transition(
            original.id,
            State::Applying,
            State::Applied,
            1200,
            Some(observed(&original, 1400)),
        )
        .unwrap();
    assert!(
        journal
            .transition(
                original.id,
                State::Applied,
                State::Retained,
                10_000,
                Some(observed(&original, 1400))
            )
            .is_err()
    );
    journal
        .transition(
            original.id,
            State::Applied,
            State::Restored,
            11_000,
            Some(observed(&original, 1500)),
        )
        .unwrap();
}

#[test]
fn aClockCorrectionDoesNotMakeRecoveryImpossible() {
    let fixture = Fixture::new();
    let original = document(6);
    let mut journal = fixture.open();
    journal.prepare(original.clone(), 1000).unwrap();
    journal
        .transition(
            original.id,
            State::Prepared,
            State::Applying,
            1100,
            Some(observed(&original, 1500)),
        )
        .unwrap();
    journal
        .transition(
            original.id,
            State::Applying,
            State::Restoring,
            500,
            Some(observed(&original, 1400)),
        )
        .unwrap();
    journal
        .transition(
            original.id,
            State::Restoring,
            State::Restored,
            600,
            Some(observed(&original, 1500)),
        )
        .unwrap();
    drop(journal);
    assert!(fixture.open().pendingRecovery().unwrap().is_empty());
}

#[test]
fn unresolvedWorkBlocksAnotherExperimentAndStaleWritersCannotAdvanceIt() {
    let fixture = Fixture::new();
    let original = document(7);
    let mut first = fixture.open();
    let mut second = fixture.open();
    first.prepare(original.clone(), 1000).unwrap();
    assert!(second.prepare(document(8), 1000).is_err());
    first
        .transition(
            original.id,
            State::Prepared,
            State::Applying,
            1100,
            Some(observed(&original, 1500)),
        )
        .unwrap();
    assert!(
        second
            .transition(original.id, State::Prepared, State::Cancelled, 1200, None)
            .is_err()
    );
    first
        .transition(
            original.id,
            State::Applying,
            State::Restored,
            1300,
            Some(observed(&original, 1500)),
        )
        .unwrap();
    assert!(second.prepare(document(8), 1400).is_ok());
}

#[test]
fn cancellationCannotEraseAPossibleMutationAndTerminalRecordsStayTerminal() {
    let fixture = Fixture::new();
    let original = document(9);
    let mut journal = fixture.open();
    journal.prepare(original.clone(), 1000).unwrap();
    journal
        .transition(original.id, State::Prepared, State::Cancelled, 1100, None)
        .unwrap();
    assert!(
        journal
            .transition(
                original.id,
                State::Cancelled,
                State::Applying,
                1200,
                Some(observed(&original, 1500))
            )
            .is_err()
    );
    let other = document(10);
    journal.prepare(other.clone(), 1300).unwrap();
    journal
        .transition(
            other.id,
            State::Prepared,
            State::Applying,
            1400,
            Some(observed(&other, 1500)),
        )
        .unwrap();
    assert!(
        journal
            .transition(other.id, State::Applying, State::Cancelled, 1500, None)
            .is_err()
    );
}

#[test]
fn corruptedOriginalOrEventChainBlocksReopeningRatherThanHidingPendingWork() {
    for event in [false, true] {
        let fixture = Fixture::new();
        let original = document(11);
        {
            let mut journal = fixture.open();
            journal.prepare(original.clone(), 1000).unwrap();
        }
        let connection = Connection::open(&fixture.path).unwrap();
        let table = if event {
            "checkpoint_events"
        } else {
            "checkpoints"
        };
        connection
            .execute(&format!("UPDATE {table} SET sha256=?1"), ["0".repeat(64)])
            .unwrap();
        drop(connection);
        assert!(Journal::open(&fixture.path).is_err());
    }
}

#[test]
fn deletingTheInitialEventCannotSilentlyClearRecovery() {
    let fixture = Fixture::new();
    let original = document(12);
    {
        let mut journal = fixture.open();
        journal.prepare(original.clone(), 1000).unwrap();
        journal
            .transition(
                original.id,
                State::Prepared,
                State::Applying,
                1100,
                Some(observed(&original, 1500)),
            )
            .unwrap();
    }
    let connection = Connection::open(&fixture.path).unwrap();
    connection
        .execute("DELETE FROM checkpoint_events WHERE sequence=0", [])
        .unwrap();
    drop(connection);
    assert!(Journal::open(&fixture.path).is_err());
}

#[test]
fn incompatibleOrUnrelatedDatabasesAreNotRepurposed() {
    let fixture = Fixture::new();
    let connection = Connection::open(&fixture.path).unwrap();
    connection
        .execute("CREATE TABLE unrelated(value TEXT)", [])
        .unwrap();
    drop(connection);
    assert!(Journal::open(&fixture.path).is_err());
    let connection = Connection::open(&fixture.path).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<u32, _>(None, "application_id", |row| row.get(0))
            .unwrap(),
        0
    );
    connection.pragma_update(None, "user_version", 99).unwrap();
    drop(connection);
    assert!(Journal::open(&fixture.path).is_err());
}

#[test]
fn failedCommitCannotProduceAnApplyIntent() {
    let fixture = Fixture::new();
    let original = document(13);
    let mut journal = fixture.open();
    let connection = Connection::open(&fixture.path).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_events BEFORE INSERT ON checkpoint_events BEGIN SELECT RAISE(ABORT,'injected persistence failure'); END;").unwrap();
    assert!(journal.prepare(original.clone(), 1000).is_err());
    assert_eq!(
        connection
            .query_row::<u32, _, _>("SELECT COUNT(*) FROM checkpoints", [], |row| row.get(0))
            .unwrap(),
        0
    );
    connection.execute("DROP TRIGGER fail_events", []).unwrap();
    journal.prepare(original.clone(), 1000).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_events BEFORE INSERT ON checkpoint_events BEGIN SELECT RAISE(ABORT,'injected persistence failure'); END;").unwrap();
    assert!(
        journal
            .transition(
                original.id,
                State::Prepared,
                State::Applying,
                1100,
                Some(observed(&original, 1500))
            )
            .is_err()
    );
    assert_eq!(journal.load(original.id).unwrap().state(), State::Prepared);
}

#[test]
fn orphanedEventsCannotBeIgnoredOnStartup() {
    let fixture = Fixture::new();
    {
        let mut journal = fixture.open();
        journal.prepare(document(16), 1000).unwrap();
    }
    let connection = Connection::open(&fixture.path).unwrap();
    connection
        .pragma_update(None, "foreign_keys", "OFF")
        .unwrap();
    connection.execute("INSERT INTO checkpoint_events(checkpoint_id,sequence,event_json,sha256) SELECT ?1,sequence,event_json,sha256 FROM checkpoint_events", [Uuid::from_u128(17).to_string()]).unwrap();
    drop(connection);
    assert!(Journal::open(&fixture.path).is_err());
}

#[test]
fn abruptProcessTerminationPreservesApplyAndRestoreIntents() {
    use std::{
        io::{BufRead, BufReader},
        process::{Command, Stdio},
        sync::mpsc,
        time::Duration,
    };
    let fixture = Fixture::new();
    let simulatedValue = fixture.path.with_extension("simulated-mtu");
    for phase in ["apply", "restore"] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "journal::tests::crashWorker",
                "--ignored",
                "--nocapture",
            ])
            .env("EPP_JOURNAL_CRASH_PATH", &fixture.path)
            .env("EPP_JOURNAL_CRASH_PHASE", phase)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if line.is_ok_and(|line| line.contains("CHECKPOINT_READY")) {
                    let _ = sender.send(());
                    break;
                }
            }
        });
        let ready = receiver.recv_timeout(Duration::from_secs(10));
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        reader.join().unwrap();
        assert!(
            ready.is_ok(),
            "Crash worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut journal = fixture.open();
        let checkpoint = journal.load(Uuid::from_u128(18)).unwrap();
        let value: u32 = std::fs::read_to_string(&simulatedValue)
            .unwrap()
            .parse()
            .unwrap();
        let observation = observed(&checkpoint.document, value);
        match phase {
            "apply" => {
                assert_eq!(checkpoint.state(), State::Applying);
                assert_eq!(value, 1400);
                journal
                    .transition(
                        checkpoint.document.id,
                        State::Applying,
                        State::Restoring,
                        11_000,
                        Some(observation),
                    )
                    .unwrap();
            }
            "restore" => {
                assert_eq!(checkpoint.state(), State::Restoring);
                assert_eq!(value, 1500);
                journal
                    .transition(
                        checkpoint.document.id,
                        State::Restoring,
                        State::Restored,
                        12_000,
                        Some(observation),
                    )
                    .unwrap();
                assert!(journal.pendingRecovery().unwrap().is_empty());
            }
            _ => unreachable!(),
        }
    }
}

#[test]
#[ignore = "only spawned by the abrupt process termination test"]
fn crashWorker() {
    use std::io::Write;
    let path =
        PathBuf::from(std::env::var_os("EPP_JOURNAL_CRASH_PATH").expect("test-only journal path"));
    let phase = std::env::var("EPP_JOURNAL_CRASH_PHASE").unwrap();
    let mut journal = Journal::open(&path).unwrap();
    match phase.as_str() {
        "apply" => {
            let original = document(18);
            journal.prepare(original.clone(), 1000).unwrap();
            journal
                .transition(
                    original.id,
                    State::Prepared,
                    State::Applying,
                    1100,
                    Some(observed(&original, 1500)),
                )
                .unwrap();
            std::fs::write(path.with_extension("simulated-mtu"), b"1400").unwrap();
        }
        "restore" => {
            assert_eq!(
                journal.load(Uuid::from_u128(18)).unwrap().state(),
                State::Restoring
            );
            std::fs::write(path.with_extension("simulated-mtu"), b"1500").unwrap();
        }
        _ => panic!("Unknown crash fixture phase"),
    }
    println!("CHECKPOINT_READY");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}

#[test]
fn malformedPlansFailBeforeAnyDurableIntentAndExactNativeValuesArePreserved() {
    let mut original = document(14);
    original.originalMtu = u32::MAX;
    assert!(original.validate().is_ok());
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    assert_eq!(
        journal
            .prepare(original.clone(), 1000)
            .unwrap()
            .document
            .originalMtu,
        u32::MAX
    );
    original.context.adapterGuid = Uuid::nil();
    assert!(original.validate().is_err());
    original = document(15);
    original.addressFamily = AddressFamily::Ipv6;
    original.proposedMtu = 1200;
    assert!(original.validate().is_err());
}

#[test]
#[ignore = "only invoked by the disposable Windows service smoke check"]
fn serviceLabPreparedCheckpoint() {
    assert_eq!(
        std::env::var("EPP_JOURNAL_LAB_ACK").unwrap(),
        "disposable-lab-no-network-setter"
    );
    let path = PathBuf::from(std::env::var_os("EPP_JOURNAL_LAB_PATH").unwrap());
    let mut journal = Journal::open(&path).unwrap();
    let mut original = document(24);
    original.context.osBuild = "simulated-lab".into();
    original.context.driverVersion = "simulated-lab".into();
    match std::env::var("EPP_JOURNAL_LAB_PHASE").unwrap().as_str() {
        "prepare" => {
            original.createdAtUnixMs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .try_into()
                .unwrap();
            original.leaseExpiresAtUnixMs = original.createdAtUnixMs + 10_000;
            journal
                .prepare(original.clone(), original.createdAtUnixMs)
                .unwrap();
        }
        "cancel" => {
            let checkpoint = journal.load(original.id).unwrap();
            journal
                .transition(
                    original.id,
                    State::Prepared,
                    State::Cancelled,
                    checkpoint.document.createdAtUnixMs + 20_000,
                    None,
                )
                .unwrap();
        }
        _ => panic!("Unknown service lab checkpoint phase"),
    }
}
