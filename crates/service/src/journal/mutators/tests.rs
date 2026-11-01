use super::*;
use crate::journal::{Journal, MtuCheckpoint, Observation, State};
use std::path::PathBuf;

struct Fixture {
    directory: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!("epp-mutators-{}", Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        Self {
            path: directory.join("recovery.sqlite3"),
            directory,
        }
    }
    fn open(&self) -> Journal {
        Journal::open(&self.path).unwrap()
    }
    fn connection(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for name in [
            "recovery.sqlite3",
            "recovery.sqlite3-wal",
            "recovery.sqlite3-shm",
        ] {
            let _ = std::fs::remove_file(self.directory.join(name));
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}
fn document() -> MtuCheckpoint {
    let original = crate::recovery::tests::nativeFixture();
    MtuCheckpoint {
        schemaVersion: 3,
        id: Uuid::new_v4(),
        createdAtUnixMs: 1000,
        leaseExpiresAtUnixMs: 10000,
        authorizedUserSid: "S-1-5-21-1-2-3-1000".into(),
        context: original.journalContext().unwrap(),
        addressFamily: original.addressFamily,
        originalMtu: 1500,
        proposedMtu: 1400,
        nativeOriginal: Some(original),
        policyOriginal: None,
    }
}
fn observation(document: &MtuCheckpoint, mtu: u32) -> Observation {
    let mut native = document.nativeOriginal.clone().unwrap();
    native.settings.nlMtu = mtu;
    Observation {
        context: document.context.clone(),
        addressFamily: document.addressFamily,
        mtu,
        native: Some(native),
    }
}
fn applying(journal: &mut Journal, document: &MtuCheckpoint) {
    journal.prepare(document.clone(), 1000).unwrap();
    journal
        .transition(
            document.id,
            State::Prepared,
            State::Applying,
            1010,
            Some(observation(document, 1500)),
        )
        .unwrap();
}
fn identity(id: u32) -> MutatorIdentity {
    MutatorIdentity {
        processId: id,
        creationTime100ns: "18446744073709551615".into(),
    }
}

#[test]
fn processIdentityIsDurableBeforeReceiptAndBoundToExactCheckpointBytes() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let document = document();
    applying(&mut journal, &document);
    let original = journal
        .load(document.id)
        .unwrap()
        .documentSha256()
        .to_owned();
    let receipt = journal
        .registerMutator(document.id, WritePurpose::Apply, identity(100), 1020)
        .unwrap();
    assert_eq!(receipt.checkpointSha256, original);
    assert_eq!(
        fixture.open().mutators(document.id).unwrap(),
        vec![receipt.clone()]
    );
    assert_eq!(
        journal.load(document.id).unwrap().documentSha256(),
        original
    );
    assert_eq!(receipt.identity.creationTime100ns, "18446744073709551615");
    drop(journal);
    assert_eq!(fixture.open().mutators(document.id).unwrap(), vec![receipt]);
}

#[test]
fn invalidOrRepeatedProcessesAndUnpreparedWritesCannotBeRegistered() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let document = document();
    journal.prepare(document.clone(), 1000).unwrap();
    assert!(
        journal
            .registerMutator(document.id, WritePurpose::Apply, identity(100), 1010)
            .is_err()
    );
    journal
        .transition(
            document.id,
            State::Prepared,
            State::Applying,
            1010,
            Some(observation(&document, 1500)),
        )
        .unwrap();
    for (processId, creation) in [
        (0, "1"),
        (4, "1"),
        (100, "00"),
        (100, "0"),
        (100, "184467440737095516150"),
        (100, "invalid"),
    ] {
        let invalid = MutatorIdentity {
            processId,
            creationTime100ns: creation.into(),
        };
        assert!(
            journal
                .registerMutator(document.id, WritePurpose::Apply, invalid, 1020)
                .is_err()
        );
    }
    journal
        .registerMutator(document.id, WritePurpose::Apply, identity(100), 1020)
        .unwrap();
    assert!(
        journal
            .registerMutator(document.id, WritePurpose::Apply, identity(104), 1021)
            .is_err()
    );
    assert!(
        journal
            .registerMutator(document.id, WritePurpose::Restore, identity(100), 1021)
            .is_err()
    );
    assert!(
        journal
            .registerMutator(Uuid::new_v4(), WritePurpose::Restore, identity(104), 1021)
            .is_err()
    );
    journal
        .registerMutator(document.id, WritePurpose::Restore, identity(104), 1022)
        .unwrap();
    assert_eq!(journal.mutators(document.id).unwrap().len(), 2);
}

#[test]
fn registrationFailureDoesNotAdvanceTheHeadOrEraseOriginals() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let document = document();
    applying(&mut journal, &document);
    let digest = journal
        .load(document.id)
        .unwrap()
        .documentSha256()
        .to_owned();
    fixture.connection().execute_batch("CREATE TRIGGER fail_mutator BEFORE INSERT ON checkpoint_mutators BEGIN SELECT RAISE(ABORT,'test full storage'); END;").unwrap();
    assert!(
        journal
            .registerMutator(document.id, WritePurpose::Apply, identity(100), 1020)
            .is_err()
    );
    assert!(journal.mutators(document.id).unwrap().is_empty());
    assert_eq!(
        fixture.open().load(document.id).unwrap().documentSha256(),
        digest
    );
}

#[test]
fn missingTailChangedPayloadOrMissingHeadCannotHideAPredecessor() {
    for sql in [
        "DELETE FROM checkpoint_mutators",
        "UPDATE checkpoint_mutators SET document_json='{}'",
        "DELETE FROM mutator_heads",
        "UPDATE mutator_heads SET count=0",
        "UPDATE mutator_heads SET sha256='changed'",
    ] {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        let document = document();
        applying(&mut journal, &document);
        journal
            .registerMutator(document.id, WritePurpose::Apply, identity(100), 1020)
            .unwrap();
        let connection = fixture.connection();
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .unwrap();
        connection.execute_batch(sql).unwrap();
        drop(connection);
        assert!(journal.load(document.id).is_err(), "{sql}");
        drop(journal);
        assert!(Journal::open(&fixture.path).is_err(), "{sql}");
    }
}

#[test]
fn rehashedRecordsStillRequireTheOriginalApplyScope() {
    for change in ["purpose", "early", "expired", "duplicate"] {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        let document = document();
        applying(&mut journal, &document);
        let mut record = journal
            .registerMutator(document.id, WritePurpose::Apply, identity(100), 1020)
            .unwrap();
        match change {
            "purpose" => record.purpose = WritePurpose::Restore,
            "early" => record.registeredAtUnixMs = 999,
            "expired" => record.registeredAtUnixMs = 10000,
            "duplicate" => {
                record = journal
                    .registerMutator(document.id, WritePurpose::Restore, identity(104), 1021)
                    .unwrap();
                record.identity = identity(100);
            }
            _ => unreachable!(),
        }
        let payload = serde_json::to_string(&record).unwrap();
        let digest = checksum(&payload);
        let connection = fixture.connection();
        connection
            .execute(
                "UPDATE checkpoint_mutators SET document_json=?1,sha256=?2 WHERE sequence=?3",
                params![payload, digest, record.sequence],
            )
            .unwrap();
        connection
            .execute("UPDATE mutator_heads SET sha256=?1", [digest])
            .unwrap();
        assert!(journal.load(document.id).is_err(), "{change}");
        drop(connection);
        drop(journal);
        assert!(Journal::open(&fixture.path).is_err(), "{change}");
    }
}

#[test]
fn migrationPreservesOriginalDocumentsAndEventsAndRejectsLegacyNativeRegistration() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let mut document = document();
    document.schemaVersion = 2;
    applying(&mut journal, &document);
    let original = journal.load(document.id).unwrap();
    drop(journal);
    let connection = fixture.connection();
    let bytes: String = connection
        .query_row("SELECT document_json FROM checkpoints", [], |row| {
            row.get(0)
        })
        .unwrap();
    connection
        .execute_batch(
            "DROP TABLE checkpoint_mutators; DROP TABLE mutator_heads; PRAGMA user_version=2;",
        )
        .unwrap();
    drop(connection);
    let mut journal = fixture.open();
    let migrated = journal.load(document.id).unwrap();
    assert_eq!(migrated.document(), original.document());
    assert_eq!(migrated.documentSha256(), original.documentSha256());
    assert_eq!(migrated.events(), original.events());
    assert_eq!(
        fixture
            .connection()
            .query_row::<String, _, _>("SELECT document_json FROM checkpoints", [], |row| row
                .get(0))
            .unwrap(),
        bytes
    );
    assert!(
        journal
            .registerMutator(document.id, WritePurpose::Apply, identity(100), 1020)
            .is_err()
    );
}

#[test]
fn trackedAppliedStateNeedsAProcessRecordAndCapacityNeverOverwritesOldRecords() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let document = document();
    applying(&mut journal, &document);
    assert!(
        journal
            .transition(
                document.id,
                State::Applying,
                State::Applied,
                1020,
                Some(observation(&document, 1400))
            )
            .is_err()
    );
    assert_eq!(journal.load(document.id).unwrap().state(), State::Applying);
    journal
        .registerMutator(document.id, WritePurpose::Apply, identity(100), 1020)
        .unwrap();
    for index in 1..MAX_MUTATORS {
        journal
            .registerMutator(
                document.id,
                WritePurpose::Restore,
                identity(100 + index as u32),
                1020 + index as u64,
            )
            .unwrap();
    }
    let records = journal.mutators(document.id).unwrap();
    assert!(
        journal
            .registerMutator(document.id, WritePurpose::Restore, identity(1000), 1100)
            .is_err()
    );
    assert_eq!(journal.mutators(document.id).unwrap(), records);
}
