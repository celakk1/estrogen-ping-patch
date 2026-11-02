use super::*;
use crate::journal::Journal;
use rusqlite::Connection;
use std::{path::PathBuf, time::Duration};

fn restoreVersionOneFixture(connection: &Connection) {
    connection
        .execute_batch(
            "DROP TABLE session_grants; DROP TABLE session_approvals; PRAGMA user_version=1;",
        )
        .unwrap();
}

#[test]
fn orphanedLegacyAuditCannotCommitTheSessionSchemaMigration() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let connection = Connection::open(fixture.path()).unwrap();
    restoreVersionOneFixture(&connection);
    connection
        .pragma_update(None, "foreign_keys", false)
        .unwrap();
    connection
        .execute(
            "INSERT INTO grant_events(grant_id,sequence,event_json,sha256) VALUES(?1,0,'{}',?2)",
            [Uuid::new_v4().to_string(), "0".repeat(64)],
        )
        .unwrap();
    assert!(AuthorizationStore::open(&fixture.path()).is_err());
    assert_eq!(
        connection
            .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        1
    );
    assert_eq!(connection.query_row::<u32, _, _>("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('session_approvals','session_grants')", [], |row| row.get(0)).unwrap(), 0);
}

#[test]
fn versionOneMigrationPreservesExactGrantAndEventBytesWithoutSessionApproval() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let document = document();
    let grant = store
        .issue(&document, &document.authorizedUserSid, false, 1001)
        .unwrap();
    drop(store);
    let connection = Connection::open(fixture.path()).unwrap();
    let grantBytes: String = connection
        .query_row(
            "SELECT document_json FROM grants WHERE id=?",
            [grant.id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let eventBytes: String = connection
        .query_row(
            "SELECT event_json FROM grant_events WHERE grant_id=?",
            [grant.id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    restoreVersionOneFixture(&connection);
    let mut reopened = fixture.open();
    assert_eq!(reopened.read(grant.id).unwrap().grant, grant);
    assert!(
        reopened
            .authorize(
                grant.id,
                &document,
                &document.authorizedUserSid,
                AuthorizationAction::Prepare,
                1002
            )
            .is_err()
    );
    assert_eq!(
        connection
            .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        2
    );
    assert_eq!(
        connection
            .query_row::<String, _, _>(
                "SELECT document_json FROM grants WHERE id=?",
                [grant.id.to_string()],
                |row| row.get(0)
            )
            .unwrap(),
        grantBytes
    );
    assert_eq!(
        connection
            .query_row::<String, _, _>(
                "SELECT event_json FROM grant_events WHERE grant_id=?",
                [grant.id.to_string()],
                |row| row.get(0)
            )
            .unwrap(),
        eventBytes
    );
    assert_eq!(
        connection
            .query_row::<u32, _, _>("SELECT COUNT(*) FROM session_approvals", [], |row| row
                .get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row::<u32, _, _>("SELECT COUNT(*) FROM session_grants", [], |row| row.get(0))
            .unwrap(),
        0
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&grantBytes)
            .unwrap()
            .get("sessionApprovalId")
            .is_none()
    );
}

#[test]
fn corruptVersionOneGrantCannotPartiallyMigrateSessionTables() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let document = document();
    store
        .issue(&document, &document.authorizedUserSid, false, 1001)
        .unwrap();
    drop(store);
    let connection = Connection::open(fixture.path()).unwrap();
    restoreVersionOneFixture(&connection);
    connection
        .execute("UPDATE grant_events SET sha256=?", ["0".repeat(64)])
        .unwrap();
    assert!(AuthorizationStore::open(&fixture.path()).is_err());
    assert_eq!(
        connection
            .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        1
    );
    assert_eq!(connection.query_row::<u32, _, _>("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('session_approvals','session_grants')", [], |row| row.get(0)).unwrap(), 0);
}

pub(crate) struct Fixture {
    directory: PathBuf,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "epp-auth-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir(&directory).unwrap();
        Self { directory }
    }
    pub(crate) fn path(&self) -> PathBuf {
        self.directory.join("authorization.sqlite3")
    }
    pub(crate) fn open(&self) -> AuthorizationStore {
        AuthorizationStore::open(&self.path()).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for base in ["authorization.sqlite3", "recovery.sqlite3"] {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(self.directory.join(format!("{base}{suffix}")));
            }
        }
        let _ = std::fs::remove_dir(&self.directory);
    }
}

fn document() -> MtuCheckpoint {
    let native = crate::recovery::tests::nativeFixture();
    MtuCheckpoint {
        schemaVersion: 2,
        id: Uuid::new_v4(),
        createdAtUnixMs: 1000,
        leaseExpiresAtUnixMs: 121_000,
        authorizedUserSid: "S-1-5-21-1-2-3-1000".into(),
        context: native.journalContext().unwrap(),
        addressFamily: native.addressFamily,
        originalMtu: native.settings.nlMtu,
        proposedMtu: 1400,
        nativeOriginal: Some(native),
        policyOriginal: None,
    }
}

#[test]
fn grantBindsTheExactDurableCheckpointAndRequiresARecordedClaim() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let document = document();
    let sid = &document.authorizedUserSid;
    let grant = store.issue(&document, sid, false, 1000).unwrap();
    let mut journal = Journal::open(&fixture.directory.join("recovery.sqlite3")).unwrap();
    let checkpoint = journal.prepare(document.clone(), 1001).unwrap();
    assert_eq!(grant.checkpointSha256, checkpoint.documentSha256());
    assert!(!store.read(grant.id).unwrap().claimed);
    assert!(
        store
            .check(grant.id, &document, sid, AuthorizationAction::Apply, 1001)
            .is_err()
    );
    store
        .authorize(grant.id, &document, sid, AuthorizationAction::Prepare, 1001)
        .unwrap();
    store
        .authorize(grant.id, &document, sid, AuthorizationAction::Apply, 1002)
        .unwrap();
    assert!(store.read(grant.id).unwrap().claimed);
    store
        .check(grant.id, &document, sid, AuthorizationAction::Apply, 1003)
        .unwrap();
    assert!(
        store
            .authorize(grant.id, &document, sid, AuthorizationAction::Prepare, 1004)
            .is_err()
    );
    assert!(
        store
            .authorize(grant.id, &document, sid, AuthorizationAction::Retain, 1004)
            .is_err()
    );
}

#[test]
fn scopeRejectsOtherUsersTargetsValuesAndOriginalEvidence() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let original = document();
    let sid = &original.authorizedUserSid;
    let mut legacy = original.clone();
    legacy.schemaVersion = 1;
    legacy.nativeOriginal = None;
    legacy.validate().unwrap();
    assert!(store.issue(&legacy, sid, false, 1000).is_err());
    let grant = store.issue(&original, sid, true, 1000).unwrap();
    store
        .authorize(grant.id, &original, sid, AuthorizationAction::Apply, 1001)
        .unwrap();
    assert!(
        store
            .check(
                grant.id,
                &original,
                "S-1-5-21-1-2-3-1001",
                AuthorizationAction::Apply,
                1002
            )
            .is_err()
    );
    for changed in 0..5 {
        let mut candidate = original.clone();
        match changed {
            0 => candidate.id = Uuid::new_v4(),
            1 => candidate.proposedMtu = 1399,
            2 => candidate.nativeOriginal.as_mut().unwrap().alias = "different alias".into(),
            3 => {
                candidate.context.adapterGuid = Uuid::new_v4();
                candidate.nativeOriginal.as_mut().unwrap().adapterGuid =
                    candidate.context.adapterGuid;
            }
            4 => {
                candidate.context.driverVersion = "2.0".into();
                if let crate::mtu::DriverContext::Captured { identity } =
                    &mut candidate.nativeOriginal.as_mut().unwrap().driver
                {
                    identity.version = "2.0".into();
                }
            }
            _ => unreachable!(),
        }
        candidate.validate().unwrap();
        assert!(
            store
                .check(grant.id, &candidate, sid, AuthorizationAction::Apply, 1002)
                .is_err()
        );
    }
    store
        .authorize(grant.id, &original, sid, AuthorizationAction::Retain, 1003)
        .unwrap();
}

#[test]
fn ownerRevocationIsDurableVisibleAcrossConnectionsAndSurvivesClockRewind() {
    let fixture = Fixture::new();
    let mut issuer = fixture.open();
    let document = document();
    let sid = &document.authorizedUserSid;
    let grant = issuer.issue(&document, sid, false, 1000).unwrap();
    issuer
        .authorize(grant.id, &document, sid, AuthorizationAction::Apply, 1002)
        .unwrap();
    let mut controller = fixture.open();
    assert!(
        controller
            .revoke(grant.id, "S-1-5-21-1-2-3-1001", 1003)
            .is_err()
    );
    controller.revoke(grant.id, sid, 500).unwrap();
    assert!(issuer.read(grant.id).unwrap().revoked);
    assert!(
        issuer
            .check(grant.id, &document, sid, AuthorizationAction::Apply, 1004)
            .is_err()
    );
    controller.revoke(grant.id, sid, 600).unwrap();
    drop(controller);
    assert!(fixture.open().read(grant.id).unwrap().revoked);
}

#[test]
fn reopeningRequiresNewExplicitApprovalAndDoesNotPermitCheckpointReplay() {
    let fixture = Fixture::new();
    let document = document();
    let sid = &document.authorizedUserSid;
    let grant = fixture.open().issue(&document, sid, false, 1000).unwrap();
    let mut reopened = fixture.open();
    assert!(reopened.read(grant.id).is_ok());
    assert!(
        reopened
            .authorize(grant.id, &document, sid, AuthorizationAction::Apply, 1001)
            .is_err()
    );
    assert!(reopened.issue(&document, sid, false, 1002).is_err());
    let mut next = document.clone();
    next.id = Uuid::new_v4();
    let newGrant = reopened.issue(&next, sid, false, 1002).unwrap();
    reopened
        .authorize(newGrant.id, &next, sid, AuthorizationAction::Prepare, 1003)
        .unwrap();
}

#[test]
fn wallClockMonotonicExpiryAndClockRewindCannotExtendPermission() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let document = document();
    let sid = &document.authorizedUserSid;
    let grant = store.issue(&document, sid, false, 1000).unwrap();
    store
        .authorize(grant.id, &document, sid, AuthorizationAction::Apply, 1002)
        .unwrap();
    store
        .check(grant.id, &document, sid, AuthorizationAction::Apply, 1010)
        .unwrap();
    assert!(
        store
            .check(grant.id, &document, sid, AuthorizationAction::Apply, 1009)
            .is_err()
    );
    assert!(
        store
            .check(grant.id, &document, sid, AuthorizationAction::Apply, 121000)
            .is_err()
    );
    let record = store.read(grant.id).unwrap();
    let mut fence = Fence {
        deadline: Instant::now() - Duration::from_millis(1),
        highWaterUnixMs: 1010,
        revoked: false,
    };
    assert!(
        validateCheck(
            &record,
            Check {
                document: &document,
                actorSid: sid,
                action: AuthorizationAction::Apply,
                nowUnixMs: 1011
            },
            grant.issuerInstanceId,
            &mut fence,
            true
        )
        .is_err()
    );
}

#[test]
fn failedGrantAndClaimCommitsNeverAuthorizeWriting() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let document = document();
    let sid = &document.authorizedUserSid;
    let connection = Connection::open(fixture.path()).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_grant BEFORE INSERT ON grants BEGIN SELECT RAISE(FAIL,'fixture'); END;").unwrap();
    assert!(store.issue(&document, sid, false, 1000).is_err());
    assert_eq!(
        connection
            .query_row::<u32, _, _>("SELECT COUNT(*) FROM grants", [], |row| row.get(0))
            .unwrap(),
        0
    );
    connection
        .execute_batch("DROP TRIGGER reject_grant")
        .unwrap();
    let grant = store.issue(&document, sid, false, 1000).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_claim BEFORE INSERT ON grant_events BEGIN SELECT RAISE(FAIL,'fixture'); END;").unwrap();
    assert!(
        store
            .authorize(grant.id, &document, sid, AuthorizationAction::Apply, 1001)
            .is_err()
    );
    assert!(!store.read(grant.id).unwrap().claimed);
    assert!(
        store
            .check(grant.id, &document, sid, AuthorizationAction::Apply, 1002)
            .is_err()
    );
}

#[test]
fn corruptAuthorizationDoesNotChangeTheIndependentRecoveryJournal() {
    let fixture = Fixture::new();
    let document = document();
    let sid = &document.authorizedUserSid;
    let grant = fixture.open().issue(&document, sid, false, 1000).unwrap();
    let recoveryPath = fixture.directory.join("recovery.sqlite3");
    let mut journal = Journal::open(&recoveryPath).unwrap();
    journal.prepare(document.clone(), 1001).unwrap();
    drop(journal);
    let before = std::fs::read(&recoveryPath).unwrap();
    let connection = Connection::open(fixture.path()).unwrap();
    connection
        .execute(
            "UPDATE grants SET document_json='{}' WHERE id=?1",
            [grant.id.to_string()],
        )
        .unwrap();
    drop(connection);
    assert!(AuthorizationStore::open(&fixture.path()).is_err());
    let journal = Journal::open(&recoveryPath).unwrap();
    assert_eq!(journal.load(document.id).unwrap().document(), &document);
    drop(journal);
    assert_eq!(std::fs::read(recoveryPath).unwrap(), before);
}

#[test]
fn failedRevocationBlocksTheIssuerWithoutPretendingItWasPersisted() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let document = document();
    let sid = &document.authorizedUserSid;
    let grant = store.issue(&document, sid, false, 1000).unwrap();
    store
        .authorize(grant.id, &document, sid, AuthorizationAction::Apply, 1001)
        .unwrap();
    let connection = Connection::open(fixture.path()).unwrap();
    connection.execute_batch("CREATE TRIGGER reject_revoke BEFORE INSERT ON grant_events BEGIN SELECT RAISE(FAIL,'fixture'); END;").unwrap();
    assert!(store.revoke(grant.id, sid, 1002).is_err());
    assert!(!store.read(grant.id).unwrap().revoked);
    assert!(
        store
            .check(grant.id, &document, sid, AuthorizationAction::Apply, 1003)
            .is_err()
    );
    assert!(
        fixture
            .open()
            .authorize(grant.id, &document, sid, AuthorizationAction::Apply, 1004)
            .is_err()
    );
}

#[test]
fn auditCapacityReservesRevocationAndFutureSchemasStayUntouched() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let document = document();
    let sid = &document.authorizedUserSid;
    let grant = store.issue(&document, sid, false, 1000).unwrap();
    for now in 1001..1063 {
        store
            .authorize(grant.id, &document, sid, AuthorizationAction::Prepare, now)
            .unwrap();
    }
    assert!(
        store
            .authorize(grant.id, &document, sid, AuthorizationAction::Apply, 1063)
            .is_err()
    );
    store.revoke(grant.id, sid, 1064).unwrap();
    assert!(store.read(grant.id).unwrap().revoked);
    drop(store);
    let connection = Connection::open(fixture.path()).unwrap();
    connection.pragma_update(None, "user_version", 99).unwrap();
    drop(connection);
    let before = std::fs::read(fixture.path()).unwrap();
    assert!(AuthorizationStore::open(&fixture.path()).is_err());
    assert_eq!(std::fs::read(fixture.path()).unwrap(), before);
}

#[test]
fn changedOrMissingAuditEventsCannotAuthorizeAnOperation() {
    for missing in [false, true] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let document = document();
        let sid = &document.authorizedUserSid;
        let grant = store.issue(&document, sid, false, 1000).unwrap();
        store
            .authorize(grant.id, &document, sid, AuthorizationAction::Apply, 1001)
            .unwrap();
        let connection = Connection::open(fixture.path()).unwrap();
        if missing {
            connection
                .execute(
                    "DELETE FROM grant_events WHERE grant_id=?1 AND sequence=0",
                    [grant.id.to_string()],
                )
                .unwrap();
        } else {
            connection
                .execute(
                    "UPDATE grant_events SET event_json='{}' WHERE grant_id=?1 AND sequence=1",
                    [grant.id.to_string()],
                )
                .unwrap();
        }
        assert!(
            store
                .check(grant.id, &document, sid, AuthorizationAction::Apply, 1002)
                .is_err()
        );
        assert!(AuthorizationStore::open(&fixture.path()).is_err());
    }
}
