use super::*;
use crate::authorization::tests::Fixture;
use rusqlite::Connection;

const OWNER: &str = "S-1-5-21-1-2-3-1000";
const OTHER: &str = "S-1-5-21-1-2-3-1001";

fn document() -> MtuCheckpoint {
    let capture = crate::mtu::policy::tests::fixture();
    MtuCheckpoint {
        schemaVersion: 4,
        id: Uuid::new_v4(),
        createdAtUnixMs: 1000,
        leaseExpiresAtUnixMs: 121_000,
        authorizedUserSid: OWNER.into(),
        context: capture.native.journalContext().unwrap(),
        addressFamily: capture.native.addressFamily,
        originalMtu: capture.native.settings.nlMtu,
        proposedMtu: 1400,
        policyOriginal: Some(capture.evidence()),
        nativeOriginal: Some(capture.native),
    }
}

fn grantCount(fixture: &Fixture) -> u32 {
    Connection::open(fixture.path())
        .unwrap()
        .query_row("SELECT COUNT(*) FROM grants", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn approvalBindsTheExactReviewedOriginalAndCannotGrantRetentionOrReplay() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let original = document();
    let mut consent = MtuConsent::new(OWNER).unwrap();
    let mut preview = consent.preview(original.clone(), OWNER, 1000).unwrap();
    assert_eq!(preview.context, original.context);
    assert_eq!(preview.originalMtu, 1500);
    assert_eq!(preview.proposedMtu, 1400);
    assert_eq!(preview.expiresAtUnixMs, 31_000);
    assert_eq!(preview.trialExpiresAtUnixMs, 121_000);
    assert_eq!(
        preview.checkpointSha256,
        checkpointChecksum(&original).unwrap()
    );
    assert!(!preview.allowRetention);
    assert_eq!(grantCount(&fixture), 0);
    preview.proposedMtu = 1450;
    preview.allowRetention = true;
    let grant = consent
        .approve(
            preview.previewId,
            &preview.checkpointSha256,
            OWNER,
            &mut store,
            1001,
        )
        .unwrap();
    assert_eq!(grant.proposedMtu, 1400);
    assert!(!grant.allowRetention);
    assert_eq!(grant.checkpointId, original.id);
    assert_eq!(
        grant.checkpointSha256,
        checkpointChecksum(&original).unwrap()
    );
    assert!(!store.read(grant.id).unwrap().claimed);
    assert!(
        consent
            .approve(
                preview.previewId,
                &preview.checkpointSha256,
                OWNER,
                &mut store,
                1002
            )
            .is_err()
    );
    assert_eq!(grantCount(&fixture), 1);
}

#[test]
fn differentUsersNoncesOrHashesCannotApproveOrReplaceAnOutstandingPreview() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let mut consent = MtuConsent::new(OWNER).unwrap();
    assert!(consent.preview(document(), OTHER, 1000).is_err());
    let preview = consent.preview(document(), OWNER, 1000).unwrap();
    assert!(consent.preview(document(), OWNER, 1001).is_err());
    assert!(
        consent
            .approve(
                preview.previewId,
                &preview.checkpointSha256,
                OTHER,
                &mut store,
                1001
            )
            .is_err()
    );
    assert!(
        consent
            .approve(
                Uuid::new_v4(),
                &preview.checkpointSha256,
                OWNER,
                &mut store,
                1001
            )
            .is_err()
    );
    assert!(
        consent
            .approve(preview.previewId, &"0".repeat(64), OWNER, &mut store, 1001)
            .is_err()
    );
    assert!(consent.cancel(preview.previewId, OTHER).is_err());
    assert!(consent.cancel(Uuid::new_v4(), OWNER).is_err());
    assert_eq!(grantCount(&fixture), 0);
    consent
        .approve(
            preview.previewId,
            &preview.checkpointSha256,
            OWNER,
            &mut store,
            1002,
        )
        .unwrap();
    assert_eq!(grantCount(&fixture), 1);
}

#[test]
fn expiryRollbackCancellationAndRestartCannotReviveAnOldApproval() {
    for fault in 0..6 {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let mut consent = MtuConsent::new(OWNER).unwrap();
        let preview = consent.preview(document(), OWNER, 1000).unwrap();
        let now = match fault {
            0 => 31_000,
            1 => {
                assert!(
                    consent
                        .approve(
                            Uuid::new_v4(),
                            &preview.checkpointSha256,
                            OWNER,
                            &mut store,
                            2000
                        )
                        .is_err()
                );
                1500
            }
            2 => {
                consent.pending.as_mut().unwrap().deadline =
                    Instant::now() - Duration::from_millis(1);
                1001
            }
            3 => {
                consent.cancel(preview.previewId, OWNER).unwrap();
                1001
            }
            4 => {
                consent = MtuConsent::new(OWNER).unwrap();
                1001
            }
            _ => {
                assert!(consent.preview(document(), OWNER, 2000).is_err());
                1500
            }
        };
        assert!(
            consent
                .approve(
                    preview.previewId,
                    &preview.checkpointSha256,
                    OWNER,
                    &mut store,
                    now
                )
                .is_err()
        );
        assert!(
            consent
                .approve(
                    preview.previewId,
                    &preview.checkpointSha256,
                    OWNER,
                    &mut store,
                    3000
                )
                .is_err()
        );
        assert_eq!(grantCount(&fixture), 0);
    }
}

#[test]
fn previewsRequireCurrentPolicyBoundOriginalsForTheirOwner() {
    let mut consent = MtuConsent::new(OWNER).unwrap();
    for fault in 0..5 {
        let mut original = document();
        let now = match fault {
            0 => {
                original.schemaVersion = 3;
                original.policyOriginal = None;
                1000
            }
            1 => {
                original.policyOriginal = None;
                1000
            }
            2 => {
                original.authorizedUserSid = OTHER.into();
                1000
            }
            3 => 999,
            _ => 121_000,
        };
        assert!(consent.preview(original, OWNER, now).is_err());
    }
    assert!(consent.preview(document(), OWNER, 1000).is_ok());
}

#[test]
fn failedGrantCommitConsumesApprovalAndRequiresAnotherExplicitPreview() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let connection = Connection::open(fixture.path()).unwrap();
    connection.execute_batch("CREATE TRIGGER refuse_consent_grant BEFORE INSERT ON grants BEGIN SELECT RAISE(FAIL,'test refused consent grant'); END;").unwrap();
    let mut consent = MtuConsent::new(OWNER).unwrap();
    let original = document();
    let preview = consent.preview(original.clone(), OWNER, 1000).unwrap();
    assert!(
        consent
            .approve(
                preview.previewId,
                &preview.checkpointSha256,
                OWNER,
                &mut store,
                1001
            )
            .is_err()
    );
    connection
        .execute_batch("DROP TRIGGER refuse_consent_grant;")
        .unwrap();
    assert!(
        consent
            .approve(
                preview.previewId,
                &preview.checkpointSha256,
                OWNER,
                &mut store,
                1002
            )
            .is_err()
    );
    assert_eq!(grantCount(&fixture), 0);
    let next = consent.preview(original, OWNER, 1002).unwrap();
    assert_ne!(next.previewId, preview.previewId);
    consent
        .approve(
            next.previewId,
            &next.checkpointSha256,
            OWNER,
            &mut store,
            1003,
        )
        .unwrap();
    assert_eq!(grantCount(&fixture), 1);
}

#[test]
fn freshPreviewsInvalidateOldNoncesAndNeverOutliveTheTrialLease() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let mut consent = MtuConsent::new(OWNER).unwrap();
    let original = document();
    let first = consent.preview(original.clone(), OWNER, 1000).unwrap();
    let second = consent.preview(original, OWNER, 31_000).unwrap();
    assert_ne!(first.previewId, second.previewId);
    assert!(
        consent
            .approve(
                first.previewId,
                &first.checkpointSha256,
                OWNER,
                &mut store,
                31_001
            )
            .is_err()
    );
    consent.cancel(second.previewId, OWNER).unwrap();
    let mut original = document();
    original.leaseExpiresAtUnixMs = 32_000;
    let preview = consent.preview(original, OWNER, 31_500).unwrap();
    assert_eq!(preview.expiresAtUnixMs, 32_000);
    assert!(
        consent
            .approve(
                preview.previewId,
                &preview.checkpointSha256,
                OWNER,
                &mut store,
                32_000
            )
            .is_err()
    );
    assert_eq!(grantCount(&fixture), 0);
}
