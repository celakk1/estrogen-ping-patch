use super::*;
use crate::{authorization::tests::Fixture, journal::MtuCheckpoint};
use epp_core::{
    comparison,
    experiment::budget::{Provider, TrafficBudget},
};
use rusqlite::Connection;

const OWNER: &str = "S-1-5-21-1-2-3-1000";
const OTHER: &str = "S-1-5-21-1-2-3-1001";

#[test]
fn persistedQuotaCannotBeExpandedByLosingTheVolatileCheckpointCount() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (mut session, plan) = approved();
    for index in 0..12 {
        let document = trial(&session, 1010 + index);
        session
            .issue(&document, &plan, OWNER, &mut store, 1010 + index)
            .unwrap();
    }
    session.checkpoints.clear();
    let document = trial(&session, 1022);
    let error = session
        .issue(&document, &plan, OWNER, &mut store, 1022)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Durable session trial allowance is exhausted")
    );
    assert_eq!(count(&fixture), 12);
    let connection = Connection::open(fixture.path()).unwrap();
    assert_eq!(
        connection
            .query_row::<u32, _, _>("SELECT COUNT(*) FROM session_approvals", [], |row| row
                .get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        connection
            .query_row::<u32, _, _>("SELECT COUNT(*) FROM session_grants", [], |row| row.get(0))
            .unwrap(),
        12
    );
    session.cancel(OWNER, &mut store, 1023).unwrap();
}

#[test]
fn rehashedAuditCannotChangeTheScopeOfAnExistingGrant() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (mut session, plan) = approved();
    let document = trial(&session, 1010);
    let grant = session
        .issue(&document, &plan, OWNER, &mut store, 1010)
        .unwrap();
    let id = grant.sessionApprovalId.unwrap();
    let connection = Connection::open(fixture.path()).unwrap();
    let original: String = connection
        .query_row(
            "SELECT document_json FROM session_approvals WHERE id=?",
            [id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let mut record: serde_json::Value = serde_json::from_str(&original).unwrap();
    let mut scope: serde_json::Value =
        serde_json::from_str(record["approval"]["scopeJson"].as_str().unwrap()).unwrap();
    scope[0]["proposedMtu"] = 1300.into();
    let scopeJson = serde_json::to_string(&scope).unwrap();
    record["approval"]["scopeJson"] = scopeJson.clone().into();
    record["approval"]["scopeSha256"] =
        format!("{:x}", Sha256::digest(scopeJson.as_bytes())).into();
    let payload = serde_json::to_string(&record).unwrap();
    let digest = format!("{:x}", Sha256::digest(payload.as_bytes()));
    connection
        .execute(
            "UPDATE session_approvals SET document_json=?,sha256=? WHERE id=?",
            [payload, digest.clone(), id.to_string()],
        )
        .unwrap();
    let grantSha256: String = connection
        .query_row(
            "SELECT sha256 FROM grants WHERE id=?",
            [grant.id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let linkSha256 = hash(&(id, grant.id, 1u32, &digest, &grantSha256)).unwrap();
    connection
        .execute(
            "UPDATE session_grants SET sha256=? WHERE grant_id=?",
            [linkSha256, grant.id.to_string()],
        )
        .unwrap();
    let error = store.read(grant.id).err().unwrap().to_string();
    assert!(
        error.contains("Trial grant differs from its durable session approval"),
        "{error}"
    );
}

#[test]
fn durableSessionScopeAndGrantLinksSurviveRestartWithoutNewAuthority() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (mut session, plan) = approved();
    let document = trial(&session, 1010);
    let grant = session
        .issue(&document, &plan, OWNER, &mut store, 1010)
        .unwrap();
    let id = grant.sessionApprovalId.unwrap();
    assert_eq!(grant.schemaVersion, 2);
    let connection = Connection::open(fixture.path()).unwrap();
    let recordJson: String = connection
        .query_row(
            "SELECT document_json FROM session_approvals WHERE id=?",
            [id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let record: serde_json::Value = serde_json::from_str(&recordJson).unwrap();
    assert_eq!(
        record["approval"]["scopeSha256"],
        session.approval.scopeSha256
    );
    let scope: (MtuPreview, Plan, u64) =
        serde_json::from_str(record["approval"]["scopeJson"].as_str().unwrap()).unwrap();
    assert_eq!(scope.0.previewId, id);
    assert_eq!(hash(&scope.1).unwrap(), hash(&plan).unwrap());
    assert_eq!(
        connection
            .query_row::<u32, _, _>(
                "SELECT ordinal FROM session_grants WHERE grant_id=? AND session_id=?",
                [grant.id.to_string(), id.to_string()],
                |row| row.get(0)
            )
            .unwrap(),
        1
    );
    drop(store);
    let mut reopened = fixture.open();
    assert_eq!(reopened.read(grant.id).unwrap().grant, grant);
    assert!(
        reopened
            .authorize(
                grant.id,
                &document,
                OWNER,
                crate::recovery::AuthorizationAction::Prepare,
                1011
            )
            .is_err()
    );
    let next = trial(&session, 1011);
    assert!(
        session
            .issue(&next, &plan, OWNER, &mut reopened, 1011)
            .is_err()
    );
    assert_eq!(count(&fixture), 1);
    session.cancel(OWNER, &mut reopened, 1012).unwrap();
    assert!(reopened.read(grant.id).unwrap().revoked);
}

#[test]
fn failedSessionAuditOrLinkCommitLeavesNoApprovalGrantOrAllowanceToRetry() {
    for table in ["session_approvals", "session_grants"] {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let connection = Connection::open(fixture.path()).unwrap();
        connection.execute_batch(&format!("CREATE TRIGGER refuse_session_audit BEFORE INSERT ON {table} BEGIN SELECT RAISE(FAIL,'test refused session audit'); END;")).unwrap();
        let (mut session, plan) = approved();
        let document = trial(&session, 1010);
        assert!(
            session
                .issue(&document, &plan, OWNER, &mut store, 1010)
                .is_err()
        );
        assert_eq!(count(&fixture), 0);
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
        connection
            .execute_batch("DROP TRIGGER refuse_session_audit;")
            .unwrap();
        assert!(
            session
                .issue(&document, &plan, OWNER, &mut store, 1011)
                .is_err()
        );
    }
}

#[test]
fn missingCorruptOrMisorderedSessionEvidenceBlocksLiveReadsAndReopen() {
    for fault in 0..4 {
        let fixture = Fixture::new();
        let mut store = fixture.open();
        let (mut session, plan) = approved();
        let document = trial(&session, 1010);
        let grant = session
            .issue(&document, &plan, OWNER, &mut store, 1010)
            .unwrap();
        let connection = Connection::open(fixture.path()).unwrap();
        match fault {
            0 => {
                connection
                    .execute("DELETE FROM session_grants", [])
                    .unwrap();
            }
            1 => {
                connection
                    .execute("UPDATE session_grants SET sha256=?", ["0".repeat(64)])
                    .unwrap();
            }
            2 => {
                connection
                    .execute("UPDATE session_grants SET ordinal=2", [])
                    .unwrap();
            }
            3 => {
                connection
                    .execute("UPDATE session_approvals SET sha256=?", ["0".repeat(64)])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(store.read(grant.id).is_err(), "fault {fault}");
        drop(store);
        assert!(
            AuthorizationStore::open(&fixture.path()).is_err(),
            "fault {fault}"
        );
    }
}

fn template() -> MtuCheckpoint {
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

fn plan(template: &MtuCheckpoint) -> Plan {
    let settings = &template.nativeOriginal.as_ref().unwrap().settings;
    let mut candidate = settings.clone();
    candidate.nlMtu = template.proposedMtu;
    let threshold = comparison::Threshold {
        absolute: 1.0,
        relativeFraction: 0.0,
    };
    Plan {
        id: Uuid::new_v4().to_string(),
        createdAtUnixMs: 1000,
        expiresAtUnixMs: 241_000,
        blockCount: 12,
        comparison: comparison::Plan {
            maximumBlockDurationMs: 5000,
            cohortSha256: "a".repeat(64),
            environmentSha256: "b".repeat(64),
            originalConfigurationSha256: hash(settings).unwrap(),
            candidateConfigurationSha256: hash(&candidate).unwrap(),
            metrics: vec![
                comparison::MetricRule {
                    id: "response-time".into(),
                    unit: comparison::Unit::Milliseconds,
                    direction: comparison::Direction::LowerIsBetter,
                    role: comparison::Role::Objective,
                    resolution: 0.1,
                    minimumImprovement: threshold,
                    maximumRegression: threshold,
                    maximumBaselineDrift: threshold,
                },
                comparison::MetricRule {
                    id: "connection-failure".into(),
                    unit: comparison::Unit::Percent,
                    direction: comparison::Direction::LowerIsBetter,
                    role: comparison::Role::Guard,
                    resolution: 0.1,
                    minimumImprovement: threshold,
                    maximumRegression: threshold,
                    maximumBaselineDrift: threshold,
                },
            ],
        },
        trafficBudget: Some(TrafficBudget {
            schemaVersion: 1,
            limits: Resources {
                probeAttempts: 108,
                ..Default::default()
            },
            providers: vec![Provider {
                id: "owned-benchmark".into(),
                perCollection: Resources {
                    probeAttempts: 3,
                    ..Default::default()
                },
                limits: Resources {
                    probeAttempts: 108,
                    ..Default::default()
                },
            }],
        }),
    }
}

fn costs() -> BTreeMap<String, Resources> {
    BTreeMap::from([(
        "owned-benchmark".into(),
        Resources {
            probeAttempts: 3,
            ..Default::default()
        },
    )])
}

fn approved() -> (ApprovedSession, Plan) {
    let template = template();
    let plan = plan(&template);
    let mut consent = SessionConsent::new(OWNER).unwrap();
    let preview = consent
        .preview(template, plan.clone(), &costs(), OWNER, 1000)
        .unwrap();
    (
        consent
            .approve(preview.mtu.previewId, &preview.scopeSha256, OWNER, 1001)
            .unwrap(),
        plan,
    )
}

fn trial(session: &ApprovedSession, now: u64) -> MtuCheckpoint {
    let mut document = session.template.clone();
    document.id = Uuid::new_v4();
    document.createdAtUnixMs = now;
    document.leaseExpiresAtUnixMs = now + 5000;
    document.nativeOriginal.as_mut().unwrap().capturedAtUnixMs = now;
    document
}

fn count(fixture: &Fixture) -> u32 {
    Connection::open(fixture.path())
        .unwrap()
        .query_row("SELECT COUNT(*) FROM grants", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn oneExactSessionApprovalIssuesOnlyItsBoundedNonRetainingTrials() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (mut session, plan) = approved();
    let mut grants = Vec::new();
    for index in 0..12 {
        let document = trial(&session, 1010 + index);
        let grant = session
            .issue(&document, &plan, OWNER, &mut store, 1010 + index)
            .unwrap();
        assert!(!grant.allowRetention);
        assert_eq!(
            grant.checkpointSha256,
            checkpointChecksum(&document).unwrap()
        );
        grants.push(grant.id);
    }
    let document = trial(&session, 1022);
    assert!(
        session
            .issue(&document, &plan, OWNER, &mut store, 1022)
            .is_err()
    );
    assert_eq!(count(&fixture), 12);
    assert!(session.cancel(OTHER, &mut store, 1023).is_err());
    session.cancel(OWNER, &mut store, 1023).unwrap();
    assert!(grants.iter().all(|id| store.read(*id).unwrap().revoked));
    session.cancel(OWNER, &mut store, 1024).unwrap();
    assert!(
        session
            .issue(&document, &plan, OWNER, &mut store, 1024)
            .is_err()
    );
}

#[test]
fn completePlanHashIsSingleUseAndReturnedChangesCannotExpandIt() {
    let template = template();
    let plan = plan(&template);
    let mut consent = SessionConsent::new(OWNER).unwrap();
    let mut preview = consent
        .preview(template, plan.clone(), &costs(), OWNER, 1000)
        .unwrap();
    preview.plan.blockCount = 32;
    preview.mtu.proposedMtu = 1300;
    preview.maximumTrialDurationMs = 300_000;
    assert!(
        consent
            .approve(preview.mtu.previewId, &preview.scopeSha256, OTHER, 1001)
            .is_err()
    );
    assert!(
        consent
            .approve(Uuid::new_v4(), &preview.scopeSha256, OWNER, 1001)
            .is_err()
    );
    assert!(
        consent
            .approve(preview.mtu.previewId, &"0".repeat(64), OWNER, 1001)
            .is_err()
    );
    let session = consent
        .approve(preview.mtu.previewId, &preview.scopeSha256, OWNER, 1001)
        .unwrap();
    assert_eq!(session.plan.blockCount, 12);
    assert_eq!(session.template.proposedMtu, 1400);
    assert_eq!(session.maximumTrialDurationMs, 120_000);
    assert!(
        consent
            .approve(preview.mtu.previewId, &preview.scopeSha256, OWNER, 1002)
            .is_err()
    );
    assert!(
        SessionConsent::new(OWNER)
            .unwrap()
            .approve(preview.mtu.previewId, &preview.scopeSha256, OWNER, 1002)
            .is_err()
    );
}

#[test]
fn sessionPreviewRequiresExactConfigurationsAndTrustedFullTrafficAllowance() {
    for fault in 0..7 {
        let mut template = template();
        let mut plan = plan(&template);
        let mut costs = costs();
        match fault {
            0 => plan.comparison.originalConfigurationSha256 = "c".repeat(64),
            1 => plan.comparison.candidateConfigurationSha256 = "c".repeat(64),
            2 => plan.trafficBudget.as_mut().unwrap().limits.probeAttempts -= 1,
            3 => {
                plan.trafficBudget.as_mut().unwrap().providers[0]
                    .limits
                    .probeAttempts -= 1
            }
            4 => costs.values_mut().next().unwrap().probeAttempts += 1,
            5 => costs.clear(),
            6 => template.leaseExpiresAtUnixMs = 1000 + 300_001,
            _ => unreachable!(),
        }
        assert!(
            SessionConsent::new(OWNER)
                .unwrap()
                .preview(template, plan, &costs, OWNER, 1000)
                .is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn changedPlanIdentityOriginalAndLeaseCannotUseSessionPermission() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (mut session, plan) = approved();
    for fault in 0..9 {
        let mut document = trial(&session, 1010);
        let mut supplied = plan.clone();
        match fault {
            0 => supplied.comparison.cohortSha256 = "c".repeat(64),
            1 => supplied.comparison.environmentSha256 = "c".repeat(64),
            2 => {
                supplied
                    .trafficBudget
                    .as_mut()
                    .unwrap()
                    .limits
                    .probeAttempts += 1
            }
            3 => document.id = session.template.id,
            4 => document.proposedMtu -= 1,
            5 => document.leaseExpiresAtUnixMs = 1010 + 120_001,
            6 => document.nativeOriginal.as_mut().unwrap().settings.metric += 1,
            7 => document.policyOriginal = None,
            8 => document.createdAtUnixMs = 999,
            _ => unreachable!(),
        }
        assert!(
            session
                .issue(&document, &supplied, OWNER, &mut store, 1010)
                .is_err(),
            "fault {fault}"
        );
    }
    let document = trial(&session, 1010);
    assert!(
        session
            .issue(&document, &plan, OTHER, &mut store, 1010)
            .is_err()
    );
    session
        .issue(&document, &plan, OWNER, &mut store, 1010)
        .unwrap();
    assert!(
        session
            .issue(&document, &plan, OWNER, &mut store, 1010)
            .is_err()
    );
    assert_eq!(count(&fixture), 1);
}

#[test]
fn expiryCancellationAndClockRollbackNeverRevivePermission() {
    for fault in 0..3 {
        let template = template();
        let plan = plan(&template);
        let mut consent = SessionConsent::new(OWNER).unwrap();
        let preview = consent
            .preview(template, plan, &costs(), OWNER, 1000)
            .unwrap();
        match fault {
            0 => consent.cancel(preview.mtu.previewId, OWNER).unwrap(),
            1 => {
                assert!(
                    consent
                        .approve(preview.mtu.previewId, &preview.scopeSha256, OWNER, 31_000)
                        .is_err()
                );
            }
            2 => {
                assert!(
                    consent
                        .approve(preview.mtu.previewId, &preview.scopeSha256, OWNER, 999)
                        .is_err()
                );
            }
            _ => unreachable!(),
        }
        assert!(
            consent
                .approve(preview.mtu.previewId, &preview.scopeSha256, OWNER, 1001)
                .is_err()
        );
    }
    let fixture = Fixture::new();
    let mut store = fixture.open();
    for fault in 0..3 {
        let (mut session, plan) = approved();
        let document = trial(&session, 1010);
        match fault {
            0 => {
                assert!(
                    session
                        .issue(&document, &plan, OWNER, &mut store, plan.expiresAtUnixMs)
                        .is_err()
                );
            }
            1 => {
                assert!(
                    session
                        .issue(&document, &plan, OWNER, &mut store, 1000)
                        .is_err()
                );
            }
            2 => {
                session.deadline = Instant::now();
            }
            _ => unreachable!(),
        }
        assert!(
            session
                .issue(&document, &plan, OWNER, &mut store, 1010)
                .is_err()
        );
    }
    assert_eq!(count(&fixture), 0);
}

#[test]
fn laterTrialsUseFreshLeasesWithinTheOriginalSessionDeadline() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let (mut session, plan) = approved();
    let document = trial(&session, 130_000);
    session
        .issue(&document, &plan, OWNER, &mut store, 130_000)
        .unwrap();
    let mut document = trial(&session, 240_000);
    assert!(
        session
            .issue(&document, &plan, OWNER, &mut store, 240_000)
            .is_err()
    );
    document.createdAtUnixMs = 235_500;
    document.leaseExpiresAtUnixMs = 240_500;
    document.nativeOriginal.as_mut().unwrap().capturedAtUnixMs = 235_500;
    session
        .issue(&document, &plan, OWNER, &mut store, 240_000)
        .unwrap();
    assert_eq!(count(&fixture), 2);
    session.cancel(OWNER, &mut store, 240_001).unwrap();
}

#[test]
fn failedGrantCommitStopsSessionAndFailedRevocationRemainsRetryable() {
    let fixture = Fixture::new();
    let mut store = fixture.open();
    let connection = Connection::open(fixture.path()).unwrap();
    connection.execute_batch("CREATE TRIGGER refuse_session_grant BEFORE INSERT ON grants BEGIN SELECT RAISE(FAIL,'test refused session grant'); END;").unwrap();
    let (mut session, plan) = approved();
    let document = trial(&session, 1010);
    assert!(
        session
            .issue(&document, &plan, OWNER, &mut store, 1010)
            .is_err()
    );
    connection
        .execute_batch("DROP TRIGGER refuse_session_grant;")
        .unwrap();
    let document = trial(&session, 1011);
    assert!(
        session
            .issue(&document, &plan, OWNER, &mut store, 1011)
            .is_err()
    );
    assert_eq!(count(&fixture), 0);

    let (mut session, plan) = approved();
    let document = trial(&session, 1010);
    let grant = session
        .issue(&document, &plan, OWNER, &mut store, 1010)
        .unwrap();
    let second = session
        .issue(&trial(&session, 1011), &plan, OWNER, &mut store, 1011)
        .unwrap();
    connection.execute_batch(&format!("CREATE TRIGGER refuse_session_revoke BEFORE INSERT ON grant_events WHEN NEW.grant_id='{}' BEGIN SELECT RAISE(FAIL,'test refused session revoke'); END;", grant.id)).unwrap();
    assert!(session.cancel(OWNER, &mut store, 1012).is_err());
    assert!(!store.read(grant.id).unwrap().revoked);
    assert!(store.read(second.id).unwrap().revoked);
    assert!(
        session
            .issue(&trial(&session, 1011), &plan, OWNER, &mut store, 1011)
            .is_err()
    );
    connection
        .execute_batch("DROP TRIGGER refuse_session_revoke;")
        .unwrap();
    session.cancel(OWNER, &mut store, 1013).unwrap();
    assert!(store.read(grant.id).unwrap().revoked);
}
