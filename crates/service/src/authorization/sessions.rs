use super::*;
use crate::consent::MtuPreview;
use rusqlite::{Connection, OptionalExtension, params};

const MAX_PAYLOAD: usize = 65_536;
const MAX_SESSIONS: usize = 2000;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Approval {
    pub actorSid: String,
    pub approvedAtUnixMs: u64,
    pub scopeJson: String,
    pub scopeSha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    schemaVersion: u32,
    issuerInstanceId: Uuid,
    approval: Approval,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlanBounds {
    createdAtUnixMs: u64,
    expiresAtUnixMs: u64,
    blockCount: u32,
}

struct Scope {
    mtu: MtuPreview,
    plan: PlanBounds,
    maximumTrialDurationMs: u64,
}

impl Approval {
    pub(super) fn id(&self) -> ServiceResult<Uuid> {
        Ok(self.scope()?.mtu.previewId)
    }
    fn scope(&self) -> ServiceResult<Scope> {
        validateSid(&self.actorSid)?;
        if self.scopeJson.len() > MAX_PAYLOAD || checksum(&self.scopeJson) != self.scopeSha256 {
            return Err("Session approval scope failed size or checksum verification".into());
        }
        let (mtu, plan, maximumTrialDurationMs): (MtuPreview, PlanBounds, u64) =
            serde_json::from_str(&self.scopeJson)?;
        crate::preview::Report {
            jobId: mtu.previewId,
            phase: crate::preview::Phase::Ready,
            preview: Some(mtu.clone()),
            grant: None,
            detail: None,
            executionAvailable: false,
        }
        .validate()?;
        if plan.createdAtUnixMs == 0
            || plan.createdAtUnixMs > self.approvedAtUnixMs
            || plan.expiresAtUnixMs > i64::MAX as u64
            || plan.expiresAtUnixMs <= self.approvedAtUnixMs
            || plan.expiresAtUnixMs - plan.createdAtUnixMs > 14_400_000
            || !(12..=32).contains(&plan.blockCount)
            || !(5000..=300_000).contains(&maximumTrialDurationMs)
            || mtu.expiresAtUnixMs <= self.approvedAtUnixMs
            || mtu.trialExpiresAtUnixMs > plan.expiresAtUnixMs
        {
            return Err("Session approval has invalid owner, time, or trial limits".into());
        }
        Ok(Scope {
            mtu,
            plan,
            maximumTrialDurationMs,
        })
    }
}

pub(super) fn initialize(connection: &Connection) -> ServiceResult<()> {
    connection.execute_batch("CREATE TABLE session_approvals(id TEXT PRIMARY KEY, document_json TEXT NOT NULL, sha256 TEXT NOT NULL);
        CREATE TABLE session_grants(grant_id TEXT PRIMARY KEY REFERENCES grants(id), session_id TEXT NOT NULL REFERENCES session_approvals(id), ordinal INTEGER NOT NULL, sha256 TEXT NOT NULL, UNIQUE(session_id,ordinal));")?;
    Ok(())
}

fn read(connection: &Connection, id: Uuid) -> ServiceResult<(Record, String, Scope)> {
    let (payload, digest): (String, String) = connection.query_row(
        "SELECT document_json,sha256 FROM session_approvals WHERE id=? AND length(CAST(document_json AS BLOB))<=65536 AND length(sha256)=64",
        [id.to_string()], |row| Ok((row.get(0)?, row.get(1)?)))?;
    if checksum(&payload) != digest {
        return Err("Session approval record failed checksum verification".into());
    }
    let record: Record = serde_json::from_str(&payload)?;
    if record.schemaVersion != 1 || record.issuerInstanceId.is_nil() {
        return Err("Session approval record has invalid identity or schema".into());
    }
    let scope = record.approval.scope()?;
    if scope.mtu.previewId != id {
        return Err("Session approval key does not match its reviewed scope".into());
    }
    Ok((record, digest, scope))
}

fn matchesScope(grant: &MtuGrant, approval: &Approval, scope: &Scope) -> ServiceResult<()> {
    if grant.schemaVersion != 2
        || grant.sessionApprovalId != Some(scope.mtu.previewId)
        || grant.authorizedUserSid != approval.actorSid
        || grant.context != scope.mtu.context
        || grant.addressFamily != scope.mtu.addressFamily
        || grant.proposedMtu != scope.mtu.proposedMtu
        || grant.allowRetention
        || grant.createdAtUnixMs < approval.approvedAtUnixMs
        || grant.expiresAtUnixMs > scope.plan.expiresAtUnixMs
        || grant.expiresAtUnixMs - grant.createdAtUnixMs > scope.maximumTrialDurationMs
    {
        return Err("Trial grant differs from its durable session approval".into());
    }
    Ok(())
}

pub(super) fn insert(
    connection: &Connection,
    approval: &Approval,
    instanceId: Uuid,
    document: &MtuCheckpoint,
    grant: &MtuGrant,
    grantSha256: &str,
) -> ServiceResult<()> {
    let scope = approval.scope()?;
    matchesScope(grant, approval, &scope)?;
    if document.schemaVersion != 4
        || document.originalMtu != scope.mtu.originalMtu
        || document.leaseExpiresAtUnixMs - document.createdAtUnixMs > scope.maximumTrialDurationMs
        || document.leaseExpiresAtUnixMs - document.createdAtUnixMs < 5000
    {
        return Err("Session trial checkpoint has a different original or lease scope".into());
    }
    let id = scope.mtu.previewId;
    let record = Record {
        schemaVersion: 1,
        issuerInstanceId: instanceId,
        approval: approval.clone(),
    };
    let payload = serde_json::to_string(&record)?;
    if payload.len() > MAX_PAYLOAD {
        return Err("Session approval record exceeds its size limit".into());
    }
    let digest = checksum(&payload);
    let existing: Option<String> = connection
        .query_row(
            "SELECT sha256 FROM session_approvals WHERE id=?",
            [id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        let (stored, _, _) = read(connection, id)?;
        if existing != digest || stored.issuerInstanceId != instanceId {
            return Err(
                "Session approval cannot change scope or resume in another service instance".into(),
            );
        }
    } else {
        let count: u32 =
            connection.query_row("SELECT COUNT(*) FROM session_approvals", [], |row| {
                row.get(0)
            })?;
        if count as usize >= MAX_SESSIONS {
            return Err("Session approval audit storage is full; preserve existing records".into());
        }
        connection.execute(
            "INSERT INTO session_approvals(id,document_json,sha256) VALUES(?1,?2,?3)",
            params![id.to_string(), payload, digest],
        )?;
    }
    let count = verify(connection, id)?;
    if count >= scope.plan.blockCount {
        return Err("Durable session trial allowance is exhausted".into());
    }
    let ordinal = count + 1;
    let linkSha256 = checksum(&serde_json::to_string(&(
        id,
        grant.id,
        ordinal,
        &digest,
        grantSha256,
    ))?);
    connection.execute(
        "INSERT INTO session_grants(grant_id,session_id,ordinal,sha256) VALUES(?1,?2,?3,?4)",
        params![grant.id.to_string(), id.to_string(), ordinal, linkSha256],
    )?;
    Ok(())
}

fn verify(connection: &Connection, id: Uuid) -> ServiceResult<u32> {
    let (record, digest, scope) = read(connection, id)?;
    let mut statement = connection.prepare("SELECT grant_id,ordinal,sha256 FROM session_grants WHERE session_id=? ORDER BY ordinal LIMIT 33")?;
    let mut rows = statement.query([id.to_string()])?;
    let mut count = 0u32;
    while let Some(row) = rows.next()? {
        count += 1;
        let grantId: String = row.get(0)?;
        let ordinal: u32 = row.get(1)?;
        let linkSha256: String = row.get(2)?;
        let (payload, grantSha256): (String, String) = connection.query_row("SELECT document_json,sha256 FROM grants WHERE id=? AND length(CAST(document_json AS BLOB))<=4096 AND length(sha256)=64", [&grantId], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let grant: MtuGrant = serde_json::from_str(&payload)?;
        grant.validate()?;
        if count > scope.plan.blockCount
            || ordinal != count
            || grant.id.to_string() != grantId
            || grant.issuerInstanceId != record.issuerInstanceId
            || checksum(&payload) != grantSha256
            || checksum(&serde_json::to_string(&(
                id,
                grant.id,
                ordinal,
                &digest,
                &grantSha256,
            ))?) != linkSha256
        {
            return Err(
                "Session trial audit identity, order, quota, or checksum is invalid".into(),
            );
        }
        matchesScope(&grant, &record.approval, &scope)?;
    }
    Ok(count)
}

pub(super) fn verifyAll(connection: &Connection) -> ServiceResult<()> {
    let linkCount: u32 =
        connection.query_row("SELECT COUNT(*) FROM session_grants", [], |row| row.get(0))?;
    if linkCount > 2000 {
        return Err("Session trial audit exceeds its supported capacity".into());
    }
    let mut statement =
        connection.prepare("SELECT id FROM session_approvals ORDER BY id LIMIT 2001")?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if ids.len() > MAX_SESSIONS {
        return Err("Session audit exceeds its supported capacity".into());
    }
    for id in ids {
        if verify(connection, Uuid::parse_str(&id)?)? == 0 {
            return Err("Session approval has no atomically linked trial grant".into());
        }
    }
    Ok(())
}

pub(super) fn verifyGrant(connection: &Connection, grant: &MtuGrant) -> ServiceResult<()> {
    let sessionId: Option<String> = connection
        .query_row(
            "SELECT session_id FROM session_grants WHERE grant_id=?",
            [grant.id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    match (grant.sessionApprovalId, sessionId) {
        (None, None) => Ok(()),
        (Some(expected), Some(actual)) if expected.to_string() == actual => {
            verify(connection, expected)?;
            Ok(())
        }
        _ => Err("Grant is missing its exact durable session approval link".into()),
    }
}
