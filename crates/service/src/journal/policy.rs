use super::{Checkpoint, MtuCheckpoint, State, store::checksum};
use crate::{ServiceResult, mtu::policy::Capture};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_RECORDS: usize = 16;
const MAX_PAYLOAD: usize = 16384;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum PolicyReadback {
    Captured { capture: Box<Capture> },
    Unavailable { error: String },
}

impl PolicyReadback {
    fn validate(&self) -> ServiceResult<()> {
        match self {
            Self::Captured { capture } => capture.validate(),
            Self::Unavailable { error } if !error.is_empty() && error.chars().count() <= 1024 => {
                Ok(())
            }
            _ => Err("Policy readback has an empty or oversized unavailable reason".into()),
        }
    }

    pub(crate) fn compare(&self, document: &MtuCheckpoint, now: u64) -> ServiceResult<()> {
        self.validate()?;
        match self {
            Self::Captured { capture } => crate::recovery::policyObservationMatches(
                document,
                capture,
                document.originalMtu,
                now,
            ),
            Self::Unavailable { error } => Err(error.clone().into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyRecord {
    pub schemaVersion: u32,
    pub checkpointId: Uuid,
    pub checkpointSha256: String,
    pub restoredEventSha256: String,
    pub sequence: u32,
    pub recordedAtUnixMs: u64,
    pub matchesOriginal: bool,
    pub readback: PolicyReadback,
    pub previousSha256: String,
}

pub(super) fn initialize(connection: &Connection) -> ServiceResult<()> {
    connection.execute_batch("CREATE TABLE policy_heads(checkpoint_id TEXT PRIMARY KEY REFERENCES checkpoints(id), count INTEGER NOT NULL, sha256 TEXT NOT NULL);
        CREATE TABLE checkpoint_policy_checks(checkpoint_id TEXT NOT NULL REFERENCES policy_heads(checkpoint_id), sequence INTEGER NOT NULL, document_json TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(checkpoint_id,sequence));")?;
    connection.execute(
        "INSERT INTO policy_heads(checkpoint_id,count,sha256) SELECT id,0,sha256 FROM checkpoints",
        [],
    )?;
    Ok(())
}

pub(super) fn insertHead(connection: &Connection, id: Uuid, digest: &str) -> ServiceResult<()> {
    connection.execute(
        "INSERT INTO policy_heads(checkpoint_id,count,sha256) VALUES(?1,0,?2)",
        params![id.to_string(), digest],
    )?;
    Ok(())
}

pub(super) fn load(
    connection: &Connection,
    checkpoint: &Checkpoint,
) -> ServiceResult<Vec<PolicyRecord>> {
    let (count, head): (u32, String) = connection.query_row(
        "SELECT count,sha256 FROM policy_heads WHERE checkpoint_id=?1",
        [checkpoint.document().id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if count as usize > MAX_RECORDS {
        return Err("Policy verification head exceeds its record bound".into());
    }
    let mut statement = connection.prepare("SELECT sequence,document_json,sha256,length(CAST(document_json AS BLOB)) FROM checkpoint_policy_checks WHERE checkpoint_id=?1 ORDER BY sequence LIMIT 17")?;
    let mut rows = statement.query([checkpoint.document().id.to_string()])?;
    let mut records: Vec<PolicyRecord> = Vec::new();
    let mut previous = checkpoint.documentSha256().to_owned();
    while let Some(row) = rows.next()? {
        let sequence: u32 = row.get(0)?;
        let length: i64 = row.get(3)?;
        if records.last().is_some_and(|record| record.matchesOriginal)
            || records.len() >= MAX_RECORDS
            || sequence as usize != records.len()
            || !(0..=MAX_PAYLOAD as i64).contains(&length)
        {
            return Err("Policy verification sequence or size is invalid".into());
        }
        let payload: String = row.get(1)?;
        let digest: String = row.get(2)?;
        if payload.len() > MAX_PAYLOAD || checksum(&payload) != digest {
            return Err("Policy verification checksum is invalid".into());
        }
        let record: PolicyRecord = serde_json::from_str(&payload)?;
        record.readback.validate()?;
        if checkpoint.document().schemaVersion != 4
            || checkpoint.state() != State::Restored
            || record.schemaVersion != 1
            || record.checkpointId != checkpoint.document().id
            || record.checkpointSha256 != checkpoint.documentSha256()
            || record.restoredEventSha256 != checkpoint.lastEventSha256
            || record.sequence != sequence
            || record.previousSha256 != previous
            || record.recordedAtUnixMs == 0
            || record.recordedAtUnixMs > i64::MAX as u64
            || record.matchesOriginal
                != record
                    .readback
                    .compare(checkpoint.document(), record.recordedAtUnixMs)
                    .is_ok()
        {
            return Err("Policy verification scope, result, or event binding is invalid".into());
        }
        records.push(record);
        previous = digest;
    }
    if records.len() != count as usize || previous != head {
        return Err("Policy verification records are missing or changed".into());
    }
    Ok(records)
}

pub(super) fn append(
    connection: &Connection,
    checkpoint: &Checkpoint,
    readback: PolicyReadback,
    now: u64,
) -> ServiceResult<PolicyRecord> {
    readback.validate()?;
    let records = load(connection, checkpoint)?;
    if records.last().is_some_and(|record| record.matchesOriginal)
        || checkpoint.document().schemaVersion != 4
        || checkpoint.state() != State::Restored
        || now == 0
        || now > i64::MAX as u64
        || records.len() >= MAX_RECORDS
    {
        return Err(
            "Policy verification requires a restored version-four checkpoint and bounded history"
                .into(),
        );
    }
    let (count, previous): (u32, String) = connection.query_row(
        "SELECT count,sha256 FROM policy_heads WHERE checkpoint_id=?1",
        [checkpoint.document().id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let record = PolicyRecord {
        schemaVersion: 1,
        checkpointId: checkpoint.document().id,
        checkpointSha256: checkpoint.documentSha256().into(),
        restoredEventSha256: checkpoint.lastEventSha256.clone(),
        sequence: count,
        recordedAtUnixMs: now,
        matchesOriginal: readback.compare(checkpoint.document(), now).is_ok(),
        readback,
        previousSha256: previous.clone(),
    };
    let payload = serde_json::to_string(&record)?;
    if payload.len() > MAX_PAYLOAD {
        return Err("Policy verification exceeds its 16 KiB record bound".into());
    }
    let digest = checksum(&payload);
    connection.execute("INSERT INTO checkpoint_policy_checks(checkpoint_id,sequence,document_json,sha256) VALUES(?1,?2,?3,?4)", params![record.checkpointId.to_string(), count, payload, digest])?;
    if connection.execute("UPDATE policy_heads SET count=?1,sha256=?2 WHERE checkpoint_id=?3 AND count=?4 AND sha256=?5", params![count+1, digest, record.checkpointId.to_string(), count, previous])? != 1 { return Err("Policy verification head changed during commit".into()); }
    Ok(record)
}
