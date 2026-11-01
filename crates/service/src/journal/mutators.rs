use super::{Checkpoint, store::checksum};
use crate::{ServiceResult, recovery::WritePurpose};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(test)]
mod tests;

const MAX_MUTATORS: usize = 32;
const MAX_PAYLOAD: usize = 2048;

pub(super) const TABLES: &str = "CREATE TABLE mutator_heads(checkpoint_id TEXT PRIMARY KEY REFERENCES checkpoints(id), count INTEGER NOT NULL, sha256 TEXT NOT NULL);
    CREATE TABLE checkpoint_mutators(checkpoint_id TEXT NOT NULL REFERENCES mutator_heads(checkpoint_id), sequence INTEGER NOT NULL, document_json TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(checkpoint_id,sequence));";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutatorIdentity {
    pub processId: u32,
    pub creationTime100ns: String,
}

impl MutatorIdentity {
    pub fn validate(&self) -> ServiceResult<()> {
        if self.creationTime100ns.len() > 20 {
            return Err("Mutator creation time exceeds its supported size".into());
        }
        let creation = self.creationTime100ns.parse::<u64>()?;
        if self.processId <= 4 || creation == 0 || creation.to_string() != self.creationTime100ns {
            return Err(
                "Mutator identity requires a real PID and exact canonical Windows creation time"
                    .into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutatorRecord {
    pub schemaVersion: u32,
    pub checkpointId: Uuid,
    pub checkpointSha256: String,
    pub sequence: u32,
    pub registeredAtUnixMs: u64,
    pub purpose: WritePurpose,
    pub identity: MutatorIdentity,
    pub previousSha256: String,
}

pub(super) fn initialize(connection: &Connection) -> ServiceResult<()> {
    connection.execute_batch(TABLES)?;
    connection.execute(
        "INSERT INTO mutator_heads(checkpoint_id,count,sha256) SELECT id,0,sha256 FROM checkpoints",
        [],
    )?;
    Ok(())
}

pub(super) fn insertHead(connection: &Connection, id: Uuid, digest: &str) -> ServiceResult<()> {
    connection.execute(
        "INSERT INTO mutator_heads(checkpoint_id,count,sha256) VALUES(?1,0,?2)",
        params![id.to_string(), digest],
    )?;
    Ok(())
}

pub(super) fn load(
    connection: &Connection,
    checkpoint: &Checkpoint,
) -> ServiceResult<Vec<MutatorRecord>> {
    let (count, head): (u32, String) = connection.query_row(
        "SELECT count,sha256 FROM mutator_heads WHERE checkpoint_id=?1",
        [checkpoint.document().id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if count as usize > MAX_MUTATORS {
        return Err("Mutator head exceeds the supported record limit".into());
    }
    let mut statement = connection.prepare("SELECT sequence,document_json,sha256,length(CAST(document_json AS BLOB)) FROM checkpoint_mutators WHERE checkpoint_id=?1 ORDER BY sequence LIMIT 33")?;
    let mut rows = statement.query([checkpoint.document().id.to_string()])?;
    let mut records: Vec<MutatorRecord> = Vec::new();
    let mut previous = checkpoint.documentSha256().to_owned();
    while let Some(row) = rows.next()? {
        let sequence: u32 = row.get(0)?;
        let length: i64 = row.get(3)?;
        if records.len() >= MAX_MUTATORS
            || sequence as usize != records.len()
            || !(0..=MAX_PAYLOAD as i64).contains(&length)
        {
            return Err("Mutator sequence or size is invalid".into());
        }
        let payload: String = row.get(1)?;
        let digest: String = row.get(2)?;
        if payload.len() > MAX_PAYLOAD || checksum(&payload) != digest {
            return Err("Mutator record checksum failed".into());
        }
        let record: MutatorRecord = serde_json::from_str(&payload)?;
        record.identity.validate()?;
        if record.schemaVersion != 1
            || record.sequence != sequence
            || record.checkpointId != checkpoint.document().id
            || record.checkpointSha256 != checkpoint.documentSha256()
            || record.previousSha256 != previous
            || record.registeredAtUnixMs == 0
            || record.registeredAtUnixMs > i64::MAX as u64
            || !matches!(checkpoint.document().schemaVersion, 3 | 4)
            || (sequence == 0 && record.purpose != WritePurpose::Apply)
            || (sequence != 0 && record.purpose != WritePurpose::Restore)
            || records
                .iter()
                .any(|prior| prior.identity == record.identity)
            || (record.purpose == WritePurpose::Apply
                && (record.registeredAtUnixMs < checkpoint.document().createdAtUnixMs
                    || record.registeredAtUnixMs >= checkpoint.document().leaseExpiresAtUnixMs))
        {
            return Err("Mutator scope or event chain is invalid".into());
        }
        previous = digest;
        records.push(record);
    }
    if records.len() != count as usize || previous != head {
        return Err("Mutator records are missing or changed".into());
    }
    if (!records.is_empty()
        && matches!(
            checkpoint.state(),
            super::State::Prepared | super::State::Cancelled
        ))
        || (matches!(checkpoint.document().schemaVersion, 3 | 4)
            && matches!(
                checkpoint.state(),
                super::State::Applied | super::State::Retained
            )
            && !records
                .iter()
                .any(|record| record.purpose == WritePurpose::Apply))
    {
        return Err("Mutator evidence does not match the checkpoint state".into());
    }
    Ok(records)
}

pub(super) fn append(
    connection: &Connection,
    checkpoint: &Checkpoint,
    purpose: WritePurpose,
    identity: MutatorIdentity,
    nowUnixMs: u64,
) -> ServiceResult<MutatorRecord> {
    use super::State;
    identity.validate()?;
    let records = load(connection, checkpoint)?;
    let validState = match purpose {
        WritePurpose::Apply => checkpoint.state() == State::Applying,
        WritePurpose::Restore => matches!(
            checkpoint.state(),
            State::Applying | State::Applied | State::Restoring | State::RecoveryRequired
        ),
    };
    if !matches!(checkpoint.document().schemaVersion, 3 | 4)
        || !validState
        || records.len() >= MAX_MUTATORS
        || nowUnixMs == 0
        || nowUnixMs > i64::MAX as u64
        || records.iter().any(|record| record.identity == identity)
    {
        return Err("Mutator registration is stale, repeated, unsupported, or outside the durable write intent".into());
    }
    if purpose == WritePurpose::Apply
        && (!records.is_empty()
            || nowUnixMs < checkpoint.document().createdAtUnixMs
            || nowUnixMs >= checkpoint.document().leaseExpiresAtUnixMs)
    {
        return Err(
            "Apply process registration must be first and within the approved time window".into(),
        );
    }
    if purpose == WritePurpose::Restore && records.is_empty() {
        return Err("A restore command requires the earlier registered apply intent".into());
    }
    let (count, previous): (u32, String) = connection.query_row(
        "SELECT count,sha256 FROM mutator_heads WHERE checkpoint_id=?1",
        [checkpoint.document().id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let record = MutatorRecord {
        schemaVersion: 1,
        checkpointId: checkpoint.document().id,
        checkpointSha256: checkpoint.documentSha256().into(),
        sequence: count,
        registeredAtUnixMs: nowUnixMs,
        purpose,
        identity,
        previousSha256: previous.clone(),
    };
    let payload = serde_json::to_string(&record)?;
    if payload.len() > MAX_PAYLOAD {
        return Err("Mutator record exceeds its storage limit".into());
    }
    let digest = checksum(&payload);
    connection.execute("INSERT INTO checkpoint_mutators(checkpoint_id,sequence,document_json,sha256) VALUES(?1,?2,?3,?4)", params![record.checkpointId.to_string(),record.sequence,payload,digest])?;
    if connection.execute("UPDATE mutator_heads SET count=?1,sha256=?2 WHERE checkpoint_id=?3 AND count=?4 AND sha256=?5", params![count+1,digest,record.checkpointId.to_string(),count,previous])? != 1 {
        return Err("Mutator head changed during registration".into());
    }
    Ok(record)
}
