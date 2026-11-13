use super::{Plan, Snapshot, State, nowUnixMs};
use crate::AppResult;
use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

const APPLICATION_ID: u32 = 0x45505045;
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;
const STORE_BYTES: u64 = 256 * 1024 * 1024;

pub struct Store {
    connection: Connection,
}

fn identity(connection: &Connection) -> AppResult<bool> {
    let applicationId: u32 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if applicationId == APPLICATION_ID && version == 1 {
        return Ok(true);
    }
    let count: u32 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if applicationId == 0 && version == 0 && count == 0 {
        return Ok(false);
    }
    Err("File is not a supported experiment store; refusing to alter or downgrade it".into())
}

fn checksum(payload: &str) -> String {
    format!("{:x}", Sha256::digest(payload.as_bytes()))
}

fn payload(snapshot: &Snapshot) -> AppResult<String> {
    snapshot.validate()?;
    let payload = serde_json::to_string(snapshot)?;
    if payload.len() > MAX_PAYLOAD {
        return Err("Experiment exceeds its four MiB durable evidence limit".into());
    }
    Ok(payload)
}

fn load(connection: &Connection, id: &str) -> AppResult<Snapshot> {
    let (payload, expected, revision, active): (String, String, u32, bool) = connection.query_row(
        "SELECT payload_json,sha256,revision,active FROM experiments WHERE id=?1 AND length(CAST(payload_json AS BLOB))<=4194304",
        [id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if checksum(&payload) != expected {
        return Err("Experiment failed its stored evidence checksum; preserve the database for investigation".into());
    }
    let snapshot: Snapshot = serde_json::from_str(&payload)?;
    snapshot.validate()?;
    if snapshot.plan.id != id
        || snapshot.revision != revision
        || snapshot.state.blocksNewExperiment() != active
    {
        return Err("Experiment progress metadata differs from its durable evidence".into());
    }
    Ok(snapshot)
}

fn verifyCapacity(connection: &Connection, reservedBytes: u64, limit: u64) -> AppResult<()> {
    let bytes: i64 = connection.query_row(
        "SELECT COALESCE(SUM(length(CAST(payload_json AS BLOB))),0) FROM experiments",
        [],
        |row| row.get(0),
    )?;
    if u64::try_from(bytes)?
        .checked_add(reservedBytes)
        .is_none_or(|total| total > limit)
    {
        return Err("Experiment evidence capacity is full; preserve and archive existing evidence before more trials".into());
    }
    Ok(())
}

impl Store {
    pub fn open(path: &Path) -> AppResult<Self> {
        if !path.is_absolute() {
            return Err("Experiment store requires an absolute local data path".into());
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        identity(&connection)?;
        let mode: String =
            connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        if mode != "wal"
            || connection.pragma_query_value::<u32, _>(None, "synchronous", |row| row.get(0))? != 2
        {
            return Err(
                "Experiment store requires durable WAL mode and FULL synchronization".into(),
            );
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !identity(&transaction)? {
            transaction.execute_batch("CREATE TABLE experiments(id TEXT PRIMARY KEY, revision INTEGER NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)), payload_json TEXT NOT NULL, sha256 TEXT NOT NULL);
                CREATE UNIQUE INDEX one_active_experiment ON experiments(active) WHERE active=1;")?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", 1)?;
        }
        transaction.commit()?;
        let integrity: String =
            connection.pragma_query_value(None, "quick_check", |row| row.get(0))?;
        if integrity != "ok" {
            return Err("Experiment store failed SQLite integrity verification".into());
        }
        let store = Self { connection };
        store.verifyAll()?;
        Ok(store)
    }

    fn verifyAll(&self) -> AppResult<()> {
        verifyCapacity(&self.connection, 0, STORE_BYTES)?;
        let mut query = self
            .connection
            .prepare("SELECT id FROM experiments ORDER BY id LIMIT 2001")?;
        let ids: Vec<String> = query
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        if ids.len() > 2000 {
            return Err("Experiment store capacity exceeded; preserve and archive evidence before more trials".into());
        }
        for id in ids {
            self.load(&id)?;
        }
        Ok(())
    }

    pub fn load(&self, id: &str) -> AppResult<Snapshot> {
        load(&self.connection, id)
    }

    pub fn pending(&self) -> AppResult<Vec<Snapshot>> {
        self.verifyAll()?;
        let mut query = self
            .connection
            .prepare("SELECT id FROM experiments WHERE active=1")?;
        let ids = query.query_map([], |row| row.get::<_, String>(0))?;
        ids.map(|id| self.load(&id?)).collect()
    }

    pub(super) fn begin(&mut self, plan: Plan, now: u64) -> AppResult<Snapshot> {
        let snapshot = Snapshot {
            schemaVersion: 2,
            revision: 0,
            updatedAtUnixMs: now,
            plan,
            state: State::Ready,
            blocks: Vec::new(),
            checkpoints: Vec::new(),
            pendingBefore: None,
            pendingCandidate: None,
            error: None,
            reservedBlocks: 0,
        };
        let payload = payload(&snapshot)?;
        self.verifyAll()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (count, active): (u32, bool) = transaction.query_row(
            "SELECT COUNT(*),COALESCE(MAX(active),0) FROM experiments",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if active || count >= 2000 {
            return Err("An unfinished experiment or full evidence store blocks new trials; verify recovery before continuing".into());
        }
        verifyCapacity(&transaction, MAX_PAYLOAD as u64, STORE_BYTES)?;
        transaction.execute(
            "INSERT INTO experiments(id,revision,active,payload_json,sha256) VALUES(?1,0,1,?2,?3)",
            params![snapshot.plan.id, payload, checksum(&payload)],
        )?;
        transaction.commit()?;
        self.load(&snapshot.plan.id)
    }

    pub(super) fn save(&mut self, snapshot: &Snapshot) -> AppResult<()> {
        let payload = payload(snapshot)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous = load(&transaction, &snapshot.plan.id)?;
        if !previous.state.blocksNewExperiment()
            || snapshot.schemaVersion != previous.schemaVersion
            || snapshot.reservedBlocks < previous.reservedBlocks
            || snapshot.revision != previous.revision + 1
            || snapshot.updatedAtUnixMs < previous.updatedAtUnixMs
            || snapshot.updatedAtUnixMs > nowUnixMs()?.max(previous.updatedAtUnixMs)
            || serde_json::to_value(&snapshot.plan)? != serde_json::to_value(&previous.plan)?
        {
            return Err("Stale experiment update or changed plan refused".into());
        }
        let changed = transaction.execute("UPDATE experiments SET revision=?1,active=?2,payload_json=?3,sha256=?4 WHERE id=?5 AND revision=?6", params![snapshot.revision, snapshot.state.blocksNewExperiment(), payload, checksum(&payload), snapshot.plan.id, previous.revision])?;
        if changed != 1 {
            return Err("Experiment ownership changed before durable progress was recorded".into());
        }
        verifyCapacity(&transaction, 0, STORE_BYTES)?;
        transaction.commit()?;
        if serde_json::to_string(&self.load(&snapshot.plan.id)?)? != payload {
            return Err("Experiment progress failed committed readback verification".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacityIncludesUtf8BytesAndReservedGrowthWithoutDeletingEvidence() {
        let database = Connection::open_in_memory().unwrap();
        database
            .execute_batch("CREATE TABLE experiments(payload_json TEXT NOT NULL);")
            .unwrap();
        database
            .execute("INSERT INTO experiments VALUES(?1),(?2)", ["é", "abc"])
            .unwrap();
        verifyCapacity(&database, 3, 8).unwrap();
        assert!(verifyCapacity(&database, 4, 8).is_err());
        assert!(verifyCapacity(&database, u64::MAX, 8).is_err());
        let count: u32 = database
            .query_row("SELECT count(*) FROM experiments", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }
}
