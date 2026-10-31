use super::{Checkpoint, Event, MtuCheckpoint, Observation, State, validateEvent};
use crate::ServiceResult;
use rusqlite::{Connection, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use uuid::Uuid;

const APPLICATION_ID: u32 = 0x45505052;
const MAX_CHECKPOINTS: u32 = 2000;
const MAX_EVENTS: u32 = 128;

pub struct Journal {
    connection: Connection,
}

impl Journal {
    pub fn open(path: &Path) -> ServiceResult<Self> {
        if !path.is_absolute() {
            return Err("Recovery journal requires an absolute, service-protected path".into());
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        validateDatabaseIdentity(&connection)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let mode: String =
            connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        if mode != "wal" {
            return Err("Recovery journal requires durable SQLite WAL mode".into());
        }
        connection.pragma_update(None, "synchronous", "FULL")?;
        if connection.pragma_query_value::<u32, _>(None, "synchronous", |row| row.get(0))? != 2 {
            return Err("Recovery journal requires FULL synchronization".into());
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if validateDatabaseIdentity(&transaction)? == 0 {
            transaction.execute_batch("CREATE TABLE checkpoints(id TEXT PRIMARY KEY, document_json TEXT NOT NULL, sha256 TEXT NOT NULL);
                CREATE TABLE checkpoint_events(checkpoint_id TEXT NOT NULL REFERENCES checkpoints(id), sequence INTEGER NOT NULL, event_json TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(checkpoint_id,sequence));")?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", 1)?;
        }
        transaction.commit()?;
        let integrity: String =
            connection.pragma_query_value(None, "quick_check", |row| row.get(0))?;
        if integrity != "ok" {
            return Err("Recovery journal failed SQLite integrity verification".into());
        }
        if connection.prepare("PRAGMA foreign_key_check")?.exists([])? {
            return Err("Recovery journal contains orphaned events".into());
        }
        let journal = Self { connection };
        journal.pendingRecovery()?;
        Ok(journal)
    }

    pub fn prepare(
        &mut self,
        document: MtuCheckpoint,
        nowUnixMs: u64,
    ) -> ServiceResult<Checkpoint> {
        document.validate()?;
        if nowUnixMs < document.createdAtUnixMs || nowUnixMs >= document.leaseExpiresAtUnixMs {
            return Err("Cannot prepare an expired or future checkpoint".into());
        }
        let payload = serde_json::to_string_pretty(&document)?;
        if payload.len() > 16_384 {
            return Err("Checkpoint document exceeds its 16 KiB limit".into());
        }
        let digest = checksum(&payload);
        let initial = Event {
            sequence: 0,
            timestampUnixMs: nowUnixMs,
            previousSha256: digest.clone(),
            state: State::Prepared,
            observation: None,
        };
        validateEvent(&document, None, &initial)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if !pending(&transaction)?.is_empty() {
            return Err("An unresolved checkpoint blocks a new experiment".into());
        }
        let count: u32 =
            transaction.query_row("SELECT COUNT(*) FROM checkpoints", [], |row| row.get(0))?;
        if count >= MAX_CHECKPOINTS {
            return Err("Recovery journal capacity reached; preserve and archive existing records before new changes".into());
        }
        transaction.execute(
            "INSERT INTO checkpoints(id,document_json,sha256) VALUES(?1,?2,?3)",
            params![document.id.to_string(), payload, digest],
        )?;
        insertEvent(&transaction, document.id, &initial)?;
        transaction.commit()?;
        self.load(document.id)
    }

    pub fn load(&self, id: Uuid) -> ServiceResult<Checkpoint> {
        load(&self.connection, id)
    }

    pub fn pendingRecovery(&self) -> ServiceResult<Vec<Checkpoint>> {
        pending(&self.connection)
    }

    pub fn transition(
        &mut self,
        id: Uuid,
        expected: State,
        next: State,
        nowUnixMs: u64,
        observation: Option<Observation>,
    ) -> ServiceResult<Checkpoint> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load(&transaction, id)?;
        if current.state() != expected {
            return Err("Recovery state changed; stale transition rejected".into());
        }
        let sequence: u32 = current.events.len().try_into()?;
        if sequence >= MAX_EVENTS {
            return Err("Recovery event limit reached; existing evidence was preserved".into());
        }
        let event = Event {
            sequence,
            timestampUnixMs: nowUnixMs,
            previousSha256: current.lastEventSha256,
            state: next,
            observation,
        };
        validateEvent(&current.document, Some(expected), &event)?;
        insertEvent(&transaction, id, &event)?;
        transaction.commit()?;
        self.load(id)
    }
}

fn validateDatabaseIdentity(connection: &Connection) -> ServiceResult<u32> {
    let applicationId: u32 =
        connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if applicationId == APPLICATION_ID && version == 1 {
        return Ok(version);
    }
    if applicationId == 0 && version == 0 {
        let tables: u32 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if tables == 0 {
            return Ok(0);
        }
    }
    Err("Database is not a supported recovery journal; refusing to alter or downgrade it".into())
}

fn checksum(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn insertEvent(connection: &Connection, id: Uuid, event: &Event) -> ServiceResult<()> {
    let payload = serde_json::to_string(event)?;
    if payload.len() > 4096 {
        return Err("Recovery event exceeds its 4096-byte limit".into());
    }
    connection.execute("INSERT INTO checkpoint_events(checkpoint_id,sequence,event_json,sha256) VALUES(?1,?2,?3,?4)", params![id.to_string(),event.sequence,payload,checksum(&payload)])?;
    Ok(())
}

fn load(connection: &Connection, id: Uuid) -> ServiceResult<Checkpoint> {
    let (payload, digest): (String,String) = connection.query_row("SELECT document_json,sha256 FROM checkpoints WHERE id=?1 AND length(CAST(document_json AS BLOB))<=16384 AND length(sha256)=64", [id.to_string()], |row| Ok((row.get(0)?, row.get(1)?)))?;
    if payload.len() > 16_384 || checksum(&payload) != digest {
        return Err("Original checkpoint document failed checksum verification".into());
    }
    let document: MtuCheckpoint = serde_json::from_str(&payload)?;
    document.validate()?;
    if document.id != id {
        return Err("Checkpoint identity does not match its storage key".into());
    }
    let mut statement = connection.prepare("SELECT sequence,event_json,sha256,length(CAST(event_json AS BLOB)) FROM checkpoint_events WHERE checkpoint_id=?1 ORDER BY sequence LIMIT 129")?;
    let mut rows = statement.query([id.to_string()])?;
    let mut events: Vec<Event> = Vec::new();
    let mut previousDigest = digest.clone();
    while let Some(row) = rows.next()? {
        let sequence: u32 = row.get(0)?;
        let length: i64 = row.get(3)?;
        if !(0..=4096).contains(&length) {
            return Err("Recovery event exceeds its supported size".into());
        }
        let eventPayload: String = row.get(1)?;
        let eventDigest: String = row.get(2)?;
        if events.len() >= MAX_EVENTS as usize
            || sequence as usize != events.len()
            || eventPayload.len() > 4096
            || checksum(&eventPayload) != eventDigest
        {
            return Err("Recovery event sequence, size, or checksum is invalid".into());
        }
        let event: Event = serde_json::from_str(&eventPayload)?;
        if event.sequence != sequence || event.previousSha256 != previousDigest {
            return Err("Recovery event chain is incomplete or changed".into());
        }
        validateEvent(&document, events.last().map(|event| event.state), &event)?;
        previousDigest = eventDigest;
        events.push(event);
    }
    if events.is_empty() {
        return Err("Checkpoint has no durable prepared event".into());
    }
    Ok(Checkpoint {
        document,
        documentSha256: digest,
        events,
        lastEventSha256: previousDigest,
    })
}

fn pending(connection: &Connection) -> ServiceResult<Vec<Checkpoint>> {
    let mut statement = connection.prepare("SELECT id FROM checkpoints ORDER BY id LIMIT 2001")?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if ids.len() > MAX_CHECKPOINTS as usize {
        return Err("Recovery journal exceeds its supported capacity".into());
    }
    let mut unresolved = Vec::new();
    for id in ids {
        let checkpoint = load(connection, Uuid::parse_str(&id)?)?;
        if !checkpoint.state().terminal() {
            unresolved.push(checkpoint);
        }
    }
    Ok(unresolved)
}
