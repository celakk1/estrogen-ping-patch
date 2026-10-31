use super::*;
use rusqlite::{Connection, TransactionBehavior, params};
use std::{collections::HashMap, path::Path, time::Duration};

const APPLICATION_ID: u32 = 0x45505041;
const MAX_GRANTS: usize = 2000;
const MAX_EVENTS: usize = 64;
const MAX_PAYLOAD: usize = 4096;

pub struct AuthorizationStore {
    connection: Connection,
    instanceId: Uuid,
    fences: HashMap<Uuid, Fence>,
}

impl AuthorizationStore {
    pub fn open(path: &Path) -> ServiceResult<Self> {
        if !path.is_absolute() {
            return Err(
                "Authorization storage requires an absolute, service-protected path".into(),
            );
        }
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        validateIdentity(&connection)?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let mode: String =
            connection.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        if mode != "wal"
            || connection.pragma_query_value::<u32, _>(None, "synchronous", |row| row.get(0))? != 2
        {
            return Err("Authorization storage requires WAL and FULL synchronization".into());
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if validateIdentity(&transaction)? == 0 {
            transaction.execute_batch("CREATE TABLE grants(id TEXT PRIMARY KEY, checkpoint_id TEXT UNIQUE NOT NULL, document_json TEXT NOT NULL, sha256 TEXT NOT NULL);
                CREATE TABLE grant_events(grant_id TEXT NOT NULL REFERENCES grants(id), sequence INTEGER NOT NULL, event_json TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY(grant_id,sequence));")?;
            transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
            transaction.pragma_update(None, "user_version", 1)?;
        }
        transaction.commit()?;
        let integrity: String =
            connection.pragma_query_value(None, "quick_check", |row| row.get(0))?;
        if integrity != "ok" || connection.prepare("PRAGMA foreign_key_check")?.exists([])? {
            return Err("Authorization storage failed integrity verification".into());
        }
        let mut statement = connection.prepare("SELECT id FROM grants ORDER BY id LIMIT 2001")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        if ids.len() > MAX_GRANTS {
            return Err("Authorization storage exceeds its supported capacity".into());
        }
        for id in ids {
            load(&connection, Uuid::parse_str(&id)?)?;
        }
        drop(statement);
        Ok(Self {
            connection,
            instanceId: Uuid::new_v4(),
            fences: HashMap::new(),
        })
    }

    pub fn issue(
        &mut self,
        document: &MtuCheckpoint,
        actorSid: &str,
        allowRetention: bool,
        nowUnixMs: u64,
    ) -> ServiceResult<MtuGrant> {
        document.validate()?;
        validateSid(actorSid)?;
        if document.schemaVersion != 2
            || actorSid != document.authorizedUserSid
            || nowUnixMs < document.createdAtUnixMs
            || nowUnixMs >= document.leaseExpiresAtUnixMs
        {
            return Err(
                "Cannot authorize a legacy, expired, future, or differently owned operation".into(),
            );
        }
        let grant = MtuGrant {
            schemaVersion: 1,
            id: Uuid::new_v4(),
            issuerInstanceId: self.instanceId,
            checkpointId: document.id,
            checkpointSha256: checkpointChecksum(document)?,
            authorizedUserSid: actorSid.into(),
            context: document.context.clone(),
            addressFamily: document.addressFamily,
            proposedMtu: document.proposedMtu,
            createdAtUnixMs: nowUnixMs,
            expiresAtUnixMs: document.leaseExpiresAtUnixMs,
            allowRetention,
        };
        grant.validate()?;
        let payload = serde_json::to_string(&grant)?;
        if payload.len() > MAX_PAYLOAD {
            return Err("Authorization document exceeds its size limit".into());
        }
        let digest = checksum(&payload);
        let event = Event {
            sequence: 0,
            timestampUnixMs: nowUnixMs,
            previousSha256: digest.clone(),
            kind: EventKind::Issued,
        };
        let deadline = Instant::now() + Duration::from_millis(grant.expiresAtUnixMs - nowUnixMs);
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: u32 =
            transaction.query_row("SELECT COUNT(*) FROM grants", [], |row| row.get(0))?;
        if count as usize >= MAX_GRANTS {
            return Err("Authorization storage is full; preserve existing audit records before new experiments".into());
        }
        transaction.execute(
            "INSERT INTO grants(id,checkpoint_id,document_json,sha256) VALUES(?1,?2,?3,?4)",
            params![
                grant.id.to_string(),
                document.id.to_string(),
                payload,
                digest
            ],
        )?;
        insertEvent(&transaction, grant.id, &event)?;
        transaction.commit()?;
        self.read(grant.id)?;
        self.fences.insert(
            grant.id,
            Fence {
                deadline,
                highWaterUnixMs: nowUnixMs,
                revoked: false,
            },
        );
        Ok(grant)
    }

    pub fn read(&self, id: Uuid) -> ServiceResult<GrantRecord> {
        load(&self.connection, id)
    }

    pub fn authorize(
        &mut self,
        id: Uuid,
        document: &MtuCheckpoint,
        actorSid: &str,
        action: AuthorizationAction,
        nowUnixMs: u64,
    ) -> ServiceResult<()> {
        let fence = self
            .fences
            .get_mut(&id)
            .ok_or("Authorization requires explicit approval in this service instance")?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = load(&transaction, id)?;
        validateCheck(
            &record,
            Check {
                document,
                actorSid,
                action,
                nowUnixMs,
            },
            self.instanceId,
            fence,
            false,
        )?;
        if record.events.len() >= MAX_EVENTS - 1 {
            return Err(
                "Authorization audit capacity reached; revocation remains available".into(),
            );
        }
        let event = Event {
            sequence: record.events.len().try_into()?,
            timestampUnixMs: nowUnixMs,
            previousSha256: record.lastSha256,
            kind: match action {
                AuthorizationAction::Prepare => EventKind::PrepareChecked,
                AuthorizationAction::Apply => EventKind::ApplyChecked,
                AuthorizationAction::Retain => EventKind::RetentionChecked,
            },
        };
        insertEvent(&transaction, id, &event)?;
        transaction.commit()?;
        self.read(id)?;
        Ok(())
    }

    pub fn check(
        &mut self,
        id: Uuid,
        document: &MtuCheckpoint,
        actorSid: &str,
        action: AuthorizationAction,
        nowUnixMs: u64,
    ) -> ServiceResult<()> {
        let record = self.read(id)?;
        let fence = self
            .fences
            .get_mut(&id)
            .ok_or("Authorization requires explicit approval in this service instance")?;
        validateCheck(
            &record,
            Check {
                document,
                actorSid,
                action,
                nowUnixMs,
            },
            self.instanceId,
            fence,
            true,
        )
    }

    pub fn revoke(&mut self, id: Uuid, actorSid: &str, nowUnixMs: u64) -> ServiceResult<()> {
        validateSid(actorSid)?;
        if nowUnixMs == 0 || nowUnixMs > i64::MAX as u64 {
            return Err("Revocation requires a valid observed timestamp".into());
        }
        let owner = self.read(id)?;
        if owner.grant.authorizedUserSid != actorSid {
            return Err("Only the authorized owner may revoke this grant".into());
        }
        if let Some(fence) = self.fences.get_mut(&id) {
            fence.revoked = true;
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = load(&transaction, id)?;
        if record.grant.authorizedUserSid != actorSid {
            return Err("Only the authorized owner may revoke this grant".into());
        }
        if record.revoked {
            return Ok(());
        }
        if record.events.len() >= MAX_EVENTS {
            return Err("Authorization audit is full; no new changes are permitted".into());
        }
        let event = Event {
            sequence: record.events.len().try_into()?,
            timestampUnixMs: nowUnixMs,
            previousSha256: record.lastSha256,
            kind: EventKind::Revoked,
        };
        insertEvent(&transaction, id, &event)?;
        transaction.commit()?;
        if !self.read(id)?.revoked {
            return Err("Authorization revocation was not verified".into());
        }
        Ok(())
    }
}

fn validateIdentity(connection: &Connection) -> ServiceResult<u32> {
    let id: u32 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if id == APPLICATION_ID && version == 1 {
        return Ok(1);
    }
    if id == 0 && version == 0 {
        let count: u32 = connection.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if count == 0 {
            return Ok(0);
        }
    }
    Err("Database is not a supported authorization store; refusing to modify it".into())
}

fn insertEvent(connection: &Connection, id: Uuid, event: &Event) -> ServiceResult<()> {
    let payload = serde_json::to_string(event)?;
    if payload.len() > MAX_PAYLOAD {
        return Err("Authorization event exceeds its size limit".into());
    }
    connection.execute(
        "INSERT INTO grant_events(grant_id,sequence,event_json,sha256) VALUES(?1,?2,?3,?4)",
        params![id.to_string(), event.sequence, payload, checksum(&payload)],
    )?;
    Ok(())
}

fn load(connection: &Connection, id: Uuid) -> ServiceResult<GrantRecord> {
    let (checkpointId,payload,digest): (String,String,String) = connection.query_row("SELECT checkpoint_id,document_json,sha256 FROM grants WHERE id=?1 AND length(CAST(document_json AS BLOB))<=4096 AND length(sha256)=64",[id.to_string()],|row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
    if checksum(&payload) != digest {
        return Err("Authorization document failed checksum verification".into());
    }
    let grant: MtuGrant = serde_json::from_str(&payload)?;
    grant.validate()?;
    if grant.id != id || grant.checkpointId.to_string() != checkpointId {
        return Err("Authorization storage key does not match its scope".into());
    }
    let mut statement = connection.prepare("SELECT sequence,event_json,sha256,length(CAST(event_json AS BLOB)) FROM grant_events WHERE grant_id=?1 ORDER BY sequence LIMIT 65")?;
    let mut rows = statement.query([id.to_string()])?;
    let mut record = GrantRecord {
        grant,
        claimed: false,
        revoked: false,
        events: Vec::new(),
        lastSha256: digest,
    };
    while let Some(row) = rows.next()? {
        let sequence: u32 = row.get(0)?;
        let length: i64 = row.get(3)?;
        if record.events.len() >= MAX_EVENTS
            || sequence as usize != record.events.len()
            || !(0..=MAX_PAYLOAD as i64).contains(&length)
        {
            return Err("Authorization event sequence or size is invalid".into());
        }
        let payload: String = row.get(1)?;
        let digest: String = row.get(2)?;
        if checksum(&payload) != digest {
            return Err("Authorization event failed checksum verification".into());
        }
        let event: Event = serde_json::from_str(&payload)?;
        if event.sequence != sequence
            || event.previousSha256 != record.lastSha256
            || record.revoked
            || event.timestampUnixMs == 0
            || event.timestampUnixMs > i64::MAX as u64
        {
            return Err("Authorization event chain is invalid or follows revocation".into());
        }
        if sequence == 0 {
            if event.kind != EventKind::Issued
                || event.timestampUnixMs != record.grant.createdAtUnixMs
            {
                return Err("Authorization requires an exact initial issued event".into());
            }
        } else {
            if event.kind == EventKind::Issued {
                return Err("Authorization cannot be reissued".into());
            }
            if event.kind != EventKind::Revoked
                && (event.timestampUnixMs < record.events.last().unwrap().timestampUnixMs
                    || event.timestampUnixMs >= record.grant.expiresAtUnixMs)
            {
                return Err("Authorization check time is invalid".into());
            }
            match event.kind {
                EventKind::PrepareChecked if record.claimed => {
                    return Err("Authorization was prepared after being claimed".into());
                }
                EventKind::ApplyChecked => record.claimed = true,
                EventKind::RetentionChecked if !record.claimed || !record.grant.allowRetention => {
                    return Err("Retention was not authorized".into());
                }
                EventKind::Revoked => record.revoked = true,
                _ => {}
            }
        }
        record.lastSha256 = digest;
        record.events.push(event);
    }
    if record.events.is_empty() {
        return Err("Authorization has no durable issued event".into());
    }
    Ok(record)
}
