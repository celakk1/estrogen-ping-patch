use super::*;
use crate::experiment::measurement;
use rusqlite::{TransactionBehavior, params};

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Metadata {
    schemaVersion: u32,
    state: State,
    eventCount: u32,
    eventBytes: u64,
    headSha256: String,
    resultSha256: Option<String>,
    detail: Option<String>,
}

pub(super) struct Recorder {
    pub header: Header,
    headerSha256: String,
    metadata: Metadata,
    metadataSha256: String,
    prefix: Prefix,
    failed: bool,
}

fn checksum(value: &str) -> String {
    epp_core::backups::checksum(value)
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn stateChecksum(id: Uuid, header: &str, metadata: &str) -> ServiceResult<String> {
    hash(&("diagnosis-state-v1", id, header, metadata))
}

fn eventChecksum(id: Uuid, head: &str, event: &str) -> ServiceResult<String> {
    hash(&("diagnosis-event-v1", id, head, event))
}

fn load(database: &Connection, id: Uuid) -> ServiceResult<(Recording, Recorder)> {
    let (headerJson, headerSha256, state, metadataJson, metadataSha256, resultJson): (String,String,String,String,String,Option<String>) = database.query_row(
        "SELECT header_json,header_sha256,state,metadata_json,metadata_sha256,result_json FROM diagnostic_recordings WHERE id=?1 AND length(CAST(header_json AS BLOB))<=16384 AND length(CAST(metadata_json AS BLOB))<=8192 AND (result_json IS NULL OR length(CAST(result_json AS BLOB))<=4194304)",
        [id.to_string()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)))?;
    if checksum(&headerJson) != headerSha256
        || stateChecksum(id, &headerSha256, &metadataJson)? != metadataSha256
    {
        return Err("Diagnostic recording header or state integrity failed".into());
    }
    let header: Header = decode(&headerJson)?;
    header.validate()?;
    let metadata: Metadata = decode(&metadataJson)?;
    if header.id != id
        || metadata.schemaVersion != 1
        || metadata.state.label() != state
        || metadata.eventCount > MAX_EVENTS
        || metadata.eventBytes > RECORDING_BYTES.saturating_sub(headerJson.len() as u64)
        || !digest(&metadata.headSha256)
        || metadata
            .resultSha256
            .as_ref()
            .is_some_and(|value| !digest(value))
        || (metadata.state == State::Finalized) != resultJson.is_some()
        || resultJson.is_some() != metadata.resultSha256.is_some()
        || metadata
            .detail
            .as_ref()
            .is_some_and(|value| value.chars().count() > 512 || value.chars().any(char::is_control))
        || (metadata.state == State::Recording && metadata.detail.is_some())
        || (metadata.state == State::Interrupted && metadata.detail.is_none())
    {
        return Err("Diagnostic recording metadata is inconsistent or unbounded".into());
    }
    let (count, bytes): (u32,i64) = database.query_row("SELECT COUNT(*),COALESCE(SUM(length(CAST(payload_json AS BLOB))),0) FROM diagnostic_recording_events WHERE recording_id=?1", [id.to_string()], |row| Ok((row.get(0)?,row.get(1)?)))?;
    if count != metadata.eventCount || u64::try_from(bytes)? != metadata.eventBytes {
        return Err("Diagnostic recording event count or byte size changed".into());
    }
    let mut query = database.prepare("SELECT sequence,payload_json,sha256 FROM diagnostic_recording_events WHERE recording_id=?1 AND length(CAST(payload_json AS BLOB))<=131072 ORDER BY sequence LIMIT 1201")?;
    let rows = query.query_map([id.to_string()], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut events = Vec::new();
    let mut prefix = Prefix::default();
    let mut head = headerSha256.clone();
    for row in rows {
        let (sequence, value, expected) = row?;
        let event: Event = decode(&value)?;
        if sequence != events.len() as u32
            || event.sequence != sequence
            || eventChecksum(id, &head, &value)? != expected
        {
            return Err("Diagnostic recording event sequence or integrity failed".into());
        }
        prefix.accept(&header, &event)?;
        events.push(event);
        head = expected;
    }
    if head != metadata.headSha256 || events.len() != metadata.eventCount as usize {
        return Err("Diagnostic recording lost its checked event prefix".into());
    }
    let result = resultJson
        .map(|value| -> ServiceResult<SavedCollection> {
            if Some(checksum(&value)) != metadata.resultSha256 {
                return Err("Diagnostic recording final result integrity failed".into());
            }
            let result = decode(&value)?;
            prefix.validateResult(&header, &result)?;
            Ok(result)
        })
        .transpose()?;
    let recorder = Recorder {
        header: header.clone(),
        headerSha256,
        metadata: metadata.clone(),
        metadataSha256,
        prefix,
        failed: false,
    };
    Ok((
        Recording {
            header,
            state: metadata.state,
            events,
            result,
            detail: metadata.detail,
        },
        recorder,
    ))
}

pub(super) fn history(database: &Connection, limit: u32) -> ServiceResult<Vec<Recording>> {
    if !(1..=50).contains(&limit) {
        return Err("Diagnostic history requires one to fifty recordings".into());
    }
    let snapshot = database.unchecked_transaction()?;
    let tables: u32 = snapshot.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('diagnostic_recordings','diagnostic_recording_events')", [], |row| row.get(0))?;
    if tables == 0 {
        return Ok(Vec::new());
    }
    if tables != 2 {
        return Err("Diagnostic recording schema is incomplete; preserve its evidence".into());
    }
    let mut query =
        snapshot.prepare("SELECT id FROM diagnostic_recordings ORDER BY rowid DESC LIMIT ?1")?;
    let ids = query
        .query_map([limit], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(query);
    let mut bytes = 0u64;
    let mut recordings = Vec::new();
    for id in ids {
        let size: i64 = snapshot.query_row("SELECT length(CAST(header_json AS BLOB))+length(CAST(metadata_json AS BLOB))+COALESCE(length(CAST(result_json AS BLOB)),0)+COALESCE((SELECT SUM(length(CAST(payload_json AS BLOB))) FROM diagnostic_recording_events WHERE recording_id=?1),0) FROM diagnostic_recordings WHERE id=?1", [&id], |row| row.get(0))?;
        bytes = bytes
            .checked_add(u64::try_from(size)?)
            .ok_or("Diagnostic history byte count overflowed")?;
        if bytes > 32 * 1024 * 1024 {
            return Err("Diagnostic history exceeds 32 MiB; request fewer recordings".into());
        }
        recordings.push(load(&snapshot, Uuid::parse_str(&id)?)?.0);
    }
    snapshot.commit()?;
    Ok(recordings)
}

fn initialize(database: &mut Connection) -> ServiceResult<()> {
    measurement::validateStorage(database)?;
    let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch("CREATE TABLE IF NOT EXISTS diagnostic_recordings(id TEXT PRIMARY KEY,header_json TEXT NOT NULL,header_sha256 TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('recording','finalized','interrupted')),metadata_json TEXT NOT NULL,metadata_sha256 TEXT NOT NULL,result_json TEXT);
        CREATE UNIQUE INDEX IF NOT EXISTS one_recording_diagnosis ON diagnostic_recordings(state) WHERE state='recording';
        CREATE TABLE IF NOT EXISTS diagnostic_recording_events(recording_id TEXT NOT NULL REFERENCES diagnostic_recordings(id),sequence INTEGER NOT NULL,payload_json TEXT NOT NULL,sha256 TEXT NOT NULL,PRIMARY KEY(recording_id,sequence));")?;
    transaction.commit()?;
    let mut query =
        database.prepare("SELECT id FROM diagnostic_recordings WHERE state='recording' LIMIT 2")?;
    let ids = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(query);
    if ids.len() > 1 {
        return Err("Multiple unfinished diagnostic recordings require investigation".into());
    }
    for id in ids {
        let (_, mut recorder) = load(database, Uuid::parse_str(&id)?)?;
        owned_process::waitForIdentity(&recorder.header.owner, Duration::ZERO).map_err(
            |error| format!("Diagnostic recording owner is alive or cannot be verified: {error}"),
        )?;
        recorder.interrupt(database, "Owner exited before diagnosis finalization")?;
    }
    Ok(())
}

impl Recorder {
    pub(super) fn start(database: &mut Connection, plan: Plan) -> ServiceResult<Self> {
        initialize(database)?;
        let header = Header {
            schemaVersion: 1,
            id: Uuid::new_v4(),
            owner: owner()?,
            createdAtUnixMs: crate::watchdog::nowUnixMs()?,
            appVersion: env!("CARGO_PKG_VERSION").into(),
            execution: "recordedDiagnosticWorkerV1".into(),
            plan,
        };
        header.validate()?;
        let headerJson = payload(&header, HEADER_BYTES)?;
        let headerSha256 = checksum(&headerJson);
        let metadata = Metadata {
            schemaVersion: 1,
            state: State::Recording,
            eventCount: 0,
            eventBytes: 0,
            headSha256: headerSha256.clone(),
            resultSha256: None,
            detail: None,
        };
        let metadataJson = payload(&metadata, 8192)?;
        let metadataSha256 = stateChecksum(header.id, &headerSha256, &metadataJson)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: u32 =
            transaction.query_row("SELECT COUNT(*) FROM diagnostic_recordings", [], |row| {
                row.get(0)
            })?;
        if count >= 500 {
            return Err("Diagnostic recording capacity is full; preserve and archive evidence before more work".into());
        }
        transaction.execute("INSERT INTO diagnostic_recordings(id,header_json,header_sha256,state,metadata_json,metadata_sha256) VALUES(?1,?2,?3,'recording',?4,?5)", params![header.id.to_string(),headerJson,headerSha256,metadataJson,metadataSha256])?;
        transaction.commit()?;
        let (_, recorder) = load(database, header.id)?;
        Ok(recorder)
    }

    fn verify(&self, database: &Connection) -> ServiceResult<()> {
        let (header, headerHash, state, metadata, metadataHash): (String,String,String,String,String) = database.query_row("SELECT header_json,header_sha256,state,metadata_json,metadata_sha256 FROM diagnostic_recordings WHERE id=?1 AND length(CAST(header_json AS BLOB))<=16384 AND length(CAST(metadata_json AS BLOB))<=8192 AND result_json IS NULL", [self.header.id.to_string()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;
        if header != payload(&self.header, HEADER_BYTES)?
            || headerHash != self.headerSha256
            || metadata != payload(&self.metadata, 8192)?
            || metadataHash != self.metadataSha256
            || state != "recording"
            || self.metadata.state != State::Recording
        {
            return Err("Diagnostic recording ownership or committed state changed".into());
        }
        Ok(())
    }

    fn update(
        &self,
        database: &Connection,
        metadata: &Metadata,
        result: Option<&str>,
    ) -> ServiceResult<String> {
        let value = payload(metadata, 8192)?;
        let checksum = stateChecksum(self.header.id, &self.headerSha256, &value)?;
        let changed = database.execute("UPDATE diagnostic_recordings SET state=?1,metadata_json=?2,metadata_sha256=?3,result_json=?4 WHERE id=?5 AND header_sha256=?6 AND metadata_sha256=?7 AND state='recording'", params![metadata.state.label(),value,checksum,result,self.header.id.to_string(),self.headerSha256,self.metadataSha256])?;
        if changed != 1 {
            return Err("Diagnostic recording changed before its next durable update".into());
        }
        Ok(checksum)
    }

    pub(super) fn append(
        &mut self,
        database: &mut Connection,
        observation: Observation,
    ) -> ServiceResult<()> {
        if self.failed {
            return Err("Diagnostic recording cannot append after a failed write".into());
        }
        let result = self.appendNext(database, observation);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn appendNext(
        &mut self,
        database: &mut Connection,
        observation: Observation,
    ) -> ServiceResult<()> {
        measurement::validateStorage(database)?;
        let event = Event {
            sequence: self.metadata.eventCount,
            capturedAtUnixMs: crate::watchdog::nowUnixMs()?,
            observation,
        };
        self.prefix.accept(&self.header, &event)?;
        let value = payload(&event, EVENT_BYTES)?;
        let head = eventChecksum(self.header.id, &self.metadata.headSha256, &value)?;
        let mut metadata = self.metadata.clone();
        metadata.eventCount += 1;
        metadata.eventBytes += value.len() as u64;
        metadata.headSha256 = head.clone();
        if metadata.eventBytes + payload(&self.header, HEADER_BYTES)?.len() as u64 > RECORDING_BYTES
        {
            return Err("Diagnostic recording reached its four MiB evidence allowance".into());
        }
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.verify(&transaction)?;
        transaction.execute("INSERT INTO diagnostic_recording_events(recording_id,sequence,payload_json,sha256) VALUES(?1,?2,?3,?4)", params![self.header.id.to_string(),event.sequence,value,head])?;
        let checksum = self.update(&transaction, &metadata, None)?;
        transaction.commit()?;
        self.metadata = metadata;
        self.metadataSha256 = checksum;
        self.verify(database)?;
        let (saved, stored): (String,String) = database.query_row("SELECT payload_json,sha256 FROM diagnostic_recording_events WHERE recording_id=?1 AND sequence=?2 AND length(CAST(payload_json AS BLOB))<=131072", params![self.header.id.to_string(),event.sequence], |row| Ok((row.get(0)?,row.get(1)?)))?;
        if saved != value || stored != head {
            return Err("Committed diagnostic event differs from its captured bytes".into());
        }
        Ok(())
    }

    pub(super) fn finish(
        &mut self,
        database: &mut Connection,
        collection: &Collection,
        failure: Option<&str>,
    ) -> ServiceResult<()> {
        measurement::validateStorage(database)?;
        let result = payload(collection, RESULT_BYTES)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.verify(&transaction)?;
        let (_, committed) = load(&transaction, self.header.id)?;
        committed
            .prefix
            .validateResult(&self.header, &decode(&result)?)?;
        let mut metadata = self.metadata.clone();
        metadata.state = State::Finalized;
        metadata.resultSha256 = Some(checksum(&result));
        metadata.detail = failure.map(detail);
        self.update(&transaction, &metadata, Some(&result))?;
        load(&transaction, self.header.id)?;
        transaction.commit()?;
        let (_, saved) = load(database, self.header.id)?;
        *self = saved;
        Ok(())
    }

    pub(super) fn interrupt(
        &mut self,
        database: &mut Connection,
        failure: &str,
    ) -> ServiceResult<()> {
        measurement::validateStorage(database)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.verify(&transaction)?;
        load(&transaction, self.header.id)?;
        let mut metadata = self.metadata.clone();
        metadata.state = State::Interrupted;
        metadata.detail = Some(detail(failure));
        self.update(&transaction, &metadata, None)?;
        transaction.commit()?;
        let (_, saved) = load(database, self.header.id)?;
        *self = saved;
        Ok(())
    }
}
