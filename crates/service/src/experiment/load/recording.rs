use super::*;
use crate::{journal::MutatorIdentity, owned_process};
use epp_core::transfer::session::{
    BoundTransferRunner, ProgressSnapshot, SessionProgress, TransferExecution,
};
use rusqlite::{TransactionBehavior, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::Duration;
use uuid::Uuid;

const HEADER_BYTES: usize = 1024 * 1024;
const EVENT_BYTES: usize = 16_384;
const MAX_EVENTS: u32 = 4096;
const MAX_RECORDINGS: u32 = 2000;
const RECORDING_BYTES: u64 = 8 * 1024 * 1024;
const HISTORY_BYTES: u64 = 32 * 1024 * 1024;

pub(super) struct Runner;

impl BoundTransferRunner for Runner {
    fn createProgress(&self) -> ServiceResult<transfer::TransferProgress> {
        crate::transfer_worker::IsolatedTransferRunner::default().createProgress()
    }

    fn execution(&self) -> Option<TransferExecution> {
        Some(TransferExecution::RecordedRestrictedWorkerV1)
    }

    fn snapshot(&self, progress: &transfer::TransferProgress) -> ServiceResult<ProgressSnapshot> {
        crate::transfer_worker::IsolatedTransferRunner::default().snapshot(progress)
    }

    fn measureFrom(
        &self,
        plan: transfer::TransferPlan,
        binding: transfer::SourceBinding,
        cancelled: &AtomicBool,
        progress: &transfer::TransferProgress,
    ) -> ServiceResult<transfer::TransferResult> {
        crate::transfer_worker::IsolatedTransferRunner::default()
            .measureFrom(plan, binding, cancelled, progress)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Header {
    pub schemaVersion: u32,
    pub id: Uuid,
    pub createdAtUnixMs: u64,
    pub owner: MutatorIdentity,
    pub appVersion: String,
    pub execution: TransferExecution,
    pub experiment: Plan,
    pub configuration: Configuration,
    pub config: Config,
    pub sessionPlan: SessionPlan,
    pub bindings: SourceBindings,
    pub selections: Vec<comparisonLoad::Selection>,
    pub policyBefore: policy::Capture,
    pub routesBefore: Vec<routing::Capture>,
    pub checkpointId: Option<Uuid>,
    pub checkpointSha256: Option<String>,
}

impl Header {
    pub(super) fn capture(
        scope: &Scope,
        experiment: &Plan,
        configuration: Configuration,
        checkpoint: Option<&MtuCheckpoint>,
        before: &(policy::Capture, Vec<routing::Capture>),
    ) -> ServiceResult<Self> {
        Ok(Self {
            schemaVersion: 1,
            id: Uuid::new_v4(),
            createdAtUnixMs: nowUnixMs()?,
            owner: owned_process::processIdentity(
                unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() },
                std::process::id(),
            )?,
            appVersion: env!("CARGO_PKG_VERSION").into(),
            execution: TransferExecution::RecordedRestrictedWorkerV1,
            experiment: experiment.clone(),
            configuration,
            config: scope.config.clone(),
            sessionPlan: scope.sessionPlan.clone(),
            bindings: scope.bindings.clone(),
            selections: scope.selections.clone(),
            policyBefore: before.0.clone(),
            routesBefore: before.1.clone(),
            checkpointId: checkpoint.map(|document| document.id),
            checkpointSha256: checkpoint
                .map(crate::authorization::checkpointChecksum)
                .transpose()?,
        })
    }

    fn validate(&self) -> ServiceResult<()> {
        self.owner.validate()?;
        self.experiment.validate()?;
        self.sessionPlan.validate(&self.config)?;
        self.bindings.validate(&self.sessionPlan)?;
        if self.schemaVersion != 1
            || self.execution != TransferExecution::RecordedRestrictedWorkerV1
            || self.id.is_nil()
            || self.createdAtUnixMs < self.experiment.createdAtUnixMs
            || self.createdAtUnixMs >= self.experiment.expiresAtUnixMs
            || (self.configuration == Configuration::Candidate) != self.checkpointId.is_some()
            || self.checkpointId.is_some_and(|id| id.is_nil())
            || self.checkpointId.is_some() != self.checkpointSha256.is_some()
            || self
                .checkpointSha256
                .as_ref()
                .is_some_and(|value| !digest(value))
        {
            return Err(
                "Load recording header has invalid scope, owner, time, or checkpoint metadata"
                    .into(),
            );
        }
        let mut blueprint = session::runSourceBoundSessionWithRunner(
            self.config.clone(),
            self.sessionPlan.clone(),
            self.bindings.clone(),
            &AtomicBool::new(true),
            |_| {},
            &Runner,
        )?;
        blueprint.appVersion = self.appVersion.clone();
        blueprint.transferExecution = Some(self.execution);
        let expected = if self.configuration == Configuration::Original {
            &self.experiment.comparison.originalConfigurationSha256
        } else {
            &self.experiment.comparison.candidateConfigurationSha256
        };
        if hash(&self.policyBefore.native.settings)? != *expected {
            return Err(
                "Load recording native original differs from its selected configuration".into(),
            );
        }
        if comparisonLoad::cohortSha256(&blueprint, &self.selections)?
            != self.experiment.comparison.cohortSha256
        {
            return Err("Load recording differs from its frozen comparison cohort".into());
        }
        Ok(())
    }

    fn validateRun(&self, run: &SessionRun, events: &[Event]) -> ServiceResult<()> {
        if run.appVersion != self.appVersion
            || run.transferExecution != Some(self.execution)
            || !matches!(
                run.status.as_str(),
                "completed" | "cancelled" | "timeLimit" | "partialFailure"
            )
            || !equal(&run.config, &self.config)?
            || !equal(&run.plan, &self.sessionPlan)?
            || run.sourceBindings.as_ref() != Some(&self.bindings)
        {
            return Err("Final load report differs from its frozen recording context".into());
        }
        let samples: Vec<_> = events
            .iter()
            .filter_map(|event| event.progress.sample.as_ref())
            .collect();
        if samples.len() > run.latencySamples.len()
            || (run.status == "completed" && samples.len() != run.latencySamples.len())
        {
            return Err("Final load report lost recorded probe evidence".into());
        }
        for (recorded, sample) in samples.iter().zip(&run.latencySamples) {
            if !equal(recorded, sample)? {
                return Err("Final load report changed a recorded probe".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum State {
    Recording,
    Finalized,
    Interrupted,
}

impl State {
    fn label(self) -> &'static str {
        match self {
            Self::Recording => "recording",
            Self::Finalized => "finalized",
            Self::Interrupted => "interrupted",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Event {
    pub sequence: u32,
    pub capturedAtUnixMs: u64,
    pub progress: SessionProgress,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Metadata {
    schemaVersion: u32,
    state: State,
    eventCount: u32,
    eventBytes: u64,
    headSha256: String,
    runId: Option<i64>,
    rawSha256: Option<String>,
    detail: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recording {
    pub header: Header,
    pub state: State,
    pub events: Vec<Event>,
    pub runId: Option<i64>,
    pub detail: Option<String>,
}

pub(super) struct Recorder {
    header: Header,
    headerSha256: String,
    headerBytes: usize,
    metadata: Metadata,
    metadataSha256: String,
    last: Option<Event>,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn checksum(value: &str) -> String {
    epp_core::backups::checksum(value)
}
fn equal(left: &impl Serialize, right: &impl Serialize) -> ServiceResult<bool> {
    Ok(serde_json::to_value(left)? == serde_json::to_value(right)?)
}
fn payload(value: &impl Serialize, limit: usize) -> ServiceResult<String> {
    let value = serde_json::to_string(value)?;
    if value.len() > limit {
        return Err("Load recording exceeded its fixed evidence allowance".into());
    }
    Ok(value)
}
fn decode<T: DeserializeOwned + Serialize>(value: &str) -> ServiceResult<T> {
    let parsed: T = serde_json::from_str(value)?;
    if serde_json::to_value(&parsed)? != serde_json::from_str::<serde_json::Value>(value)? {
        return Err("Load recording fields differ from the supported schema".into());
    }
    Ok(parsed)
}
fn detail(value: &str) -> String {
    value
        .chars()
        .take(512)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}
fn phaseOrdinal(progress: &SessionProgress) -> usize {
    progress.providerIndex * 4
        + match progress.phase {
            session::Phase::Idle => 0,
            session::Phase::Download => 1,
            session::Phase::Upload => 2,
            session::Phase::Recovery => 3,
        }
}
fn validateEvent(header: &Header, event: &Event, previous: Option<&Event>) -> ServiceResult<()> {
    let progress = &event.progress;
    if event.sequence >= MAX_EVENTS
        || progress.providerIndex >= header.sessionPlan.providers.len()
        || progress.providerCount != header.sessionPlan.providers.len()
        || event.capturedAtUnixMs < header.createdAtUnixMs
        || event.capturedAtUnixMs >= header.experiment.expiresAtUnixMs
    {
        return Err("Load progress has invalid identity, time, or sequence".into());
    }
    let downloadLimit = if progress.phase == session::Phase::Download {
        header.sessionPlan.downloadBytesPerProvider
    } else {
        0
    };
    let uploadLimit = if progress.phase == session::Phase::Upload {
        header.sessionPlan.uploadBytesPerProvider
    } else {
        0
    };
    if progress.downloadBytesRead > downloadLimit || progress.uploadBodyBytesProvided > uploadLimit
    {
        return Err("Load progress exceeded its frozen direction or payload allowance".into());
    }
    if let Some(previous) = previous {
        if event.sequence != previous.sequence + 1
            || event.capturedAtUnixMs < previous.capturedAtUnixMs
            || phaseOrdinal(progress) < phaseOrdinal(&previous.progress)
            || (phaseOrdinal(progress) == phaseOrdinal(&previous.progress)
                && (progress.downloadBytesRead < previous.progress.downloadBytesRead
                    || progress.uploadBodyBytesProvided
                        < previous.progress.uploadBodyBytesProvided))
        {
            return Err("Load progress time, phase, sequence, or payload regressed".into());
        }
    } else if event.sequence != 0
        || progress.providerIndex != 0
        || progress.phase != session::Phase::Idle
        || progress.sample.is_some()
    {
        return Err("Load progress must start with its first idle phase".into());
    }
    if let Some(sample) = &progress.sample {
        let endpoint = header
            .sessionPlan
            .latencyEndpoints
            .iter()
            .find(|endpoint| endpoint.id == sample.sample.endpointId)
            .ok_or("Recorded probe has an unknown endpoint")?;
        let activeLimit = if matches!(
            progress.phase,
            session::Phase::Download | session::Phase::Upload
        ) {
            u64::from(header.sessionPlan.streams)
        } else {
            0
        };
        if sample.providerIndex != progress.providerIndex
            || sample.phase != progress.phase
            || sample.sample.address != endpoint.address
            || sample.inFlightRequestsAtStart > activeLimit
            || sample.inFlightRequestsAtEnd > activeLimit
            || sample.payloadProgressDuringProbe > downloadLimit + uploadLimit
        {
            return Err(
                "Recorded probe differs from its phase, endpoint, or traffic allowance".into(),
            );
        }
    }
    Ok(())
}

fn stateChecksum(id: Uuid, headerSha256: &str, value: &str) -> ServiceResult<String> {
    hash(&("adapter-load-recording-state-v1", id, headerSha256, value))
}
fn eventChecksum(id: Uuid, previous: &str, value: &str) -> ServiceResult<String> {
    hash(&("adapter-load-recording-event-v1", id, previous, value))
}

fn load(database: &Connection, id: Uuid) -> ServiceResult<(Recording, Recorder)> {
    let (headerJson, headerSha256, state, runId, metadataJson, metadataSha256): (String,String,String,Option<i64>,String,String) = database.query_row(
        "SELECT header_json,header_sha256,state,run_id,metadata_json,metadata_sha256 FROM adapter_load_recordings WHERE id=?1 AND length(CAST(header_json AS BLOB))<=1048576 AND length(CAST(metadata_json AS BLOB))<=8192", [id.to_string()], |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)))?;
    if checksum(&headerJson) != headerSha256
        || stateChecksum(id, &headerSha256, &metadataJson)? != metadataSha256
    {
        return Err("Load recording header or state checksum failed".into());
    }
    let header: Header = decode(&headerJson)?;
    header.validate()?;
    let metadata: Metadata = decode(&metadataJson)?;
    if header.id != id
        || metadata.schemaVersion != 1
        || metadata.state.label() != state
        || metadata.runId != runId
        || metadata.eventCount > MAX_EVENTS
        || metadata.eventBytes > RECORDING_BYTES.saturating_sub(headerJson.len() as u64)
        || !digest(&metadata.headSha256)
        || metadata
            .detail
            .as_ref()
            .is_some_and(|value| value.chars().count() > 512 || value.chars().any(char::is_control))
        || (metadata.state == State::Finalized) != metadata.runId.is_some()
        || metadata.runId.is_some_and(|id| id <= 0)
        || metadata.runId.is_some() != metadata.rawSha256.is_some()
        || metadata
            .rawSha256
            .as_ref()
            .is_some_and(|value| !digest(value))
        || (metadata.state == State::Recording && metadata.detail.is_some())
        || (metadata.state == State::Interrupted && metadata.detail.is_none())
    {
        return Err("Load recording state differs from its bounded metadata".into());
    }
    let (count,bytes):(u32,i64)=database.query_row("SELECT COUNT(*),COALESCE(SUM(length(CAST(payload_json AS BLOB))),0) FROM adapter_load_recording_events WHERE recording_id=?1",[id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?;
    if count != metadata.eventCount || u64::try_from(bytes)? != metadata.eventBytes {
        return Err("Load recording event count or byte allowance changed".into());
    }
    let mut query = database.prepare("SELECT sequence,payload_json,sha256 FROM adapter_load_recording_events WHERE recording_id=?1 AND length(CAST(payload_json AS BLOB))<=16384 ORDER BY sequence LIMIT 4097")?;
    let rows = query.query_map([id.to_string()], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut events = Vec::new();
    let mut head = headerSha256.clone();
    for row in rows {
        let (sequence, value, expected) = row?;
        let event: Event = decode(&value)?;
        if sequence != events.len() as u32
            || event.sequence != sequence
            || eventChecksum(id, &head, &value)? != expected
        {
            return Err("Load recording event sequence or checksum failed".into());
        }
        validateEvent(&header, &event, events.last())?;
        events.push(event);
        head = expected;
    }
    if events.len() != metadata.eventCount as usize || head != metadata.headSha256 {
        return Err("Load recording lost events or its final chain head".into());
    }
    if let Some(runId) = runId {
        let raw: String = database.query_row(
            "SELECT report_json FROM load_sessions WHERE id=?1 AND length(CAST(report_json AS BLOB))<=8388608",
            [runId],
            |row| row.get(0),
        )?;
        if Some(checksum(&raw)) != metadata.rawSha256 {
            return Err("Finalized load recording lost its exact raw report".into());
        }
        let run: SessionRun = serde_json::from_str(&raw)?;
        if run.id != runId {
            return Err("Finalized raw report has a different identity".into());
        }
        header.validateRun(&run, &events)?;
    }
    let recorder = Recorder {
        header: header.clone(),
        headerSha256,
        headerBytes: headerJson.len(),
        metadata: metadata.clone(),
        metadataSha256,
        last: events.last().cloned(),
    };
    Ok((
        Recording {
            header,
            state: metadata.state,
            events,
            runId,
            detail: metadata.detail,
        },
        recorder,
    ))
}

pub fn history(database: &Connection, limit: u32) -> ServiceResult<Vec<Recording>> {
    let snapshot = database.unchecked_transaction()?;
    let database = &snapshot;
    let tables:u32=database.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('adapter_load_recordings','adapter_load_recording_events')",[],|row|row.get(0))?;
    if tables == 0 {
        return Ok(Vec::new());
    }
    if tables != 2 {
        return Err("Load recording schema is incomplete; preserve its evidence".into());
    }
    let mut query =
        database.prepare("SELECT id FROM adapter_load_recordings ORDER BY rowid DESC LIMIT ?1")?;
    let ids = query
        .query_map([limit.min(100)], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(query);
    let mut bytes = 0u64;
    let mut recordings = Vec::new();
    for id in ids {
        let size:i64=database.query_row("SELECT length(CAST(header_json AS BLOB))+length(CAST(metadata_json AS BLOB))+COALESCE((SELECT SUM(length(CAST(payload_json AS BLOB))) FROM adapter_load_recording_events WHERE recording_id=?1),0) FROM adapter_load_recordings WHERE id=?1",[&id],|row|row.get(0))?;
        bytes = bytes
            .checked_add(u64::try_from(size)?)
            .ok_or("Load recording history size overflowed")?;
        if bytes > HISTORY_BYTES {
            return Err("Load recording history exceeds 32 MiB; request fewer recordings".into());
        }
        recordings.push(load(database, Uuid::parse_str(&id)?)?.0);
    }
    snapshot.commit()?;
    Ok(recordings)
}

pub(super) fn initialize(database: &mut Connection) -> ServiceResult<()> {
    measurement::validateStorage(database)?;
    let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch("CREATE TABLE IF NOT EXISTS adapter_load_recordings(id TEXT PRIMARY KEY,header_json TEXT NOT NULL,header_sha256 TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('recording','finalized','interrupted')),run_id INTEGER UNIQUE REFERENCES load_sessions(id),metadata_json TEXT NOT NULL,metadata_sha256 TEXT NOT NULL);
        CREATE UNIQUE INDEX IF NOT EXISTS one_recording_load ON adapter_load_recordings(state) WHERE state='recording';
        CREATE TABLE IF NOT EXISTS adapter_load_recording_events(recording_id TEXT NOT NULL REFERENCES adapter_load_recordings(id),sequence INTEGER NOT NULL,payload_json TEXT NOT NULL,sha256 TEXT NOT NULL,PRIMARY KEY(recording_id,sequence));")?;
    transaction.commit()?;
    let mut query = database
        .prepare("SELECT id FROM adapter_load_recordings WHERE state='recording' LIMIT 2")?;
    let ids = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    drop(query);
    if ids.len() > 1 {
        return Err("More than one unfinished load recording was found".into());
    }
    for id in ids {
        let (_, mut recorder) = load(database, Uuid::parse_str(&id)?)?;
        owned_process::waitForIdentity(&recorder.header.owner, Duration::ZERO).map_err(
            |error| format!("Load recording owner is still alive or cannot be verified: {error}"),
        )?;
        recorder.abort(
            database,
            "Measurement owner exited before final report commit",
        )?;
    }
    Ok(())
}

impl Recorder {
    pub(super) fn start(database: &mut Connection, header: Header) -> ServiceResult<Self> {
        initialize(database)?;
        header.validate()?;
        let now = nowUnixMs()?;
        if now < header.createdAtUnixMs || now >= header.experiment.expiresAtUnixMs {
            return Err("New load recording has an expired or future context".into());
        }
        let current = owned_process::processIdentity(
            unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() },
            std::process::id(),
        )?;
        if header.owner != current {
            return Err("New load recording must belong to its actual process".into());
        }
        let headerJson = payload(&header, HEADER_BYTES)?;
        let headerSha256 = checksum(&headerJson);
        let metadata = Metadata {
            schemaVersion: 1,
            state: State::Recording,
            eventCount: 0,
            eventBytes: 0,
            headSha256: headerSha256.clone(),
            runId: None,
            rawSha256: None,
            detail: None,
        };
        let metadataJson = payload(&metadata, 8192)?;
        let metadataSha256 = stateChecksum(header.id, &headerSha256, &metadataJson)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: u32 =
            transaction.query_row("SELECT COUNT(*) FROM adapter_load_recordings", [], |row| {
                row.get(0)
            })?;
        if count >= MAX_RECORDINGS {
            return Err(
                "Load recording capacity is full; preserve and archive evidence before more work"
                    .into(),
            );
        }
        transaction.execute("INSERT INTO adapter_load_recordings(id,header_json,header_sha256,state,run_id,metadata_json,metadata_sha256) VALUES(?1,?2,?3,'recording',NULL,?4,?5)",params![header.id.to_string(),headerJson,headerSha256,metadataJson,metadataSha256])?;
        transaction.commit()?;
        let recorder = Self {
            header,
            headerSha256,
            headerBytes: headerJson.len(),
            metadata,
            metadataSha256,
            last: None,
        };
        load(database, recorder.header.id)?;
        recorder.verify(database)?;
        Ok(recorder)
    }

    fn verify(&self, database: &Connection) -> ServiceResult<()> {
        let (header,value,metadata,state,runId):(String,String,String,String,Option<i64>)=database.query_row("SELECT header_sha256,metadata_json,metadata_sha256,state,run_id FROM adapter_load_recordings WHERE id=?1 AND length(CAST(metadata_json AS BLOB))<=8192",[self.header.id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;
        if header != self.headerSha256
            || metadata != self.metadataSha256
            || value != payload(&self.metadata, 8192)?
            || stateChecksum(self.header.id, &header, &value)? != metadata
            || state != self.metadata.state.label()
            || runId != self.metadata.runId
        {
            return Err("Load recording ownership or committed state changed".into());
        }
        Ok(())
    }

    fn update(&self, database: &Connection, metadata: &Metadata) -> ServiceResult<String> {
        let value = payload(metadata, 8192)?;
        let checksum = stateChecksum(self.header.id, &self.headerSha256, &value)?;
        let changed=database.execute("UPDATE adapter_load_recordings SET state=?1,run_id=?2,metadata_json=?3,metadata_sha256=?4 WHERE id=?5 AND header_sha256=?6 AND metadata_sha256=?7 AND state='recording'",params![metadata.state.label(),metadata.runId,value,checksum,self.header.id.to_string(),self.headerSha256,self.metadataSha256])?;
        if changed != 1 {
            return Err("Load recording changed before its next durable update".into());
        }
        Ok(checksum)
    }

    pub(super) fn append(
        &mut self,
        database: &mut Connection,
        progress: SessionProgress,
        capturedAtUnixMs: u64,
    ) -> ServiceResult<()> {
        measurement::validateStorage(database)?;
        if self.metadata.state != State::Recording {
            return Err("Finished load recordings cannot receive more progress".into());
        }
        let event = Event {
            sequence: self.metadata.eventCount,
            capturedAtUnixMs,
            progress,
        };
        validateEvent(&self.header, &event, self.last.as_ref())?;
        let value = payload(&event, EVENT_BYTES)?;
        let head = eventChecksum(self.header.id, &self.metadata.headSha256, &value)?;
        let mut metadata = self.metadata.clone();
        metadata.eventCount += 1;
        metadata.eventBytes = metadata
            .eventBytes
            .checked_add(value.len() as u64)
            .ok_or("Load recording byte count overflowed")?;
        if metadata.eventBytes > RECORDING_BYTES.saturating_sub(self.headerBytes as u64) {
            return Err("Load recording reached its 8 MiB evidence allowance".into());
        }
        metadata.headSha256 = head.clone();
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.verify(&transaction)?;
        transaction.execute("INSERT INTO adapter_load_recording_events(recording_id,sequence,payload_json,sha256) VALUES(?1,?2,?3,?4)",params![self.header.id.to_string(),event.sequence,value,head])?;
        let checksum = self.update(&transaction, &metadata)?;
        transaction.commit()?;
        self.metadata = metadata;
        self.metadataSha256 = checksum;
        self.last = Some(event);
        self.verify(database)?;
        let (saved,stored):(String,String)=database.query_row("SELECT payload_json,sha256 FROM adapter_load_recording_events WHERE recording_id=?1 AND sequence=?2 AND length(CAST(payload_json AS BLOB))<=16384",params![self.header.id.to_string(),self.metadata.eventCount-1],|row|Ok((row.get(0)?,row.get(1)?)))?;
        if saved != value || stored != head {
            return Err("Committed load progress differs from its captured evidence".into());
        }
        Ok(())
    }

    pub(super) fn finish(
        &mut self,
        database: &mut Connection,
        run: &mut SessionRun,
        failure: Option<&str>,
    ) -> ServiceResult<()> {
        measurement::validateStorage(database)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.verify(&transaction)?;
        let (recording, _) = load(&transaction, self.header.id)?;
        self.header.validateRun(run, &recording.events)?;
        payload(run, RECORDING_BYTES as usize)?;
        epp_core::storage::saveLoadSessionInTransaction(&transaction, run)?;
        let mut metadata = self.metadata.clone();
        metadata.state = State::Finalized;
        metadata.runId = Some(run.id);
        metadata.rawSha256 = Some(checksum(&serde_json::to_string(run)?));
        metadata.detail = failure.map(detail);
        let checksum = self.update(&transaction, &metadata)?;
        load(&transaction, self.header.id)?;
        transaction.commit()?;
        self.metadata = metadata;
        self.metadataSha256 = checksum;
        load(database, self.header.id)?;
        self.verify(database)
    }

    pub(super) fn abort(&mut self, database: &mut Connection, reason: &str) -> ServiceResult<()> {
        measurement::validateStorage(database)?;
        let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.verify(&transaction)?;
        load(&transaction, self.header.id)?;
        let mut metadata = self.metadata.clone();
        metadata.state = State::Interrupted;
        metadata.detail = Some(detail(reason));
        let checksum = self.update(&transaction, &metadata)?;
        transaction.commit()?;
        self.metadata = metadata;
        self.metadataSha256 = checksum;
        load(database, self.header.id)?;
        self.verify(database)
    }
}

#[cfg(test)]
mod tests;
