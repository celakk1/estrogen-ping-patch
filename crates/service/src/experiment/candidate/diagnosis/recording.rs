use super::*;
use crate::{journal::MutatorIdentity, owned_process};
use rusqlite::Connection;
use serde::de::DeserializeOwned;

mod store;

const HEADER_BYTES: usize = 16_384;
const EVENT_BYTES: usize = 131_072;
const RESULT_BYTES: usize = 4 * 1024 * 1024;
const RECORDING_BYTES: u64 = 4 * 1024 * 1024;
const MAX_EVENTS: u32 = 1200;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Header {
    pub schemaVersion: u32,
    pub id: Uuid,
    pub owner: MutatorIdentity,
    pub createdAtUnixMs: u64,
    pub appVersion: String,
    pub execution: String,
    pub plan: Plan,
}

impl Header {
    fn validate(&self) -> ServiceResult<()> {
        self.owner.validate()?;
        self.plan.validate()?;
        if self.schemaVersion != 1
            || self.id.is_nil()
            || self.createdAtUnixMs == 0
            || self.createdAtUnixMs > i64::MAX as u64 - self.plan.maximumDurationMs
            || self.appVersion.is_empty()
            || self.appVersion.len() > 64
            || self.appVersion.chars().any(char::is_control)
            || self.execution != "recordedDiagnosticWorkerV1"
        {
            return Err("Diagnostic recording has invalid identity, version, or time".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Observation {
    Context {
        before: Box<policy::Capture>,
        routes: Vec<routing::Capture>,
    },
    Target {
        index: usize,
        plan: packet_size::Plan,
        limits: Limits,
    },
    Sample {
        sample: Sample,
    },
    Report {
        report: Box<Report>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Event {
    pub sequence: u32,
    pub capturedAtUnixMs: u64,
    pub observation: Observation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum SavedCollection {
    Completed {
        plan: Plan,
        evidence: Box<Evidence>,
        proposal: Option<Box<Summary>>,
    },
    Stopped {
        plan: Plan,
        reason: StopReason,
        detail: String,
        evidence: Box<Partial>,
    },
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recording {
    pub header: Header,
    pub state: State,
    pub events: Vec<Event>,
    pub result: Option<SavedCollection>,
    pub detail: Option<String>,
}

pub struct RecordedCollection {
    pub recordingId: Uuid,
    pub collection: Collection,
}

fn equal(
    left: &(impl Serialize + ?Sized),
    right: &(impl Serialize + ?Sized),
) -> ServiceResult<bool> {
    Ok(serde_json::to_value(left)? == serde_json::to_value(right)?)
}

fn payload(value: &impl Serialize, limit: usize) -> ServiceResult<String> {
    let value = serde_json::to_string(value)?;
    if value.len() > limit {
        return Err("Diagnostic recording exceeded its fixed evidence allowance".into());
    }
    Ok(value)
}

fn decode<T: DeserializeOwned + Serialize>(value: &str) -> ServiceResult<T> {
    let parsed: T = serde_json::from_str(value)?;
    if !equal(&parsed, &serde_json::from_str::<serde_json::Value>(value)?)? {
        return Err("Diagnostic recording contains missing or unsupported fields".into());
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

fn owner() -> ServiceResult<MutatorIdentity> {
    owned_process::processIdentity(
        unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() },
        std::process::id(),
    )
}

struct Target {
    plan: packet_size::Plan,
    limits: Limits,
    startedAtUnixMs: u64,
    samples: Vec<Sample>,
    requestedBytes: u64,
}

#[derive(Default)]
struct Prefix {
    context: Option<(policy::Capture, Vec<routing::Capture>)>,
    active: Option<Target>,
    reports: Vec<Report>,
    totalProbes: usize,
    totalBytes: u64,
    lastAtUnixMs: u64,
}

impl Prefix {
    fn accept(&mut self, header: &Header, event: &Event) -> ServiceResult<()> {
        if event.sequence >= MAX_EVENTS
            || event.capturedAtUnixMs < header.createdAtUnixMs.max(self.lastAtUnixMs)
            || event.capturedAtUnixMs
                > header.createdAtUnixMs + header.plan.maximumDurationMs + 6000
        {
            return Err("Diagnostic event has invalid sequence or capture time".into());
        }
        match &event.observation {
            Observation::Context { before, routes } => {
                if event.sequence != 0
                    || self.context.is_some()
                    || before.native.adapterGuid != header.plan.adapterGuid
                    || before.native.capturedAtUnixMs < header.createdAtUnixMs
                    || before.native.capturedAtUnixMs > event.capturedAtUnixMs
                {
                    return Err("Diagnostic originals differ from their recording context".into());
                }
                routesMatch(&header.plan.targets, routes, before)?;
                if !routeTimes(routes, |time| {
                    time >= before.native.capturedAtUnixMs && time <= event.capturedAtUnixMs
                }) {
                    return Err("Diagnostic routes are outside their captured context".into());
                }
                self.context = Some(((**before).clone(), routes.clone()));
            }
            Observation::Target {
                index,
                plan,
                limits,
            } => {
                plan.validate()?;
                limits.validate()?;
                let (before, routes) = self
                    .context
                    .as_ref()
                    .ok_or("Diagnostic context is missing")?;
                if self.active.is_some()
                    || *index != self.reports.len()
                    || *index >= header.plan.targets.len()
                    || self.reports.last().is_some_and(|report| {
                        !matches!(
                            report.outcome,
                            Outcome::TestedLimitReached | Outcome::SizeBoundaryObserved
                        )
                    })
                    || self.totalProbes >= header.plan.maximumProbes
                    || self.totalBytes >= header.plan.maximumRequestedIpv4Bytes
                    || limits.maximumProbes > header.plan.maximumProbes - self.totalProbes
                    || limits.maximumRequestedIpv4Bytes
                        > header.plan.maximumRequestedIpv4Bytes - self.totalBytes
                    || plan.destination != header.plan.targets[*index].ip
                    || plan.interfaceMtu != before.native.settings.nlMtu
                    || plan.timeoutMs != 750
                    || plan.intervalMs != 75
                    || u64::from(plan.budgetMs) > header.plan.maximumDurationMs
                {
                    return Err(
                        "Diagnostic target differs from its frozen cohort or remaining allowance"
                            .into(),
                    );
                }
                let routing::Capture::Captured { snapshot } = &routes[*index] else {
                    return Err("Diagnostic source route is unavailable".into());
                };
                if plan.source != snapshot.source.ip {
                    return Err("Diagnostic target uses a different local source".into());
                }
                self.active = Some(Target {
                    plan: plan.clone(),
                    limits: *limits,
                    startedAtUnixMs: event.capturedAtUnixMs,
                    samples: Vec::new(),
                    requestedBytes: 0,
                });
            }
            Observation::Sample { sample } => {
                let active = self
                    .active
                    .as_mut()
                    .ok_or("Diagnostic probe has no active target")?;
                let previous = active
                    .samples
                    .last()
                    .map_or(active.startedAtUnixMs, |sample| sample.timestampUnixMs);
                let bytes = u64::from(sample.packetBytes);
                if sample.sequence != active.samples.len()
                    || sample.timestampUnixMs < previous
                    || sample.timestampUnixMs > event.capturedAtUnixMs.saturating_add(250)
                    || !sample.dontFragment
                    || !(84..=active.plan.interfaceMtu.min(packet_size::MAX_PACKET_BYTES))
                        .contains(&sample.packetBytes)
                    || (sample.control && sample.packetBytes != 84)
                    || !sample.echo.callDurationMs.is_finite()
                    || sample.echo.callDurationMs < 0.0
                    || sample.echo.rttUnitMs != 1
                    || active.samples.len() >= active.limits.maximumProbes
                    || active.requestedBytes + bytes > active.limits.maximumRequestedIpv4Bytes
                    || self.totalProbes >= header.plan.maximumProbes
                    || self.totalBytes + bytes > header.plan.maximumRequestedIpv4Bytes
                {
                    return Err(
                        "Diagnostic probe contradicts its frozen target or allowance".into(),
                    );
                }
                active.samples.push(sample.clone());
                active.requestedBytes += bytes;
                self.totalProbes += 1;
                self.totalBytes += bytes;
            }
            Observation::Report { report } => {
                report.validate()?;
                let active = self
                    .active
                    .as_ref()
                    .ok_or("Diagnostic report has no active target")?;
                if !equal(&report.plan, &active.plan)?
                    || !equal(&report.samples, &active.samples)?
                    || report.startedAtUnixMs < active.startedAtUnixMs
                    || report.finishedAtUnixMs > event.capturedAtUnixMs.saturating_add(250)
                {
                    return Err("Diagnostic report changed its recorded probe prefix".into());
                }
                self.reports.push((**report).clone());
                self.active = None;
            }
        }
        self.lastAtUnixMs = event.capturedAtUnixMs;
        Ok(())
    }

    fn validateResult(&self, header: &Header, result: &SavedCollection) -> ServiceResult<()> {
        let (plan, before, routes, reports, completed) = match result {
            SavedCollection::Completed {
                plan,
                evidence,
                proposal,
            } => {
                let now = proposal
                    .as_ref()
                    .map_or(evidence.after.native.capturedAtUnixMs, |summary| {
                        summary.diagnosedAtUnixMs
                    });
                let expected = proposeMtu(&plan.targets, evidence, now)?;
                if !equal(&expected.as_ref().map(|value| value.summary()), proposal)? {
                    return Err("Saved diagnostic proposal differs from its raw evidence".into());
                }
                (
                    plan,
                    Some(&evidence.before),
                    &evidence.routesBefore,
                    &evidence.reports,
                    true,
                )
            }
            SavedCollection::Stopped {
                plan,
                detail: failure,
                evidence,
                ..
            } => {
                if failure.chars().count() > 512 || failure.chars().any(char::is_control) {
                    return Err("Saved diagnostic failure detail is unbounded".into());
                }
                (
                    plan,
                    evidence.before.as_ref(),
                    &evidence.routesBefore,
                    &evidence.reports,
                    false,
                )
            }
        };
        for report in reports {
            report.validate()?;
        }
        if !equal(plan, &header.plan)?
            || reports.len() > header.plan.targets.len()
            || reports
                .iter()
                .map(|report| report.samples.len())
                .sum::<usize>()
                > header.plan.maximumProbes
            || reports
                .iter()
                .map(|report| report.requestedIpv4Bytes)
                .sum::<u64>()
                > header.plan.maximumRequestedIpv4Bytes
            || self.reports.len() > reports.len()
            || reports.len() > self.reports.len() + usize::from(self.active.is_some())
        {
            return Err("Saved diagnosis changed its plan or shared traffic allowance".into());
        }
        if let Some((original, selected)) = &self.context
            && (!before
                .map(|before| equal(before, original))
                .transpose()?
                .unwrap_or(false)
                || !equal(routes, selected)?)
        {
            return Err("Saved diagnosis changed its recorded originals or routes".into());
        }
        for (saved, report) in self.reports.iter().zip(reports) {
            if !equal(saved, report)? {
                return Err("Saved diagnosis changed a recorded terminal report".into());
            }
        }
        if let Some(active) = &self.active
            && let Some(report) = reports.get(self.reports.len())
            && (!equal(&active.plan, &report.plan)?
                || active.samples.len() > report.samples.len()
                || !equal(&active.samples, &report.samples[..active.samples.len()])?)
        {
            return Err("Saved diagnosis lost its recorded sample prefix".into());
        }
        if completed
            && (self.active.is_some()
                || self.reports.len() != reports.len()
                || self.context.is_none())
        {
            return Err("Completed diagnosis was not completely recorded".into());
        }
        Ok(())
    }
}

pub fn history(database: &Connection, limit: u32) -> ServiceResult<Vec<Recording>> {
    store::history(database, limit)
}

pub fn collect(
    database: &mut Connection,
    plan: Plan,
    cancelled: &AtomicBool,
    progress: impl FnMut(usize, &Sample) -> ServiceResult<()>,
) -> ServiceResult<RecordedCollection> {
    collectUsing(database, plan, cancelled, progress, &mut Native)
}

struct BackendRecorder<'a, B> {
    database: &'a mut Connection,
    recorder: store::Recorder,
    backend: &'a mut B,
    before: Option<policy::Capture>,
    routes: Vec<routing::Capture>,
    index: usize,
    failure: Option<String>,
}

impl<B: Backend> Backend for BackendRecorder<'_, B> {
    fn policy(
        &mut self,
        adapterGuid: Uuid,
        cancelled: &AtomicBool,
    ) -> ServiceResult<policy::Capture> {
        let capture = self.backend.policy(adapterGuid, cancelled)?;
        if self.before.is_none() {
            self.before = Some(capture.clone());
        }
        Ok(capture)
    }

    fn routes(
        &mut self,
        targets: &[routing::Address],
        cancelled: &AtomicBool,
    ) -> ServiceResult<Vec<routing::Capture>> {
        let captures = self.backend.routes(targets, cancelled)?;
        if self.routes.is_empty() {
            self.routes = captures.clone();
        }
        Ok(captures)
    }

    fn diagnose(
        &mut self,
        plan: packet_size::Plan,
        limits: Limits,
        cancelled: &AtomicBool,
        progress: &mut dyn FnMut(&Sample) -> ServiceResult<()>,
    ) -> ServiceResult<Report> {
        if self.index == 0 {
            self.recorder.append(
                self.database,
                Observation::Context {
                    before: Box::new(
                        self.before
                            .clone()
                            .ok_or("Diagnostic originals are missing")?,
                    ),
                    routes: self.routes.clone(),
                },
            )?;
        }
        self.recorder.append(
            self.database,
            Observation::Target {
                index: self.index,
                plan: plan.clone(),
                limits,
            },
        )?;
        let report = self
            .backend
            .diagnose(plan, limits, cancelled, &mut |sample| {
                if self.failure.is_none()
                    && let Err(error) = self.recorder.append(
                        self.database,
                        Observation::Sample {
                            sample: sample.clone(),
                        },
                    )
                {
                    self.failure = Some(error.to_string());
                    cancelled.store(true, Ordering::SeqCst);
                }
                if let Some(failure) = &self.failure {
                    return Err(failure.clone().into());
                }
                progress(sample)
            })?;
        if self.failure.is_none()
            && let Err(error) = self.recorder.append(
                self.database,
                Observation::Report {
                    report: Box::new(report.clone()),
                },
            )
        {
            self.failure = Some(error.to_string());
            cancelled.store(true, Ordering::SeqCst);
        }
        self.index += 1;
        Ok(report)
    }
}

fn collectUsing<B: Backend>(
    database: &mut Connection,
    plan: Plan,
    cancelled: &AtomicBool,
    progress: impl FnMut(usize, &Sample) -> ServiceResult<()>,
    backend: &mut B,
) -> ServiceResult<RecordedCollection> {
    plan.validate()?;
    if cancelled.load(Ordering::SeqCst) {
        return Err("Diagnostic recording was cancelled before storage or collection".into());
    }
    let recorder = store::Recorder::start(database, plan.clone())?;
    let recordingId = recorder.header.id;
    let mut backend = BackendRecorder {
        database,
        recorder,
        backend,
        before: None,
        routes: Vec::new(),
        index: 0,
        failure: None,
    };
    let result = collectWithBackend(plan, cancelled, progress, &mut backend);
    match result {
        Ok(collection) => {
            backend
                .recorder
                .finish(backend.database, &collection, backend.failure.as_deref())
                .map_err(|error| {
                    format!("Diagnostic recording {recordingId} could not finalize: {error}")
                })?;
            Ok(RecordedCollection {
                recordingId,
                collection,
            })
        }
        Err(error) => {
            backend
                .recorder
                .interrupt(backend.database, &error.to_string())?;
            Err(format!("Diagnostic recording {recordingId} stopped: {error}").into())
        }
    }
}

#[cfg(test)]
mod tests;
