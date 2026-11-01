mod store;
pub use store::Store;

use crate::{
    AppResult,
    comparison::{self, MatchedBlock, Session},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
mod tests;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Plan {
    pub id: String,
    pub createdAtUnixMs: u64,
    pub expiresAtUnixMs: u64,
    pub blockCount: usize,
    pub comparison: comparison::Plan,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

impl Plan {
    pub fn validate(&self) -> AppResult<()> {
        self.comparison.validate()?;
        if !identifier(&self.id)
            || self.createdAtUnixMs == 0
            || self.expiresAtUnixMs > i64::MAX as u64
            || self.expiresAtUnixMs <= self.createdAtUnixMs
            || self.expiresAtUnixMs - self.createdAtUnixMs > 14_400_000
            || !(12..=32).contains(&self.blockCount)
            || self.comparison.originalConfigurationSha256
                == self.comparison.candidateConfigurationSha256
        {
            return Err("Repeated trials require a unique identity, twelve to thirty-two blocks, distinct configurations, and a fixed budget of at most four hours".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum State {
    Ready,
    BaselineBefore,
    Candidate,
    BaselineAfter,
    Completed,
    Rejected,
    Invalid,
    Cancelled,
    Expired,
    Failed,
    RecoveryRequired,
    Interrupted,
}

impl State {
    pub fn blocksNewExperiment(self) -> bool {
        matches!(
            self,
            Self::Ready
                | Self::BaselineBefore
                | Self::Candidate
                | Self::BaselineAfter
                | Self::RecoveryRequired
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrialOutcome {
    Completed,
    Interrupted,
    Failed,
    RecoveryRequired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateResult {
    pub checkpointId: String,
    pub outcome: TrialOutcome,
    pub measurement: Option<Session>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    pub schemaVersion: u32,
    pub revision: u32,
    pub plan: Plan,
    pub updatedAtUnixMs: u64,
    pub state: State,
    pub blocks: Vec<MatchedBlock>,
    pub checkpoints: Vec<String>,
    pub pendingBefore: Option<Session>,
    pub pendingCandidate: Option<CandidateResult>,
    pub error: Option<String>,
}

impl Snapshot {
    fn validate(&self) -> AppResult<()> {
        self.plan.validate()?;
        if self.schemaVersion != 1
            || self.revision > 256
            || !(self.plan.createdAtUnixMs..=i64::MAX as u64).contains(&self.updatedAtUnixMs)
            || self.blocks.len() > self.plan.blockCount
            || self.checkpoints.len() != self.blocks.len()
            || self.checkpoints.iter().any(|id| !identifier(id))
            || self.checkpoints.iter().collect::<BTreeSet<_>>().len() != self.checkpoints.len()
            || self.error.as_ref().is_some_and(|error| error.len() > 4096)
            || (self.state == State::Completed && self.blocks.len() != self.plan.blockCount)
        {
            return Err("Experiment state has inconsistent bounds, identity, or progress".into());
        }
        if !self.blocks.is_empty() {
            comparison::validateSessions(&self.plan.comparison, &self.blocks)?;
        }
        if let Some(candidate) = &self.pendingCandidate
            && (!identifier(&candidate.checkpointId)
                || self.checkpoints.contains(&candidate.checkpointId)
                || candidate
                    .error
                    .as_ref()
                    .is_some_and(|error| error.len() > 4096))
        {
            return Err("Candidate result requires its exact recovery checkpoint identity".into());
        }
        match self.state {
            State::Ready | State::BaselineBefore | State::Completed
                if self.pendingBefore.is_some() || self.pendingCandidate.is_some() =>
            {
                return Err("Experiment phase has unexpected pending measurements".into());
            }
            State::Candidate if self.pendingBefore.is_none() || self.pendingCandidate.is_some() => {
                return Err(
                    "Candidate phase requires a preceding baseline and no completed candidate"
                        .into(),
                );
            }
            State::BaselineAfter
                if self.pendingBefore.is_none()
                    || self.pendingCandidate.as_ref().is_none_or(|candidate| {
                        candidate.outcome != TrialOutcome::Completed
                            || candidate.measurement.is_none()
                    }) =>
            {
                return Err(
                    "Post-trial baseline requires completed and restored candidate measurements"
                        .into(),
                );
            }
            _ => {}
        }
        let mut identifiers = BTreeSet::new();
        let mut previousEnd = 0;
        for block in &self.blocks {
            for session in [
                &block.originalBefore,
                &block.candidate,
                &block.originalAfter,
            ] {
                identifiers.insert(session.id.clone());
                previousEnd = session.finishedAtUnixMs;
                self.validateTime(session)?;
            }
        }
        for (session, configuration) in [
            (
                self.pendingBefore.as_ref(),
                &self.plan.comparison.originalConfigurationSha256,
            ),
            (
                self.pendingCandidate
                    .as_ref()
                    .and_then(|candidate| candidate.measurement.as_ref()),
                &self.plan.comparison.candidateConfigurationSha256,
            ),
        ] {
            if let Some(session) = session {
                comparison::validateSession(
                    &self.plan.comparison,
                    session,
                    configuration,
                    &mut identifiers,
                    previousEnd,
                )?;
                self.validateTime(session)?;
                previousEnd = session.finishedAtUnixMs;
            }
        }
        Ok(())
    }

    fn validateTime(&self, session: &Session) -> AppResult<()> {
        if session.startedAtUnixMs < self.plan.createdAtUnixMs
            || session.finishedAtUnixMs > self.plan.expiresAtUnixMs.min(self.updatedAtUnixMs)
        {
            return Err(
                "Saved measurements are outside the experiment's recorded time budget".into(),
            );
        }
        Ok(())
    }
}

pub struct Control<'a> {
    cancelled: &'a AtomicBool,
    expiresAtUnixMs: u64,
    deadline: Instant,
    startedAtUnixMs: u64,
}

impl Control<'_> {
    pub fn check(&self) -> AppResult<()> {
        self.reason()?.map_or(Ok(()), |reason| {
            Err(format!("Experiment stopped: {reason:?}").into())
        })
    }

    fn reason(&self) -> AppResult<Option<State>> {
        let now = nowUnixMs()?;
        Ok(if self.cancelled.load(Ordering::SeqCst) {
            Some(State::Cancelled)
        } else if now < self.startedAtUnixMs {
            Some(State::Invalid)
        } else if now >= self.expiresAtUnixMs || Instant::now() >= self.deadline {
            Some(State::Expired)
        } else {
            None
        })
    }
}

pub trait Host {
    fn verifyOriginal(&mut self, plan: &Plan) -> AppResult<()>;
    fn measureOriginal(&mut self, control: &Control<'_>) -> AppResult<Session>;
    fn measureCandidate(&mut self, control: &Control<'_>) -> AppResult<CandidateResult>;
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub snapshot: Snapshot,
    pub comparison: Option<comparison::Report>,
}

fn nowUnixMs() -> AppResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn bounded(error: impl std::fmt::Display) -> String {
    error.to_string().chars().take(1024).collect()
}

fn guarded<T>(callback: impl FnOnce() -> AppResult<T>) -> AppResult<T> {
    catch_unwind(AssertUnwindSafe(callback))
        .map_err(|_| "Experiment host panicked".into())
        .and_then(|result| result)
}

fn persist(store: &mut Store, snapshot: &mut Snapshot, state: State) -> AppResult<()> {
    let previousRevision = snapshot.revision;
    snapshot.revision += 1;
    snapshot.updatedAtUnixMs = nowUnixMs()?.max(snapshot.updatedAtUnixMs);
    snapshot.state = state;
    if let Err(error) = store.save(snapshot) {
        snapshot.revision = previousRevision;
        return Err(error);
    }
    Ok(())
}

fn finish<H: Host>(
    store: &mut Store,
    snapshot: &mut Snapshot,
    host: &mut H,
    state: State,
    error: Option<String>,
    control: &Control<'_>,
) -> AppResult<()> {
    snapshot.error = error;
    let verified = guarded(|| host.verifyOriginal(&snapshot.plan));
    let state = match verified {
        Ok(()) => {
            if state == State::RecoveryRequired {
                state
            } else {
                control.reason()?.unwrap_or(state)
            }
        }
        Err(error) => {
            snapshot.error = Some(bounded(format!(
                "{}; original-state verification: {error}",
                snapshot.error.as_deref().unwrap_or("Experiment stopped")
            )));
            State::RecoveryRequired
        }
    };
    persist(store, snapshot, state)
}

fn validateNext(snapshot: &Snapshot, session: &Session, configuration: &str) -> AppResult<()> {
    let mut ids = BTreeSet::new();
    let mut end = 0;
    for block in &snapshot.blocks {
        for measured in [
            &block.originalBefore,
            &block.candidate,
            &block.originalAfter,
        ] {
            ids.insert(measured.id.clone());
            end = measured.finishedAtUnixMs;
        }
    }
    for measured in [
        snapshot.pendingBefore.as_ref(),
        snapshot
            .pendingCandidate
            .as_ref()
            .and_then(|candidate| candidate.measurement.as_ref()),
    ]
    .into_iter()
    .flatten()
    {
        ids.insert(measured.id.clone());
        end = measured.finishedAtUnixMs;
    }
    comparison::validateSession(
        &snapshot.plan.comparison,
        session,
        configuration,
        &mut ids,
        end,
    )?;
    if session.startedAtUnixMs < snapshot.plan.createdAtUnixMs
        || session.finishedAtUnixMs > snapshot.plan.expiresAtUnixMs
        || session.finishedAtUnixMs > nowUnixMs()?
    {
        return Err(
            "Measurements must fall within the experiment budget and cannot be future-dated".into(),
        );
    }
    Ok(())
}

fn advance<H: Host>(
    store: &mut Store,
    snapshot: &mut Snapshot,
    host: &mut H,
    control: &Control<'_>,
) -> AppResult<State> {
    while snapshot.blocks.len() < snapshot.plan.blockCount {
        control.check()?;
        guarded(|| host.verifyOriginal(&snapshot.plan))?;
        persist(store, snapshot, State::BaselineBefore)?;
        let before = guarded(|| host.measureOriginal(control))?;
        validateNext(
            snapshot,
            &before,
            &snapshot.plan.comparison.originalConfigurationSha256,
        )?;
        snapshot.pendingBefore = Some(before);
        control.check()?;
        guarded(|| host.verifyOriginal(&snapshot.plan))?;
        persist(store, snapshot, State::Candidate)?;
        // the host must not return completed until its independent recovery verifies the original.
        let mut candidate = guarded(|| host.measureCandidate(control))?;
        candidate.error = candidate.error.take().map(bounded);
        let checkpointId = candidate.checkpointId.clone();
        if !identifier(&checkpointId) || snapshot.checkpoints.contains(&checkpointId) {
            return Err(
                "A candidate reused or omitted its exact recovery checkpoint identity".into(),
            );
        }
        if candidate.outcome != TrialOutcome::Completed {
            snapshot.error = Some(candidate.error.as_ref().map_or_else(
                || match candidate.outcome {
                    TrialOutcome::RecoveryRequired => "Original settings could not be fully verified; recovery is required before another trial".into(),
                    TrialOutcome::Interrupted => "The temporary trial stopped before all measurements finished".into(),
                    _ => "The temporary trial failed before its measurements could be accepted".into(),
                },
                bounded,
            ));
            let state = match candidate.outcome {
                TrialOutcome::RecoveryRequired => State::RecoveryRequired,
                TrialOutcome::Interrupted => control.reason()?.unwrap_or(State::Interrupted),
                _ => control.reason()?.unwrap_or(State::Failed),
            };
            snapshot.pendingCandidate = Some(candidate);
            return Ok(state);
        }
        if candidate.error.is_some() {
            return Err(
                "A candidate with an unresolved error cannot supply completed measurements".into(),
            );
        }
        let measured = candidate
            .measurement
            .as_ref()
            .ok_or("Completed candidate has no measurements")?;
        validateNext(
            snapshot,
            measured,
            &snapshot.plan.comparison.candidateConfigurationSha256,
        )?;
        snapshot.pendingCandidate = Some(candidate);
        guarded(|| host.verifyOriginal(&snapshot.plan))?;
        control.check()?;
        persist(store, snapshot, State::BaselineAfter)?;
        let after = guarded(|| host.measureOriginal(control))?;
        validateNext(
            snapshot,
            &after,
            &snapshot.plan.comparison.originalConfigurationSha256,
        )?;
        let block = MatchedBlock {
            originalBefore: snapshot
                .pendingBefore
                .as_ref()
                .ok_or("Missing preceding baseline")?
                .clone(),
            candidate: snapshot
                .pendingCandidate
                .as_ref()
                .and_then(|candidate| candidate.measurement.as_ref())
                .ok_or("Missing candidate measurements")?
                .clone(),
            originalAfter: after,
        };
        comparison::validateSessions(&snapshot.plan.comparison, std::slice::from_ref(&block))?;
        snapshot.pendingBefore = None;
        snapshot.pendingCandidate = None;
        snapshot.blocks.push(block);
        snapshot.checkpoints.push(checkpointId);
        let comparison = comparison::analyze(&snapshot.plan.comparison, &snapshot.blocks)?;
        persist(store, snapshot, State::Ready)?;
        control.check()?;
        match comparison.outcome {
            comparison::Outcome::Invalid => return Ok(State::Invalid),
            comparison::Outcome::Reject => return Ok(State::Rejected),
            _ => {}
        }
    }
    Ok(State::Completed)
}

pub fn execute<H: Host>(
    store: &mut Store,
    plan: Plan,
    host: &mut H,
    cancelled: &AtomicBool,
) -> AppResult<Report> {
    plan.validate()?;
    let now = nowUnixMs()?;
    if now < plan.createdAtUnixMs || now >= plan.expiresAtUnixMs || cancelled.load(Ordering::SeqCst)
    {
        return Err(
            "Experiment is not within its authorized time budget or has been cancelled".into(),
        );
    }
    let control = Control {
        cancelled,
        expiresAtUnixMs: plan.expiresAtUnixMs,
        deadline: Instant::now() + Duration::from_millis(plan.expiresAtUnixMs - now),
        startedAtUnixMs: now,
    };
    let mut snapshot = store.begin(plan, now)?;
    let result = advance(store, &mut snapshot, host, &control);
    let (state, error) = match result {
        Ok(state) => (state, snapshot.error.clone()),
        Err(error) => (
            control.reason()?.unwrap_or(State::Failed),
            Some(bounded(error)),
        ),
    };
    let primaryError = error.clone();
    if let Err(error) = finish(store, &mut snapshot, host, state, error, &control) {
        return Err(match primaryError {
            Some(primary) => format!("{primary}; durable finalization failed: {error}"),
            None => format!("Durable finalization failed: {error}"),
        }
        .into());
    }
    let comparison = if snapshot.blocks.is_empty() {
        None
    } else {
        Some(comparison::analyze(
            &snapshot.plan.comparison,
            &snapshot.blocks,
        )?)
    };
    Ok(Report {
        snapshot,
        comparison,
    })
}

pub fn acknowledgeRecovery<H: Host>(
    store: &mut Store,
    id: &str,
    host: &mut H,
) -> AppResult<Snapshot> {
    let mut snapshot = store.load(id)?;
    if !snapshot.state.blocksNewExperiment() {
        return Err(
            "Experiment has already finished; recovery acknowledgement is not applicable".into(),
        );
    }
    guarded(|| host.verifyOriginal(&snapshot.plan))?;
    persist(store, &mut snapshot, State::Interrupted)?;
    Ok(snapshot)
}
