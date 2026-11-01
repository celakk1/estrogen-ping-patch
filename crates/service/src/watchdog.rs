use crate::{
    ServiceResult,
    journal::{Journal, MtuCheckpoint, State},
    recovery::{MtuBackend, MtuCoordinator, RecoveryResult},
};
use serde::Serialize;
use std::{
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[cfg(test)]
pub(crate) mod tests;

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub heartbeatTimeout: Duration,
    pub verificationInterval: Duration,
    pub pollInterval: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            heartbeatTimeout: Duration::from_secs(5),
            verificationInterval: Duration::from_secs(1),
            pollInterval: Duration::from_millis(100),
        }
    }
}

impl Policy {
    pub fn validate(&self) -> ServiceResult<()> {
        if !(Duration::from_millis(50)..=Duration::from_secs(30)).contains(&self.heartbeatTimeout)
            || !(Duration::from_millis(50)..=Duration::from_secs(5))
                .contains(&self.verificationInterval)
            || !(Duration::from_millis(10)..=Duration::from_millis(250))
                .contains(&self.pollInterval)
            || self.pollInterval > self.heartbeatTimeout
            || self.pollInterval > self.verificationInterval
        {
            return Err("Watchdog heartbeat, verification, or polling interval is outside its supported bounds".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Trigger {
    TrialFinished,
    UserStopped,
    ServiceStopping,
    ConnectivityLost,
    LeaseExpired,
    HeartbeatLost,
    ClockChanged,
    VerificationFailed,
    MonitorFailed,
}

struct ControlState {
    armed: bool,
    closed: bool,
    heartbeat: Instant,
    heartbeatTimeout: Duration,
    requested: Option<Trigger>,
}

struct Shared {
    state: Mutex<ControlState>,
    wake: Condvar,
}

#[derive(Clone)]
pub struct Control {
    checkpointId: Uuid,
    shared: Arc<Shared>,
}

impl Control {
    pub fn new(checkpointId: Uuid) -> ServiceResult<Self> {
        if checkpointId.is_nil() {
            return Err("Watchdog control requires one exact checkpoint identity".into());
        }
        Ok(Self {
            checkpointId,
            shared: Arc::new(Shared {
                state: Mutex::new(ControlState {
                    armed: false,
                    closed: false,
                    heartbeat: Instant::now(),
                    heartbeatTimeout: Duration::ZERO,
                    requested: None,
                }),
                wake: Condvar::new(),
            }),
        })
    }

    pub fn heartbeat(&self) -> ServiceResult<()> {
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| "Watchdog control lock failed")?;
        if !state.armed || state.closed || state.requested.is_some() {
            return Err("This watchdog session is not accepting heartbeats".into());
        }
        let now = Instant::now();
        let late = match now.checked_duration_since(state.heartbeat) {
            None => Some(Trigger::ClockChanged),
            Some(elapsed) if elapsed >= state.heartbeatTimeout => Some(Trigger::HeartbeatLost),
            _ => None,
        };
        if let Some(trigger) = late {
            state.requested = Some(trigger);
            self.shared.wake.notify_one();
            return Err("The watchdog heartbeat expired and cannot be renewed".into());
        }
        state.heartbeat = now;
        self.shared.wake.notify_one();
        Ok(())
    }

    pub fn requestRollback(&self, reason: Trigger) -> ServiceResult<()> {
        if !matches!(
            reason,
            Trigger::TrialFinished | Trigger::UserStopped | Trigger::ConnectivityLost
        ) {
            return Err("The caller cannot supply an internal watchdog trigger".into());
        }
        let mut state = self
            .shared
            .state
            .lock()
            .map_err(|_| "Watchdog control lock failed")?;
        if state.closed {
            return Err("This watchdog session has already closed".into());
        }
        if state.requested.is_none() {
            state.requested = Some(reason);
        }
        self.shared.wake.notify_one();
        Ok(())
    }

    pub(crate) fn close(&self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        self.shared.wake.notify_all();
    }
}

struct Guard {
    expiresAtUnixMs: u64,
    deadline: Instant,
    previousWall: u64,
    previousMonotonic: Instant,
}

impl Guard {
    fn new(document: &MtuCheckpoint, wall: u64, monotonic: Instant) -> ServiceResult<Self> {
        document.validate()?;
        if document.schemaVersion != 3
            || document.leaseExpiresAtUnixMs - document.createdAtUnixMs > 1_800_000
        {
            return Err(
                "Watchdog requires a tracked-process checkpoint with a lease of at most 30 minutes"
                    .into(),
            );
        }
        let deadline = monotonic
            .checked_add(Duration::from_millis(
                document.leaseExpiresAtUnixMs.saturating_sub(wall),
            ))
            .ok_or("Watchdog monotonic deadline overflow")?;
        Ok(Self {
            expiresAtUnixMs: document.leaseExpiresAtUnixMs,
            deadline,
            previousWall: document.createdAtUnixMs.max(wall),
            previousMonotonic: monotonic,
        })
    }

    fn check(
        &mut self,
        wall: u64,
        monotonic: Instant,
        heartbeat: Instant,
        timeout: Duration,
    ) -> Option<Trigger> {
        if wall < self.previousWall || monotonic < self.previousMonotonic || heartbeat > monotonic {
            return Some(Trigger::ClockChanged);
        }
        self.previousWall = wall;
        self.previousMonotonic = monotonic;
        if wall >= self.expiresAtUnixMs || monotonic >= self.deadline {
            Some(Trigger::LeaseExpired)
        } else if monotonic.duration_since(heartbeat) >= timeout {
            Some(Trigger::HeartbeatLost)
        } else {
            None
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub checkpointId: Uuid,
    pub trigger: Trigger,
    pub recovery: Option<RecoveryResult>,
    pub monitorError: Option<String>,
    pub recoveryError: Option<String>,
}

impl Report {
    pub fn originalVerified(&self) -> bool {
        self.recovery.as_ref().is_some_and(|result| {
            result.originalMtuVerified
                && result.journalFinalized
                && !result.unrelatedSettingsDrifted
                && result.durableState == State::Restored
                && result.error.is_none()
        }) && self.recoveryError.is_none()
    }
}

pub(crate) fn nowUnixMs() -> ServiceResult<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn bounded(error: impl std::fmt::Display) -> String {
    error.to_string().chars().take(1024).collect()
}

fn currentTrigger(
    control: &Control,
    serviceStop: &AtomicBool,
    guard: &mut Guard,
    heartbeatTimeout: Duration,
) -> ServiceResult<Option<Trigger>> {
    if serviceStop.load(Ordering::SeqCst) {
        return Ok(Some(Trigger::ServiceStopping));
    }
    let (heartbeat, requested) = {
        let state = control
            .shared
            .state
            .lock()
            .map_err(|_| "Watchdog control lock failed")?;
        (state.heartbeat, state.requested)
    };
    Ok(guard
        .check(nowUnixMs()?, Instant::now(), heartbeat, heartbeatTimeout)
        .or(requested))
}

fn verificationFailureTrigger(
    control: &Control,
    serviceStop: &AtomicBool,
    guard: &mut Guard,
    heartbeatTimeout: Duration,
) -> ServiceResult<Trigger> {
    Ok(
        match currentTrigger(control, serviceStop, guard, heartbeatTimeout)? {
            None | Some(Trigger::TrialFinished) => Trigger::VerificationFailed,
            Some(trigger) => trigger,
        },
    )
}

pub fn watch<B: MtuBackend>(
    journal: &mut Journal,
    backend: &mut B,
    id: Uuid,
    control: &Control,
    serviceStop: &AtomicBool,
    policy: Policy,
    armed: impl FnOnce() -> ServiceResult<()>,
) -> ServiceResult<Report> {
    if id != control.checkpointId {
        return Err("Watchdog control belongs to a different checkpoint".into());
    }
    let checkpoint = journal.load(id)?;
    if checkpoint.document().schemaVersion != 3 || checkpoint.state() != State::Applied {
        return Err("Watchdog requires one applied tracked-process checkpoint".into());
    }
    {
        let mut state = control
            .shared
            .state
            .lock()
            .map_err(|_| "Watchdog control lock failed")?;
        if state.armed || state.closed {
            return Err("Watchdog controls cannot be reused across sessions".into());
        }
        state.armed = true;
        state.heartbeat = Instant::now();
        state.heartbeatTimeout = policy.heartbeatTimeout;
    }
    let mut monitorError = None;
    let monitored = (|| -> ServiceResult<Trigger> {
        policy.validate()?;
        let mut guard = Guard::new(checkpoint.document(), nowUnixMs()?, Instant::now())?;
        let mut nextVerification = Instant::now();
        let mut armed = Some(armed);
        loop {
            if let Some(trigger) =
                currentTrigger(control, serviceStop, &mut guard, policy.heartbeatTimeout)?
            {
                if trigger == Trigger::TrialFinished {
                    if let Err(error) =
                        MtuCoordinator::new(journal, backend, nowUnixMs).verifyApplied(id)
                    {
                        monitorError = Some(bounded(error));
                        return verificationFailureTrigger(
                            control,
                            serviceStop,
                            &mut guard,
                            policy.heartbeatTimeout,
                        );
                    }
                    return Ok(currentTrigger(
                        control,
                        serviceStop,
                        &mut guard,
                        policy.heartbeatTimeout,
                    )?
                    .unwrap_or(Trigger::TrialFinished));
                }
                return Ok(trigger);
            }
            let monotonic = Instant::now();
            if monotonic >= nextVerification {
                if let Err(error) =
                    MtuCoordinator::new(journal, backend, nowUnixMs).verifyApplied(id)
                {
                    monitorError = Some(bounded(error));
                    return verificationFailureTrigger(
                        control,
                        serviceStop,
                        &mut guard,
                        policy.heartbeatTimeout,
                    );
                }
                if let Some(armed) = armed.take() {
                    armed()?;
                }
                nextVerification = Instant::now() + policy.verificationInterval;
                continue;
            }
            let state = control
                .shared
                .state
                .lock()
                .map_err(|_| "Watchdog control lock failed")?;
            drop(
                control
                    .shared
                    .wake
                    .wait_timeout(state, policy.pollInterval)
                    .map_err(|_| "Watchdog wait lock failed")?,
            );
        }
    })();
    let trigger = match monitored {
        Ok(trigger) => trigger,
        Err(error) => {
            monitorError = Some(bounded(error));
            Trigger::MonitorFailed
        }
    };
    control.close();
    let (recovery, recoveryError) =
        match MtuCoordinator::new(journal, backend, nowUnixMs).restore(id) {
            Ok(result) => (Some(result), None),
            Err(error) => (None, Some(bounded(error))),
        };
    Ok(Report {
        checkpointId: id,
        trigger,
        recovery,
        monitorError,
        recoveryError,
    })
}
