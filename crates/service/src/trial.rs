use crate::{
    ServiceResult,
    journal::{Journal, MtuCheckpoint, State},
    recovery::{ApplyResult, MtuBackend, MtuCoordinator, RecoveryResult},
    watchdog::{self, Control, Policy, Trigger, nowUnixMs},
};
use serde::Serialize;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Duration,
};
use uuid::Uuid;

#[cfg(test)]
mod tests;

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    Completed,
    ApplyFailed,
    Interrupted,
    MeasurementFailed,
    RecoveryRequired,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report<T> {
    pub checkpointId: Uuid,
    pub outcome: Outcome,
    pub measurement: Option<T>,
    pub watchdog: Option<watchdog::Report>,
    pub recovery: Option<RecoveryResult>,
    pub error: Option<String>,
}

fn bounded(error: impl std::fmt::Display) -> String {
    error.to_string().chars().take(1024).collect()
}

fn cleanRecovery(result: &RecoveryResult) -> bool {
    result.journalFinalized
        && result.error.is_none()
        && !result.unrelatedSettingsDrifted
        && (result.durableState == State::Cancelled
            || (result.originalMtuVerified && result.durableState == State::Restored))
}

fn recover<B: MtuBackend>(
    journal: &mut Journal,
    backend: &mut B,
    id: Uuid,
) -> Result<RecoveryResult, String> {
    catch_unwind(AssertUnwindSafe(|| {
        MtuCoordinator::new(journal, backend, nowUnixMs).restore(id)
    }))
    .map_err(|_| {
        "Recovery worker panicked; preserved checkpoint requires investigation".to_string()
    })?
    .map_err(bounded)
}

fn failed<T, B: MtuBackend>(
    journal: &mut Journal,
    backend: &mut B,
    id: Uuid,
    error: String,
    outcome: Outcome,
) -> Report<T> {
    let (recovery, recoveryError) = match recover(journal, backend, id) {
        Ok(result) => (Some(result), None),
        Err(error) => (None, Some(error)),
    };
    Report {
        checkpointId: id,
        outcome: if recovery.as_ref().is_some_and(cleanRecovery) {
            outcome
        } else {
            Outcome::RecoveryRequired
        },
        measurement: None,
        watchdog: None,
        recovery,
        error: Some(match recoveryError {
            Some(recoveryError) => bounded(format!("{error}; recovery: {recoveryError}")),
            None => error,
        }),
    }
}

pub fn execute<T, B: MtuBackend + Send>(
    journal: &mut Journal,
    backend: &mut B,
    document: MtuCheckpoint,
    serviceStop: &AtomicBool,
    policy: Policy,
    collect: impl FnOnce(&Control) -> ServiceResult<T>,
) -> ServiceResult<Report<T>> {
    policy.validate()?;
    document.validate()?;
    if !matches!(document.schemaVersion, 3 | 4)
        || document.leaseExpiresAtUnixMs - document.createdAtUnixMs > 1_800_000
    {
        return Err(
            "Automatic trials require a tracked checkpoint and a lease of at most thirty minutes"
                .into(),
        );
    }
    if serviceStop.load(Ordering::SeqCst)
        || !journal.pendingRecovery()?.is_empty()
        || !journal.pendingPolicyVerification()?.is_empty()
    {
        return Err(
            "Automatic trials require a running service with no unresolved checkpoints".into(),
        );
    }
    let id = document.id;
    let control = Control::new(id)?;
    let prepared = catch_unwind(AssertUnwindSafe(|| {
        MtuCoordinator::new(journal, backend, nowUnixMs).prepare(document)
    }));
    match prepared {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            return Ok(
                if journal
                    .pendingRecovery()
                    .is_ok_and(|pending| pending.is_empty())
                {
                    Report {
                        checkpointId: id,
                        outcome: Outcome::ApplyFailed,
                        measurement: None,
                        watchdog: None,
                        recovery: None,
                        error: Some(bounded(error)),
                    }
                } else {
                    failed(journal, backend, id, bounded(error), Outcome::ApplyFailed)
                },
            );
        }
        Err(_) => {
            return Ok(failed(
                journal,
                backend,
                id,
                "Checkpoint preparation panicked".into(),
                Outcome::ApplyFailed,
            ));
        }
    };
    let applied = catch_unwind(AssertUnwindSafe(|| {
        MtuCoordinator::new(journal, backend, nowUnixMs).apply(id)
    }));
    match applied {
        Ok(Ok(ApplyResult::Applied { .. })) => {}
        Ok(Ok(ApplyResult::Failed { recovery, error })) => {
            return Ok(Report {
                checkpointId: id,
                outcome: if cleanRecovery(&recovery) {
                    Outcome::ApplyFailed
                } else {
                    Outcome::RecoveryRequired
                },
                measurement: None,
                watchdog: None,
                recovery: Some(recovery),
                error: Some(error),
            });
        }
        Ok(Err(error)) => {
            return Ok(failed(
                journal,
                backend,
                id,
                bounded(error),
                Outcome::ApplyFailed,
            ));
        }
        Err(_) => {
            return Ok(failed(
                journal,
                backend,
                id,
                "Setting worker panicked before trial completion".into(),
                Outcome::ApplyFailed,
            ));
        }
    }
    let (watched, measurement, measurementError) = std::thread::scope(|scope| {
        let (readySender, readyReceiver) = mpsc::sync_channel(1);
        let journalRef = &mut *journal;
        let backendRef = &mut *backend;
        let workerControl = &control;
        let worker = scope.spawn(move || {
            watchdog::watch(
                journalRef,
                backendRef,
                id,
                workerControl,
                serviceStop,
                policy,
                || {
                    readySender
                        .send(())
                        .map_err(|_| "Measurement worker left before watchdog readiness".into())
                },
            )
        });
        let collected = match readyReceiver.recv_timeout(Duration::from_secs(5)) {
            Ok(()) => catch_unwind(AssertUnwindSafe(|| collect(&control)))
                .map_err(|_| "Measurement worker panicked".to_string())
                .and_then(|result| result.map_err(bounded)),
            Err(_) => {
                Err("Watchdog did not authorize measurement startup within five seconds".into())
            }
        };
        let (measurement, measurementError) = match collected {
            Ok(value) => (Some(value), None),
            Err(error) => (None, Some(error)),
        };
        let _ = control.requestRollback(if measurementError.is_some() {
            Trigger::UserStopped
        } else {
            Trigger::TrialFinished
        });
        let watched = worker
            .join()
            .map_err(|_| "Watchdog worker panicked".to_string())
            .and_then(|result| result.map_err(bounded));
        (watched, measurement, measurementError)
    });
    control.close();
    let watched = match watched {
        Ok(report) => report,
        Err(error) => return Ok(failed(journal, backend, id, error, Outcome::Interrupted)),
    };
    let outcome = if !watched.originalVerified() {
        Outcome::RecoveryRequired
    } else if measurementError.is_some() {
        Outcome::MeasurementFailed
    } else if watched.trigger != Trigger::TrialFinished || watched.monitorError.is_some() {
        Outcome::Interrupted
    } else {
        Outcome::Completed
    };
    Ok(Report {
        checkpointId: id,
        outcome,
        measurement,
        watchdog: Some(watched),
        recovery: None,
        error: measurementError,
    })
}
