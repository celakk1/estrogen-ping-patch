use crate::{
    ServiceResult,
    journal::{Journal, MtuCheckpoint},
    mtu::Snapshot,
    recovery::MtuBackend,
    trial,
    watchdog::{self, nowUnixMs},
};
use epp_core::{
    comparison::Session,
    experiment::{CandidateResult, Control, Host, Plan, TrialOutcome},
};
use std::sync::atomic::{AtomicBool, Ordering};

pub mod baseline;
pub mod load;
mod measurement;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Configuration {
    Original,
    Candidate,
}

pub struct Progress<'a, 'b> {
    experiment: &'a Control<'b>,
    watchdog: Option<&'a watchdog::Control>,
    serviceStop: &'a AtomicBool,
}

impl Progress<'_, '_> {
    pub fn check(&self) -> ServiceResult<()> {
        self.experiment.check()?;
        if self.serviceStop.load(Ordering::SeqCst) {
            return Err("Service shutdown interrupted experiment measurements".into());
        }
        if let Some(watchdog) = self.watchdog {
            watchdog.heartbeat()?;
        }
        Ok(())
    }
}

pub trait Measurements {
    fn bindCheckpoint(&mut self, _: Option<&MtuCheckpoint>) -> ServiceResult<()> {
        Ok(())
    }
    fn maximumTraffic(
        &self,
    ) -> ServiceResult<std::collections::BTreeMap<String, epp_core::experiment::budget::Resources>>;
    fn verifyEnvironment(&mut self, plan: &Plan, original: &Snapshot) -> ServiceResult<()>;
    fn collect(
        &mut self,
        configuration: Configuration,
        progress: &Progress<'_, '_>,
    ) -> ServiceResult<Session>;
}

pub struct MtuHost<'a, B, M, F> {
    journal: &'a mut Journal,
    backend: &'a mut B,
    template: MtuCheckpoint,
    policy: watchdog::Policy,
    serviceStop: &'a AtomicBool,
    measurements: M,
    issueCheckpoint: F,
    plan: Option<Plan>,
    lastCheckpoint: Option<uuid::Uuid>,
}

impl<'a, B: MtuBackend + Send, M: Measurements, F> MtuHost<'a, B, M, F>
where
    F: FnMut(&mut B, &Snapshot, &Plan) -> ServiceResult<MtuCheckpoint>,
{
    pub fn new(
        journal: &'a mut Journal,
        backend: &'a mut B,
        template: MtuCheckpoint,
        policy: watchdog::Policy,
        serviceStop: &'a AtomicBool,
        measurements: M,
        issueCheckpoint: F,
    ) -> ServiceResult<Self> {
        template.validate()?;
        policy.validate()?;
        if !matches!(template.schemaVersion, 3 | 4) {
            return Err(
                "Repeated MTU trials require a tracked native original checkpoint template".into(),
            );
        }
        Ok(Self {
            journal,
            backend,
            template,
            policy,
            serviceStop,
            measurements,
            issueCheckpoint,
            plan: None,
            lastCheckpoint: None,
        })
    }

    fn original(&mut self) -> ServiceResult<Snapshot> {
        if !self.journal.pendingRecovery()?.is_empty()
            || !self.journal.pendingPolicyVerification()?.is_empty()
        {
            return Err("Unresolved native recovery blocks the repeated experiment".into());
        }
        if let Some(id) = self.lastCheckpoint {
            for record in self.journal.mutators(id)? {
                self.backend.waitForMutator(&record)?;
            }
        }
        let original = self
            .template
            .nativeOriginal
            .as_ref()
            .ok_or("Missing native original")?;
        let observed = self.backend.observe(&self.template)?;
        let native = observed
            .native
            .ok_or("Original verification has no native observation")?;
        native.validateMtuObservation(original)?;
        let now = nowUnixMs()?;
        if observed.context != self.template.context
            || observed.addressFamily != self.template.addressFamily
            || observed.mtu != self.template.originalMtu
            || native.settings != original.settings
            || native.operationalStatus != 1
            || native.mediaConnectState != 1
            || native.capturedAtUnixMs > now.saturating_add(250)
            || now.saturating_sub(native.capturedAtUnixMs) > 5000
        {
            return Err(
                "Original MTU, native context, link state, settings, or readback freshness changed"
                    .into(),
            );
        }
        Ok(native)
    }
}

impl<B: MtuBackend + Send, M: Measurements, F> Host for MtuHost<'_, B, M, F>
where
    F: FnMut(&mut B, &Snapshot, &Plan) -> ServiceResult<MtuCheckpoint>,
{
    fn maximumTraffic(
        &self,
    ) -> ServiceResult<std::collections::BTreeMap<String, epp_core::experiment::budget::Resources>>
    {
        self.measurements.maximumTraffic()
    }

    fn verifyOriginal(&mut self, plan: &Plan) -> ServiceResult<()> {
        let original = self.original()?;
        self.measurements.verifyEnvironment(plan, &original)?;
        self.plan = Some(plan.clone());
        Ok(())
    }

    fn measureOriginal(&mut self, control: &Control<'_>) -> ServiceResult<Session> {
        self.measurements.bindCheckpoint(None)?;
        let progress = Progress {
            experiment: control,
            watchdog: None,
            serviceStop: self.serviceStop,
        };
        progress.check()?;
        let measured = self
            .measurements
            .collect(Configuration::Original, &progress)?;
        progress.check()?;
        Ok(measured)
    }

    fn measureCandidate(&mut self, control: &Control<'_>) -> ServiceResult<CandidateResult> {
        control.check()?;
        let plan = self
            .plan
            .clone()
            .ok_or("Original environment has not been verified")?;
        self.verifyOriginal(&plan)?;
        let original = self.original()?;
        let document = (self.issueCheckpoint)(self.backend, &original, &plan)?;
        document.validate()?;
        if document.schemaVersion != self.template.schemaVersion
            || document.context != self.template.context
            || document.addressFamily != self.template.addressFamily
            || document.authorizedUserSid != self.template.authorizedUserSid
            || document.originalMtu != self.template.originalMtu
            || document.proposedMtu != self.template.proposedMtu
            || document.leaseExpiresAtUnixMs > plan.expiresAtUnixMs
            || document
                .nativeOriginal
                .as_ref()
                .is_none_or(|native| native != &original)
        {
            return Err("Issued checkpoint differs from the exact repeated-trial scope or fresh original evidence".into());
        }
        control.check()?;
        self.measurements.bindCheckpoint(Some(&document))?;
        let stopped = AtomicBool::new(self.serviceStop.load(Ordering::SeqCst));
        let finished = AtomicBool::new(false);
        struct Finish<'a>(&'a AtomicBool);
        impl Drop for Finish<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let result = std::thread::scope(|scope| {
            let _finish = Finish(&finished);
            let serviceStop = self.serviceStop;
            let finishedRef = &finished;
            let stoppedRef = &stopped;
            scope.spawn(move || {
                while !finishedRef.load(Ordering::SeqCst) {
                    if serviceStop.load(Ordering::SeqCst) || control.check().is_err() {
                        stoppedRef.store(true, Ordering::SeqCst);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            });
            let measurements = &mut self.measurements;
            trial::execute(
                self.journal,
                self.backend,
                document,
                &stopped,
                self.policy,
                |watchdog| {
                    let progress = Progress {
                        experiment: control,
                        watchdog: Some(watchdog),
                        serviceStop,
                    };
                    progress.check()?;
                    let session = measurements.collect(Configuration::Candidate, &progress)?;
                    progress.check()?;
                    Ok(session)
                },
            )
        })?;
        if result.watchdog.is_some() || result.recovery.is_some() {
            self.lastCheckpoint = Some(result.checkpointId);
        }
        let error = if result.outcome == trial::Outcome::Completed {
            None
        } else {
            let watched = result.watchdog.as_ref();
            let details = [
                watched.and_then(|report| report.recoveryError.as_deref()),
                watched
                    .and_then(|report| report.recovery.as_ref())
                    .and_then(|recovery| recovery.error.as_deref()),
                result
                    .recovery
                    .as_ref()
                    .and_then(|recovery| recovery.error.as_deref()),
                watched.and_then(|report| report.monitorError.as_deref()),
                result.error.as_deref(),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            let detail = if details.is_empty() {
                match result.outcome {
                    trial::Outcome::RecoveryRequired => "Original settings could not be fully verified; recover the recorded checkpoint before another trial".into(),
                    trial::Outcome::Interrupted => match watched.map(|report| report.trigger) {
                        Some(watchdog::Trigger::HeartbeatLost) => "Measurements stopped reporting progress, so the temporary trial was stopped",
                        Some(watchdog::Trigger::LeaseExpired) => "The temporary trial reached its time limit",
                        Some(watchdog::Trigger::ClockChanged) => "The system clock changed during the temporary trial",
                        Some(watchdog::Trigger::ConnectivityLost) => "The connection stopped responding during the temporary trial",
                        Some(watchdog::Trigger::VerificationFailed) => "The candidate setting or its permission changed during the temporary trial",
                        _ => "The temporary trial stopped before all measurements finished",
                    }.into(),
                    _ => "Temporary trial failed before its measurements could be accepted".into(),
                }
            } else {
                details.join("; ")
            };
            Some(detail.chars().take(1024).collect())
        };
        Ok(CandidateResult {
            checkpointId: result.checkpointId.to_string(),
            outcome: match result.outcome {
                trial::Outcome::Completed => TrialOutcome::Completed,
                trial::Outcome::Interrupted => TrialOutcome::Interrupted,
                trial::Outcome::RecoveryRequired => TrialOutcome::RecoveryRequired,
                _ => TrialOutcome::Failed,
            },
            measurement: result.measurement,
            error,
        })
    }
}
