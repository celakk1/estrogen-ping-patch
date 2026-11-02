use super::*;
use crate::{
    mtu::{Snapshot, write_scope::TargetGuard},
    protocol::{CheckpointStoreStatus, RecoveryPhase, RecoveryStatus},
    storage::OwnedJournal,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};
use windows_service::service::{
    ServiceAction, ServiceActionType, ServiceFailureActions, ServiceFailureResetPeriod,
};

struct Permit;

impl Permit {
    fn attest(ownerSid: &str) -> ServiceResult<Self> {
        if security::currentSid()? != "S-1-5-18" {
            return Err(
                "Recovery-only service requires its explicit LocalSystem installation".into(),
            );
        }
        let mut session = u32::MAX;
        if unsafe {
            windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                std::process::id(),
                &mut session,
            )
        } == 0
            || session != 0
        {
            return Err("Recovery requires service session zero".into());
        }
        security::requireServiceMembership(&security::serviceSid()?)?;
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_CONFIG
                | ServiceAccess::QUERY_STATUS
                | ServiceAccess::CHANGE_CONFIG,
        )?;
        let config = service.query_config()?;
        let status = service.query_status()?;
        let executable = std::env::current_exe()?;
        let expected = format!(
            "\"{}\" --recovery-service --owner-sid {ownerSid}",
            executable.display()
        );
        if config.service_type != ServiceType::OWN_PROCESS
            || status.process_id != Some(std::process::id())
            || !isSystemAccount(config.account_name.as_deref())
            || config.executable_path.as_os_str() != std::ffi::OsStr::new(&expected)
        {
            return Err(
                "Recovery process differs from its exact SCM binary, owner, mode, account, or PID"
                    .into(),
            );
        }
        if service.get_failure_actions_on_non_crash_failures()? {
            return Err("Recovery service refuses unexpected non-crash restart policy".into());
        }
        let actions = vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(1),
            },
            ServiceAction {
                action_type: ServiceActionType::None,
                delay: Duration::ZERO,
            },
        ];
        service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(60)),
            reboot_msg: Some(OsString::new()),
            command: Some(OsString::new()),
            actions: Some(actions.clone()),
        })?;
        let actual = service.get_failure_actions()?;
        if actual.actions != Some(actions)
            || actual.command.is_some_and(|value| !value.is_empty())
            || actual.reboot_msg.is_some_and(|value| !value.is_empty())
        {
            return Err("Recovery service restart policy differs from its bounded restart-only configuration".into());
        }
        Ok(Self)
    }
}

impl TargetGuard for Permit {
    fn validateTarget(&self, snapshot: &Snapshot) -> ServiceResult<()> {
        snapshot.journalContext().map(|_| ())
    }
}

#[derive(Clone)]
pub(crate) struct Control {
    shared: Arc<Mutex<(CheckpointStoreStatus, RecoveryStatus)>>,
    stop: Arc<AtomicBool>,
}

impl Control {
    pub(crate) fn snapshot(&self) -> ServiceResult<(CheckpointStoreStatus, RecoveryStatus)> {
        Ok(self
            .shared
            .lock()
            .map_err(|_| "Recovery status is unavailable")?
            .clone())
    }
}

pub(crate) struct Worker {
    control: Control,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub(crate) fn start(ownerSid: &str, mut journal: OwnedJournal) -> ServiceResult<Self> {
        let permit = Permit::attest(ownerSid)?;
        let control = Control {
            shared: Arc::new(Mutex::new((
                journal.status.clone(),
                RecoveryStatus {
                    phase: RecoveryPhase::Running,
                    verifiedCount: 0,
                    detail: None,
                },
            ))),
            stop: Arc::new(AtomicBool::new(false)),
        };
        let worker = control.clone();
        let thread = std::thread::Builder::new().name("network-recovery".into()).spawn(move || {
            let outcome = catch_unwind(AssertUnwindSafe(|| -> ServiceResult<(CheckpointStoreStatus, u32, Option<String>)> {
                let results = crate::recovery::native::restorePending(journal.journal(), &permit, &worker.stop)?;
                let status = CheckpointStoreStatus::fromJournal(journal.journal(), transport::nowUnixMs()?)?;
                let verified = results.iter().filter(|result| result.originalMtuVerified && result.journalFinalized
                    && result.error.is_none() && result.policyOriginalVerified != Some(false)
                    && result.policyVerificationRecorded != Some(false)).count().try_into()?;
                let detail = results.iter().find_map(|result| result.error.as_ref()).map(|error| error.chars().take(256).collect());
                Ok((status, verified, detail))
            }));
            let mut shared = worker.shared.lock().unwrap_or_else(|error| error.into_inner());
            match outcome {
                Ok(Ok((status, verified, detail))) => {
                    shared.1.phase = if status.pendingRecoveryCount == 0 { RecoveryPhase::Completed } else { RecoveryPhase::RecoveryRequired };
                    shared.1.verifiedCount = verified;
                    shared.1.detail = if status.pendingRecoveryCount > 0 { Some(detail.unwrap_or_else(|| "Some original settings or final checks still need recovery. Preserve the journal; restart the service to retry.".into())) } else { None };
                    shared.0 = status;
                }
                failure => {
                    let detail = match failure { Ok(Err(error)) => error.to_string(), _ => "Recovery worker stopped unexpectedly; preserve the journal and restart the service to retry".into() };
                    shared.1.phase = RecoveryPhase::RecoveryRequired;
                    shared.1.detail = Some(detail.chars().take(256).collect());
                    reportFailure(shared.1.detail.as_deref().unwrap_or("Recovery failed"));
                }
            }
        })?;
        Ok(Self {
            control,
            thread: Some(thread),
        })
    }

    pub(crate) fn control(&self) -> Control {
        self.control.clone()
    }

    pub(crate) fn finish(&mut self, handle: ServiceStatusHandle) -> ServiceResult<()> {
        self.control.stop.store(true, Ordering::SeqCst);
        let mut checkpoint = 1u32;
        if let Some(thread) = &self.thread {
            while !thread.is_finished() {
                checkpoint = checkpoint.saturating_add(1);
                setStateProgress(handle, ServiceState::StopPending, false, checkpoint)?;
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        if let Some(thread) = self.thread.take() {
            thread.join().map_err(|_| "Recovery worker join failed")?;
        }
        Ok(())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.control.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactiveProcessCannotObtainRecoveryAuthority() {
        assert!(Permit::attest("S-1-5-21-1-2-3-1000").is_err());
    }
}
