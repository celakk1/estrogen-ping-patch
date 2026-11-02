use crate::{
    PIPE_NAME, SERVICE_ACCOUNT_SID, SERVICE_NAME, ServiceReport, ServiceResult, security, storage,
    transport,
};
use std::{ffi::OsString, time::Duration};
use tokio::sync::watch;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

define_windows_service!(serviceEntry, serviceMain);

pub fn run(ownerSid: String) -> ServiceResult<()> {
    runMode(ownerSid, Mode::ReadOnly)
}

#[cfg(feature = "native-recovery")]
pub(crate) mod recovery_worker;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    ReadOnly,
    RecoveryOnly,
}

struct Entry {
    ownerSid: String,
    mode: Mode,
}

#[cfg(feature = "native-recovery")]
pub fn runRecovery(ownerSid: String) -> ServiceResult<()> {
    runMode(ownerSid, Mode::RecoveryOnly)
}

fn runMode(ownerSid: String, mode: Mode) -> ServiceResult<()> {
    let ownerSid = security::canonicalSid(&ownerSid)?;
    ENTRY
        .set(Entry { ownerSid, mode })
        .map_err(|_| "Service entry was already initialized")?;
    service_dispatcher::start(SERVICE_NAME, serviceEntry)?;
    Ok(())
}

static ENTRY: std::sync::OnceLock<Entry> = std::sync::OnceLock::new();

fn isSystemAccount(account: Option<&std::ffi::OsStr>) -> bool {
    account.is_some_and(|account| {
        let text = account.to_string_lossy();
        text.eq_ignore_ascii_case("LocalSystem")
            || text.eq_ignore_ascii_case(r"NT AUTHORITY\SYSTEM")
    })
}

fn registeredMode(config: &windows_service::service::ServiceConfig) -> ServiceResult<Mode> {
    registrationMode(
        config.service_type,
        config.account_name.as_deref(),
        &config.executable_path.to_string_lossy(),
    )
}

fn registrationMode(
    serviceType: ServiceType,
    account: Option<&std::ffi::OsStr>,
    command: &str,
) -> ServiceResult<Mode> {
    if serviceType != ServiceType::OWN_PROCESS {
        return Err("Registered service has an unexpected process type".into());
    }
    let localService = account.is_some_and(|account| {
        account
            .to_string_lossy()
            .eq_ignore_ascii_case(r"NT AUTHORITY\LocalService")
    });
    if localService && validServiceCommand(command, "--service") {
        return Ok(Mode::ReadOnly);
    }
    if isSystemAccount(account) && validServiceCommand(command, "--recovery-service") {
        return Ok(Mode::RecoveryOnly);
    }
    Err("Registered service has an unexpected account or recovery command".into())
}

fn validServiceCommand(command: &str, mode: &str) -> bool {
    command
        .rsplit_once(&format!(" {mode} --owner-sid "))
        .is_some_and(|(binary, owner)| {
            let Some(binary) = binary
                .strip_prefix('"')
                .and_then(|binary| binary.strip_suffix('"'))
            else {
                return false;
            };
            !binary.contains('"')
                && std::path::Path::new(binary).is_absolute()
                && security::canonicalSid(owner).is_ok()
        })
}

enum ServiceWorker {
    Preview(crate::preview::Worker),
    #[cfg(feature = "native-recovery")]
    Recovery(recovery_worker::Worker),
}

impl ServiceWorker {
    fn state(
        &self,
        checkpointStore: crate::protocol::CheckpointStoreStatus,
    ) -> transport::ServerState {
        match self {
            Self::Preview(worker) => {
                transport::ServerState::readOnly(checkpointStore, Some(worker.control()))
            }
            #[cfg(feature = "native-recovery")]
            Self::Recovery(worker) => {
                transport::ServerState::recovery(checkpointStore, worker.control())
            }
        }
    }

    fn finish(&mut self, _handle: ServiceStatusHandle) -> ServiceResult<()> {
        #[cfg(feature = "native-recovery")]
        if let Self::Recovery(worker) = self {
            worker.finish(_handle)?;
        }
        Ok(())
    }
}

pub(crate) fn setState(
    handle: ServiceStatusHandle,
    state: ServiceState,
    failed: bool,
) -> ServiceResult<()> {
    setStateProgress(handle, state, failed, 1)
}

fn setStateProgress(
    handle: ServiceStatusHandle,
    state: ServiceState,
    failed: bool,
    checkpoint: u32,
) -> ServiceResult<()> {
    handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: if failed {
            ServiceExitCode::ServiceSpecific(1)
        } else {
            ServiceExitCode::Win32(0)
        },
        checkpoint: if matches!(
            state,
            ServiceState::StartPending | ServiceState::StopPending
        ) {
            checkpoint
        } else {
            0
        },
        wait_hint: if matches!(
            state,
            ServiceState::StartPending | ServiceState::StopPending
        ) {
            Duration::from_secs(10)
        } else {
            Duration::ZERO
        },
        process_id: None,
    })?;
    Ok(())
}

fn serviceMain(_arguments: Vec<OsString>) {
    if let Err(error) = serviceLoop() {
        reportFailure(&error.to_string());
    }
}

fn serviceLoop() -> ServiceResult<()> {
    let (stop, receiver) = watch::channel(false);
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop.send(true);
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    setState(handle, ServiceState::StartPending, false)?;
    let result = (|| {
        let entry = ENTRY.get().ok_or("Missing service entry configuration")?;
        if matches!(entry.mode, Mode::ReadOnly) && security::currentSid()? != SERVICE_ACCOUNT_SID {
            return Err("The service must run as NT AUTHORITY\\LocalService".into());
        }
        let ownerSid = entry.ownerSid.clone();
        let serviceSid = security::serviceSid()?;
        let journal = storage::open(&serviceSid)?;
        let checkpointStore = journal.status.clone();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let pipe = transport::createServer(PIPE_NAME, &ownerSid, &serviceSid, true)?;
            setState(handle, ServiceState::Running, false)?;
            let mut worker = match entry.mode {
                Mode::ReadOnly => {
                    ServiceWorker::Preview(crate::preview::Worker::start(&ownerSid, journal)?)
                }
                Mode::RecoveryOnly => {
                    #[cfg(feature = "native-recovery")]
                    {
                        ServiceWorker::Recovery(recovery_worker::Worker::start(&ownerSid, journal)?)
                    }
                    #[cfg(not(feature = "native-recovery"))]
                    {
                        return Err("This service build does not include native recovery".into());
                    }
                }
            };
            let result = transport::serve(
                pipe,
                PIPE_NAME.into(),
                ownerSid,
                serviceSid,
                receiver,
                worker.state(checkpointStore),
            )
            .await;
            setState(handle, ServiceState::StopPending, result.is_err())?;
            worker.finish(handle)?;
            result
        })
    })();
    setState(handle, ServiceState::Stopped, result.is_err())?;
    result
}

fn reportFailure(message: &str) {
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_ERROR_TYPE, RegisterEventSourceW, ReportEventW,
    };
    let source: Vec<u16> = SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let text: Vec<u16> = format!("Dedicated service: {message}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        let handle = RegisterEventSourceW(std::ptr::null(), source.as_ptr());
        if !handle.is_null() {
            ReportEventW(
                handle,
                EVENTLOG_ERROR_TYPE,
                0,
                1,
                std::ptr::null_mut(),
                1,
                0,
                &text.as_ptr(),
                std::ptr::null(),
            );
            DeregisterEventSource(handle);
        }
    }
}

pub async fn inspect() -> ServiceResult<ServiceReport> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => return Ok(ServiceReport {state:"notInstalled".into(),detail:"The optional dedicated Windows service is not installed. Network changes remain disabled.".into(),response:None}),
        Err(error) => return Err(error.into()),
    };
    let config = service.query_config()?;
    let mode = registeredMode(&config)?;
    let status = service.query_status()?;
    if status.current_state != ServiceState::Running {
        return Ok(ServiceReport {state:format!("{:?}", status.current_state).to_lowercase(),detail:"Dedicated service is installed but is not running. Use service management to start it.".into(),response:None});
    }
    let pid = status
        .process_id
        .filter(|pid| *pid != 0)
        .ok_or("Running service has no process identifier")?;
    let response = transport::query(PIPE_NAME, pid, 0).await.map_err(|error| {
        format!("The registered service did not answer the current protocol: {error}. If updating an older preview, use uninstall-service.bat and then install-service.bat to update it.")
    })?;
    let confirmed = service.query_status()?;
    if confirmed.current_state != ServiceState::Running || confirmed.process_id != Some(pid) {
        return Err("Service identity changed during the request; retry status".into());
    }
    if registeredMode(&service.query_config()?)? != mode
        || response.mode
            != match mode {
                Mode::ReadOnly => "readOnly",
                Mode::RecoveryOnly => "recoveryOnly",
            }
    {
        return Err("Service mode or account changed during the request".into());
    }
    let pending = response.checkpointStore.pendingRecoveryCount;
    let (state, detail) = if let Some(recovery) = &response.recovery {
        use crate::protocol::RecoveryPhase;
        match recovery.phase {
            RecoveryPhase::Running => ("recovering", format!("The service is checking {pending} pending recovery record(s). Keep the service running while it restores saved originals and verifies them. Candidate changes remain disabled.")),
            RecoveryPhase::Completed => ("ready", format!("Recovery-only service finished with no pending records; {} recovery result(s) verified. Candidate changes remain disabled.", recovery.verifiedCount)),
            RecoveryPhase::RecoveryRequired => ("recoveryRequired", recovery.detail.clone().unwrap_or_else(|| format!("{pending} recovery record(s) still need attention. Preserve the journal and restart the service to retry."))),
        }
    } else if pending > 0 {
        (
            "recoveryRequired",
            format!(
                "The read-only service found {pending} network recovery record(s) needing attention. Restoring a setting and completing its final verification are separate checks. Preserve the recovery journal for investigation. Automatic restoration and network changes remain disabled."
            ),
        )
    } else {
        ("ready", "Authenticated LocalService process; recovery journal verified at service startup. Network changes and restoration remain disabled.".into())
    };
    Ok(ServiceReport {
        state: state.into(),
        detail,
        response: Some(response),
    })
}

pub fn identity() -> ServiceResult<String> {
    security::currentSid()
}

pub fn inspectBlocking() -> ServiceResult<ServiceReport> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(inspect())
}

pub fn previewBlocking(
    operation: crate::protocol::Operation,
) -> ServiceResult<crate::preview::Report> {
    let expectedJobId = match &operation {
        crate::protocol::Operation::GetStatus => {
            return Err("Expected an MTU preview operation".into());
        }
        crate::protocol::Operation::StartMtuPreview(_) => None,
        crate::protocol::Operation::GetMtuPreview { jobId }
        | crate::protocol::Operation::ApproveMtuPreview { jobId, .. }
        | crate::protocol::Operation::CancelMtuPreview { jobId } => Some(*jobId),
    };
    let before = inspectBlocking()?;
    let status = before.response.ok_or(
        "The dedicated service must be installed and running before reviewing an MTU trial",
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let reply = runtime.block_on(transport::exchange(
        PIPE_NAME,
        status.servicePid,
        0,
        operation,
    ))?;
    let after = inspectBlocking()?;
    if after
        .response
        .as_ref()
        .is_none_or(|confirmed| confirmed.servicePid != status.servicePid)
    {
        return Err("Service identity changed during the MTU preview request".into());
    }
    match reply.result {
        crate::protocol::ReplyBody::MtuPreview(report) => {
            report.validate()?;
            if expectedJobId.is_some_and(|expected| expected != report.jobId) {
                return Err("Service returned another MTU preview job".into());
            }
            Ok(report)
        }
        crate::protocol::ReplyBody::Rejected { detail } => Err(detail.into()),
        _ => Err("Service returned an unexpected or unsafe MTU preview response".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn systemRecoveryRequiresItsExactModeAndCanonicalOwnerCommand() {
        let system = Some(OsStr::new("LocalSystem"));
        let localService = Some(OsStr::new(r"NT AUTHORITY\LocalService"));
        let recovery = r#""C:\Program Files\estrogen ping patch service\epp-network-service.exe" --recovery-service --owner-sid S-1-5-21-1-2-3-1000"#;
        let normal = recovery.replace("--recovery-service", "--service");
        assert_eq!(
            registrationMode(ServiceType::OWN_PROCESS, system, recovery).unwrap(),
            Mode::RecoveryOnly
        );
        assert_eq!(
            registrationMode(ServiceType::OWN_PROCESS, localService, &normal).unwrap(),
            Mode::ReadOnly
        );
        assert!(registrationMode(ServiceType::OWN_PROCESS, system, &normal).is_err());
        assert!(registrationMode(ServiceType::OWN_PROCESS, localService, recovery).is_err());
        assert!(registrationMode(ServiceType::SHARE_PROCESS, system, recovery).is_err());
        assert!(registrationMode(ServiceType::OWN_PROCESS, None, recovery).is_err());
        for command in [
            recovery.replace(" --owner-sid ", " "),
            format!("{recovery} --extra"),
            recovery.replace("S-1-5-21-1-2-3-1000", "not-a-sid"),
            recovery.trim_start_matches('"').into(),
            recovery.replace(r"C:\Program Files\estrogen ping patch service\", ""),
        ] {
            assert!(
                registrationMode(ServiceType::OWN_PROCESS, system, &command).is_err(),
                "{command}"
            );
        }
    }
}
