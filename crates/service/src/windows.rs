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
    let ownerSid = security::canonicalSid(&ownerSid)?;
    OWNER_SID
        .set(ownerSid)
        .map_err(|_| "Service entry was already initialized")?;
    service_dispatcher::start(SERVICE_NAME, serviceEntry)?;
    Ok(())
}

static OWNER_SID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub(crate) fn setState(
    handle: ServiceStatusHandle,
    state: ServiceState,
    failed: bool,
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
            1
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
        if security::currentSid()? != SERVICE_ACCOUNT_SID {
            return Err("The service must run as NT AUTHORITY\\LocalService".into());
        }
        let ownerSid = OWNER_SID
            .get()
            .ok_or("Missing authorized user SID")?
            .clone();
        let serviceSid = security::serviceSid()?;
        let journal = storage::open(&serviceSid)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let pipe = transport::createServer(PIPE_NAME, &ownerSid, &serviceSid, true)?;
            setState(handle, ServiceState::Running, false)?;
            let result = transport::serve(
                pipe,
                PIPE_NAME.into(),
                ownerSid,
                serviceSid,
                receiver,
                journal.status.clone(),
            )
            .await;
            setState(handle, ServiceState::StopPending, result.is_err())?;
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
    let text: Vec<u16> = format!("Dedicated service stopped: {message}")
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
    if config.service_type != ServiceType::OWN_PROCESS
        || !config.account_name.as_ref().is_some_and(|account| {
            account
                .to_string_lossy()
                .eq_ignore_ascii_case(r"NT AUTHORITY\LocalService")
        })
    {
        return Err("Registered service has an unexpected account or process type".into());
    }
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
    let pending = response.checkpointStore.pendingRecoveryCount;
    let (state, detail) = if pending > 0 {
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
