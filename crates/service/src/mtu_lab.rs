use crate::{
    ServiceResult,
    journal::{AddressFamily, MtuCheckpoint, Observation},
    mtu::{self, DriverContext, Snapshot},
    recovery::{ApplyResult, AuthorizationAction, MtuBackend, MtuCoordinator, WritePurpose},
    security, storage,
    transport::nowUnixMs,
};
use serde_json::json;
use std::{
    ffi::OsString,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use uuid::Uuid;
use windows_service::{
    define_windows_service,
    service::{ServiceAccess, ServiceControl, ServiceState, ServiceType},
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

pub const LAB_SERVICE_NAME: &str = "EstrogenPingPatchMtuLab";
const LAB_DEADLINE: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq)]
enum Phase {
    Apply,
    Restore,
    Complete,
    Revoke,
    AuthorizationUnavailable,
}

struct Config {
    ownerSid: String,
    guid: Uuid,
    family: AddressFamily,
    phase: Phase,
    trialId: Uuid,
}
static CONFIG: OnceLock<Config> = OnceLock::new();
define_windows_service!(labEntry, labMain);

pub(crate) struct ServicePermit {
    guid: Uuid,
    family: AddressFamily,
}

impl ServicePermit {
    pub(crate) fn validateTarget(&self, snapshot: &Snapshot) -> ServiceResult<()> {
        snapshot.journalContext()?;
        let DriverContext::Captured { identity } = &snapshot.driver else {
            return Err("Native lab requires complete driver evidence".into());
        };
        if snapshot.adapterGuid != self.guid
            || snapshot.addressFamily != self.family
            || snapshot.alias != format!("epp-mtu-lab-{}", self.guid)
            || snapshot.interfaceType != 6
            || snapshot.tunnelType != 0
            || !identity.infPath.eq_ignore_ascii_case("netloop.inf")
            || !identity
                .deviceInstanceId
                .to_ascii_uppercase()
                .starts_with("ROOT\\NET\\")
        {
            return Err("Native lab refuses any target other than its GUID-bound Microsoft loopback adapter".into());
        }
        Ok(())
    }
}

fn config(arguments: &[String]) -> ServiceResult<Config> {
    let [ownerSid, guid, family, phase, trialId] = arguments else {
        return Err(
            "Native lab service requires SID GUID ipv4|ipv6 complete|apply|restore|revoke|authorization-unavailable TRIAL_ID".into(),
        );
    };
    let guid = Uuid::parse_str(guid)?;
    let trialId = Uuid::parse_str(trialId)?;
    if guid.is_nil() || trialId.is_nil() {
        return Err("Native lab identities cannot be nil".into());
    }
    Ok(Config {
        ownerSid: security::canonicalSid(ownerSid)?,
        guid,
        trialId,
        family: match family.as_str() {
            "ipv4" => AddressFamily::Ipv4,
            "ipv6" => AddressFamily::Ipv6,
            _ => return Err("Unsupported native lab address family".into()),
        },
        phase: match phase.as_str() {
            "apply" => Phase::Apply,
            "restore" => Phase::Restore,
            "complete" => Phase::Complete,
            "revoke" => Phase::Revoke,
            "authorization-unavailable" => Phase::AuthorizationUnavailable,
            _ => return Err("Unsupported native lab interruption phase".into()),
        },
    })
}

pub fn run(arguments: &[String]) -> ServiceResult<()> {
    CONFIG
        .set(config(arguments)?)
        .map_err(|_| "Native lab service already initialized")?;
    service_dispatcher::start(LAB_SERVICE_NAME, labEntry)?;
    Ok(())
}

fn event(value: serde_json::Value) -> ServiceResult<()> {
    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_INFORMATION_TYPE, RegisterEventSourceW, ReportEventW,
    };
    let value = serde_json::to_string(&value)?;
    if value.len() > 24_000 {
        return Err("Native lab report exceeds its bounded event size".into());
    }
    let source: Vec<u16> = LAB_SERVICE_NAME.encode_utf16().chain(Some(0)).collect();
    let message: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
    let handle = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = unsafe {
        ReportEventW(
            handle,
            EVENTLOG_INFORMATION_TYPE,
            0,
            100,
            std::ptr::null_mut(),
            1,
            0,
            &message.as_ptr(),
            std::ptr::null(),
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        DeregisterEventSource(handle);
    }
    if result == 0 {
        return Err(error.into());
    }
    Ok(())
}

fn servicePermit(config: &Config) -> ServiceResult<ServicePermit> {
    if security::currentSid()? != "S-1-5-18" {
        return Err("Native MTU lab requires its separately installed LocalSystem service".into());
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
        return Err("Native MTU lab requires service session zero".into());
    }
    let serviceSid = security::serviceSidForName(LAB_SERVICE_NAME)?;
    security::requireServiceMembership(&serviceSid)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        LAB_SERVICE_NAME,
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
    )?;
    let registered = service.query_config()?;
    let status = service.query_status()?;
    if registered.service_type != ServiceType::OWN_PROCESS
        || status.process_id != Some(std::process::id())
        || !registered.account_name.is_some_and(|account| {
            let text = account.to_string_lossy();
            text.eq_ignore_ascii_case("LocalSystem")
                || text.eq_ignore_ascii_case(r"NT AUTHORITY\SYSTEM")
        })
    {
        return Err("Native MTU lab process does not match its SCM registration".into());
    }
    Ok(ServicePermit {
        guid: config.guid,
        family: config.family,
    })
}

struct Backend<'a> {
    config: &'a Config,
    permit: ServicePermit,
    stop: Arc<AtomicBool>,
    started: Instant,
    pause: Option<WritePurpose>,
    writes: usize,
    authorization: Option<&'a mut crate::authorization::AuthorizationStore>,
    grantId: Option<Uuid>,
}

impl MtuBackend for Backend<'_> {
    fn authorize(
        &mut self,
        document: &MtuCheckpoint,
        action: AuthorizationAction,
        now: u64,
    ) -> ServiceResult<()> {
        document.validate()?;
        if document.id != self.config.trialId
            || document.authorizedUserSid != self.config.ownerSid
            || document.context.adapterGuid != self.config.guid
            || document.addressFamily != self.config.family
            || document.proposedMtu != 1400
            || document.leaseExpiresAtUnixMs - document.createdAtUnixMs != 120_000
            || action == AuthorizationAction::Retain
            || now < document.createdAtUnixMs
            || now >= document.leaseExpiresAtUnixMs
            || self.started.elapsed() >= LAB_DEADLINE
            || self.stop.load(Ordering::SeqCst)
        {
            return Err("Native lab authorization is out of scope, revoked, or expired; retention is never allowed".into());
        }
        self.permit.validateTarget(
            document
                .nativeOriginal
                .as_ref()
                .ok_or("Native lab original is missing")?,
        )?;
        self.authorization
            .as_deref_mut()
            .ok_or("Native application requires the protected authorization store")?
            .authorize(
                self.grantId
                    .ok_or("Native operation has no authorization grant")?,
                document,
                &self.config.ownerSid,
                action,
                now,
            )
    }
    fn observe(&mut self, document: &MtuCheckpoint) -> ServiceResult<Observation> {
        mtu::ensureLabCommandStopped()?;
        if document.context.adapterGuid != self.config.guid
            || document.addressFamily != self.config.family
        {
            return Err("Native lab observation target is outside its fixed adapter scope".into());
        }
        let native = mtu::capture(
            self.config.guid,
            self.config.family,
            &AtomicBool::new(false),
        )?;
        self.permit.validateTarget(&native)?;
        Ok(Observation {
            context: native.journalContext()?,
            addressFamily: native.addressFamily,
            mtu: native.settings.nlMtu,
            native: Some(native),
        })
    }
    fn writeMtu(
        &mut self,
        document: &MtuCheckpoint,
        expected: &Observation,
        value: u32,
        purpose: WritePurpose,
    ) -> ServiceResult<()> {
        if purpose == WritePurpose::Apply {
            self.authorize(document, AuthorizationAction::Apply, nowUnixMs()?)?;
        }
        let original = document
            .nativeOriginal
            .as_ref()
            .ok_or("Native lab original is missing")?;
        if (purpose == WritePurpose::Apply && value != 1400)
            || (purpose == WritePurpose::Restore && value != original.settings.nlMtu)
        {
            return Err("Native lab write does not match its typed purpose".into());
        }
        {
            let mut authorization = self.authorization.as_deref_mut();
            let grantId = self.grantId;
            let ownerSid = &self.config.ownerSid;
            let stop = &self.stop;
            let mut check = || -> ServiceResult<()> {
                if stop.load(Ordering::SeqCst) {
                    return Err("Native lab application was stopped".into());
                }
                authorization
                    .as_deref_mut()
                    .ok_or("Native application requires a protected authorization store")?
                    .check(
                        grantId.ok_or("Native operation has no authorization grant")?,
                        document,
                        ownerSid,
                        AuthorizationAction::Apply,
                        nowUnixMs()?,
                    )
            };
            mtu::writeLabMtu(
                &self.permit,
                original,
                expected
                    .native
                    .as_ref()
                    .ok_or("Native lab expected observation is missing")?,
                value,
                if purpose == WritePurpose::Apply {
                    (Instant::now() + Duration::from_secs(5)).min(self.started + LAB_DEADLINE)
                } else {
                    Instant::now() + Duration::from_secs(5)
                },
                if purpose == WritePurpose::Apply {
                    Some(&mut check as &mut dyn FnMut() -> ServiceResult<()>)
                } else {
                    None
                },
            )?;
        }
        self.writes += 1;
        if self.config.phase == Phase::Revoke && purpose == WritePurpose::Apply {
            let id = self.grantId.ok_or("Revocation requires a recorded grant")?;
            self.authorization
                .as_deref_mut()
                .ok_or("Revocation requires its protected store")?
                .revoke(id, &self.config.ownerSid, nowUnixMs()?)?;
            event(json!({"phase":"grantRevoked", "trialId":document.id, "grantId":id}))?;
        }
        event(
            json!({"phase":"nativeWriteReturned", "trialId":document.id, "adapterGuid":self.config.guid, "family":self.config.family,
            "purpose":format!("{purpose:?}"), "value":value, "processId":std::process::id()}),
        )?;
        if self.pause == Some(purpose) {
            while !self.stop.load(Ordering::SeqCst) && self.started.elapsed() < LAB_DEADLINE {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        Ok(())
    }
}

fn trial(config: &Config, stop: Arc<AtomicBool>) -> ServiceResult<()> {
    let permit = servicePermit(config)?;
    let serviceSid = security::serviceSidForName(LAB_SERVICE_NAME)?;
    let mut owned = storage::openMtuLab(&serviceSid)?;
    let needsAuthorization = owned.journal().pendingRecovery()?.is_empty()
        && owned.journal().load(config.trialId).is_err();
    let mut authorization = if needsAuthorization {
        Some(owned.authorization()?)
    } else {
        None
    };
    let journal = owned.journal();
    let mut backend = Backend {
        config,
        permit,
        stop,
        started: Instant::now(),
        pause: None,
        writes: 0,
        authorization: authorization.as_mut().map(|owned| &mut owned.store),
        grantId: None,
    };
    let pending = journal.pendingRecovery()?;
    if !pending.is_empty() {
        if pending.iter().any(|checkpoint| {
            checkpoint.document().id != config.trialId || checkpoint.document().schemaVersion != 2
        }) {
            return Err("Native lab found recovery work outside this trial; preserving it without new writes".into());
        }
        let results = MtuCoordinator::new(journal, &mut backend, nowUnixMs).restoreAllPending()?;
        if results
            .iter()
            .any(|result| !result.originalMtuVerified || !result.journalFinalized)
        {
            event(
                json!({"phase":"recoveryIncomplete", "trialId":config.trialId, "results":results}),
            )?;
            return Err("Native lab recovery is incomplete".into());
        }
    } else if let Ok(existing) = journal.load(config.trialId) {
        if !existing.state().terminal() {
            return Err("Native lab trial is unexpectedly unresolved".into());
        }
    } else {
        let original = mtu::capture(config.guid, config.family, &AtomicBool::new(false))?;
        backend.permit.validateTarget(&original)?;
        let now = nowUnixMs()?;
        let document = MtuCheckpoint {
            schemaVersion: 2,
            id: config.trialId,
            createdAtUnixMs: now,
            leaseExpiresAtUnixMs: now
                .checked_add(120_000)
                .ok_or("Native lab lease overflow")?,
            authorizedUserSid: config.ownerSid.clone(),
            context: original.journalContext()?,
            addressFamily: config.family,
            originalMtu: original.settings.nlMtu,
            proposedMtu: 1400,
            nativeOriginal: Some(original),
        };
        let grant = backend
            .authorization
            .as_deref_mut()
            .ok_or("Native operation has no authorization store")?
            .issue(&document, &config.ownerSid, false, nowUnixMs()?)?;
        backend.grantId = Some(grant.id);
        event(
            json!({"phase":"grantIssued", "trialId":document.id, "grantId":grant.id, "checkpointSha256":grant.checkpointSha256}),
        )?;
        MtuCoordinator::new(journal, &mut backend, nowUnixMs).prepare(document.clone())?;
        backend.pause = match config.phase {
            Phase::Apply | Phase::Revoke | Phase::AuthorizationUnavailable => {
                Some(WritePurpose::Apply)
            }
            Phase::Restore => Some(WritePurpose::Restore),
            Phase::Complete => None,
        };
        let applied = MtuCoordinator::new(journal, &mut backend, nowUnixMs).apply(document.id)?;
        match applied {
            ApplyResult::Applied { .. } => {
                let recovered =
                    MtuCoordinator::new(journal, &mut backend, nowUnixMs).restore(document.id)?;
                if !recovered.originalMtuVerified || !recovered.journalFinalized {
                    return Err("Native lab could not finish exact original restoration".into());
                }
            }
            ApplyResult::Failed { recovery, error } => {
                event(
                    json!({"phase":"applyFailed", "trialId":config.trialId, "recovery":recovery,"error":error}),
                )?;
                return Err("Native lab application was not confirmed".into());
            }
        }
    }
    let checkpoint = journal.load(config.trialId)?;
    let after = backend.observe(checkpoint.document())?;
    let original = checkpoint
        .document()
        .nativeOriginal
        .as_ref()
        .ok_or("Native lab original missing after recovery")?;
    after
        .native
        .as_ref()
        .unwrap()
        .validateMtuObservation(original)?;
    if checkpoint.state() != crate::journal::State::Restored || after.mtu != original.settings.nlMtu
    {
        return Err("Native lab trial did not finish in a verified restored state".into());
    }
    event(
        json!({"phase":"complete", "trialId":config.trialId, "state":checkpoint.state(), "original":original,
        "after":after.native, "writesThisProcess":backend.writes, "pendingRecoveryCount":journal.pendingRecovery()?.len()}),
    )
}

fn labMain(_arguments: Vec<OsString>) {
    let result = (|| -> ServiceResult<()> {
        let config = CONFIG
            .get()
            .ok_or("Missing native lab service configuration")?;
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let handle =
            service_control_handler::register(LAB_SERVICE_NAME, move |control| match control {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    signal.store(true, Ordering::SeqCst);
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            })?;
        crate::windows::setState(handle, ServiceState::StartPending, false)?;
        crate::windows::setState(handle, ServiceState::Running, false)?;
        let result = trial(config, stop);
        if let Err(error) = &result {
            let _ = event(
                json!({"phase":"error", "trialId":config.trialId, "error":error.to_string()}),
            );
        }
        crate::windows::setState(handle, ServiceState::StopPending, result.is_err())?;
        crate::windows::setState(handle, ServiceState::Stopped, result.is_err())?;
        result
    })();
    if let Err(error) = result {
        let _ = event(json!({"phase":"serviceFailed", "error":error.to_string()}));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nativeLabRejectsUnscopedArgumentsAndPhysicalAdapterEvidence() {
        assert!(config(&[]).is_err());
        let mut snapshot = crate::recovery::tests::nativeFixture();
        let permit = ServicePermit {
            guid: snapshot.adapterGuid,
            family: snapshot.addressFamily,
        };
        assert!(permit.validateTarget(&snapshot).is_err());
        let DriverContext::Captured { identity } = &mut snapshot.driver else {
            unreachable!()
        };
        identity.infPath = "netloop.inf".into();
        identity.deviceInstanceId = "ROOT\\NET\\0000".into();
        assert!(permit.validateTarget(&snapshot).is_err());
        snapshot.alias = format!("epp-mtu-lab-{}", snapshot.adapterGuid);
        assert!(permit.validateTarget(&snapshot).is_ok());
        snapshot.adapterGuid = Uuid::nil();
        assert!(permit.validateTarget(&snapshot).is_err());
    }

    #[test]
    fn nativeLabAuthorizationIsBoundedRevocableAndNeverAllowsRetention() {
        let mut original = crate::recovery::tests::nativeFixture();
        original.alias = format!("epp-mtu-lab-{}", original.adapterGuid);
        let DriverContext::Captured { identity } = &mut original.driver else {
            unreachable!()
        };
        identity.infPath = "netloop.inf".into();
        identity.deviceInstanceId = "ROOT\\NET\\0000".into();
        let document = MtuCheckpoint {
            schemaVersion: 2,
            id: Uuid::from_u128(123),
            authorizedUserSid: "S-1-5-21-1-2-3-1000".into(),
            context: original.journalContext().unwrap(),
            addressFamily: original.addressFamily,
            createdAtUnixMs: 1000,
            leaseExpiresAtUnixMs: 121000,
            originalMtu: 1500,
            proposedMtu: 1400,
            nativeOriginal: Some(original.clone()),
        };
        let config = Config {
            guid: original.adapterGuid,
            family: original.addressFamily,
            ownerSid: document.authorizedUserSid.clone(),
            trialId: document.id,
            phase: Phase::Complete,
        };
        assert!(servicePermit(&config).is_err());
        let fixture = crate::authorization::tests::Fixture::new();
        let mut authorization = fixture.open();
        let grant = authorization
            .issue(&document, &config.ownerSid, false, 1000)
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let mut backend = Backend {
            config: &config,
            permit: ServicePermit {
                guid: config.guid,
                family: config.family,
            },
            stop: stop.clone(),
            started: Instant::now(),
            pause: None,
            writes: 0,
            authorization: Some(&mut authorization),
            grantId: Some(grant.id),
        };
        assert!(
            backend
                .authorize(&document, AuthorizationAction::Prepare, 1001)
                .is_ok()
        );
        assert!(
            backend
                .authorize(&document, AuthorizationAction::Retain, 1001)
                .is_err()
        );
        assert!(
            backend
                .authorize(&document, AuthorizationAction::Apply, 121000)
                .is_err()
        );
        let mut changed = document.clone();
        changed.proposedMtu = 1399;
        assert!(
            backend
                .authorize(&changed, AuthorizationAction::Apply, 1001)
                .is_err()
        );
        changed = document.clone();
        changed.authorizedUserSid = "S-1-5-21-1-2-3-1001".into();
        assert!(
            backend
                .authorize(&changed, AuthorizationAction::Apply, 1001)
                .is_err()
        );
        stop.store(true, Ordering::SeqCst);
        assert!(
            backend
                .authorize(&document, AuthorizationAction::Apply, 1001)
                .is_err()
        );
        assert_eq!(backend.writes, 0);
    }
}
