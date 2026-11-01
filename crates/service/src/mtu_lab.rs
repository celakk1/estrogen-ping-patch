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
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceState, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

mod repeated;

pub const LAB_SERVICE_NAME: &str = "EstrogenPingPatchMtuLab";
const LAB_DEADLINE: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq)]
enum Phase {
    Apply,
    Restore,
    Complete,
    Repeated,
    Revoke,
    AuthorizationUnavailable,
    Registered,
    WatchdogDeadline,
    WatchdogHeartbeat,
    WatchdogStop,
    WatchdogCrash,
}

struct Config {
    ownerSid: String,
    guid: Uuid,
    family: AddressFamily,
    phase: Phase,
    trialId: Uuid,
}

impl Config {
    fn leaseMs(&self) -> u64 {
        if self.phase == Phase::Repeated {
            30_000
        } else if self.phase == Phase::WatchdogDeadline {
            20_000
        } else {
            120_000
        }
    }

    fn deadline(&self) -> Duration {
        if self.phase == Phase::Repeated {
            Duration::from_secs(300)
        } else {
            LAB_DEADLINE
        }
    }

    fn checkpointIds(&self) -> Vec<Uuid> {
        if self.phase == Phase::Repeated {
            (0..12)
                .map(|index| repeated::checkpointId(self.trialId, index))
                .collect()
        } else {
            vec![self.trialId]
        }
    }

    fn usesWatchdog(&self) -> bool {
        matches!(
            self.phase,
            Phase::WatchdogDeadline
                | Phase::WatchdogHeartbeat
                | Phase::WatchdogStop
                | Phase::WatchdogCrash
        )
    }
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
        return Err("Native lab service requires SID GUID ipv4|ipv6 PHASE TRIAL_ID".into());
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
            "repeated" => Phase::Repeated,
            "revoke" => Phase::Revoke,
            "authorization-unavailable" => Phase::AuthorizationUnavailable,
            "registered" => Phase::Registered,
            "watchdog-deadline" => Phase::WatchdogDeadline,
            "watchdog-heartbeat" => Phase::WatchdogHeartbeat,
            "watchdog-stop" => Phase::WatchdogStop,
            "watchdog-crash" => Phase::WatchdogCrash,
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
        ServiceAccess::QUERY_CONFIG
            | ServiceAccess::QUERY_STATUS
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::START,
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
    let actions = if config.phase == Phase::WatchdogCrash {
        vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(1),
            },
            ServiceAction {
                action_type: ServiceActionType::None,
                delay: Duration::ZERO,
            },
        ]
    } else {
        vec![ServiceAction {
            action_type: ServiceActionType::None,
            delay: Duration::ZERO,
        }]
    };
    if service.get_failure_actions_on_non_crash_failures()? {
        return Err("Native lab refuses unexpected non-crash restart policy".into());
    }
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
        return Err(
            "Native lab recovery policy did not match its bounded restart-only configuration"
                .into(),
        );
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
    checkpointIds: Vec<Uuid>,
}

impl Backend<'_> {
    fn policyOriginal(&mut self, original: &mtu::Snapshot) -> ServiceResult<mtu::policy::Evidence> {
        let capture = mtu::policy::inspect(self.config.guid, self.config.family, &self.stop)?;
        self.permit.validateTarget(&capture.native)?;
        capture.native.validateMtuObservation(original)?;
        if capture.native.settings != original.settings
            || capture.native.interfaceIndex != original.interfaceIndex
            || capture.native.interfaceLuid != original.interfaceLuid
        {
            return Err("Native original changed during exact IP policy capture".into());
        }
        Ok(capture.evidence())
    }

    fn validateAuthorizationScope(
        &self,
        document: &MtuCheckpoint,
        action: AuthorizationAction,
        now: u64,
    ) -> ServiceResult<()> {
        document.validate()?;
        if !self.checkpointIds.contains(&document.id)
            || document.authorizedUserSid != self.config.ownerSid
            || document.context.adapterGuid != self.config.guid
            || document.addressFamily != self.config.family
            || document.proposedMtu != 1400
            || document.leaseExpiresAtUnixMs - document.createdAtUnixMs != self.config.leaseMs()
            || action == AuthorizationAction::Retain
            || now < document.createdAtUnixMs
            || now >= document.leaseExpiresAtUnixMs
            || self.started.elapsed() >= self.config.deadline()
            || self.stop.load(Ordering::SeqCst)
        {
            return Err("Native lab authorization is out of scope, revoked, or expired; retention is never allowed".into());
        }
        self.permit.validateTarget(
            document
                .nativeOriginal
                .as_ref()
                .ok_or("Native lab original is missing")?,
        )
    }
}

impl MtuBackend for Backend<'_> {
    fn observePolicy(
        &mut self,
        document: &MtuCheckpoint,
        purpose: crate::recovery::PolicyPurpose,
    ) -> ServiceResult<mtu::policy::Capture> {
        mtu::ensureLabCommandStopped()?;
        if document.context.adapterGuid != self.config.guid
            || document.addressFamily != self.config.family
        {
            return Err("IP policy observation target is outside the native trial".into());
        }
        let recovering = AtomicBool::new(false);
        let cancelled = if purpose == crate::recovery::PolicyPurpose::VerifyRestored {
            &recovering
        } else {
            &self.stop
        };
        let capture = mtu::policy::inspect(self.config.guid, self.config.family, cancelled)?;
        self.permit.validateTarget(&capture.native)?;
        Ok(capture)
    }

    fn checkAuthorization(&mut self, document: &MtuCheckpoint, now: u64) -> ServiceResult<()> {
        self.validateAuthorizationScope(document, AuthorizationAction::Apply, now)?;
        self.authorization
            .as_deref_mut()
            .ok_or("Native operation has no authorization store")?
            .check(
                self.grantId
                    .ok_or("Native operation has no authorization grant")?,
                document,
                &self.config.ownerSid,
                AuthorizationAction::Apply,
                now,
            )
    }

    fn authorize(
        &mut self,
        document: &MtuCheckpoint,
        action: AuthorizationAction,
        now: u64,
    ) -> ServiceResult<()> {
        self.validateAuthorizationScope(document, action, now)?;
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
    fn waitForMutator(&mut self, record: &crate::journal::MutatorRecord) -> ServiceResult<()> {
        if !self.checkpointIds.contains(&record.checkpointId) {
            return Err("Mutator is outside this native trial".into());
        }
        mtu::waitForLabMutator(&record.identity)?;
        event(
            json!({"phase":"mutatorExitVerified", "trialId":record.checkpointId, "purpose":format!("{:?}",record.purpose), "mutator":record.identity, "processId":std::process::id()}),
        )
    }
    fn writeMtu(
        &mut self,
        document: &MtuCheckpoint,
        expected: &Observation,
        value: u32,
        purpose: WritePurpose,
        register: &mut crate::recovery::MutatorRegistrar<'_>,
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
            let deadline = if purpose == WritePurpose::Apply {
                (Instant::now() + Duration::from_secs(5)).min(self.started + self.config.deadline())
            } else {
                Instant::now() + Duration::from_secs(5)
            };
            let mut record = |identity: crate::journal::MutatorIdentity| -> ServiceResult<()> {
                register(identity.clone())?;
                event(
                    json!({"phase":"mutatorRegistered", "trialId":document.id, "purpose":format!("{purpose:?}"), "mutator":identity, "processId":std::process::id()}),
                )?;
                if self.config.phase == Phase::Registered && purpose == WritePurpose::Apply {
                    while !stop.load(Ordering::SeqCst) && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
                Ok(())
            };
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
                deadline,
                if purpose == WritePurpose::Apply {
                    Some(&mut check as &mut dyn FnMut() -> ServiceResult<()>)
                } else {
                    None
                },
                &mut record,
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
            while !self.stop.load(Ordering::SeqCst)
                && self.started.elapsed() < self.config.deadline()
            {
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
        checkpointIds: config.checkpointIds(),
    };
    if config.phase == Phase::Repeated {
        repeated::recover(journal, &mut backend)?;
        let mut experiments = owned.experiments()?;
        return repeated::run(owned.journal(), &mut backend, &mut experiments);
    }
    let pending = journal.pendingRecovery()?;
    if !pending.is_empty() {
        if pending.iter().any(|checkpoint| {
            checkpoint.document().id != config.trialId
                || !matches!(checkpoint.document().schemaVersion, 3 | 4)
        }) {
            return Err("Native lab requires current tracked-process checkpoints; preserving legacy or unrelated recovery work without new writes".into());
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
        let capture = mtu::policy::inspect(config.guid, config.family, &backend.stop)?;
        let policyOriginal = capture.evidence();
        let original = capture.native;
        backend.permit.validateTarget(&original)?;
        let now = nowUnixMs()?;
        let document = MtuCheckpoint {
            schemaVersion: 4,
            id: config.trialId,
            createdAtUnixMs: now,
            leaseExpiresAtUnixMs: now
                .checked_add(config.leaseMs())
                .ok_or("Native lab lease overflow")?,
            authorizedUserSid: config.ownerSid.clone(),
            context: original.journalContext()?,
            addressFamily: config.family,
            originalMtu: original.settings.nlMtu,
            proposedMtu: 1400,
            nativeOriginal: Some(original),
            policyOriginal: Some(policyOriginal),
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
        if config.phase == Phase::Complete {
            let stop = backend.stop.clone();
            let report = crate::trial::execute(
                journal,
                &mut backend,
                document.clone(),
                &stop,
                crate::watchdog::Policy::default(),
                |control| {
                    let listeners = [
                        std::net::TcpListener::bind("127.0.0.1:0")?,
                        std::net::TcpListener::bind("[::1]:0")?,
                    ];
                    let addresses = [listeners[0].local_addr()?, listeners[1].local_addr()?];
                    let mut measurements = Vec::new();
                    for _ in 0..3 {
                        for address in addresses {
                            control.heartbeat()?;
                            let start = Instant::now();
                            let _connection = std::net::TcpStream::connect_timeout(
                                &address,
                                Duration::from_millis(100),
                            )?;
                            measurements.push(json!({"endpoint":address.to_string(),"connectMs":start.elapsed().as_secs_f64()*1000.0}));
                        }
                    }
                    Ok(measurements)
                },
            )?;
            event(
                json!({"phase":"automaticTrialComplete", "trialId":document.id, "report":report}),
            )?;
            if report.outcome != crate::trial::Outcome::Completed
                || report.measurement.as_ref().map(Vec::len) != Some(6)
            {
                return Err(
                    "Automatic native trial did not complete measurement and verified recovery"
                        .into(),
                );
            }
        } else {
            MtuCoordinator::new(journal, &mut backend, nowUnixMs).prepare(document.clone())?;
            backend.pause = match config.phase {
                Phase::Apply | Phase::Revoke | Phase::AuthorizationUnavailable => {
                    Some(WritePurpose::Apply)
                }
                Phase::Restore => Some(WritePurpose::Restore),
                Phase::Complete
                | Phase::Repeated
                | Phase::Registered
                | Phase::WatchdogDeadline
                | Phase::WatchdogHeartbeat
                | Phase::WatchdogStop
                | Phase::WatchdogCrash => None,
            };
            let applied =
                MtuCoordinator::new(journal, &mut backend, nowUnixMs).apply(document.id)?;
            match applied {
                ApplyResult::Applied { .. } => {
                    if config.usesWatchdog() {
                        let control = crate::watchdog::Control::new(document.id)?;
                        let serviceStop = backend.stop.clone();
                        let report = crate::watchdog::watch(
                            journal,
                            &mut backend,
                            document.id,
                            &control,
                            &serviceStop,
                            crate::watchdog::Policy {
                                heartbeatTimeout: Duration::from_secs(
                                    if config.phase == Phase::WatchdogHeartbeat {
                                        5
                                    } else {
                                        30
                                    },
                                ),
                                ..Default::default()
                            },
                            || {
                                event(
                                    json!({"phase":"watchdogArmed", "trialId":document.id, "processId":std::process::id()}),
                                )
                            },
                        )?;
                        event(
                            json!({"phase":"watchdogReturned", "trialId":document.id, "report":report}),
                        )?;
                        if !report.originalVerified() {
                            return Err(
                                "Native watchdog did not verify complete original restoration"
                                    .into(),
                            );
                        }
                    } else {
                        let recovered = MtuCoordinator::new(journal, &mut backend, nowUnixMs)
                            .restore(document.id)?;
                        if !recovered.originalMtuVerified || !recovered.journalFinalized {
                            return Err(
                                "Native lab could not finish exact original restoration".into()
                            );
                        }
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
    }
    let checkpoint = journal.load(config.trialId)?;
    let mutators = journal.mutators(config.trialId)?;
    for record in &mutators {
        backend.waitForMutator(record)?;
    }
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
        "checkpointSchemaVersion":checkpoint.document().schemaVersion, "policyOriginal":checkpoint.document().policyOriginal,
        "after":after.native, "writesThisProcess":backend.writes, "pendingRecoveryCount":journal.pendingRecovery()?.len(), "mutators":mutators, "processId":std::process::id()}),
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
            schemaVersion: 3,
            id: Uuid::from_u128(123),
            authorizedUserSid: "S-1-5-21-1-2-3-1000".into(),
            context: original.journalContext().unwrap(),
            addressFamily: original.addressFamily,
            createdAtUnixMs: 1000,
            leaseExpiresAtUnixMs: 121000,
            originalMtu: 1500,
            proposedMtu: 1400,
            nativeOriginal: Some(original.clone()),
            policyOriginal: None,
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
            checkpointIds: config.checkpointIds(),
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
