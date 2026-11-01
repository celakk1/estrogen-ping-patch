use super::*;
use crate::{
    journal::{MtuCheckpoint, MutatorIdentity, MutatorRecord, Observation},
    mtu::Snapshot,
    recovery::{ApplyResult, AuthorizationAction, MutatorRegistrar, WritePurpose},
};

pub(crate) struct Backend {
    pub(crate) native: Snapshot,
    pub(crate) allow: bool,
    pub(crate) failRestore: bool,
    pub(crate) panicAfterApply: bool,
    pub(crate) externalOriginal: Option<Arc<AtomicBool>>,
    pub(crate) observedMtu: Option<Arc<std::sync::atomic::AtomicU32>>,
    checks: usize,
    stopDuringVerification: Option<Arc<AtomicBool>>,
    pub(crate) writes: Vec<WritePurpose>,
}

impl MtuBackend for Backend {
    fn checkAuthorization(&mut self, _: &MtuCheckpoint, _: u64) -> ServiceResult<()> {
        self.checks += 1;
        if let Some(stop) = &self.stopDuringVerification {
            stop.store(true, Ordering::SeqCst);
            return Err("fixture service stopped during verification".into());
        }
        if !self.allow {
            return Err("fixture permission revoked".into());
        }
        Ok(())
    }
    fn authorize(
        &mut self,
        document: &MtuCheckpoint,
        _: AuthorizationAction,
        now: u64,
    ) -> ServiceResult<()> {
        if !self.allow || now >= document.leaseExpiresAtUnixMs {
            return Err("fixture apply permission unavailable".into());
        }
        Ok(())
    }
    fn observe(&mut self, _: &MtuCheckpoint) -> ServiceResult<Observation> {
        if self
            .externalOriginal
            .as_ref()
            .is_some_and(|signal| signal.load(Ordering::SeqCst))
        {
            self.native.settings.nlMtu = 1500;
        }
        self.native.capturedAtUnixMs = nowUnixMs()?;
        Ok(Observation {
            context: self.native.journalContext()?,
            addressFamily: self.native.addressFamily,
            mtu: self.native.settings.nlMtu,
            native: Some(self.native.clone()),
        })
    }
    fn waitForMutator(&mut self, _: &MutatorRecord) -> ServiceResult<()> {
        Ok(())
    }
    fn writeMtu(
        &mut self,
        _: &MtuCheckpoint,
        expected: &Observation,
        value: u32,
        purpose: WritePurpose,
        register: &mut MutatorRegistrar<'_>,
    ) -> ServiceResult<()> {
        if self.failRestore && purpose == WritePurpose::Restore {
            return Err("fixture restoration failed".into());
        }
        assert_eq!(self.native.settings.nlMtu, expected.mtu);
        register(MutatorIdentity {
            processId: 100 + self.writes.len() as u32,
            creationTime100ns: "10000".into(),
        })?;
        self.writes.push(purpose);
        self.native.settings.nlMtu = value;
        if let Some(observed) = &self.observedMtu {
            observed.store(value, Ordering::SeqCst);
        }
        if self.panicAfterApply && purpose == WritePurpose::Apply {
            panic!("fixture setting worker panic after application");
        }
        Ok(())
    }
}

fn document() -> MtuCheckpoint {
    let now = nowUnixMs().unwrap();
    let mut native = crate::recovery::tests::nativeFixture();
    native.capturedAtUnixMs = now;
    MtuCheckpoint {
        schemaVersion: 3,
        id: Uuid::new_v4(),
        createdAtUnixMs: now,
        leaseExpiresAtUnixMs: now + 10_000,
        authorizedUserSid: "S-1-5-21-1-2-3-1000".into(),
        context: native.journalContext().unwrap(),
        addressFamily: native.addressFamily,
        originalMtu: 1500,
        proposedMtu: 1400,
        nativeOriginal: Some(native),
    }
}

struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut path = self.0.clone().into_os_string();
            path.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(path));
        }
    }
}
pub(crate) struct Fixture {
    pub(crate) journal: Journal,
    pub(crate) backend: Backend,
    pub(crate) document: MtuCheckpoint,
    _temporary: Temporary,
}
pub(crate) fn fixture() -> Fixture {
    let document = document();
    let temporary = Temporary(
        std::env::temp_dir().join(format!("epp-watchdog-fixture-{}.sqlite3", Uuid::new_v4())),
    );
    let journal = Journal::open(&temporary.0).unwrap();
    let backend = Backend {
        native: document.nativeOriginal.clone().unwrap(),
        allow: true,
        failRestore: false,
        panicAfterApply: false,
        externalOriginal: None,
        observedMtu: None,
        checks: 0,
        stopDuringVerification: None,
        writes: Vec::new(),
    };
    Fixture {
        journal,
        backend,
        document,
        _temporary: temporary,
    }
}

fn applied() -> Fixture {
    let mut fixture = fixture();
    let mut coordinator =
        MtuCoordinator::new(&mut fixture.journal, &mut fixture.backend, nowUnixMs);
    coordinator.prepare(fixture.document.clone()).unwrap();
    assert!(matches!(
        coordinator.apply(fixture.document.id).unwrap(),
        ApplyResult::Applied { .. }
    ));
    fixture
}

#[test]
fn heartbeatsCannotExtendEitherLeaseClockAndRegressionsTriggerRecovery() {
    let document = document();
    let base = Instant::now();
    let mut guard = Guard::new(&document, document.createdAtUnixMs, base).unwrap();
    for elapsed in [1000, 5000, 9999] {
        let now = base + Duration::from_millis(elapsed);
        assert_eq!(
            guard.check(document.createdAtUnixMs, now, now, Duration::from_secs(1)),
            None
        );
    }
    let now = base + Duration::from_secs(10);
    assert_eq!(
        guard.check(document.createdAtUnixMs, now, now, Duration::from_secs(1)),
        Some(Trigger::LeaseExpired)
    );
    let mut guard = Guard::new(&document, document.createdAtUnixMs, base).unwrap();
    assert_eq!(
        guard.check(
            document.leaseExpiresAtUnixMs,
            base,
            base,
            Duration::from_secs(30)
        ),
        Some(Trigger::LeaseExpired)
    );
    let mut guard = Guard::new(&document, document.createdAtUnixMs, base).unwrap();
    assert_eq!(
        guard.check(
            document.createdAtUnixMs - 1,
            base,
            base,
            Duration::from_secs(30)
        ),
        Some(Trigger::ClockChanged)
    );
    let mut invalid = document.clone();
    invalid.leaseExpiresAtUnixMs = invalid.createdAtUnixMs + 1_800_001;
    assert!(Guard::new(&invalid, invalid.createdAtUnixMs, base).is_err());
}

#[test]
fn serviceWorkerRestoresWithoutClientActivityAndClosesTheExactControl() {
    let mut fixture = applied();
    let document = fixture.document.clone();
    let control = Control::new(document.id).unwrap();
    let client = control.clone();
    let (readySender, readyReceiver) = std::sync::mpsc::channel();
    let (doneSender, doneReceiver) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let report = watch(
            &mut fixture.journal,
            &mut fixture.backend,
            document.id,
            &control,
            &AtomicBool::new(false),
            Policy {
                heartbeatTimeout: Duration::from_millis(100),
                verificationInterval: Duration::from_millis(50),
                pollInterval: Duration::from_millis(10),
            },
            || {
                readySender.send(()).unwrap();
                Ok(())
            },
        )
        .unwrap();
        assert!(report.originalVerified());
        assert_eq!(report.trigger, Trigger::HeartbeatLost);
        assert_eq!(
            fixture.backend.writes,
            [WritePurpose::Apply, WritePurpose::Restore]
        );
        assert!(fixture.journal.pendingRecovery().unwrap().is_empty());
        doneSender.send(()).unwrap();
    });
    readyReceiver.recv_timeout(Duration::from_secs(5)).unwrap();
    client.heartbeat().unwrap();
    doneReceiver.recv_timeout(Duration::from_secs(5)).unwrap();
    worker.join().unwrap();
    assert!(client.heartbeat().is_err());
    assert!(client.requestRollback(Trigger::TrialFinished).is_err());
}

#[test]
fn aLateHeartbeatCannotReviveAnExpiredSessionWhileTheWorkerWasBusy() {
    let mut fixture = applied();
    let control = Control::new(fixture.document.id).unwrap();
    let client = control.clone();
    let report = watch(
        &mut fixture.journal,
        &mut fixture.backend,
        fixture.document.id,
        &control,
        &AtomicBool::new(false),
        Policy {
            heartbeatTimeout: Duration::from_millis(100),
            verificationInterval: Duration::from_millis(50),
            pollInterval: Duration::from_millis(10),
        },
        || {
            client.shared.state.lock().unwrap().heartbeat =
                Instant::now() - Duration::from_millis(101);
            assert!(
                client.heartbeat().is_err(),
                "a late heartbeat must not conceal an already missed deadline"
            );
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(report.trigger, Trigger::HeartbeatLost);
    assert!(report.originalVerified());
}

#[test]
fn cancelledFinishedAndDisconnectedSessionsAlwaysRestoreRatherThanRetain() {
    for reason in [
        Trigger::UserStopped,
        Trigger::TrialFinished,
        Trigger::ConnectivityLost,
    ] {
        let mut fixture = applied();
        let document = fixture.document.clone();
        let control = Control::new(document.id).unwrap();
        control.requestRollback(reason).unwrap();
        let report = watch(
            &mut fixture.journal,
            &mut fixture.backend,
            document.id,
            &control,
            &AtomicBool::new(false),
            Policy::default(),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(report.trigger, reason);
        assert!(report.originalVerified());
        assert_eq!(fixture.backend.native.settings.nlMtu, 1500);
        assert_eq!(fixture.backend.writes.len(), 2);
    }
}

#[test]
fn shutdownAndMonitorErrorsCannotLeaveAnAppliedSettingUnattended() {
    for stopped in [false, true] {
        let mut fixture = applied();
        let document = fixture.document.clone();
        let control = Control::new(document.id).unwrap();
        let report = watch(
            &mut fixture.journal,
            &mut fixture.backend,
            document.id,
            &control,
            &AtomicBool::new(stopped),
            Policy::default(),
            || Err("fixture observer unavailable".into()),
        )
        .unwrap();
        assert_eq!(
            report.trigger,
            if stopped {
                Trigger::ServiceStopping
            } else {
                Trigger::MonitorFailed
            }
        );
        assert!(report.originalVerified());
    }
}

#[test]
fn shutdownDuringReadbackKeepsItsActualRecoveryTrigger() {
    let mut fixture = applied();
    let stop = Arc::new(AtomicBool::new(false));
    fixture.backend.stopDuringVerification = Some(stop.clone());
    let control = Control::new(fixture.document.id).unwrap();
    let report = watch(
        &mut fixture.journal,
        &mut fixture.backend,
        fixture.document.id,
        &control,
        &stop,
        Policy::default(),
        || Ok(()),
    )
    .unwrap();
    assert_eq!(report.trigger, Trigger::ServiceStopping);
    assert!(report.originalVerified());
}

#[test]
fn revokedPermissionAndLostLinkTriggerRecoveryWithoutAnApplyGrant() {
    for revoke in [true, false] {
        let mut fixture = applied();
        let document = fixture.document.clone();
        if revoke {
            fixture.backend.allow = false;
        } else {
            fixture.backend.native.operationalStatus = 2;
        }
        let control = Control::new(document.id).unwrap();
        let report = watch(
            &mut fixture.journal,
            &mut fixture.backend,
            document.id,
            &control,
            &AtomicBool::new(false),
            Policy::default(),
            || Ok(()),
        )
        .unwrap();
        assert_eq!(report.trigger, Trigger::VerificationFailed);
        assert!(report.originalVerified());
        assert!(report.monitorError.is_some());
        assert_eq!(fixture.backend.native.settings.nlMtu, 1500);
    }
}

#[test]
fn externalChangesAndFailedRestoreStayExplicitlyUnrecovered() {
    for fault in ["thirdValue", "unrelated", "restore"] {
        let mut fixture = applied();
        let document = fixture.document.clone();
        match fault {
            "thirdValue" => fixture.backend.native.settings.nlMtu = 1300,
            "unrelated" => fixture.backend.native.settings.metric = 99,
            "restore" => fixture.backend.failRestore = true,
            _ => unreachable!(),
        }
        let control = Control::new(document.id).unwrap();
        if fault == "restore" {
            control.requestRollback(Trigger::UserStopped).unwrap();
        }
        let report = watch(
            &mut fixture.journal,
            &mut fixture.backend,
            document.id,
            &control,
            &AtomicBool::new(false),
            Policy::default(),
            || Ok(()),
        )
        .unwrap();
        assert!(!report.originalVerified());
        if fault == "thirdValue" {
            assert_eq!(fixture.backend.native.settings.nlMtu, 1300);
            assert_eq!(fixture.backend.writes.len(), 1);
        } else if fault == "unrelated" {
            assert_eq!(fixture.backend.native.settings.nlMtu, 1500);
            assert_eq!(fixture.backend.native.settings.metric, 99);
            assert!(report.recovery.unwrap().unrelatedSettingsDrifted);
        } else {
            assert_eq!(fixture.backend.native.settings.nlMtu, 1400);
            assert_eq!(
                fixture.journal.load(document.id).unwrap().state(),
                State::RecoveryRequired
            );
        }
    }
}

#[test]
fn invalidPoliciesAndWrongSessionHandlesDoNotEnableUnboundedMonitoring() {
    let mut fixture = applied();
    let document = fixture.document.clone();
    let wrong = Control::new(Uuid::new_v4()).unwrap();
    assert!(
        watch(
            &mut fixture.journal,
            &mut fixture.backend,
            document.id,
            &wrong,
            &AtomicBool::new(false),
            Policy::default(),
            || Ok(())
        )
        .is_err()
    );
    assert_eq!(fixture.backend.writes.len(), 1);
    let control = Control::new(document.id).unwrap();
    assert!(control.heartbeat().is_err());
    assert!(control.requestRollback(Trigger::LeaseExpired).is_err());
    let report = watch(
        &mut fixture.journal,
        &mut fixture.backend,
        document.id,
        &control,
        &AtomicBool::new(false),
        Policy {
            pollInterval: Duration::ZERO,
            ..Policy::default()
        },
        || Ok(()),
    )
    .unwrap();
    assert_eq!(report.trigger, Trigger::MonitorFailed);
    assert!(report.originalVerified());
}
