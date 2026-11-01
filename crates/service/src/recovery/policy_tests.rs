use super::*;
use crate::mtu::policy::{Capture, Evidence};

struct PolicyBackend {
    inner: Backend,
    evidence: Evidence,
    unavailable: bool,
    failAt: Option<usize>,
    expireAt: Option<usize>,
    reads: usize,
    exitOnVerification: bool,
}

fn setup(fixture: &Fixture) -> (MtuCheckpoint, PolicyBackend) {
    let mut capture = crate::mtu::policy::tests::fixture();
    let mut persistent = capture.active.clone();
    persistent.store = 0;
    persistent.compartmentId.value = None;
    persistent.values.get_mut("NlMtu").unwrap().value = None;
    capture.persistent = Some(persistent);
    let mut document = document(0x504f4c49);
    document.schemaVersion = 4;
    document.policyOriginal = Some(capture.evidence());
    document.nativeOriginal = Some(capture.native.clone());
    save(&fixture.value, &capture.native);
    let backend = PolicyBackend {
        inner: fixture.backend(Arc::new(AtomicU64::new(1000))),
        evidence: capture.evidence(),
        unavailable: false,
        failAt: None,
        expireAt: None,
        reads: 0,
        exitOnVerification: false,
    };
    (document, backend)
}

impl MtuBackend for PolicyBackend {
    fn checkAuthorization(&mut self, document: &MtuCheckpoint, now: u64) -> ServiceResult<()> {
        self.inner
            .authorize(document, AuthorizationAction::Apply, now)
    }
    fn authorize(
        &mut self,
        document: &MtuCheckpoint,
        action: AuthorizationAction,
        now: u64,
    ) -> ServiceResult<()> {
        self.inner.authorize(document, action, now)
    }

    fn observe(&mut self, document: &MtuCheckpoint) -> ServiceResult<Observation> {
        self.inner.observe(document)
    }

    fn observePolicy(
        &mut self,
        _: &MtuCheckpoint,
        purpose: PolicyPurpose,
    ) -> ServiceResult<Capture> {
        self.reads += 1;
        if self.expireAt == Some(self.reads) {
            self.inner.clock.store(20000, Ordering::SeqCst);
        }
        let mut native = read(&self.inner.value);
        native.capturedAtUnixMs = self.inner.clock.load(Ordering::SeqCst);
        if purpose == PolicyPurpose::VerifyRestored {
            assert_eq!(native.settings.nlMtu, 1500);
            if self.exitOnVerification {
                println!("MTU_RESTORED_BEFORE_POLICY_RECEIPT");
                std::io::stdout().flush().unwrap();
                std::process::exit(0);
            }
        }
        if self.unavailable || self.failAt == Some(self.reads) {
            return Err("Simulated IP policy provider unavailable".into());
        }
        let mut active = self.evidence.active.clone();
        active.interfaceIndex = native.interfaceIndex;
        active.values.get_mut("NlMtu").unwrap().value = Some(native.settings.nlMtu);
        Ok(Capture {
            schemaVersion: 1,
            native,
            active,
            persistent: self.evidence.persistent.clone(),
        })
    }

    fn waitForMutator(&mut self, record: &crate::journal::MutatorRecord) -> ServiceResult<()> {
        self.inner.waitForMutator(record)
    }

    fn writeMtu(
        &mut self,
        document: &MtuCheckpoint,
        expected: &Observation,
        value: u32,
        purpose: WritePurpose,
        register: &mut MutatorRegistrar<'_>,
    ) -> ServiceResult<()> {
        self.inner
            .writeMtu(document, expected, value, purpose, register)
    }
}

#[path = "policy_receipt_tests.rs"]
mod receipt_tests;

#[test]
fn missingOrUnavailablePolicyBlocksPreparationAndVerifiedOriginalSurvivesReopen() {
    let fixture = Fixture::new();
    let (document, mut backend) = setup(&fixture);
    let mut journal = fixture.open();
    let mut missing = document.clone();
    missing.policyOriginal = None;
    assert!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .prepare(missing)
            .is_err()
    );
    backend.unavailable = true;
    assert!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .prepare(document.clone())
            .is_err()
    );
    assert!(journal.load(document.id).is_err());
    assert!(backend.inner.writes.is_empty());
    backend.unavailable = false;
    let prepared = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .prepare(document.clone())
        .unwrap();
    let checksum = prepared.documentSha256().to_owned();
    drop(journal);
    let journal = fixture.open();
    let saved = journal.load(document.id).unwrap();
    assert_eq!(saved.document(), &document);
    assert_eq!(saved.documentSha256(), checksum);
    assert_eq!(
        saved
            .document()
            .policyOriginal
            .as_ref()
            .unwrap()
            .persistent
            .as_ref()
            .unwrap()
            .values["NlMtu"]
            .value,
        None
    );
    let mut downgraded = document;
    downgraded.schemaVersion = 3;
    assert!(downgraded.validate().is_err());
}

#[test]
fn failedPolicyCheckpointCommitCannotReachASettingWrite() {
    let fixture = Fixture::new();
    let (document, mut backend) = setup(&fixture);
    let mut journal = fixture.open();
    Connection::open(&fixture.journal).unwrap().execute_batch("CREATE TRIGGER refuse_policy_checkpoint BEFORE INSERT ON checkpoints BEGIN SELECT RAISE(FAIL, 'simulated checkpoint commit refusal'); END;").unwrap();
    assert!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .prepare(document.clone())
            .is_err()
    );
    assert!(journal.load(document.id).is_err());
    assert!(backend.inner.writes.is_empty());
    assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
}

#[test]
fn activeAndPersistentDriftCannotStartAnApply() {
    for fault in 0..4 {
        let fixture = Fixture::new();
        let (document, mut backend) = setup(&fixture);
        let mut journal = fixture.open();
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .prepare(document.clone())
            .unwrap();
        match fault {
            0 => {
                backend
                    .evidence
                    .active
                    .values
                    .get_mut("Dhcp")
                    .unwrap()
                    .value = Some(1)
            }
            1 => {
                backend
                    .evidence
                    .persistent
                    .as_mut()
                    .unwrap()
                    .values
                    .get_mut("NlMtu")
                    .unwrap()
                    .value = Some(1500)
            }
            2 => backend.evidence.persistent = None,
            _ => {
                backend
                    .evidence
                    .persistent
                    .as_mut()
                    .unwrap()
                    .values
                    .get_mut("NlMtu")
                    .unwrap()
                    .cimType = 18
            }
        }
        assert!(
            MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
                .apply(document.id)
                .is_err(),
            "fault {fault}"
        );
        assert_eq!(journal.load(document.id).unwrap().state(), State::Prepared);
        assert!(backend.inner.writes.is_empty());
        assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
    }
}

#[test]
fn policyFailureAfterIntentNeverStartsTheMutator() {
    let fixture = Fixture::new();
    let (document, mut backend) = setup(&fixture);
    let mut journal = fixture.open();
    MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .prepare(document.clone())
        .unwrap();
    backend.failAt = Some(3);
    let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .apply(document.id)
        .unwrap();
    let ApplyResult::Failed { recovery, error } = result else {
        panic!("policy failure was ignored");
    };
    assert!(error.contains("provider unavailable"));
    assert!(recovery.originalMtuVerified && recovery.journalFinalized);
    assert!(recovery.error.is_none());
    assert!(backend.inner.writes.is_empty());
    assert!(journal.mutators(document.id).unwrap().is_empty());
    assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
}

#[test]
fn slowPolicyReadCannotOutliveTheLeaseAndStartAMutator() {
    let fixture = Fixture::new();
    let (document, mut backend) = setup(&fixture);
    let clock = backend.inner.clock.clone();
    let mut journal = fixture.open();
    MtuCoordinator::new(&mut journal, &mut backend, || {
        Ok(clock.load(Ordering::SeqCst))
    })
    .prepare(document.clone())
    .unwrap();
    backend.expireAt = Some(3);
    let result = MtuCoordinator::new(&mut journal, &mut backend, || {
        Ok(clock.load(Ordering::SeqCst))
    })
    .apply(document.id)
    .unwrap();
    let ApplyResult::Failed { recovery, error } = result else {
        panic!("expired lease was ignored");
    };
    assert!(error.contains("lease expired"));
    assert!(recovery.originalMtuVerified && recovery.journalFinalized);
    assert!(backend.inner.writes.is_empty());
    assert!(journal.mutators(document.id).unwrap().is_empty());
}

#[test]
fn revokedExpiredRecoveryRestoresMtuBeforeReportingUnavailableOrChangedPolicy() {
    for unavailable in [false, true] {
        let fixture = Fixture::new();
        let (document, mut backend) = setup(&fixture);
        let mut journal = fixture.open();
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .prepare(document.clone())
            .unwrap();
        assert!(matches!(
            MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
                .apply(document.id)
                .unwrap(),
            ApplyResult::Applied { .. }
        ));
        backend.inner.allow = false;
        backend.inner.clock.store(20000, Ordering::SeqCst);
        backend.unavailable = unavailable;
        backend
            .evidence
            .persistent
            .as_mut()
            .unwrap()
            .values
            .get_mut("NlMtu")
            .unwrap()
            .value = Some(1400);
        let changed = backend.evidence.clone();
        drop(journal);
        let mut journal = fixture.open();
        let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(20000))
            .restore(document.id)
            .unwrap();
        assert!(
            result.originalMtuVerified
                && result.journalFinalized
                && result.unrelatedSettingsDrifted
        );
        assert!(
            result
                .error
                .unwrap()
                .contains("exact IP policy readback failed")
        );
        assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
        assert_eq!(backend.evidence, changed);
        assert_eq!(journal.load(document.id).unwrap().document(), &document);
        assert_eq!(journal.mutators(document.id).unwrap().len(), 2);
    }
}

#[test]
fn retentionChecksPolicyWhileAllowingOnlyTheCandidateActiveMtuDifference() {
    for changed in [false, true] {
        let fixture = Fixture::new();
        let (document, mut backend) = setup(&fixture);
        let mut journal = fixture.open();
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .prepare(document.clone())
            .unwrap();
        assert!(matches!(
            MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
                .apply(document.id)
                .unwrap(),
            ApplyResult::Applied { .. }
        ));
        backend.inner.retainConfirmed = true;
        if changed {
            backend
                .evidence
                .active
                .values
                .get_mut("Dhcp")
                .unwrap()
                .value = Some(1);
        }
        let result =
            MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000)).retain(document.id);
        if changed {
            assert!(result.is_err());
            assert_eq!(journal.load(document.id).unwrap().state(), State::Applied);
        } else {
            assert_eq!(result.unwrap().state(), State::Retained);
        }
    }
}

#[test]
fn policyCheckpointRunsThroughTemporaryTrialAndIndependentWatchdogRecovery() {
    let fixture = Fixture::new();
    let (mut document, mut backend) = setup(&fixture);
    let now = crate::watchdog::nowUnixMs().unwrap();
    document.createdAtUnixMs = now;
    document.leaseExpiresAtUnixMs = now + 30000;
    document.nativeOriginal.as_mut().unwrap().capturedAtUnixMs = now;
    backend.inner.clock.store(now, Ordering::SeqCst);
    save(&fixture.value, document.nativeOriginal.as_ref().unwrap());
    let mut journal = fixture.open();
    let result = crate::trial::execute(
        &mut journal,
        &mut backend,
        document.clone(),
        &std::sync::atomic::AtomicBool::new(false),
        crate::watchdog::Policy::default(),
        |control| {
            control.heartbeat()?;
            Ok(7u32)
        },
    )
    .unwrap();
    assert_eq!(result.outcome, crate::trial::Outcome::Completed);
    assert_eq!(result.measurement, Some(7));
    let recovery = result.watchdog.unwrap().recovery.unwrap();
    assert!(
        recovery.originalMtuVerified
            && recovery.journalFinalized
            && !recovery.unrelatedSettingsDrifted
            && recovery.error.is_none()
    );
    assert_eq!(journal.load(document.id).unwrap().state(), State::Restored);
    assert_eq!(journal.mutators(document.id).unwrap().len(), 2);
    assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
}
