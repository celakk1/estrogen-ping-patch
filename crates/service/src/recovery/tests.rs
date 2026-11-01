use super::*;
use crate::{journal::AddressFamily, mtu::Snapshot};
use rusqlite::Connection;
use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[path = "policy_tests.rs"]
mod policy_tests;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

struct Fixture {
    directory: PathBuf,
    journal: PathBuf,
    value: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "epp-coordinator-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_FIXTURE.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&directory).unwrap();
        let fixture = Self {
            journal: directory.join("recovery.sqlite3"),
            value: directory.join("simulated-interface.json"),
            directory,
        };
        save(&fixture.value, &nativeFixture());
        fixture
    }
    fn open(&self) -> Journal {
        Journal::open(&self.journal).unwrap()
    }
    fn backend(&self, clock: Arc<AtomicU64>) -> Backend {
        Backend {
            value: self.value.clone(),
            journal: self.journal.clone(),
            clock,
            writes: Vec::new(),
            fault: Fault::None,
            allow: true,
            retainConfirmed: false,
            revokeAfterIntent: false,
            applyChecks: 0,
            pauseAfterWrite: None,
            mutatorLive: false,
            observations: 0,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let (Ok(directory), Ok(temp)) = (
            self.directory.canonicalize(),
            std::env::temp_dir().canonicalize(),
        ) && directory.parent() == Some(temp.as_path())
            && directory
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("epp-coordinator-")
        {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}

fn save(path: &Path, value: &Snapshot) {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();
    file.write_all(&serde_json::to_vec(value).unwrap()).unwrap();
    file.sync_all().unwrap();
}
fn read(path: &Path) -> Snapshot {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
pub(crate) fn nativeFixture() -> Snapshot {
    serde_json::from_value(serde_json::json!({"schemaVersion":1,"capturedAtUnixMs":1000,"adapterGuid":Uuid::from_u128(100),"addressFamily":"ipv4","interfaceLuid":"18446744073709551615","interfaceIndex":7,"alias":"simulated","description":"simulated interface","linkMtu":1500,"interfaceType":6,"tunnelType":0,"operationalStatus":1,"mediaConnectState":1,"interfaceStatusFlags":5,
        "os":{"major":10,"minor":0,"build":26100,"updateRevision":100,"nativeArchitecture":9},
        "driver":{"status":"captured","identity":{"version":"1.2.3","infPath":"epp-fixture.inf","infSection":"fixture","deviceInstanceId":"ROOT\\EPP_FIXTURE\\0001"}},
        "settings":{"advertisingEnabled":false,"forwardingEnabled":false,"weakHostSend":false,"weakHostReceive":false,"useAutomaticMetric":true,"useNeighborUnreachabilityDetection":true,"managedAddressConfigurationSupported":false,"otherStatefulConfigurationSupported":false,"advertiseDefaultRoute":false,"routerDiscoveryBehavior":0,"dadTransmits":1,"baseReachableTime":30000,"retransmitTime":1000,"pathMtuDiscoveryTimeout":600000,"linkLocalAddressBehavior":0,"linkLocalAddressTimeout":0,"zoneIndices":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sitePrefixLength":0,"metric":25,"nlMtu":1500,"disableDefaultRoutes":false}})).unwrap()
}
fn document(id: u128) -> MtuCheckpoint {
    let native = nativeFixture();
    MtuCheckpoint {
        schemaVersion: 2,
        id: Uuid::from_u128(id),
        createdAtUnixMs: 1000,
        leaseExpiresAtUnixMs: 10000,
        authorizedUserSid: "S-1-5-21-1-2-3-1000".into(),
        context: native.journalContext().unwrap(),
        addressFamily: AddressFamily::Ipv4,
        originalMtu: 1500,
        proposedMtu: 1400,
        nativeOriginal: Some(native),
        policyOriginal: None,
    }
}

#[test]
fn serviceOwnedOriginsCommitExactlyAndMissingOrDriftedEvidenceBlocksApply() {
    use crate::mtu::origins::{OriginCapture, RawValue, tests::fixture as originFixture};
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let mut backend = fixture.backend(Arc::new(AtomicU64::new(1000)));
    let mut document = document(91);
    let native = document.nativeOriginal.as_mut().unwrap();
    native.schemaVersion = 2;
    native.registryOrigins = Some(OriginCapture::Unavailable {
        error: "fixture denied".into(),
    });
    save(&fixture.value, native);
    assert!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .prepare(document.clone())
            .is_err()
    );
    assert!(journal.load(document.id).is_err());
    assert!(backend.writes.is_empty());
    let native = document.nativeOriginal.as_mut().unwrap();
    native.registryOrigins = Some(OriginCapture::Captured {
        evidence: originFixture(native.adapterGuid),
    });
    save(&fixture.value, native);
    MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .prepare(document.clone())
        .unwrap();
    let stored = journal.load(document.id).unwrap();
    assert_eq!(stored.document(), &document);
    let mut changed = read(&fixture.value);
    let Some(OriginCapture::Captured { evidence }) = &mut changed.registryOrigins else {
        unreachable!()
    };
    evidence.stacks[0].values[5].value = Some(RawValue {
        valueType: 1,
        dataHex: "0000".into(),
    });
    save(&fixture.value, &changed);
    assert!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .apply(document.id)
            .is_err()
    );
    assert!(backend.writes.is_empty());
    assert_eq!(read(&fixture.value), changed);
    assert_eq!(journal.load(document.id).unwrap().document(), &document);
}

#[test]
fn offlineMtuRecoveryPreservesExternalOriginsAndDoesNotNeedTheirReaderOrApplyPermission() {
    use crate::mtu::origins::{OriginCapture, RawValue, tests::fixture as originFixture};
    for unavailable in [false, true] {
        let fixture = Fixture::new();
        let mut journal = fixture.open();
        let clock = Arc::new(AtomicU64::new(1000));
        let mut backend = fixture.backend(clock.clone());
        let mut document = document(92);
        document.schemaVersion = 3;
        let native = document.nativeOriginal.as_mut().unwrap();
        native.schemaVersion = 2;
        native.registryOrigins = Some(OriginCapture::Captured {
            evidence: originFixture(native.adapterGuid),
        });
        save(&fixture.value, native);
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .prepare(document.clone())
            .unwrap();
        assert!(matches!(
            MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
                .apply(document.id)
                .unwrap(),
            ApplyResult::Applied { .. }
        ));
        drop(journal);
        let mut changed = read(&fixture.value);
        if unavailable {
            changed.registryOrigins = Some(OriginCapture::Unavailable {
                error: "fixture reader unavailable after restart".into(),
            });
        } else {
            let Some(OriginCapture::Captured { evidence }) = &mut changed.registryOrigins else {
                unreachable!()
            };
            evidence.stacks[0].values[1].value = Some(RawValue {
                valueType: 4,
                dataHex: "01000000".into(),
            });
        }
        let expectedOrigins = changed.registryOrigins.clone();
        save(&fixture.value, &changed);
        backend.allow = false;
        clock.store(20000, Ordering::SeqCst);
        let mut journal = fixture.open();
        let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(20000))
            .restore(document.id)
            .unwrap();
        assert!(
            result.originalMtuVerified
                && result.journalFinalized
                && result.unrelatedSettingsDrifted
        );
        let restored = read(&fixture.value);
        assert_eq!(restored.settings.nlMtu, 1500);
        assert_eq!(restored.registryOrigins, expectedOrigins);
        assert_eq!(journal.load(document.id).unwrap().document(), &document);
        assert_eq!(journal.mutators(document.id).unwrap().len(), 2);
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Fault {
    None,
    BeforeApply,
    AfterApply,
    NoApply,
    OtherDrift,
    ThirdValue,
    RestoreFails,
}
struct Backend {
    value: PathBuf,
    journal: PathBuf,
    clock: Arc<AtomicU64>,
    writes: Vec<(u32, WritePurpose)>,
    fault: Fault,
    allow: bool,
    retainConfirmed: bool,
    revokeAfterIntent: bool,
    applyChecks: usize,
    pauseAfterWrite: Option<WritePurpose>,
    mutatorLive: bool,
    observations: usize,
}
impl MtuBackend for Backend {
    fn authorize(
        &mut self,
        _: &MtuCheckpoint,
        action: AuthorizationAction,
        _: u64,
    ) -> ServiceResult<()> {
        if !self.allow {
            return Err("Simulated authorization denied".into());
        }
        if action == AuthorizationAction::Apply {
            self.applyChecks += 1;
            if self.revokeAfterIntent && self.applyChecks > 1 {
                return Err("Simulated authorization revoked after durable intent".into());
            }
        }
        if action == AuthorizationAction::Retain && !self.retainConfirmed {
            return Err("Simulated retention lacks confirmation".into());
        }
        Ok(())
    }
    fn observe(&mut self, _: &MtuCheckpoint) -> ServiceResult<Observation> {
        self.observations += 1;
        let mut native = read(&self.value);
        native.capturedAtUnixMs = self.clock.load(Ordering::SeqCst);
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
        register: &mut MutatorRegistrar<'_>,
    ) -> ServiceResult<()> {
        let checkpoint = Journal::open(&self.journal)?.load(document.id)?;
        assert!(matches!(
            (purpose, checkpoint.state()),
            (WritePurpose::Apply, State::Applying)
                | (
                    WritePurpose::Restore,
                    State::Applying | State::Applied | State::Restoring | State::RecoveryRequired
                )
        ));
        assert_eq!(checkpoint.document(), document);
        if matches!(document.schemaVersion, 3 | 4) {
            register(crate::journal::MutatorIdentity {
                processId: 100 + self.writes.len() as u32,
                creationTime100ns: "10000".into(),
            })?;
        }
        self.writes.push((value, purpose));
        if purpose == WritePurpose::Apply && self.fault == Fault::BeforeApply {
            return Err("Simulated write failed before mutation".into());
        }
        if purpose == WritePurpose::Restore && self.fault == Fault::RestoreFails {
            return Err("Simulated restore failed".into());
        }
        let mut native = read(&self.value);
        assert_eq!(native.settings.nlMtu, expected.mtu);
        if !(purpose == WritePurpose::Apply && self.fault == Fault::NoApply) {
            native.settings.nlMtu = value;
        }
        if purpose == WritePurpose::Apply && self.fault == Fault::OtherDrift {
            native.settings.metric = 99;
        }
        if purpose == WritePurpose::Apply && self.fault == Fault::ThirdValue {
            native.settings.nlMtu = 1300;
        }
        save(&self.value, &native);
        if self.pauseAfterWrite == Some(purpose) {
            println!("COORDINATOR_WRITE_READY");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        }
        if purpose == WritePurpose::Apply && self.fault == Fault::AfterApply {
            return Err("Simulated write reported failure after mutation".into());
        }
        Ok(())
    }

    fn waitForMutator(&mut self, _: &crate::journal::MutatorRecord) -> ServiceResult<()> {
        if self.mutatorLive {
            Err("Simulated predecessor has not exited".into())
        } else {
            Ok(())
        }
    }
}

#[test]
fn trackedPredecessorBlocksObservationAndRestoreUntilExitWithoutRenewingPermission() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let clock = Arc::new(AtomicU64::new(1000));
    let mut backend = fixture.backend(clock.clone());
    let mut document = document(90);
    document.schemaVersion = 3;
    MtuCoordinator::new(&mut journal, &mut backend, || {
        Ok(clock.load(Ordering::SeqCst))
    })
    .prepare(document.clone())
    .unwrap();
    assert!(matches!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(
            clock.load(Ordering::SeqCst)
        ))
        .apply(document.id)
        .unwrap(),
        ApplyResult::Applied { .. }
    ));
    assert_eq!(journal.mutators(document.id).unwrap().len(), 1);
    backend.mutatorLive = true;
    backend.allow = false;
    clock.store(20000, Ordering::SeqCst);
    let observations = backend.observations;
    let writes = backend.writes.len();
    let recovered = MtuCoordinator::new(&mut journal, &mut backend, || {
        Ok(clock.load(Ordering::SeqCst))
    })
    .restore(document.id)
    .unwrap();
    assert!(!recovered.originalMtuVerified && !recovered.journalFinalized);
    assert_eq!(backend.observations, observations);
    assert_eq!(backend.writes.len(), writes);
    assert_eq!(read(&fixture.value).settings.nlMtu, 1400);
    backend.mutatorLive = false;
    let recovered = MtuCoordinator::new(&mut journal, &mut backend, || {
        Ok(clock.load(Ordering::SeqCst))
    })
    .restore(document.id)
    .unwrap();
    assert!(recovered.originalMtuVerified && recovered.journalFinalized);
    assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
    assert_eq!(journal.mutators(document.id).unwrap().len(), 2);
}

#[test]
fn registrationCommitFailureStopsTheTrackedWriteBeforeItsMutation() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let clock = Arc::new(AtomicU64::new(1000));
    let mut backend = fixture.backend(clock.clone());
    let mut document = document(91);
    document.schemaVersion = 3;
    MtuCoordinator::new(&mut journal, &mut backend, || {
        Ok(clock.load(Ordering::SeqCst))
    })
    .prepare(document.clone())
    .unwrap();
    Connection::open(&fixture.journal).unwrap().execute_batch("CREATE TRIGGER fail_mutator BEFORE INSERT ON checkpoint_mutators BEGIN SELECT RAISE(ABORT,'test full storage'); END;").unwrap();
    let result = MtuCoordinator::new(&mut journal, &mut backend, || {
        Ok(clock.load(Ordering::SeqCst))
    })
    .apply(document.id)
    .unwrap();
    assert!(failed(result).originalMtuVerified);
    assert!(backend.writes.is_empty());
    assert!(journal.mutators(document.id).unwrap().is_empty());
    assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
}

#[test]
fn candidateValueWithoutAnApplyProcessIsAnExternalChange() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let clock = Arc::new(AtomicU64::new(1000));
    let mut backend = fixture.backend(clock.clone());
    let mut document = document(92);
    document.schemaVersion = 3;
    MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .prepare(document.clone())
        .unwrap();
    let original = backend.observe(&document).unwrap();
    journal
        .transition(
            document.id,
            State::Prepared,
            State::Applying,
            1000,
            Some(original),
        )
        .unwrap();
    let mut external = read(&fixture.value);
    external.settings.nlMtu = 1400;
    save(&fixture.value, &external);
    let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .restore(document.id)
        .unwrap();
    assert!(!result.originalMtuVerified && !result.journalFinalized);
    assert!(result.error.unwrap().contains("external MTU change"));
    assert!(backend.writes.is_empty());
    assert_eq!(read(&fixture.value).settings.nlMtu, 1400);
}
fn failed(result: ApplyResult) -> RecoveryResult {
    match result {
        ApplyResult::Failed { recovery, .. } => recovery,
        _ => panic!("Expected failed apply outcome"),
    }
}

#[test]
fn coordinatorCommitsNativeEvidenceBeforeWritesAndRestoresWithoutAuthorityRenewal() {
    let fixture = Fixture::new();
    let clock = Arc::new(AtomicU64::new(1000));
    let mut journal = fixture.open();
    let mut backend = fixture.backend(clock.clone());
    let document = document(1);
    {
        let mut coordinator = MtuCoordinator::new(&mut journal, &mut backend, || {
            Ok(clock.load(Ordering::SeqCst))
        });
        coordinator.prepare(document.clone()).unwrap();
        assert!(matches!(
            coordinator.apply(document.id).unwrap(),
            ApplyResult::Applied { .. }
        ));
        assert!(coordinator.retain(document.id).is_err());
    }
    assert_eq!(read(&fixture.value).settings.nlMtu, 1400);
    backend.allow = false;
    clock.store(20000, Ordering::SeqCst);
    let result = MtuCoordinator::new(&mut journal, &mut backend, || {
        Ok(clock.load(Ordering::SeqCst))
    })
    .restore(document.id)
    .unwrap();
    assert!(result.originalMtuVerified && result.journalFinalized);
    assert_eq!(result.durableState, State::Restored);
    assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
    assert_eq!(backend.writes.len(), 2);
    assert!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(20000))
            .restore(document.id)
            .is_err()
    );
}

#[test]
fn backupAndIntentFailureBlockWritesAndRevocationAfterIntentCannotMutate() {
    let fixture = Fixture::new();
    let clock = Arc::new(AtomicU64::new(1000));
    let mut journal = fixture.open();
    let mut backend = fixture.backend(clock.clone());
    let document = document(2);
    backend.allow = false;
    assert!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .prepare(document.clone())
            .is_err()
    );
    assert!(journal.pendingRecovery().unwrap().is_empty());
    backend.allow = true;
    MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .prepare(document.clone())
        .unwrap();
    let connection = Connection::open(&fixture.journal).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_intent BEFORE INSERT ON checkpoint_events WHEN json_extract(NEW.event_json,'$.state')='applying' BEGIN SELECT RAISE(ABORT,'simulated intent failure'); END;").unwrap();
    assert!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .apply(document.id)
            .is_err()
    );
    assert!(backend.writes.is_empty());
    assert_eq!(journal.load(document.id).unwrap().state(), State::Prepared);
    connection
        .execute_batch("DROP TRIGGER fail_intent")
        .unwrap();
    backend.revokeAfterIntent = true;
    backend.applyChecks = 0;
    let result = failed(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .apply(document.id)
            .unwrap(),
    );
    assert!(result.originalMtuVerified && result.journalFinalized);
    assert!(backend.writes.is_empty());
}

#[test]
fn failedAndUnconfirmedWritesNeverBecomeAppliedAndCanRecoverTheirOriginal() {
    for fault in [
        Fault::BeforeApply,
        Fault::AfterApply,
        Fault::NoApply,
        Fault::OtherDrift,
    ] {
        let fixture = Fixture::new();
        let clock = Arc::new(AtomicU64::new(1000));
        let mut journal = fixture.open();
        let mut backend = fixture.backend(clock.clone());
        backend.fault = fault;
        let document = document(3);
        let result = {
            let mut coordinator = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000));
            coordinator.prepare(document.clone()).unwrap();
            failed(coordinator.apply(document.id).unwrap())
        };
        assert!(result.originalMtuVerified && result.journalFinalized);
        assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
        assert_eq!(result.unrelatedSettingsDrifted, fault == Fault::OtherDrift);
        if fault == Fault::OtherDrift {
            assert_eq!(read(&fixture.value).settings.metric, 99);
        }
    }
}

#[test]
fn externalMtuOrIdentityChangesAreNeverOverwrittenAndFailedRestoresStayPending() {
    for fault in [Fault::ThirdValue, Fault::RestoreFails] {
        let fixture = Fixture::new();
        let clock = Arc::new(AtomicU64::new(1000));
        let mut journal = fixture.open();
        let mut backend = fixture.backend(clock.clone());
        let document = document(4);
        {
            let mut coordinator = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000));
            coordinator.prepare(document.clone()).unwrap();
            coordinator.apply(document.id).unwrap();
        }
        if fault == Fault::ThirdValue {
            let mut value = read(&fixture.value);
            value.settings.nlMtu = 1300;
            save(&fixture.value, &value);
        } else {
            backend.fault = Fault::RestoreFails;
        }
        let before = backend.writes.len();
        let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .restore(document.id)
            .unwrap();
        assert!(!result.originalMtuVerified && !result.journalFinalized);
        assert_eq!(result.durableState, State::RecoveryRequired);
        assert!(result.error.is_some());
        if fault == Fault::ThirdValue {
            assert_eq!(backend.writes.len(), before);
            assert_eq!(read(&fixture.value).settings.nlMtu, 1300);
        }
    }
}

#[test]
fn storageFailureStillAllowsVerifiedRollbackButNeverClaimsJournalCompletion() {
    let fixture = Fixture::new();
    let clock = Arc::new(AtomicU64::new(1000));
    let mut journal = fixture.open();
    let mut backend = fixture.backend(clock.clone());
    let document = document(5);
    {
        let mut coordinator = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000));
        coordinator.prepare(document.clone()).unwrap();
        coordinator.apply(document.id).unwrap();
    }
    let connection = Connection::open(&fixture.journal).unwrap();
    connection.execute_batch("CREATE TRIGGER fail_recovery_events BEFORE INSERT ON checkpoint_events BEGIN SELECT RAISE(ABORT,'simulated full or unwritable event store'); END;").unwrap();
    let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .restore(document.id)
        .unwrap();
    assert!(result.originalMtuVerified && !result.journalFinalized);
    assert_eq!(result.durableState, State::Applied);
    assert!(result.error.is_some());
    assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
    connection
        .execute_batch("DROP TRIGGER fail_recovery_events")
        .unwrap();
    let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .restore(document.id)
        .unwrap();
    assert!(result.originalMtuVerified && result.journalFinalized);
}

#[test]
fn retentionRequiresConfirmationFreshReadbackAndUnchangedNativeSettings() {
    let fixture = Fixture::new();
    let clock = Arc::new(AtomicU64::new(1000));
    let mut journal = fixture.open();
    let mut backend = fixture.backend(clock.clone());
    let document = document(6);
    {
        let mut coordinator = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000));
        coordinator.prepare(document.clone()).unwrap();
        coordinator.apply(document.id).unwrap();
    }
    backend.retainConfirmed = true;
    let mut value = read(&fixture.value);
    value.settings.metric = 99;
    save(&fixture.value, &value);
    assert!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .retain(document.id)
            .is_err()
    );
    assert_eq!(journal.load(document.id).unwrap().state(), State::Applied);
    value.settings.metric = 25;
    save(&fixture.value, &value);
    assert_eq!(
        MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .retain(document.id)
            .unwrap()
            .state(),
        State::Retained
    );
}

#[test]
fn nativeCheckpointSchemaGuardsContextFreshnessAndPreservesLegacyHistory() {
    let original = document(7);
    assert!(original.validate().is_ok());
    let mut stale = original.clone();
    stale.nativeOriginal.as_mut().unwrap().capturedAtUnixMs = 1100;
    assert!(stale.validate().is_err());
    let mut mismatched = original.clone();
    mismatched.nativeOriginal.as_mut().unwrap().settings.nlMtu = 1499;
    assert!(mismatched.validate().is_err());
    let mut missing = original.clone();
    missing.nativeOriginal = None;
    assert!(missing.validate().is_err());
    let fixture = Fixture::new();
    let mut legacy = original.clone();
    legacy.schemaVersion = 1;
    legacy.nativeOriginal = None;
    let mut journal = fixture.open();
    journal.prepare(legacy.clone(), 1000).unwrap();
    drop(journal);
    let connection = Connection::open(&fixture.journal).unwrap();
    connection
        .execute_batch("DROP TABLE checkpoint_mutators; DROP TABLE mutator_heads;")
        .unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    drop(connection);
    let journal = fixture.open();
    assert_eq!(journal.load(legacy.id).unwrap().document(), &legacy);
    let connection = Connection::open(&fixture.journal).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        crate::journal::SCHEMA_VERSION
    );
}

#[test]
fn nativeObservationsSurviveLargeEventsAndRejectMissingEvidence() {
    let fixture = Fixture::new();
    let clock = Arc::new(AtomicU64::new(1000));
    let mut journal = fixture.open();
    let mut backend = fixture.backend(clock.clone());
    let mut document = document(8);
    let mut value = read(&fixture.value);
    value.alias = "a".repeat(1500);
    value.description = "d".repeat(1500);
    save(&fixture.value, &value);
    document.nativeOriginal = Some(value);
    {
        let mut coordinator = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000));
        coordinator.prepare(document.clone()).unwrap();
        coordinator.apply(document.id).unwrap();
    }
    assert!(
        serde_json::to_string(journal.load(document.id).unwrap().events().last().unwrap())
            .unwrap()
            .len()
            > 4096
    );
    let mut observed = backend.observe(&document).unwrap();
    observed.native = None;
    assert!(
        journal
            .transition(
                document.id,
                State::Applied,
                State::Retained,
                1000,
                Some(observed)
            )
            .is_err()
    );
    drop(journal);
    assert_eq!(
        fixture.open().load(document.id).unwrap().state(),
        State::Applied
    );
}

#[test]
fn nativeIdentityDriftBlocksRecoveryButGuidMatchedReindexingDoesNot() {
    for changedDriver in [true, false] {
        let fixture = Fixture::new();
        let clock = Arc::new(AtomicU64::new(1000));
        let mut journal = fixture.open();
        let mut backend = fixture.backend(clock);
        let document = document(9);
        {
            let mut coordinator = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000));
            coordinator.prepare(document.clone()).unwrap();
            coordinator.apply(document.id).unwrap();
        }
        let mut value = read(&fixture.value);
        value.interfaceIndex = 41;
        value.interfaceLuid = "123456".into();
        value.alias = "renamed".into();
        if changedDriver {
            value.os.updateRevision += 1;
        }
        save(&fixture.value, &value);
        let result = MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
            .restore(document.id)
            .unwrap();
        assert_eq!(result.originalMtuVerified, !changedDriver);
        assert_eq!(result.journalFinalized, !changedDriver);
        assert_eq!(backend.writes.len(), if changedDriver { 1 } else { 2 });
        assert_eq!(
            read(&fixture.value).settings.nlMtu,
            if changedDriver { 1400 } else { 1500 }
        );
    }
}

#[test]
fn reopeningDoesNotRewriteVerifiedJournalAndCorruptLegacyIsNotUpgraded() {
    let fixture = Fixture::new();
    let mut journal = fixture.open();
    let document = document(10);
    journal.prepare(document.clone(), 1000).unwrap();
    drop(journal);
    let before = std::fs::read(&fixture.journal).unwrap();
    drop(fixture.open());
    assert_eq!(before, std::fs::read(&fixture.journal).unwrap());
    let connection = Connection::open(&fixture.journal).unwrap();
    connection.pragma_update(None, "user_version", 1).unwrap();
    connection
        .execute("UPDATE checkpoints SET sha256=?1", ["0".repeat(64)])
        .unwrap();
    drop(connection);
    assert!(Journal::open(&fixture.journal).is_err());
    let connection = Connection::open(&fixture.journal).unwrap();
    assert_eq!(
        connection
            .pragma_query_value::<u32, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        1
    );
}

#[test]
fn coordinatorRecoversAfterProcessTerminationDuringApplyAndRestore() {
    use std::{
        io::{BufRead, BufReader},
        process::{Command, Stdio},
        sync::mpsc,
        time::Duration,
    };
    for phase in ["apply", "restore"] {
        let fixture = Fixture::new();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "recovery::tests::coordinatorCrashWorker",
                "--ignored",
                "--nocapture",
            ])
            .env("EPP_COORDINATOR_CRASH_DIRECTORY", &fixture.directory)
            .env("EPP_COORDINATOR_CRASH_PHASE", phase)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line.is_ok_and(|line| line.contains("COORDINATOR_WRITE_READY")) {
                    let _ = sender.send(());
                    break;
                }
            }
        });
        let ready = receiver.recv_timeout(Duration::from_secs(15));
        let _ = child.kill();
        let output = child.wait_with_output().unwrap();
        reader.join().unwrap();
        assert!(
            ready.is_ok(),
            "Coordinator crash worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut journal = fixture.open();
        let checkpoint = journal.load(Uuid::from_u128(11)).unwrap();
        assert_eq!(
            checkpoint.state(),
            if phase == "apply" {
                State::Applying
            } else {
                State::Restoring
            }
        );
        assert_eq!(
            read(&fixture.value).settings.nlMtu,
            if phase == "apply" { 1400 } else { 1500 }
        );
        let clock = Arc::new(AtomicU64::new(20000));
        let mut backend = fixture.backend(clock);
        backend.allow = false;
        let results = MtuCoordinator::new(&mut journal, &mut backend, || Ok(20000))
            .restoreAllPending()
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].originalMtuVerified && results[0].journalFinalized);
        assert_eq!(read(&fixture.value).settings.nlMtu, 1500);
        assert_eq!(backend.writes.len(), usize::from(phase == "apply"));
        assert!(journal.pendingRecovery().unwrap().is_empty());
    }
}

#[test]
#[ignore = "only spawned by the coordinator process termination test"]
fn coordinatorCrashWorker() {
    let directory = PathBuf::from(
        std::env::var_os("EPP_COORDINATOR_CRASH_DIRECTORY").expect("test-only fixture directory"),
    )
    .canonicalize()
    .unwrap();
    assert_eq!(
        directory.parent(),
        Some(std::env::temp_dir().canonicalize().unwrap().as_path())
    );
    assert!(
        directory
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("epp-coordinator-")
    );
    let phase = std::env::var("EPP_COORDINATOR_CRASH_PHASE").unwrap();
    let fixture = Fixture {
        journal: directory.join("recovery.sqlite3"),
        value: directory.join("simulated-interface.json"),
        directory,
    };
    let clock = Arc::new(AtomicU64::new(1000));
    let mut journal = fixture.open();
    let mut backend = fixture.backend(clock);
    let document = document(11);
    MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .prepare(document.clone())
        .unwrap();
    if phase == "apply" {
        backend.pauseAfterWrite = Some(WritePurpose::Apply);
    } else {
        assert_eq!(phase, "restore");
    }
    MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .apply(document.id)
        .unwrap();
    backend.pauseAfterWrite = Some(WritePurpose::Restore);
    MtuCoordinator::new(&mut journal, &mut backend, || Ok(1000))
        .restore(document.id)
        .unwrap();
    panic!("Coordinator crash worker unexpectedly completed");
}
