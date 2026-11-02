use super::*;
use crate::authorization::{AuthorizationStore, tests::Fixture};
use std::time::Instant;

const OWNER: &str = "S-1-5-21-1-2-3-1000";
const OTHER: &str = "S-1-5-21-1-2-3-1001";

struct TestBackend {
    store: AuthorizationStore,
    captureGate: Arc<AtomicBool>,
    issueGate: Arc<AtomicBool>,
    entered: Arc<AtomicBool>,
    failCapture: bool,
    failIssue: bool,
    commitAfterCancel: bool,
}

impl TestBackend {
    fn new(fixture: &Fixture) -> Self {
        Self {
            store: fixture.open(),
            captureGate: Arc::new(AtomicBool::new(true)),
            issueGate: Arc::new(AtomicBool::new(true)),
            entered: Arc::new(AtomicBool::new(false)),
            failCapture: false,
            failIssue: false,
            commitAfterCancel: false,
        }
    }
}

fn awaitGate(gate: &AtomicBool, cancelled: &AtomicBool) -> ServiceResult<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !gate.load(Ordering::SeqCst) && !cancelled.load(Ordering::SeqCst) {
        if Instant::now() >= deadline {
            return Err("fixture gate deadline".into());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

impl Backend for TestBackend {
    fn capture(&mut self, _: &Proposal, cancelled: &AtomicBool) -> ServiceResult<Capture> {
        self.entered.store(true, Ordering::SeqCst);
        awaitGate(&self.captureGate, cancelled)?;
        if self.failCapture {
            return Err("fixture capture unavailable".into());
        }
        let mut capture = crate::mtu::policy::tests::fixture();
        capture.native.capturedAtUnixMs = nowUnixMs()?;
        Ok(capture)
    }

    fn issue(
        &mut self,
        approval: ApprovedMtu,
        cancelled: &AtomicBool,
    ) -> ServiceResult<Option<MtuGrant>> {
        self.entered.store(true, Ordering::SeqCst);
        awaitGate(&self.issueGate, cancelled)?;
        if self.failIssue {
            return Err("fixture authorization storage unavailable".into());
        }
        if cancelled.load(Ordering::SeqCst) && !self.commitAfterCancel {
            return Ok(None);
        }
        approval.issue(&mut self.store, nowUnixMs()?).map(Some)
    }

    fn revoke(&mut self, id: Uuid, actorSid: &str) -> ServiceResult<()> {
        self.store.revoke(id, actorSid, nowUnixMs()?)
    }
}

fn proposal() -> Proposal {
    Proposal {
        adapterGuid: Uuid::from_u128(100),
        addressFamily: crate::journal::AddressFamily::Ipv4,
        proposedMtu: 1400,
        trialDurationMs: 120_000,
    }
}

fn wait(control: &Control, id: Uuid, phase: Phase) -> Report {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let report = control.get(id, OWNER).unwrap();
        if report.phase == phase {
            return report;
        }
        assert_ne!(report.phase, Phase::Failed, "{:?}", report.detail);
        assert!(
            Instant::now() < deadline,
            "phase {:?}, expected {phase:?}",
            report.phase
        );
        std::thread::sleep(Duration::from_millis(3));
    }
}

fn waitEntered(entered: &AtomicBool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn waitingStatusRequestCannotLookLikeAClockRollback() {
    let fixture = Fixture::new();
    let worker = Worker::new(OWNER, TestBackend::new(&fixture)).unwrap();
    let control = worker.control();
    let job = control.start(proposal(), OWNER).unwrap();
    wait(&control, job.jobId, Phase::Ready);
    let mut state = control.shared.lock().unwrap();
    let before = nowUnixMs().unwrap();
    let observer = control.clone();
    let (entered, receiving) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        entered.send(()).unwrap();
        observer.get(job.jobId, OWNER).unwrap()
    });
    receiving.recv_timeout(Duration::from_secs(1)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    while nowUnixMs().unwrap() <= before {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(state.consent.currentPreview(nowUnixMs().unwrap()).is_some());
    drop(state);
    assert_eq!(thread.join().unwrap().phase, Phase::Ready);
}

fn waitFailed(control: &Control, id: Uuid) -> Report {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let report = control.get(id, OWNER).unwrap();
        if report.phase == Phase::Failed {
            return report;
        }
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn mismatchedNativeIdentityAndNonReducingMtuCannotReachApproval() {
    for fault in 0..3 {
        let fixture = Fixture::new();
        let worker = Worker::new(OWNER, TestBackend::new(&fixture)).unwrap();
        let control = worker.control();
        let mut request = proposal();
        match fault {
            0 => request.adapterGuid = Uuid::from_u128(101),
            1 => request.addressFamily = crate::journal::AddressFamily::Ipv6,
            _ => request.proposedMtu = 1500,
        }
        let job = control.start(request, OWNER).unwrap();
        let report = waitFailed(&control, job.jobId);
        assert!(report.preview.is_none() && report.grant.is_none());
        assert!(!report.executionAvailable);
    }
}

#[test]
fn workerCapturesApprovesAndDurablyRevokesWithoutAnExecutionCapability() {
    let fixture = Fixture::new();
    let worker = Worker::new(OWNER, TestBackend::new(&fixture)).unwrap();
    let control = worker.control();
    assert!(control.start(proposal(), OTHER).is_err());
    let job = control.start(proposal(), OWNER).unwrap();
    let ready = wait(&control, job.jobId, Phase::Ready);
    let preview = ready.preview.unwrap();
    assert!(!ready.executionAvailable);
    assert!(
        control
            .approve(job.jobId, preview.previewId, &"0".repeat(64), OWNER,)
            .is_err()
    );
    assert!(
        control
            .approve(
                job.jobId,
                preview.previewId,
                &preview.checkpointSha256,
                OTHER,
            )
            .is_err()
    );
    control
        .approve(
            job.jobId,
            preview.previewId,
            &preview.checkpointSha256,
            OWNER,
        )
        .unwrap();
    let approved = wait(&control, job.jobId, Phase::Approved);
    approved.validate().unwrap();
    for fault in 0..5 {
        let mut invalid = approved.clone();
        match fault {
            0 => invalid.executionAvailable = true,
            1 => invalid.grant.as_mut().unwrap().allowRetention = true,
            2 => invalid.grant.as_mut().unwrap().checkpointId = Uuid::new_v4(),
            3 => invalid.grant.as_mut().unwrap().checkpointSha256 = "0".repeat(64),
            _ => invalid.preview = None,
        }
        assert!(invalid.validate().is_err());
    }
    let grant = approved.grant.unwrap();
    assert!(!approved.executionAvailable && !grant.allowRetention);
    assert_eq!(grant.checkpointSha256, preview.checkpointSha256);
    assert!(!fixture.open().read(grant.grantId).unwrap().claimed);
    assert!(control.start(proposal(), OWNER).is_err());
    control.cancel(job.jobId, OWNER).unwrap();
    let cancelled = wait(&control, job.jobId, Phase::Cancelled);
    assert!(cancelled.grant.unwrap().revoked);
    assert!(fixture.open().read(grant.grantId).unwrap().revoked);
    let next = control.start(proposal(), OWNER).unwrap();
    assert_ne!(next.jobId, job.jobId);
    assert!(control.get(job.jobId, OWNER).is_err());
}

#[test]
fn blockedCaptureDoesNotBlockStatusOrCancellationAndShutdownReapsTheWorker() {
    let fixture = Fixture::new();
    let backend = TestBackend::new(&fixture);
    backend.captureGate.store(false, Ordering::SeqCst);
    let entered = backend.entered.clone();
    let worker = Worker::new(OWNER, backend).unwrap();
    let control = worker.control();
    let job = control.start(proposal(), OWNER).unwrap();
    waitEntered(&entered);
    assert_eq!(
        control.get(job.jobId, OWNER).unwrap().phase,
        Phase::Capturing
    );
    control.cancel(job.jobId, OWNER).unwrap();
    wait(&control, job.jobId, Phase::Cancelled);
    let next = control.start(proposal(), OWNER).unwrap();
    drop(worker);
    assert!(control.get(next.jobId, OWNER).is_err());
}

#[test]
fn cancellationDuringGrantCommitEitherPreventsOrRevokesTheGrant() {
    for commitAfterCancel in [false, true] {
        let fixture = Fixture::new();
        let mut backend = TestBackend::new(&fixture);
        backend.commitAfterCancel = commitAfterCancel;
        backend.issueGate.store(false, Ordering::SeqCst);
        let entered = backend.entered.clone();
        let worker = Worker::new(OWNER, backend).unwrap();
        let control = worker.control();
        let job = control.start(proposal(), OWNER).unwrap();
        let preview = wait(&control, job.jobId, Phase::Ready).preview.unwrap();
        entered.store(false, Ordering::SeqCst);
        control
            .approve(
                job.jobId,
                preview.previewId,
                &preview.checkpointSha256,
                OWNER,
            )
            .unwrap();
        waitEntered(&entered);
        control.cancel(job.jobId, OWNER).unwrap();
        let report = wait(&control, job.jobId, Phase::Cancelled);
        if commitAfterCancel {
            let grant = report.grant.unwrap();
            assert!(grant.revoked);
            assert!(fixture.open().read(grant.grantId).unwrap().revoked);
        } else {
            assert!(report.grant.is_none());
        }
    }
}

#[test]
fn failedStorageConsumesApprovalAndFailedCaptureCannotCreateAReadyPreview() {
    for failCapture in [false, true] {
        let fixture = Fixture::new();
        let mut backend = TestBackend::new(&fixture);
        backend.failCapture = failCapture;
        backend.failIssue = !failCapture;
        let worker = Worker::new(OWNER, backend).unwrap();
        let control = worker.control();
        let job = control.start(proposal(), OWNER).unwrap();
        if !failCapture {
            let preview = wait(&control, job.jobId, Phase::Ready).preview.unwrap();
            control
                .approve(
                    job.jobId,
                    preview.previewId,
                    &preview.checkpointSha256,
                    OWNER,
                )
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let report = control.get(job.jobId, OWNER).unwrap();
            if report.phase == Phase::Failed {
                assert!(report.grant.is_none());
                assert!(
                    control
                        .approve(job.jobId, Uuid::new_v4(), &"0".repeat(64), OWNER,)
                        .is_err()
                );
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

#[test]
fn realPipeUsesTheWindowsCallerForPreviewApprovalAndRevocation() {
    use crate::{
        protocol::{self, Operation, ReplyBody},
        transport,
    };
    let fixture = Fixture::new();
    let ownerSid = crate::security::currentSid().unwrap();
    let worker = Worker::new(&ownerSid, TestBackend::new(&fixture)).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let name = format!(r"\\.\pipe\epp-preview-test-{}", Uuid::new_v4());
        let pipe = transport::createServer(&name, &ownerSid, &ownerSid, true).unwrap();
        let (stop, receiver) = tokio::sync::watch::channel(false);
        let checkpointStore = protocol::CheckpointStoreStatus {
            schemaVersion: crate::journal::SCHEMA_VERSION,
            verifiedAtUnixMs: nowUnixMs().unwrap(),
            pendingRecoveryCount: 0,
        };
        let server = transport::serve(
            pipe,
            name.clone(),
            ownerSid.clone(),
            ownerSid.clone(),
            receiver,
            transport::ServerState::readOnly(checkpointStore, Some(worker.control())),
        );
        let client = async {
            let (first, session) =
                transport::localTestExchange(&name, Operation::StartMtuPreview(proposal()))
                    .await
                    .unwrap();
            let request =
                |operation| transport::exchange(&name, std::process::id(), session, operation);
            let ReplyBody::MtuPreview(job) = first.result else {
                panic!("missing preview job")
            };
            let mut ready = None;
            let deadline = Instant::now() + Duration::from_secs(5);
            while ready.is_none() {
                let ReplyBody::MtuPreview(report) =
                    request(Operation::GetMtuPreview { jobId: job.jobId })
                        .await
                        .unwrap()
                        .result
                else {
                    panic!("missing preview report")
                };
                assert!(Instant::now() < deadline);
                if report.phase == Phase::Ready {
                    ready = report.preview;
                } else {
                    assert_ne!(report.phase, Phase::Failed, "{:?}", report.detail);
                    tokio::time::sleep(Duration::from_millis(3)).await;
                }
            }
            let preview = ready.unwrap();
            let bad = request(Operation::ApproveMtuPreview {
                jobId: job.jobId,
                previewId: preview.previewId,
                checkpointSha256: "0".repeat(64),
            })
            .await
            .unwrap();
            assert!(matches!(bad.result, ReplyBody::Rejected { .. }));
            request(Operation::ApproveMtuPreview {
                jobId: job.jobId,
                previewId: preview.previewId,
                checkpointSha256: preview.checkpointSha256,
            })
            .await
            .unwrap();
            let mut grantId = None;
            while grantId.is_none() {
                let ReplyBody::MtuPreview(report) =
                    request(Operation::GetMtuPreview { jobId: job.jobId })
                        .await
                        .unwrap()
                        .result
                else {
                    panic!("missing approval report")
                };
                assert!(Instant::now() < deadline);
                assert!(!report.executionAvailable);
                if report.phase == Phase::Approved {
                    grantId = Some(report.grant.unwrap().grantId);
                } else {
                    assert_ne!(report.phase, Phase::Failed, "{:?}", report.detail);
                    tokio::time::sleep(Duration::from_millis(3)).await;
                }
            }
            assert_eq!(
                fixture
                    .open()
                    .read(grantId.unwrap())
                    .unwrap()
                    .grant
                    .authorizedUserSid,
                ownerSid
            );
            request(Operation::CancelMtuPreview { jobId: job.jobId })
                .await
                .unwrap();
            loop {
                let ReplyBody::MtuPreview(report) =
                    request(Operation::GetMtuPreview { jobId: job.jobId })
                        .await
                        .unwrap()
                        .result
                else {
                    panic!("missing cancellation report")
                };
                assert!(Instant::now() < deadline);
                if report.phase == Phase::Cancelled {
                    assert!(report.grant.unwrap().revoked);
                    break;
                }
                assert_ne!(report.phase, Phase::Failed, "{:?}", report.detail);
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
            let status = transport::query(&name, std::process::id(), session)
                .await
                .unwrap();
            assert!(!status.modificationsPermitted && !status.rollbackAvailable);
            crate::security::assertNoThreadImpersonation();
            stop.send(true).unwrap();
        };
        let (result, ()) = tokio::join!(server, client);
        result.unwrap();
    });
}
