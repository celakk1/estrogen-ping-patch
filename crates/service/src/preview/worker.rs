use super::*;
use crate::{
    consent::{ApprovedMtu, MtuConsent},
    journal::MtuCheckpoint,
    mtu::policy::Capture,
    storage::{OwnedAuthorization, OwnedJournal},
    transport::nowUnixMs,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    thread::JoinHandle,
    time::Duration,
};

trait Backend: Send {
    fn capture(&mut self, proposal: &Proposal, cancelled: &AtomicBool) -> ServiceResult<Capture>;
    fn issue(
        &mut self,
        approval: ApprovedMtu,
        cancelled: &AtomicBool,
    ) -> ServiceResult<Option<MtuGrant>>;
    fn revoke(&mut self, id: Uuid, ownerSid: &str) -> ServiceResult<()>;
}

struct WindowsBackend {
    journal: OwnedJournal,
    authorization: Option<OwnedAuthorization>,
    approvedCheckpoint: Option<(Uuid, MtuCheckpoint)>,
}

impl Backend for WindowsBackend {
    fn capture(&mut self, proposal: &Proposal, cancelled: &AtomicBool) -> ServiceResult<Capture> {
        if cancelled.load(Ordering::SeqCst) {
            return Err("MTU preview was cancelled".into());
        }
        if self.journal.hasPendingWork()? {
            return Err(
                "Unfinished recovery or final verification blocks another experiment".into(),
            );
        }
        if cancelled.load(Ordering::SeqCst) {
            return Err("MTU preview was cancelled".into());
        }
        crate::mtu::policy::inspect(proposal.adapterGuid, proposal.addressFamily, cancelled)
    }

    fn issue(
        &mut self,
        approval: ApprovedMtu,
        cancelled: &AtomicBool,
    ) -> ServiceResult<Option<MtuGrant>> {
        if self.journal.hasPendingWork()? {
            return Err("Unfinished recovery or final verification blocks approval".into());
        }
        if cancelled.load(Ordering::SeqCst) {
            return Ok(None);
        }
        if self.authorization.is_none() {
            self.authorization = Some(self.journal.authorization()?);
        }
        if cancelled.load(Ordering::SeqCst) {
            return Ok(None);
        }
        let (grant, document) = approval.issueWithOriginal(
            &mut self
                .authorization
                .as_mut()
                .ok_or("Authorization storage unavailable")?
                .store,
            nowUnixMs()?,
        )?;
        self.approvedCheckpoint = Some((grant.id, document));
        Ok(Some(grant))
    }

    fn revoke(&mut self, id: Uuid, ownerSid: &str) -> ServiceResult<()> {
        self.authorization
            .as_mut()
            .ok_or("Authorization storage unavailable")?
            .store
            .revoke(id, ownerSid, nowUnixMs()?)?;
        if self
            .approvedCheckpoint
            .as_ref()
            .is_some_and(|(grantId, _)| *grantId == id)
        {
            self.approvedCheckpoint = None;
        }
        Ok(())
    }
}

struct Shared {
    ownerSid: String,
    consent: MtuConsent,
    report: Option<Report>,
    cancelled: Arc<AtomicBool>,
}

impl Shared {
    fn checkActor(&self, actorSid: &str) -> ServiceResult<()> {
        if actorSid != self.ownerSid {
            return Err("MTU preview belongs to a different Windows user".into());
        }
        Ok(())
    }

    fn current(&mut self, jobId: Uuid, now: u64) -> ServiceResult<Report> {
        let report = self.report.as_mut().ok_or("No MTU preview is available")?;
        if report.jobId != jobId {
            return Err("MTU preview identifier does not match the current job".into());
        }
        if report.phase == Phase::Ready && self.consent.currentPreview(now).is_none() {
            report.phase = Phase::Expired;
        }
        if report.phase == Phase::Approved
            && report
                .grant
                .as_ref()
                .is_some_and(|grant| now >= grant.expiresAtUnixMs)
        {
            report.phase = Phase::Expired;
        }
        Ok(report.clone())
    }

    fn fail(&mut self, error: &str) {
        if let Some(report) = &mut self.report {
            report.phase = Phase::Failed;
            report.detail = Some(error.chars().take(256).collect());
        }
    }
}

enum Command {
    Capture(Uuid, Proposal),
    Issue(Uuid, Box<ApprovedMtu>),
    Revoke(Uuid, Uuid),
    Stop,
}

#[derive(Clone)]
pub(crate) struct Control {
    shared: Arc<Mutex<Shared>>,
    sender: SyncSender<Command>,
    stopped: Arc<AtomicBool>,
}

impl Control {
    fn lock(&self, actorSid: &str) -> ServiceResult<MutexGuard<'_, Shared>> {
        if self.stopped.load(Ordering::SeqCst) {
            return Err("MTU preview worker is unavailable".into());
        }
        let state = self
            .shared
            .lock()
            .map_err(|_| "MTU preview state is unavailable")?;
        state.checkActor(actorSid)?;
        Ok(state)
    }

    fn enqueue(&self, command: Command, state: &mut Shared) -> ServiceResult<()> {
        if self.sender.try_send(command).is_err() {
            state.fail("MTU preview worker is busy or unavailable");
            return Err("MTU preview worker is busy or unavailable".into());
        }
        Ok(())
    }

    pub(crate) fn start(&self, proposal: Proposal, actorSid: &str) -> ServiceResult<Report> {
        proposal.validate()?;
        let mut state = self.lock(actorSid)?;
        let now = nowUnixMs()?;
        if let Some(previous) = state.report.clone() {
            let previous = state.current(previous.jobId, now)?;
            if !matches!(
                previous.phase,
                Phase::Cancelled | Phase::Expired | Phase::Failed
            ) || previous.grant.as_ref().is_some_and(|grant| !grant.revoked)
            {
                return Err(
                    "Cancel the current MTU preview or approval before starting another".into(),
                );
            }
        }
        let jobId = Uuid::new_v4();
        state.cancelled = Arc::new(AtomicBool::new(false));
        state.report = Some(Report {
            jobId,
            phase: Phase::Capturing,
            preview: None,
            grant: None,
            detail: None,
            executionAvailable: false,
        });
        self.enqueue(Command::Capture(jobId, proposal), &mut state)?;
        state.current(jobId, now)
    }

    pub(crate) fn get(&self, jobId: Uuid, actorSid: &str) -> ServiceResult<Report> {
        let mut state = self.lock(actorSid)?;
        state.current(jobId, nowUnixMs()?)
    }

    pub(crate) fn approve(
        &self,
        jobId: Uuid,
        previewId: Uuid,
        sha256: &str,
        actorSid: &str,
    ) -> ServiceResult<Report> {
        let mut state = self.lock(actorSid)?;
        let now = nowUnixMs()?;
        if state.current(jobId, now)?.phase != Phase::Ready {
            return Err("MTU preview is not ready for approval".into());
        }
        let approval = state
            .consent
            .takeApproval(previewId, sha256, actorSid, now)?;
        state
            .report
            .as_mut()
            .ok_or("MTU preview disappeared")?
            .phase = Phase::Authorizing;
        self.enqueue(Command::Issue(jobId, Box::new(approval)), &mut state)?;
        state.current(jobId, now)
    }

    pub(crate) fn cancel(&self, jobId: Uuid, actorSid: &str) -> ServiceResult<Report> {
        let mut state = self.lock(actorSid)?;
        let now = nowUnixMs()?;
        let report = state.current(jobId, now)?;
        state.cancelled.store(true, Ordering::SeqCst);
        if report.phase == Phase::Cancelling {
            return Ok(report);
        }
        if let Some(grant) = report.grant.filter(|grant| !grant.revoked) {
            state
                .report
                .as_mut()
                .ok_or("MTU preview disappeared")?
                .phase = Phase::Cancelling;
            self.enqueue(Command::Revoke(jobId, grant.grantId), &mut state)?;
        } else if matches!(report.phase, Phase::Capturing | Phase::Authorizing) {
            state
                .report
                .as_mut()
                .ok_or("MTU preview disappeared")?
                .phase = Phase::Cancelling;
        } else {
            if report.phase == Phase::Ready {
                state.consent.cancel(
                    report.preview.ok_or("MTU preview is missing")?.previewId,
                    actorSid,
                )?;
            }
            state
                .report
                .as_mut()
                .ok_or("MTU preview disappeared")?
                .phase = Phase::Cancelled;
        }
        state.current(jobId, now)
    }
}

pub(crate) struct Worker {
    control: Control,
    thread: Option<JoinHandle<()>>,
}

impl Worker {
    pub(crate) fn start(ownerSid: &str, journal: OwnedJournal) -> ServiceResult<Self> {
        Self::new(
            ownerSid,
            WindowsBackend {
                journal,
                authorization: None,
                approvedCheckpoint: None,
            },
        )
    }

    fn new(ownerSid: &str, mut backend: impl Backend + 'static) -> ServiceResult<Self> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let control = Control {
            shared: Arc::new(Mutex::new(Shared {
                ownerSid: ownerSid.into(),
                consent: MtuConsent::new(ownerSid)?,
                report: None,
                cancelled: Arc::new(AtomicBool::new(false)),
            })),
            sender,
            stopped: Arc::new(AtomicBool::new(false)),
        };
        let worker = control.clone();
        let thread = std::thread::Builder::new()
            .name("mtu-preview".into())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| -> ServiceResult<()> {
                    while !worker.stopped.load(Ordering::SeqCst) {
                        let command = match receiver.recv_timeout(Duration::from_millis(50)) {
                            Ok(Command::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                            Err(mpsc::RecvTimeoutError::Timeout) => continue,
                            Ok(command) => command,
                        };
                        if let Err(error) = process(command, &worker, &mut backend) {
                            worker
                                .shared
                                .lock()
                                .map_err(|_| "MTU preview state unavailable")?
                                .fail(&error.to_string());
                        }
                    }
                    Ok(())
                }));
                worker.stopped.store(true, Ordering::SeqCst);
                if !matches!(result, Ok(Ok(()))) {
                    worker
                        .shared
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .fail("MTU preview worker stopped unexpectedly");
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
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.control.stopped.store(true, Ordering::SeqCst);
        self.control
            .shared
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .cancelled
            .store(true, Ordering::SeqCst);
        let _ = self.control.sender.try_send(Command::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn process(command: Command, control: &Control, backend: &mut impl Backend) -> ServiceResult<()> {
    let (jobId, cancelled, ownerSid) = {
        let state = control
            .shared
            .lock()
            .map_err(|_| "MTU preview state unavailable")?;
        let jobId = match &command {
            Command::Capture(id, _) | Command::Issue(id, _) | Command::Revoke(id, _) => *id,
            Command::Stop => return Ok(()),
        };
        if state
            .report
            .as_ref()
            .is_none_or(|report| report.jobId != jobId)
        {
            return Err("MTU preview job was replaced before execution".into());
        }
        (jobId, state.cancelled.clone(), state.ownerSid.clone())
    };
    match command {
        Command::Capture(_, proposal) => {
            let capture = backend.capture(&proposal, &cancelled);
            let mut state = control
                .shared
                .lock()
                .map_err(|_| "MTU preview state unavailable")?;
            if cancelled.load(Ordering::SeqCst) {
                state.report.as_mut().ok_or("MTU preview missing")?.phase = Phase::Cancelled;
                return Ok(());
            }
            let capture = capture?;
            capture.validate()?;
            if capture.native.adapterGuid != proposal.adapterGuid
                || capture.native.addressFamily != proposal.addressFamily
                || proposal.proposedMtu >= capture.native.settings.nlMtu
            {
                return Err(
                    "Captured interface does not match the proposed temporary MTU reduction".into(),
                );
            }
            let now = nowUnixMs()?;
            let document = MtuCheckpoint {
                schemaVersion: 4,
                id: Uuid::new_v4(),
                createdAtUnixMs: now,
                leaseExpiresAtUnixMs: now
                    .checked_add(proposal.trialDurationMs)
                    .ok_or("MTU trial lease overflow")?,
                authorizedUserSid: ownerSid.clone(),
                context: capture.native.journalContext()?,
                addressFamily: proposal.addressFamily,
                originalMtu: capture.native.settings.nlMtu,
                proposedMtu: proposal.proposedMtu,
                policyOriginal: Some(capture.evidence()),
                nativeOriginal: Some(capture.native),
            };
            let preview = state.consent.preview(document, &ownerSid, now)?;
            let report = state.report.as_mut().ok_or("MTU preview missing")?;
            report.preview = Some(preview);
            report.phase = Phase::Ready;
        }
        Command::Issue(_, approval) => {
            if cancelled.load(Ordering::SeqCst) {
                control
                    .shared
                    .lock()
                    .map_err(|_| "MTU preview state unavailable")?
                    .report
                    .as_mut()
                    .ok_or("MTU preview missing")?
                    .phase = Phase::Cancelled;
                return Ok(());
            }
            let Some(grant) = backend.issue(*approval, &cancelled)? else {
                control
                    .shared
                    .lock()
                    .map_err(|_| "MTU preview state unavailable")?
                    .report
                    .as_mut()
                    .ok_or("MTU preview missing")?
                    .phase = Phase::Cancelled;
                return Ok(());
            };
            let mut state = control
                .shared
                .lock()
                .map_err(|_| "MTU preview state unavailable")?;
            let grantId = grant.id;
            state.report.as_mut().ok_or("MTU preview missing")?.grant = Some(grant.into());
            if !cancelled.load(Ordering::SeqCst) {
                state.report.as_mut().ok_or("MTU preview missing")?.phase = Phase::Approved;
                return Ok(());
            }
            drop(state);
            backend.revoke(grantId, &ownerSid)?;
            publishRevocation(control, jobId)?;
        }
        Command::Revoke(_, grantId) => {
            backend.revoke(grantId, &ownerSid)?;
            publishRevocation(control, jobId)?;
        }
        Command::Stop => {}
    }
    Ok(())
}

fn publishRevocation(control: &Control, jobId: Uuid) -> ServiceResult<()> {
    let mut state = control
        .shared
        .lock()
        .map_err(|_| "MTU preview state unavailable")?;
    let report = state
        .report
        .as_mut()
        .filter(|report| report.jobId == jobId)
        .ok_or("MTU preview changed during revocation")?;
    report
        .grant
        .as_mut()
        .ok_or("MTU grant missing after revocation")?
        .revoked = true;
    report.phase = Phase::Cancelled;
    Ok(())
}

#[cfg(test)]
mod tests;
