use crate::{
    ServiceResult,
    journal::{
        Checkpoint, Journal, MtuCheckpoint, MutatorIdentity, MutatorRecord, Observation,
        PolicyReadback, State,
    },
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationAction {
    Prepare,
    Apply,
    Retain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum WritePurpose {
    Apply,
    Restore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyPurpose {
    Validate,
    VerifyRestored,
}

pub type MutatorRegistrar<'a> = dyn FnMut(MutatorIdentity) -> ServiceResult<()> + 'a;

#[cfg(any(test, all(windows, feature = "native-mtu-lab")))]
pub(crate) mod only;

pub trait MtuBackend {
    fn checkAuthorization(&mut self, _: &MtuCheckpoint, _: u64) -> ServiceResult<()> {
        Err("This backend cannot recheck an active operation's authorization".into())
    }
    fn authorize(
        &mut self,
        document: &MtuCheckpoint,
        action: AuthorizationAction,
        nowUnixMs: u64,
    ) -> ServiceResult<()>;
    fn observe(&mut self, document: &MtuCheckpoint) -> ServiceResult<Observation>;
    fn observePolicy(
        &mut self,
        _: &MtuCheckpoint,
        _: PolicyPurpose,
    ) -> ServiceResult<crate::mtu::policy::Capture> {
        Err("This backend cannot capture exact active and persistent IP policy".into())
    }
    fn waitForMutator(&mut self, _: &MutatorRecord) -> ServiceResult<()> {
        Err("This backend cannot verify a registered mutator's termination".into())
    }
    fn writeMtu(
        &mut self,
        document: &MtuCheckpoint,
        expected: &Observation,
        value: u32,
        purpose: WritePurpose,
        register: &mut MutatorRegistrar<'_>,
    ) -> ServiceResult<()>;
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryResult {
    pub checkpointId: Uuid,
    pub durableState: State,
    pub originalMtuVerified: bool,
    pub journalFinalized: bool,
    pub unrelatedSettingsDrifted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policyOriginalVerified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policyVerificationRecorded: Option<bool>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "camelCase")]
pub enum ApplyResult {
    Applied {
        checkpointId: Uuid,
    },
    Failed {
        recovery: RecoveryResult,
        error: String,
    },
}

pub struct MtuCoordinator<'a, B: MtuBackend, C: FnMut() -> ServiceResult<u64>> {
    journal: &'a mut Journal,
    backend: &'a mut B,
    now: C,
}

fn nativeDocument(checkpoint: &Checkpoint) -> ServiceResult<&MtuCheckpoint> {
    let document = checkpoint.document();
    if !matches!(document.schemaVersion, 2..=4) || document.nativeOriginal.is_none() {
        return Err(
            "Native MTU coordination requires a supported checkpoint with native original evidence"
                .into(),
        );
    }
    Ok(document)
}

fn observationMatches(
    document: &MtuCheckpoint,
    observed: &Observation,
    expectedMtu: u32,
    nowUnixMs: u64,
    strict: bool,
) -> ServiceResult<()> {
    if observed.context != document.context
        || observed.addressFamily != document.addressFamily
        || observed.mtu != expectedMtu
    {
        return Err(
            "Live MTU or adapter context does not match the required checkpoint value".into(),
        );
    }
    let original = document
        .nativeOriginal
        .as_ref()
        .ok_or("Native original evidence is missing")?;
    let native = observed
        .native
        .as_ref()
        .ok_or("Native observation evidence is missing")?;
    if strict {
        native.validateMtuObservation(original)?;
    } else {
        native.validateMtuIdentity(original)?;
    }
    if native.settings.nlMtu != observed.mtu
        || native.capturedAtUnixMs > nowUnixMs.saturating_add(250)
        || nowUnixMs.saturating_sub(native.capturedAtUnixMs) > 5000
    {
        return Err("Native observation value or freshness is invalid".into());
    }
    Ok(())
}

fn bounded(error: impl std::fmt::Display) -> String {
    error.to_string().chars().take(1024).collect()
}

pub(crate) fn policyObservationMatches(
    document: &MtuCheckpoint,
    current: &crate::mtu::policy::Capture,
    expectedMtu: u32,
    now: u64,
) -> ServiceResult<()> {
    current.validate()?;
    let observed = Observation {
        context: current.native.journalContext()?,
        addressFamily: current.native.addressFamily,
        mtu: current.native.settings.nlMtu,
        native: Some(current.native.clone()),
    };
    observationMatches(document, &observed, expectedMtu, now, true)?;
    document
        .policyOriginal
        .as_ref()
        .ok_or("Checkpoint IP policy original is missing")?
        .validateMtuObservation(document.nativeOriginal.as_ref().unwrap(), current)
}

impl<'a, B: MtuBackend, C: FnMut() -> ServiceResult<u64>> MtuCoordinator<'a, B, C> {
    fn verifyPolicy(
        &mut self,
        document: &MtuCheckpoint,
        expectedMtu: u32,
        purpose: PolicyPurpose,
    ) -> ServiceResult<()> {
        if document.schemaVersion != 4 {
            return Ok(());
        }
        let current = self.backend.observePolicy(document, purpose)?;
        policyObservationMatches(document, &current, expectedMtu, (self.now)()?)
    }

    fn restoredPolicyReadback(&mut self, document: &MtuCheckpoint) -> PolicyReadback {
        match self
            .backend
            .observePolicy(document, PolicyPurpose::VerifyRestored)
        {
            Ok(capture) => match capture.validate() {
                Ok(()) => PolicyReadback::Captured {
                    capture: Box::new(capture),
                },
                Err(error) => PolicyReadback::Unavailable {
                    error: bounded(error),
                },
            },
            Err(error) => PolicyReadback::Unavailable {
                error: bounded(error),
            },
        }
    }

    fn saveRestoredPolicy(
        &mut self,
        document: &MtuCheckpoint,
        readback: PolicyReadback,
    ) -> (bool, bool, Option<String>) {
        let now = match (self.now)() {
            Ok(now) => now,
            Err(error) => {
                return (
                    false,
                    false,
                    Some(bounded(format!(
                        "Policy verification time unavailable: {error}"
                    ))),
                );
            }
        };
        let comparison = readback.compare(document, now);
        let verified = comparison.is_ok();
        let mut error = comparison.err().map(|error| {
            bounded(format!(
                "Post-restoration check: exact IP policy readback failed: {error}"
            ))
        });
        match self
            .journal
            .recordPolicyVerification(document.id, readback, now)
        {
            Ok(_) => (verified, true, error),
            Err(storageError) => {
                let storageError =
                    format!("Policy verification was not durably recorded: {storageError}");
                error = Some(bounded(match error {
                    Some(previous) => format!("{previous}; {storageError}"),
                    None => storageError,
                }));
                (verified, false, error)
            }
        }
    }

    fn observe(&mut self, document: &MtuCheckpoint) -> ServiceResult<Observation> {
        if matches!(document.schemaVersion, 3 | 4) {
            for record in self.journal.mutators(document.id)? {
                self.backend.waitForMutator(&record)?;
            }
        }
        self.backend.observe(document)
    }

    fn write(
        &mut self,
        document: &MtuCheckpoint,
        expected: &Observation,
        value: u32,
        purpose: WritePurpose,
    ) -> ServiceResult<()> {
        let mut registered = false;
        let journal = &mut self.journal;
        let now = &mut self.now;
        let mut register = |identity| {
            journal.registerMutator(document.id, purpose, identity, (now)()?)?;
            registered = true;
            Ok(())
        };
        self.backend
            .writeMtu(document, expected, value, purpose, &mut register)?;
        if matches!(document.schemaVersion, 3 | 4) && !registered {
            return Err(
                "Native setting write returned without a durable mutator registration".into(),
            );
        }
        Ok(())
    }
    pub fn new(journal: &'a mut Journal, backend: &'a mut B, now: C) -> Self {
        Self {
            journal,
            backend,
            now,
        }
    }

    pub fn prepare(&mut self, document: MtuCheckpoint) -> ServiceResult<Checkpoint> {
        document.validate()?;
        if !matches!(document.schemaVersion, 2..=4) {
            return Err("MTU coordinator cannot prepare legacy simulation checkpoints".into());
        }
        let now = (self.now)()?;
        self.backend
            .authorize(&document, AuthorizationAction::Prepare, now)?;
        self.verifyPolicy(&document, document.originalMtu, PolicyPurpose::Validate)?;
        let observed = self.backend.observe(&document)?;
        let now = (self.now)()?;
        observationMatches(&document, &observed, document.originalMtu, now, true)?;
        self.backend
            .authorize(&document, AuthorizationAction::Prepare, now)?;
        self.journal.prepare(document, now)
    }

    pub fn apply(&mut self, id: Uuid) -> ServiceResult<ApplyResult> {
        let checkpoint = self.journal.load(id)?;
        let document = nativeDocument(&checkpoint)?.clone();
        if checkpoint.state() != State::Prepared {
            return Err("Only a prepared checkpoint can start an MTU apply".into());
        }
        self.backend
            .authorize(&document, AuthorizationAction::Apply, (self.now)()?)?;
        self.verifyPolicy(&document, document.originalMtu, PolicyPurpose::Validate)?;
        let observed = self.observe(&document)?;
        let now = (self.now)()?;
        observationMatches(&document, &observed, document.originalMtu, now, true)?;
        self.journal.transition(
            id,
            State::Prepared,
            State::Applying,
            now,
            Some(observed.clone()),
        )?;
        let result: ServiceResult<()> = (|| {
            let now = (self.now)()?;
            if now < document.createdAtUnixMs || now >= document.leaseExpiresAtUnixMs {
                return Err("MTU lease expired before the native write".into());
            }
            self.backend
                .authorize(&document, AuthorizationAction::Apply, now)?;
            let fresh = if document.schemaVersion == 4 {
                self.verifyPolicy(&document, document.originalMtu, PolicyPurpose::Validate)?;
                let observed = self.observe(&document)?;
                let now = (self.now)()?;
                if now < document.createdAtUnixMs || now >= document.leaseExpiresAtUnixMs {
                    return Err("MTU lease expired during IP policy verification".into());
                }
                observationMatches(&document, &observed, document.originalMtu, now, true)?;
                self.backend
                    .authorize(&document, AuthorizationAction::Apply, now)?;
                Some(observed)
            } else {
                None
            };
            self.write(
                &document,
                fresh.as_ref().unwrap_or(&observed),
                document.proposedMtu,
                WritePurpose::Apply,
            )?;
            let after = self.observe(&document)?;
            let now = (self.now)()?;
            observationMatches(&document, &after, document.proposedMtu, now, true)?;
            self.journal
                .transition(id, State::Applying, State::Applied, now, Some(after))?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(ApplyResult::Applied { checkpointId: id }),
            Err(error) => Ok(ApplyResult::Failed {
                recovery: self.restore(id)?,
                error: bounded(error),
            }),
        }
    }

    pub fn retain(&mut self, id: Uuid) -> ServiceResult<Checkpoint> {
        let checkpoint = self.journal.load(id)?;
        let document = nativeDocument(&checkpoint)?.clone();
        if checkpoint.state() != State::Applied {
            return Err("Only a verified applied MTU can be retained".into());
        }
        self.backend
            .authorize(&document, AuthorizationAction::Retain, (self.now)()?)?;
        self.verifyPolicy(&document, document.proposedMtu, PolicyPurpose::Validate)?;
        let observed = self.observe(&document)?;
        let now = (self.now)()?;
        observationMatches(&document, &observed, document.proposedMtu, now, true)?;
        self.backend
            .authorize(&document, AuthorizationAction::Retain, now)?;
        self.journal
            .transition(id, State::Applied, State::Retained, now, Some(observed))
    }

    pub fn verifyApplied(&mut self, id: Uuid) -> ServiceResult<Observation> {
        let checkpoint = self.journal.load(id)?;
        let document = nativeDocument(&checkpoint)?.clone();
        if checkpoint.state() != State::Applied {
            return Err("Only a verified applied MTU can be monitored".into());
        }
        self.backend.checkAuthorization(&document, (self.now)()?)?;
        let observed = self.observe(&document)?;
        let now = (self.now)()?;
        observationMatches(&document, &observed, document.proposedMtu, now, true)?;
        let native = observed.native.as_ref().unwrap();
        if native.operationalStatus != 1 || native.mediaConnectState != 1 {
            return Err("The monitored network interface is no longer up and connected".into());
        }
        self.backend.checkAuthorization(&document, now)?;
        Ok(observed)
    }

    pub fn restore(&mut self, id: Uuid) -> ServiceResult<RecoveryResult> {
        let checkpoint = self.journal.load(id)?;
        let document = nativeDocument(&checkpoint)?.clone();
        let mut state = checkpoint.state();
        if state.terminal() {
            return Err("Terminal MTU checkpoints cannot be replayed as recovery requests".into());
        }
        if state == State::Prepared {
            let checkpoint = self.journal.transition(
                id,
                State::Prepared,
                State::Cancelled,
                (self.now)()?,
                None,
            )?;
            return Ok(RecoveryResult {
                checkpointId: id,
                durableState: checkpoint.state(),
                originalMtuVerified: false,
                journalFinalized: true,
                unrelatedSettingsDrifted: false,
                policyOriginalVerified: None,
                policyVerificationRecorded: None,
                error: None,
            });
        }
        let mut originalMtuVerified = false;
        let mut unrelatedSettingsDrifted = false;
        let mut persistenceError = None;
        let recovered: ServiceResult<()> = (|| {
            let observed = self.observe(&document)?;
            let now = (self.now)()?;
            if matches!(document.schemaVersion, 3 | 4)
                && observed.mtu != document.originalMtu
                && self.journal.mutators(document.id)?.is_empty()
            {
                return Err("No registered apply could have changed this value; refusing to overwrite an external MTU change".into());
            }
            if observed.mtu != document.originalMtu && observed.mtu != document.proposedMtu {
                return Err("Live MTU is neither the original nor the candidate; refusing to overwrite an external change".into());
            }
            observationMatches(&document, &observed, observed.mtu, now, false)?;
            let original = document.nativeOriginal.as_ref().unwrap();
            unrelatedSettingsDrifted = observed
                .native
                .as_ref()
                .unwrap()
                .validateMtuObservation(original)
                .is_err();
            let after = if observed.mtu == document.originalMtu {
                observed
            } else {
                if state != State::Restoring {
                    match self.journal.transition(
                        id,
                        state,
                        State::Restoring,
                        now,
                        Some(observed.clone()),
                    ) {
                        Ok(checkpoint) => state = checkpoint.state(),
                        Err(error) => persistenceError = Some(bounded(error)),
                    }
                }
                // the verified original and durable apply intent still permit safe rollback if appending a restore event fails.
                self.write(
                    &document,
                    &observed,
                    document.originalMtu,
                    WritePurpose::Restore,
                )?;
                self.observe(&document)?
            };
            let now = (self.now)()?;
            observationMatches(&document, &after, document.originalMtu, now, false)?;
            originalMtuVerified = true;
            unrelatedSettingsDrifted |= after
                .native
                .as_ref()
                .unwrap()
                .validateMtuObservation(original)
                .is_err();
            match self
                .journal
                .transition(id, state, State::Restored, now, Some(after))
            {
                Ok(checkpoint) => {
                    state = checkpoint.state();
                    Ok(())
                }
                Err(error) => Err(error),
            }
        })();
        let mut error = match recovered {
            Ok(()) => persistenceError,
            Err(error) => {
                if !originalMtuVerified
                    && state != State::RecoveryRequired
                    && let Ok(checkpoint) = self.journal.transition(
                        id,
                        state,
                        State::RecoveryRequired,
                        (self.now)()?,
                        None,
                    )
                {
                    state = checkpoint.state();
                }
                Some(bounded(error))
            }
        };
        let mut policyOriginalVerified = None;
        let mut policyVerificationRecorded = None;
        if originalMtuVerified && document.schemaVersion == 4 {
            let (verified, recorded, policyError) = if state == State::Restored {
                let readback = self.restoredPolicyReadback(&document);
                self.saveRestoredPolicy(&document, readback)
            } else {
                (
                    false,
                    false,
                    Some("Policy verification awaits durable MTU recovery finalization".into()),
                )
            };
            policyOriginalVerified = Some(verified);
            policyVerificationRecorded = Some(recorded);
            unrelatedSettingsDrifted |= !verified;
            if let Some(policyError) = policyError {
                error = Some(bounded(match error {
                    Some(previous) => format!("{previous}; {policyError}"),
                    None => policyError,
                }));
            }
        }
        Ok(RecoveryResult {
            checkpointId: id,
            durableState: state,
            originalMtuVerified,
            journalFinalized: state == State::Restored,
            unrelatedSettingsDrifted,
            policyOriginalVerified,
            policyVerificationRecorded,
            error,
        })
    }

    pub fn verifyRestoredPolicy(&mut self, id: Uuid) -> ServiceResult<RecoveryResult> {
        let checkpoint = self.journal.load(id)?;
        let document = checkpoint.document().clone();
        if document.schemaVersion != 4 || checkpoint.state() != State::Restored {
            return Err(
                "Policy-only verification requires a restored version-four checkpoint".into(),
            );
        }
        if checkpoint
            .policyVerifications()
            .last()
            .is_some_and(|record| record.matchesOriginal)
        {
            return Err("This checkpoint has no pending policy verification".into());
        }
        let original = self.observe(&document).and_then(|observed| {
            observationMatches(
                &document,
                &observed,
                document.originalMtu,
                (self.now)()?,
                false,
            )
        });
        let originalMtuVerified = original.is_ok();
        let readback = match original {
            Ok(()) => self.restoredPolicyReadback(&document),
            Err(error) => PolicyReadback::Unavailable {
                error: bounded(error),
            },
        };
        let (verified, recorded, error) = self.saveRestoredPolicy(&document, readback);
        Ok(RecoveryResult {
            checkpointId: id,
            durableState: State::Restored,
            originalMtuVerified,
            journalFinalized: true,
            unrelatedSettingsDrifted: !verified,
            policyOriginalVerified: Some(verified),
            policyVerificationRecorded: Some(recorded),
            error,
        })
    }

    pub fn restoreAllPending(&mut self) -> ServiceResult<Vec<RecoveryResult>> {
        let pending = self.journal.pendingRecovery()?;
        let mut results = Vec::new();
        for checkpoint in pending {
            if matches!(checkpoint.document().schemaVersion, 2..=4) {
                results.push(self.restore(checkpoint.document().id)?);
            }
        }
        for checkpoint in self.journal.pendingPolicyVerification()? {
            if !results
                .iter()
                .any(|result| result.checkpointId == checkpoint.document().id)
            {
                results.push(self.verifyRestoredPolicy(checkpoint.document().id)?);
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
pub(crate) mod tests;
