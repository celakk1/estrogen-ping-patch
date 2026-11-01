use crate::{
    ServiceResult,
    journal::{
        Checkpoint, Journal, MtuCheckpoint, MutatorIdentity, MutatorRecord, Observation, State,
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

pub type MutatorRegistrar<'a> = dyn FnMut(MutatorIdentity) -> ServiceResult<()> + 'a;

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
    if !matches!(document.schemaVersion, 2 | 3) || document.nativeOriginal.is_none() {
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

impl<'a, B: MtuBackend, C: FnMut() -> ServiceResult<u64>> MtuCoordinator<'a, B, C> {
    fn observe(&mut self, document: &MtuCheckpoint) -> ServiceResult<Observation> {
        if document.schemaVersion == 3 {
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
        if document.schemaVersion == 3 && !registered {
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
        if !matches!(document.schemaVersion, 2 | 3) {
            return Err("MTU coordinator cannot prepare legacy simulation checkpoints".into());
        }
        let now = (self.now)()?;
        self.backend
            .authorize(&document, AuthorizationAction::Prepare, now)?;
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
            self.write(
                &document,
                &observed,
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
                error: None,
            });
        }
        let mut originalMtuVerified = false;
        let mut unrelatedSettingsDrifted = false;
        let mut persistenceError = None;
        let recovered: ServiceResult<()> = (|| {
            let observed = self.observe(&document)?;
            let now = (self.now)()?;
            if document.schemaVersion == 3
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
        let error = match recovered {
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
        Ok(RecoveryResult {
            checkpointId: id,
            durableState: state,
            originalMtuVerified,
            journalFinalized: state == State::Restored,
            unrelatedSettingsDrifted,
            error,
        })
    }

    pub fn restoreAllPending(&mut self) -> ServiceResult<Vec<RecoveryResult>> {
        let pending = self.journal.pendingRecovery()?;
        let mut results = Vec::new();
        for checkpoint in pending {
            if matches!(checkpoint.document().schemaVersion, 2 | 3) {
                results.push(self.restore(checkpoint.document().id)?);
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
pub(crate) mod tests;
