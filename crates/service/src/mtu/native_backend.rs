use super::{
    policy,
    write_scope::{TargetGuard, WriteScope},
};
use crate::{
    ServiceResult,
    authorization::AuthorizationStore,
    journal::{MtuCheckpoint, MutatorRecord, Observation},
    recovery::{AuthorizationAction, MtuBackend, MutatorRegistrar, PolicyPurpose, WritePurpose},
    transport::nowUnixMs,
};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub(crate) struct ApplyAuthorization<'a> {
    pub store: &'a mut AuthorizationStore,
    pub grantId: Uuid,
    pub actorSid: &'a str,
}

pub(crate) struct NativeBackend<'a> {
    document: &'a MtuCheckpoint,
    guard: &'a dyn TargetGuard,
    stop: &'a AtomicBool,
    authorization: Option<ApplyAuthorization<'a>>,
    applyDeadline: Instant,
    commandLimit: Option<Instant>,
}

impl<'a> NativeBackend<'a> {
    pub(crate) fn new(
        document: &'a MtuCheckpoint,
        guard: &'a dyn TargetGuard,
        stop: &'a AtomicBool,
        authorization: Option<ApplyAuthorization<'a>>,
        applyDeadline: Instant,
    ) -> ServiceResult<Self> {
        document.validate()?;
        if document.nativeOriginal.is_none() {
            return Err("Native backend requires its captured checkpoint original".into());
        }
        if let Some(authorization) = &authorization {
            crate::authorization::validateSid(authorization.actorSid)?;
            if authorization.grantId.is_nil()
                || authorization.actorSid != document.authorizedUserSid
            {
                return Err(
                    "Native backend grant identity differs from the checkpoint owner".into(),
                );
            }
        }
        Ok(Self {
            document,
            guard,
            stop,
            authorization,
            applyDeadline,
            commandLimit: None,
        })
    }

    fn validateDocument(&self, document: &MtuCheckpoint) -> ServiceResult<()> {
        if document != self.document {
            return Err(
                "Native backend refuses a different checkpoint than its bound original".into(),
            );
        }
        Ok(())
    }

    fn validateApply(&self, document: &MtuCheckpoint, now: u64) -> ServiceResult<()> {
        self.validateDocument(document)?;
        if self.stop.load(Ordering::SeqCst)
            || Instant::now() >= self.applyDeadline
            || now < document.createdAtUnixMs
            || now >= document.leaseExpiresAtUnixMs
        {
            return Err("Native application was stopped or its checkpoint lease expired".into());
        }
        Ok(())
    }

    pub(crate) fn commandDeadline(&self, purpose: WritePurpose) -> ServiceResult<Instant> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or("Native command deadline overflow")?;
        let deadline = self
            .commandLimit
            .map_or(deadline, |limit| deadline.min(limit));
        Ok(if purpose == WritePurpose::Apply {
            deadline.min(self.applyDeadline)
        } else {
            deadline
        })
    }

    pub(crate) fn limitCommandDeadline(&mut self, deadline: Instant) {
        self.commandLimit = Some(
            self.commandLimit
                .map_or(deadline, |limit| limit.min(deadline)),
        );
    }
}

impl MtuBackend for NativeBackend<'_> {
    fn checkAuthorization(&mut self, document: &MtuCheckpoint, now: u64) -> ServiceResult<()> {
        self.validateApply(document, now)?;
        let authorization = self
            .authorization
            .as_mut()
            .ok_or("Native application requires a live grant")?;
        authorization.store.check(
            authorization.grantId,
            document,
            authorization.actorSid,
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
        self.validateApply(document, now)?;
        if action == AuthorizationAction::Retain {
            return Err("Temporary native backend never authorizes retention".into());
        }
        let authorization = self
            .authorization
            .as_mut()
            .ok_or("Native application requires a live grant")?;
        authorization.store.authorize(
            authorization.grantId,
            document,
            authorization.actorSid,
            action,
            now,
        )
    }

    fn observe(&mut self, document: &MtuCheckpoint) -> ServiceResult<Observation> {
        self.validateDocument(document)?;
        self.guard.validateTarget(
            document
                .nativeOriginal
                .as_ref()
                .ok_or("Native original missing")?,
        )?;
        super::ensureLabCommandStopped()?;
        let native = super::capture(
            document.context.adapterGuid,
            document.addressFamily,
            &AtomicBool::new(false),
        )?;
        self.guard.validateTarget(&native)?;
        Ok(Observation {
            context: native.journalContext()?,
            addressFamily: native.addressFamily,
            mtu: native.settings.nlMtu,
            native: Some(native),
        })
    }

    fn observePolicy(
        &mut self,
        document: &MtuCheckpoint,
        purpose: PolicyPurpose,
    ) -> ServiceResult<policy::Capture> {
        self.validateDocument(document)?;
        self.guard.validateTarget(
            document
                .nativeOriginal
                .as_ref()
                .ok_or("Native original missing")?,
        )?;
        super::ensureLabCommandStopped()?;
        let recovering = AtomicBool::new(false);
        let cancelled = if purpose == PolicyPurpose::VerifyRestored {
            &recovering
        } else {
            self.stop
        };
        let capture = policy::inspect(
            document.context.adapterGuid,
            document.addressFamily,
            cancelled,
        )?;
        self.guard.validateTarget(&capture.native)?;
        Ok(capture)
    }

    fn waitForMutator(&mut self, record: &MutatorRecord) -> ServiceResult<()> {
        if record.checkpointId != self.document.id
            || record.checkpointSha256 != crate::authorization::checkpointChecksum(self.document)?
        {
            return Err("Native mutator does not belong to the bound checkpoint".into());
        }
        super::waitForLabMutator(&record.identity)
    }

    fn writeMtu(
        &mut self,
        document: &MtuCheckpoint,
        expected: &Observation,
        value: u32,
        purpose: WritePurpose,
        register: &mut MutatorRegistrar<'_>,
    ) -> ServiceResult<()> {
        self.validateDocument(document)?;
        let scope = WriteScope::new(document, purpose, value)?;
        if purpose == WritePurpose::Apply {
            self.authorize(document, AuthorizationAction::Apply, nowUnixMs()?)?;
        }
        self.guard.validateTarget(scope.original())?;
        let expected = expected
            .native
            .as_ref()
            .ok_or("Native write expected observation is missing")?;
        let deadline = self.commandDeadline(purpose)?;
        let guard = self.guard;
        let mut check = || self.checkAuthorization(document, nowUnixMs()?);
        super::writeLabMtu(
            guard,
            &scope,
            expected,
            deadline,
            if purpose == WritePurpose::Apply {
                Some(&mut check)
            } else {
                None
            },
            register,
        )
    }
}

#[cfg(test)]
mod tests;
