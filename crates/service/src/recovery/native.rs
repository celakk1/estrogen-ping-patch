use super::*;
use crate::mtu::{self, Snapshot, native_backend::NativeBackend, write_scope::TargetGuard};
use std::{sync::atomic::AtomicBool, time::Instant};

struct ScopedTarget<'a> {
    original: &'a Snapshot,
    guard: &'a dyn TargetGuard,
}

impl TargetGuard for ScopedTarget<'_> {
    fn validateTarget(&self, snapshot: &Snapshot) -> ServiceResult<()> {
        snapshot.validateMtuIdentity(self.original)?;
        self.guard.validateTarget(snapshot)
    }
}

pub(crate) struct Dispatch<'a> {
    guard: &'a dyn TargetGuard,
    stop: AtomicBool,
}

impl<'a> Dispatch<'a> {
    pub(crate) fn new(guard: &'a dyn TargetGuard) -> Self {
        Self {
            guard,
            stop: AtomicBool::new(false),
        }
    }

    fn withBackend<T>(
        &self,
        document: &MtuCheckpoint,
        operation: impl FnOnce(&mut NativeBackend<'_>) -> ServiceResult<T>,
    ) -> ServiceResult<T> {
        let target = ScopedTarget {
            original: document
                .nativeOriginal
                .as_ref()
                .ok_or("Recovery requires its native original")?,
            guard: self.guard,
        };
        let mut backend = NativeBackend::new(document, &target, &self.stop, None, Instant::now())?;
        operation(&mut backend)
    }
}

impl MtuBackend for Dispatch<'_> {
    fn authorize(
        &mut self,
        _: &MtuCheckpoint,
        _: AuthorizationAction,
        _: u64,
    ) -> ServiceResult<()> {
        Err("Native recovery cannot prepare, apply, or retain a candidate".into())
    }

    fn observe(&mut self, document: &MtuCheckpoint) -> ServiceResult<Observation> {
        self.withBackend(document, |backend| backend.observe(document))
    }

    fn observePolicy(
        &mut self,
        document: &MtuCheckpoint,
        purpose: PolicyPurpose,
    ) -> ServiceResult<mtu::policy::Capture> {
        self.withBackend(document, |backend| backend.observePolicy(document, purpose))
    }

    fn waitForMutator(&mut self, record: &MutatorRecord) -> ServiceResult<()> {
        mtu::waitForLabMutator(&record.identity)
    }

    fn writeMtu(
        &mut self,
        document: &MtuCheckpoint,
        expected: &Observation,
        value: u32,
        purpose: WritePurpose,
        register: &mut MutatorRegistrar<'_>,
    ) -> ServiceResult<()> {
        if purpose != WritePurpose::Restore || value != document.originalMtu {
            return Err("Native recovery permits only the checkpoint's exact original MTU".into());
        }
        self.withBackend(document, |backend| {
            backend.writeMtu(document, expected, value, purpose, register)
        })
    }
}

#[cfg(feature = "native-recovery")]
pub(crate) fn restorePending(
    journal: &mut Journal,
    guard: &dyn TargetGuard,
    stop: &AtomicBool,
) -> ServiceResult<Vec<RecoveryResult>> {
    let mut pending: Vec<_> = journal
        .pendingRecovery()?
        .into_iter()
        .filter(|checkpoint| matches!(checkpoint.document().schemaVersion, 2..=4))
        .map(|checkpoint| (checkpoint.document().id, false))
        .collect();
    for checkpoint in journal.pendingPolicyVerification()? {
        if !pending
            .iter()
            .any(|(id, _)| *id == checkpoint.document().id)
        {
            pending.push((checkpoint.document().id, true));
        }
    }
    let mut dispatch = Dispatch::new(guard);
    let mut recovery = only::RecoveryOnly::capture(journal, &mut dispatch)?;
    let mut coordinator = MtuCoordinator::new(journal, &mut recovery, crate::transport::nowUnixMs);
    let mut results = Vec::new();
    for (id, policyOnly) in pending {
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        results.push(if policyOnly {
            coordinator.verifyRestoredPolicy(id)?
        } else {
            coordinator.restore(id)?
        });
    }
    Ok(results)
}

#[cfg(test)]
mod tests;
