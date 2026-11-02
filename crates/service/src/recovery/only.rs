use super::*;
use std::collections::BTreeMap;

pub(crate) struct RecoveryOnly<'a, B> {
    inner: &'a mut B,
    documents: BTreeMap<Uuid, MtuCheckpoint>,
}

impl<'a, B: MtuBackend> RecoveryOnly<'a, B> {
    pub(crate) fn capture(journal: &Journal, inner: &'a mut B) -> ServiceResult<Self> {
        let mut pending = journal.pendingRecovery()?;
        pending.extend(journal.pendingPolicyVerification()?);
        let mut documents = BTreeMap::new();
        for checkpoint in pending {
            let document = checkpoint.document();
            document.validate()?;
            if let Some(original) = documents.insert(document.id, document.clone())
                && original != *document
            {
                return Err("Pending recovery scope changed during capture".into());
            }
            if documents.len() > 2000 {
                return Err("Recovery scope exceeds its supported checkpoint allowance".into());
            }
        }
        Ok(Self { inner, documents })
    }

    fn validateDocument(&self, document: &MtuCheckpoint) -> ServiceResult<()> {
        if self.documents.get(&document.id) != Some(document) {
            return Err("Recovery-only backend refuses a new or changed checkpoint".into());
        }
        Ok(())
    }
}

impl<B: MtuBackend> MtuBackend for RecoveryOnly<'_, B> {
    fn checkAuthorization(&mut self, _: &MtuCheckpoint, _: u64) -> ServiceResult<()> {
        Err("Recovery-only backend cannot authorize candidate application".into())
    }

    fn authorize(
        &mut self,
        _: &MtuCheckpoint,
        _: AuthorizationAction,
        _: u64,
    ) -> ServiceResult<()> {
        Err("Recovery-only backend cannot prepare, apply, or retain settings".into())
    }

    fn observe(&mut self, document: &MtuCheckpoint) -> ServiceResult<Observation> {
        self.validateDocument(document)?;
        self.inner.observe(document)
    }

    fn observePolicy(
        &mut self,
        document: &MtuCheckpoint,
        purpose: PolicyPurpose,
    ) -> ServiceResult<crate::mtu::policy::Capture> {
        self.validateDocument(document)?;
        self.inner.observePolicy(document, purpose)
    }

    fn waitForMutator(&mut self, record: &MutatorRecord) -> ServiceResult<()> {
        let original = self
            .documents
            .get(&record.checkpointId)
            .ok_or("Mutator is outside the pending recovery scope")?;
        if record.checkpointSha256 != crate::authorization::checkpointChecksum(original)? {
            return Err("Mutator differs from the frozen recovery original".into());
        }
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
        self.validateDocument(document)?;
        if purpose != WritePurpose::Restore || value != document.originalMtu {
            return Err("Recovery-only backend permits only the captured original value".into());
        }
        self.inner
            .writeMtu(document, expected, value, purpose, register)
    }
}
