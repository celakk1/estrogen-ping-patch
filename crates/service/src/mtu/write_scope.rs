use super::Snapshot;
use crate::{ServiceResult, journal::MtuCheckpoint, recovery::WritePurpose};

pub(crate) trait TargetGuard: Send + Sync {
    fn validateTarget(&self, snapshot: &Snapshot) -> ServiceResult<()>;
}

#[derive(Debug)]
pub(crate) struct WriteScope<'a> {
    document: &'a MtuCheckpoint,
    original: &'a Snapshot,
    purpose: WritePurpose,
}

impl<'a> WriteScope<'a> {
    pub(crate) fn new(
        document: &'a MtuCheckpoint,
        purpose: WritePurpose,
        requestedValue: u32,
    ) -> ServiceResult<Self> {
        document.validate()?;
        let original = document
            .nativeOriginal
            .as_ref()
            .ok_or("Native write requires its checkpoint original")?;
        if !matches!(document.schemaVersion, 2..=4)
            || original.settings.nlMtu != document.originalMtu
            || (purpose == WritePurpose::Apply
                && (document.schemaVersion != 4
                    || !(1280..document.originalMtu).contains(&document.proposedMtu)))
        {
            return Err("Native apply requires an exact policy-bound MTU reduction; recovery requires a captured original".into());
        }
        let scope = Self {
            document,
            original,
            purpose,
        };
        if scope.value() != requestedValue {
            return Err(
                "Requested native MTU differs from the checkpoint's exact write purpose".into(),
            );
        }
        Ok(scope)
    }

    pub(crate) fn original(&self) -> &Snapshot {
        self.original
    }

    pub(crate) fn value(&self) -> u32 {
        match self.purpose {
            WritePurpose::Apply => self.document.proposedMtu,
            WritePurpose::Restore => self.document.originalMtu,
        }
    }

    pub(crate) fn validateAuthorization(&self, present: bool) -> ServiceResult<()> {
        if present != (self.purpose == WritePurpose::Apply) {
            return Err("Native apply requires live authorization; exact-original recovery must remain authorization-independent".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn document() -> MtuCheckpoint {
        let capture = crate::mtu::policy::tests::fixture();
        MtuCheckpoint {
            schemaVersion: 4,
            id: Uuid::new_v4(),
            createdAtUnixMs: 1000,
            leaseExpiresAtUnixMs: 121_000,
            authorizedUserSid: "S-1-5-21-1-2-3-1000".into(),
            context: capture.native.journalContext().unwrap(),
            addressFamily: capture.native.addressFamily,
            originalMtu: capture.native.settings.nlMtu,
            proposedMtu: 1400,
            policyOriginal: Some(capture.evidence()),
            nativeOriginal: Some(capture.native),
        }
    }

    #[test]
    fn candidateAndRestoreAreDerivedOnlyFromTheExactCheckpointPurpose() {
        for candidate in [1280, 1372, 1427, 1499] {
            let mut document = document();
            document.proposedMtu = candidate;
            let apply = WriteScope::new(&document, WritePurpose::Apply, candidate).unwrap();
            assert_eq!(apply.value(), candidate);
            assert_eq!(apply.original(), document.nativeOriginal.as_ref().unwrap());
            assert!(apply.validateAuthorization(true).is_ok());
            assert!(apply.validateAuthorization(false).is_err());
            let restore =
                WriteScope::new(&document, WritePurpose::Restore, document.originalMtu).unwrap();
            assert_eq!(restore.value(), 1500);
            assert!(restore.validateAuthorization(false).is_ok());
            assert!(restore.validateAuthorization(true).is_err());
            for value in [68, 1279, 1400, 1500, 9000, 65535] {
                if value != candidate {
                    assert!(WriteScope::new(&document, WritePurpose::Apply, value).is_err());
                }
                if value != document.originalMtu {
                    assert!(WriteScope::new(&document, WritePurpose::Restore, value).is_err());
                }
            }
        }
    }

    #[test]
    fn restoreUsesANonDefaultOriginalWithoutGuessingAnotherValue() {
        let mut document = document();
        document.originalMtu = 1492;
        document.proposedMtu = 1372;
        document.nativeOriginal.as_mut().unwrap().settings.nlMtu = 1492;
        document
            .policyOriginal
            .as_mut()
            .unwrap()
            .active
            .values
            .get_mut("NlMtu")
            .unwrap()
            .value = Some(1492);
        let restore = WriteScope::new(&document, WritePurpose::Restore, 1492).unwrap();
        assert_eq!(restore.value(), 1492);
        assert!(WriteScope::new(&document, WritePurpose::Restore, 1500).is_err());
        assert!(WriteScope::new(&document, WritePurpose::Apply, 1372).is_ok());
    }

    #[test]
    fn legacyOriginalCanRecoverButCannotAdmitANewCandidate() {
        let mut legacyDocument = document();
        legacyDocument.schemaVersion = 3;
        legacyDocument.policyOriginal = None;
        assert!(WriteScope::new(&legacyDocument, WritePurpose::Apply, 1400).is_err());
        assert!(WriteScope::new(&legacyDocument, WritePurpose::Restore, 1500).is_ok());
        for candidate in [1279, 1500, 1600] {
            let mut document = document();
            document.proposedMtu = candidate;
            assert!(WriteScope::new(&document, WritePurpose::Apply, candidate).is_err());
        }
    }
}
