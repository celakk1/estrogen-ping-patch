use crate::{
    ServiceResult,
    authorization::{AuthorizationStore, MtuGrant, checkpointChecksum, validateSid},
    journal::{AdapterContext, AddressFamily, MtuCheckpoint},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use uuid::Uuid;

const PREVIEW_LIFETIME_MS: u64 = 30_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MtuPreview {
    pub schemaVersion: u32,
    pub previewId: Uuid,
    pub checkpointId: Uuid,
    pub checkpointSha256: String,
    pub context: AdapterContext,
    pub addressFamily: AddressFamily,
    pub originalMtu: u32,
    pub proposedMtu: u32,
    pub expiresAtUnixMs: u64,
    pub trialExpiresAtUnixMs: u64,
    pub allowRetention: bool,
}

struct Pending {
    preview: MtuPreview,
    document: MtuCheckpoint,
    deadline: Instant,
    highWaterUnixMs: u64,
}

pub struct MtuConsent {
    ownerSid: String,
    pending: Option<Pending>,
}

impl MtuConsent {
    pub fn new(ownerSid: &str) -> ServiceResult<Self> {
        validateSid(ownerSid)?;
        Ok(Self {
            ownerSid: ownerSid.into(),
            pending: None,
        })
    }

    fn checkActor(&self, actorSid: &str) -> ServiceResult<()> {
        validateSid(actorSid)?;
        if actorSid != self.ownerSid {
            return Err("MTU consent belongs to a different Windows user".into());
        }
        Ok(())
    }

    fn expire(&mut self, nowUnixMs: u64) {
        if self.pending.as_ref().is_some_and(|pending| {
            nowUnixMs < pending.highWaterUnixMs
                || nowUnixMs >= pending.preview.expiresAtUnixMs
                || Instant::now() >= pending.deadline
        }) {
            self.pending = None;
        } else if let Some(pending) = &mut self.pending {
            // rejected requests must still advance the clock fence.
            pending.highWaterUnixMs = nowUnixMs;
        }
    }

    pub fn preview(
        &mut self,
        document: MtuCheckpoint,
        actorSid: &str,
        nowUnixMs: u64,
    ) -> ServiceResult<MtuPreview> {
        self.checkActor(actorSid)?;
        self.expire(nowUnixMs);
        if self.pending.is_some() {
            return Err("An MTU preview is already awaiting approval; cancel it first".into());
        }
        document.validate()?;
        if document.schemaVersion != 4
            || document.authorizedUserSid != self.ownerSid
            || nowUnixMs < document.createdAtUnixMs
            || nowUnixMs >= document.leaseExpiresAtUnixMs
        {
            return Err(
                "MTU consent requires a current policy-bound original for this user".into(),
            );
        }
        let expiresAtUnixMs = nowUnixMs
            .checked_add(PREVIEW_LIFETIME_MS)
            .ok_or("MTU preview expiry overflow")?
            .min(document.leaseExpiresAtUnixMs);
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(expiresAtUnixMs - nowUnixMs))
            .ok_or("MTU preview monotonic deadline overflow")?;
        let preview = MtuPreview {
            schemaVersion: 1,
            previewId: Uuid::new_v4(),
            checkpointId: document.id,
            checkpointSha256: checkpointChecksum(&document)?,
            context: document.context.clone(),
            addressFamily: document.addressFamily,
            originalMtu: document.originalMtu,
            proposedMtu: document.proposedMtu,
            expiresAtUnixMs,
            trialExpiresAtUnixMs: document.leaseExpiresAtUnixMs,
            allowRetention: false,
        };
        self.pending = Some(Pending {
            preview: preview.clone(),
            document,
            deadline,
            highWaterUnixMs: nowUnixMs,
        });
        Ok(preview)
    }

    pub fn approve(
        &mut self,
        previewId: Uuid,
        expectedSha256: &str,
        actorSid: &str,
        store: &mut AuthorizationStore,
        nowUnixMs: u64,
    ) -> ServiceResult<MtuGrant> {
        self.checkActor(actorSid)?;
        self.expire(nowUnixMs);
        let pending = self
            .pending
            .as_ref()
            .ok_or("MTU preview is missing, expired, cancelled, or already used")?;
        if pending.preview.previewId != previewId
            || pending.preview.checkpointSha256 != expectedSha256
        {
            return Err("MTU approval does not match the preview being reviewed".into());
        }
        // consume approval before storage so a failed write cannot silently retry it.
        let pending = self.pending.take().ok_or("MTU preview was consumed")?;
        store.issue(&pending.document, actorSid, false, nowUnixMs)
    }

    pub fn cancel(&mut self, previewId: Uuid, actorSid: &str) -> ServiceResult<()> {
        self.checkActor(actorSid)?;
        if self
            .pending
            .as_ref()
            .is_none_or(|pending| pending.preview.previewId != previewId)
        {
            return Err("MTU cancellation does not match a pending preview".into());
        }
        self.pending = None;
        Ok(())
    }
}

#[cfg(test)]
#[path = "consent_tests.rs"]
mod tests;
