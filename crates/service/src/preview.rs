use crate::{ServiceResult, authorization::MtuGrant, consent::MtuPreview, journal::AddressFamily};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(windows)]
mod worker;
#[cfg(windows)]
pub(crate) use worker::{Control, Worker};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Proposal {
    pub adapterGuid: Uuid,
    pub addressFamily: AddressFamily,
    pub proposedMtu: u32,
    pub trialDurationMs: u64,
}

impl Proposal {
    pub fn validate(&self) -> ServiceResult<()> {
        if self.adapterGuid.is_nil()
            || !(1280..=65_535).contains(&self.proposedMtu)
            || !(5000..=300_000).contains(&self.trialDurationMs)
        {
            return Err("MTU preview requires an adapter GUID, MTU 1280..65535, and a trial lease of 5..300 seconds".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Capturing,
    Ready,
    Authorizing,
    Approved,
    Cancelling,
    Cancelled,
    Expired,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantSummary {
    pub grantId: Uuid,
    pub checkpointId: Uuid,
    pub checkpointSha256: String,
    pub expiresAtUnixMs: u64,
    pub allowRetention: bool,
    pub revoked: bool,
}

impl From<MtuGrant> for GrantSummary {
    fn from(grant: MtuGrant) -> Self {
        Self {
            grantId: grant.id,
            checkpointId: grant.checkpointId,
            checkpointSha256: grant.checkpointSha256,
            expiresAtUnixMs: grant.expiresAtUnixMs,
            allowRetention: grant.allowRetention,
            revoked: false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Report {
    pub jobId: Uuid,
    pub phase: Phase,
    pub preview: Option<MtuPreview>,
    pub grant: Option<GrantSummary>,
    pub detail: Option<String>,
    pub executionAvailable: bool,
}

impl Report {
    pub fn validate(&self) -> ServiceResult<()> {
        if self.jobId.is_nil() || self.executionAvailable {
            return Err(
                "MTU preview response has invalid identity or execution permissions".into(),
            );
        }
        if matches!(
            self.phase,
            Phase::Ready | Phase::Authorizing | Phase::Approved
        ) && self.preview.is_none()
        {
            return Err("MTU preview response is missing its reviewed scope".into());
        }
        if self.phase == Phase::Approved && self.grant.is_none() {
            return Err("MTU approval response is missing its recorded grant".into());
        }
        if let Some(preview) = &self.preview
            && (preview.schemaVersion != 1
                || preview.previewId.is_nil()
                || preview.checkpointId.is_nil()
                || preview.context.adapterGuid.is_nil()
                || preview.allowRetention
                || !(1280..preview.originalMtu).contains(&preview.proposedMtu)
                || preview.expiresAtUnixMs == 0
                || preview.expiresAtUnixMs > preview.trialExpiresAtUnixMs
                || preview.checkpointSha256.len() != 64
                || !preview
                    .checkpointSha256
                    .bytes()
                    .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value)))
        {
            return Err("MTU preview response has invalid or unsupported trial scope".into());
        }
        if let Some(grant) = &self.grant {
            let preview = self
                .preview
                .as_ref()
                .ok_or("MTU grant response is missing its original preview")?;
            if grant.grantId.is_nil()
                || grant.allowRetention
                || grant.checkpointId != preview.checkpointId
                || grant.checkpointSha256 != preview.checkpointSha256
                || grant.expiresAtUnixMs != preview.trialExpiresAtUnixMs
            {
                return Err(
                    "MTU grant response does not match the reviewed temporary trial".into(),
                );
            }
        }
        Ok(())
    }
}
