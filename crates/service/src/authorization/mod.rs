mod store;
pub use store::AuthorizationStore;

use crate::{
    ServiceResult,
    journal::{AdapterContext, AddressFamily, MtuCheckpoint},
    recovery::AuthorizationAction,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;
use uuid::Uuid;

const MAX_LIFETIME_MS: u64 = 86_400_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MtuGrant {
    pub schemaVersion: u32,
    pub id: Uuid,
    pub issuerInstanceId: Uuid,
    pub checkpointId: Uuid,
    pub checkpointSha256: String,
    pub authorizedUserSid: String,
    pub context: AdapterContext,
    pub addressFamily: AddressFamily,
    pub proposedMtu: u32,
    pub createdAtUnixMs: u64,
    pub expiresAtUnixMs: u64,
    pub allowRetention: bool,
}

impl MtuGrant {
    fn validate(&self) -> ServiceResult<()> {
        if self.schemaVersion != 1
            || self.id.is_nil()
            || self.issuerInstanceId.is_nil()
            || self.checkpointId.is_nil()
            || self.context.adapterGuid.is_nil()
            || self.checkpointSha256.len() != 64
            || !self
                .checkpointSha256
                .bytes()
                .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
            || self.createdAtUnixMs == 0
            || self.expiresAtUnixMs > i64::MAX as u64
            || self.expiresAtUnixMs <= self.createdAtUnixMs
            || self.expiresAtUnixMs - self.createdAtUnixMs > MAX_LIFETIME_MS
        {
            return Err("Authorization grant identity, fingerprint, or lifetime is invalid".into());
        }
        validateSid(&self.authorizedUserSid)?;
        for value in [&self.context.osBuild, &self.context.driverVersion] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err("Authorization grant requires exact OS and driver context".into());
            }
        }
        let minimum = match self.addressFamily {
            AddressFamily::Ipv4 => 68,
            AddressFamily::Ipv6 => 1280,
        };
        if !(minimum..=65_535).contains(&self.proposedMtu) {
            return Err("Authorization grant MTU is outside the supported range".into());
        }
        Ok(())
    }
}

fn validateSid(value: &str) -> ServiceResult<()> {
    if !value.starts_with("S-1-")
        || value.len() > 184
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && byte != b'-' && byte != b'S')
    {
        return Err("Authorization requires a canonical Windows user SID".into());
    }
    #[cfg(windows)]
    if crate::security::canonicalSid(value)? != value {
        return Err("Authorization SID is not canonical".into());
    }
    Ok(())
}

fn checksum(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn checkpointChecksum(document: &MtuCheckpoint) -> ServiceResult<String> {
    Ok(checksum(&serde_json::to_string_pretty(document)?))
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
enum EventKind {
    Issued,
    PrepareChecked,
    ApplyChecked,
    RetentionChecked,
    Revoked,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Event {
    sequence: u32,
    timestampUnixMs: u64,
    previousSha256: String,
    kind: EventKind,
}

pub struct GrantRecord {
    pub grant: MtuGrant,
    pub claimed: bool,
    pub revoked: bool,
    events: Vec<Event>,
    lastSha256: String,
}

struct Fence {
    deadline: Instant,
    highWaterUnixMs: u64,
    revoked: bool,
}

struct Check<'a> {
    document: &'a MtuCheckpoint,
    actorSid: &'a str,
    action: AuthorizationAction,
    nowUnixMs: u64,
}

fn validateCheck(
    record: &GrantRecord,
    request: Check<'_>,
    instanceId: Uuid,
    fence: &mut Fence,
    requireClaim: bool,
) -> ServiceResult<()> {
    let grant = &record.grant;
    let document = request.document;
    document.validate()?;
    validateSid(request.actorSid)?;
    if record.revoked || fence.revoked || grant.issuerInstanceId != instanceId {
        return Err("Authorization was revoked or belongs to an earlier service instance".into());
    }
    if !matches!(document.schemaVersion, 2..=4)
        || grant.checkpointId != document.id
        || grant.checkpointSha256 != checkpointChecksum(document)?
        || grant.context != document.context
        || grant.addressFamily != document.addressFamily
        || grant.proposedMtu != document.proposedMtu
        || grant.authorizedUserSid != request.actorSid
        || document.authorizedUserSid != request.actorSid
        || grant.expiresAtUnixMs != document.leaseExpiresAtUnixMs
    {
        return Err(
            "Authorization does not match this user, adapter, or exact checkpoint operation".into(),
        );
    }
    let lastChecked = record
        .events
        .last()
        .ok_or("Authorization has no issued event")?
        .timestampUnixMs;
    if request.nowUnixMs < grant.createdAtUnixMs
        || request.nowUnixMs < lastChecked.max(fence.highWaterUnixMs)
        || request.nowUnixMs >= grant.expiresAtUnixMs
        || Instant::now() >= fence.deadline
    {
        return Err("Authorization expired or the system clock moved backward".into());
    }
    match request.action {
        AuthorizationAction::Prepare if record.claimed => {
            return Err("A claimed authorization cannot prepare another operation".into());
        }
        AuthorizationAction::Apply if requireClaim && !record.claimed => {
            return Err("Apply authorization must be durably claimed before writing".into());
        }
        AuthorizationAction::Retain if !record.claimed || !grant.allowRetention => {
            return Err("Authorization does not permit retention".into());
        }
        _ => {}
    }
    fence.highWaterUnixMs = request.nowUnixMs;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
