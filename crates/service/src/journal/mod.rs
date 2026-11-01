mod mutators;
mod policy;
mod store;
pub use mutators::{MutatorIdentity, MutatorRecord};
pub use policy::{PolicyReadback, PolicyRecord};
pub use store::Journal;
pub const SCHEMA_VERSION: u32 = 4;

use crate::ServiceResult;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterContext {
    pub adapterGuid: Uuid,
    pub osBuild: String,
    pub driverVersion: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MtuCheckpoint {
    pub schemaVersion: u32,
    pub id: Uuid,
    pub createdAtUnixMs: u64,
    pub leaseExpiresAtUnixMs: u64,
    pub authorizedUserSid: String,
    pub context: AdapterContext,
    pub addressFamily: AddressFamily,
    pub originalMtu: u32,
    pub proposedMtu: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nativeOriginal: Option<crate::mtu::Snapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policyOriginal: Option<crate::mtu::policy::Evidence>,
}

impl MtuCheckpoint {
    pub fn validate(&self) -> ServiceResult<()> {
        if !matches!(self.schemaVersion, 1..=4)
            || self.id.is_nil()
            || self.context.adapterGuid.is_nil()
        {
            return Err("Unsupported checkpoint schema or missing durable identity".into());
        }
        for value in [&self.context.osBuild, &self.context.driverVersion] {
            if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                return Err("Checkpoint OS/driver context is missing or malformed".into());
            }
        }
        if !self.authorizedUserSid.starts_with("S-1-")
            || self.authorizedUserSid.len() > 184
            || self
                .authorizedUserSid
                .bytes()
                .any(|byte| !byte.is_ascii_digit() && byte != b'-' && byte != b'S')
        {
            return Err("Checkpoint requires an authorized Windows user SID".into());
        }
        #[cfg(windows)]
        if crate::security::canonicalSid(&self.authorizedUserSid)? != self.authorizedUserSid {
            return Err("Checkpoint SID must be canonical".into());
        }
        if self.createdAtUnixMs == 0
            || self.leaseExpiresAtUnixMs > i64::MAX as u64
            || self.leaseExpiresAtUnixMs <= self.createdAtUnixMs
            || self.leaseExpiresAtUnixMs - self.createdAtUnixMs > 86_400_000
        {
            return Err("Checkpoint lease must be positive and bounded to 24 hours".into());
        }
        let minimum = match self.addressFamily {
            AddressFamily::Ipv4 => 68,
            AddressFamily::Ipv6 => 1280,
        };
        if self.originalMtu < minimum
            || !(minimum..=65_535).contains(&self.proposedMtu)
            || self.originalMtu == self.proposedMtu
        {
            return Err("Checkpoint MTU values are unsupported or unchanged".into());
        }
        match (self.schemaVersion, &self.nativeOriginal) {
            (1, None) => {}
            (2..=4, Some(native)) => {
                native.requireOriginalOrigins()?;
                if native.journalContext()? != self.context
                    || native.addressFamily != self.addressFamily
                    || native.settings.nlMtu != self.originalMtu
                    || self.proposedMtu > native.linkMtu
                    || native.capturedAtUnixMs > self.createdAtUnixMs
                    || self.createdAtUnixMs - native.capturedAtUnixMs > 5000
                {
                    return Err("Native checkpoint original, context, capability, or capture time is inconsistent".into());
                }
            }
            _ => {
                return Err("Checkpoint schema does not match its native original snapshot".into());
            }
        }
        match (
            self.schemaVersion,
            &self.policyOriginal,
            &self.nativeOriginal,
        ) {
            (1..=3, None, _) => {}
            (4, Some(policy), Some(native)) => policy.validate(native)?,
            _ => {
                return Err("Checkpoint schema does not match its exact IP policy original".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum State {
    Prepared,
    Applying,
    Applied,
    Restoring,
    RecoveryRequired,
    Restored,
    Retained,
    Cancelled,
}

impl State {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Restored | Self::Retained | Self::Cancelled)
    }

    fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepared, Self::Applying | Self::Cancelled)
                | (
                    Self::Applying,
                    Self::Applied | Self::Restoring | Self::Restored | Self::RecoveryRequired
                )
                | (
                    Self::Applied,
                    Self::Retained | Self::Restoring | Self::Restored | Self::RecoveryRequired
                )
                | (Self::Restoring, Self::Restored | Self::RecoveryRequired)
                | (Self::RecoveryRequired, Self::Restoring | Self::Restored)
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub context: AdapterContext,
    pub addressFamily: AddressFamily,
    pub mtu: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<crate::mtu::Snapshot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Event {
    pub sequence: u32,
    pub timestampUnixMs: u64,
    pub previousSha256: String,
    pub state: State,
    pub observation: Option<Observation>,
}

#[derive(Clone, Debug)]
pub struct Checkpoint {
    document: MtuCheckpoint,
    documentSha256: String,
    events: Vec<Event>,
    lastEventSha256: String,
    policyVerifications: Vec<PolicyRecord>,
}

impl Checkpoint {
    pub fn document(&self) -> &MtuCheckpoint {
        &self.document
    }
    pub fn documentSha256(&self) -> &str {
        &self.documentSha256
    }
    pub fn events(&self) -> &[Event] {
        &self.events
    }
    pub fn policyVerifications(&self) -> &[PolicyRecord] {
        &self.policyVerifications
    }
    pub fn state(&self) -> State {
        self.events
            .last()
            .expect("validated checkpoint has an initial event")
            .state
    }
}

fn validateEvent(
    document: &MtuCheckpoint,
    previous: Option<State>,
    event: &Event,
) -> ServiceResult<()> {
    if event.timestampUnixMs == 0 || event.timestampUnixMs > i64::MAX as u64 {
        return Err("Checkpoint event timestamp is invalid".into());
    }
    match previous {
        None if event.state != State::Prepared || event.observation.is_some() => {
            return Err("Checkpoint must begin with a prepared event".into());
        }
        Some(previous) if !previous.permits(event.state) => {
            return Err("Checkpoint state transition is not permitted".into());
        }
        _ => {}
    }
    if matches!(
        event.state,
        State::Prepared | State::Applying | State::Applied | State::Retained
    ) && (event.timestampUnixMs < document.createdAtUnixMs
        || event.timestampUnixMs >= document.leaseExpiresAtUnixMs)
    {
        return Err("Checkpoint lease expired; only cancellation or recovery is permitted".into());
    }
    if matches!(
        event.state,
        State::Applying | State::Applied | State::Restoring | State::Restored | State::Retained
    ) {
        let observed = event
            .observation
            .as_ref()
            .ok_or("Checkpoint transition requires a fresh setting observation")?;
        if observed.context != document.context || observed.addressFamily != document.addressFamily
        {
            return Err("Adapter GUID, OS, driver, or address family changed; refusing an unsafe transition".into());
        }
        let matchesOriginal = observed.mtu == document.originalMtu;
        let matchesProposed = observed.mtu == document.proposedMtu;
        let valid = match event.state {
            State::Applying | State::Restored => matchesOriginal,
            State::Applied | State::Retained => matchesProposed,
            State::Restoring => matchesOriginal || matchesProposed,
            _ => false,
        };
        if !valid {
            return Err("Live setting differs from the expected original/candidate; manual investigation is required".into());
        }
        match (&document.nativeOriginal, &observed.native) {
            (Some(original), Some(native)) => {
                if matches!(event.state, State::Restoring | State::Restored) {
                    native.validateMtuIdentity(original)?;
                } else {
                    native.validateMtuObservation(original)?;
                }
                if native.settings.nlMtu != observed.mtu
                    || native.journalContext()? != observed.context
                    || native.capturedAtUnixMs > event.timestampUnixMs.saturating_add(250)
                    || event
                        .timestampUnixMs
                        .saturating_sub(native.capturedAtUnixMs)
                        > 5000
                {
                    return Err(
                        "Native observation value, identity, or freshness is invalid".into(),
                    );
                }
            }
            (None, None) => {}
            _ => return Err("Native checkpoint and observation evidence do not match".into()),
        }
    } else if event.observation.is_some() {
        return Err("Unexpected observation on a non-verification event".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
