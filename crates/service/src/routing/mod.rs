use crate::ServiceResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::IpAddr,
    sync::atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

pub(crate) const MAX_DESTINATIONS: usize = 16;

mod statistics;
#[cfg(test)]
pub(crate) mod tests;
pub use statistics::LinkStatistics;
#[cfg(windows)]
mod windows;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Address {
    pub ip: IpAddr,
    pub scopeId: u32,
}

impl Address {
    pub fn validateDestination(&self) -> ServiceResult<()> {
        if self.ip.is_unspecified()
            || self.ip.is_multicast()
            || matches!(self.ip, IpAddr::V4(ip) if ip.is_broadcast() || self.scopeId != 0)
            || matches!(self.ip, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() || (ip.is_unicast_link_local() && self.scopeId == 0))
        {
            return Err("Route inspection requires a numeric unicast destination; IPv6 link-local addresses require an interface scope".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    pub schemaVersion: u32,
    pub capturedAtUnixMs: u64,
    pub destination: Address,
    pub adapterGuid: Uuid,
    pub interfaceLuid: String,
    pub interfaceIndex: u32,
    pub source: Address,
    pub destinationPrefix: Address,
    pub prefixLength: u8,
    pub nextHop: Address,
    pub routeMetric: u32,
    pub protocol: i32,
    pub origin: i32,
    pub sitePrefixLength: u8,
    pub loopback: bool,
    pub autoconfigureAddress: bool,
    pub publish: bool,
    pub immortal: bool,
    pub validLifetimeSeconds: u32,
    pub preferredLifetimeSeconds: u32,
    pub ageSeconds: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linkStatistics: Option<Box<LinkStatistics>>,
}

impl Snapshot {
    pub fn validate(&self) -> ServiceResult<()> {
        self.destination.validateDestination()?;
        if let Some(statistics) = &self.linkStatistics {
            statistics.validate(self.capturedAtUnixMs)?;
        }
        let luid: u64 = self.interfaceLuid.parse()?;
        let prefixMatches = match (self.destination.ip, self.destinationPrefix.ip) {
            (IpAddr::V4(destination), IpAddr::V4(prefix)) if self.prefixLength <= 32 => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefixLength))
                    .unwrap_or(0);
                u32::from(destination) & mask == u32::from(prefix) & mask
            }
            (IpAddr::V6(destination), IpAddr::V6(prefix)) if self.prefixLength <= 128 => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefixLength))
                    .unwrap_or(0);
                u128::from(destination) & mask == u128::from(prefix) & mask
            }
            _ => false,
        };
        if self.schemaVersion != 1
            || self.capturedAtUnixMs == 0
            || self.capturedAtUnixMs > i64::MAX as u64
            || self.adapterGuid.is_nil()
            || self.interfaceIndex == 0
            || luid == 0
            || luid.to_string() != self.interfaceLuid
            || !prefixMatches
            || self.source.ip.is_unspecified()
            || self.source.ip.is_multicast()
            || self.source.ip.is_ipv4() != self.destination.ip.is_ipv4()
            || self.nextHop.ip.is_ipv4() != self.destination.ip.is_ipv4()
            || (self.destination.ip.is_ipv4()
                && (self.source.scopeId != 0
                    || self.nextHop.scopeId != 0
                    || self.destinationPrefix.scopeId != 0))
            || (matches!(self.destination.ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
                && self.destination.scopeId != self.interfaceIndex)
        {
            return Err(
                "Native route evidence has an invalid identity, family, source, or prefix".into(),
            );
        }
        Ok(())
    }

    pub fn matchesInterface(&self, interface: &crate::mtu::Snapshot) -> ServiceResult<()> {
        self.validate()?;
        if self.adapterGuid != interface.adapterGuid
            || self.interfaceLuid != interface.interfaceLuid
            || self.interfaceIndex != interface.interfaceIndex
            || self.destination.ip.is_ipv4()
                != (interface.addressFamily == crate::journal::AddressFamily::Ipv4)
        {
            return Err("Selected route and native interface evidence do not identify the same adapter and family".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Capture {
    Captured { snapshot: Snapshot },
    Unavailable { destination: Address, error: String },
}

pub fn capture(destinations: &[Address], cancelled: &AtomicBool) -> ServiceResult<Vec<Capture>> {
    if !(1..=MAX_DESTINATIONS).contains(&destinations.len()) {
        return Err(format!(
            "Route inspection requires one to {MAX_DESTINATIONS} numeric destinations"
        )
        .into());
    }
    for destination in destinations {
        destination.validateDestination()?;
    }
    let mut results = Vec::new();
    for destination in destinations {
        if cancelled.load(Ordering::SeqCst) {
            return Err("Route inspection was cancelled".into());
        }
        #[cfg(windows)]
        let result = windows::capture(destination);
        #[cfg(not(windows))]
        let result: ServiceResult<Snapshot> =
            Err("Native route inspection requires Windows".into());
        results.push(match result {
            Ok(snapshot) => Capture::Captured { snapshot },
            Err(error) => Capture::Unavailable {
                destination: destination.clone(),
                error: error.to_string().chars().take(512).collect(),
            },
        });
    }
    if cancelled.load(Ordering::SeqCst) {
        return Err("Route inspection was cancelled".into());
    }
    Ok(results)
}

pub fn fingerprint(captures: &[Capture]) -> ServiceResult<Option<String>> {
    if !(1..=MAX_DESTINATIONS).contains(&captures.len()) {
        return Err(
            format!("Routing identity requires one to {MAX_DESTINATIONS} capture results").into(),
        );
    }
    let mut stable = Vec::new();
    for capture in captures {
        let Capture::Captured { snapshot } = capture else {
            return Ok(None);
        };
        snapshot.validate()?;
        let mut value = snapshot.clone();
        // exclude volatile observations while comparing lifetime categories.
        value.capturedAtUnixMs = 1;
        value.ageSeconds = 0;
        value.linkStatistics = None;
        let category = |lifetime| match lifetime {
            0 => 0,
            u32::MAX => u32::MAX,
            _ => 1,
        };
        value.validLifetimeSeconds = category(value.validLifetimeSeconds);
        value.preferredLifetimeSeconds = category(value.preferredLifetimeSeconds);
        stable.push(value);
    }
    Ok(Some(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&("selected-route-v1", stable))?)
    )))
}
