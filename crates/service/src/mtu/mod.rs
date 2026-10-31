use crate::{ServiceResult, journal::AddressFamily};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;
use uuid::Uuid;

#[cfg(windows)]
mod windows;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OsContext {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub updateRevision: u32,
    pub nativeArchitecture: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DriverIdentity {
    pub version: String,
    pub infPath: String,
    pub infSection: String,
    pub deviceInstanceId: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum DriverContext {
    Captured { identity: DriverIdentity },
    Unavailable { error: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InterfaceSettings {
    pub advertisingEnabled: bool,
    pub forwardingEnabled: bool,
    pub weakHostSend: bool,
    pub weakHostReceive: bool,
    pub useAutomaticMetric: bool,
    pub useNeighborUnreachabilityDetection: bool,
    pub managedAddressConfigurationSupported: bool,
    pub otherStatefulConfigurationSupported: bool,
    pub advertiseDefaultRoute: bool,
    pub routerDiscoveryBehavior: i32,
    pub dadTransmits: u32,
    pub baseReachableTime: u32,
    pub retransmitTime: u32,
    pub pathMtuDiscoveryTimeout: u32,
    pub linkLocalAddressBehavior: i32,
    pub linkLocalAddressTimeout: u32,
    pub zoneIndices: [u32; 16],
    pub sitePrefixLength: u32,
    pub metric: u32,
    pub nlMtu: u32,
    pub disableDefaultRoutes: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Snapshot {
    pub schemaVersion: u32,
    pub capturedAtUnixMs: u64,
    pub adapterGuid: Uuid,
    pub addressFamily: AddressFamily,
    pub interfaceLuid: String,
    pub interfaceIndex: u32,
    pub alias: String,
    pub description: String,
    pub linkMtu: u32,
    pub interfaceType: u32,
    pub tunnelType: i32,
    pub operationalStatus: i32,
    pub mediaConnectState: i32,
    pub interfaceStatusFlags: u8,
    pub os: OsContext,
    pub driver: DriverContext,
    pub settings: InterfaceSettings,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureEntry {
    pub interfaceIndex: u32,
    pub adapterGuid: Option<Uuid>,
    pub addressFamily: AddressFamily,
    pub snapshot: Option<Snapshot>,
    pub error: Option<String>,
}

pub fn capture(
    adapterGuid: Uuid,
    addressFamily: AddressFamily,
    cancelled: &AtomicBool,
) -> ServiceResult<Snapshot> {
    if adapterGuid.is_nil() {
        return Err("Native MTU capture requires a nonempty adapter GUID".into());
    }
    #[cfg(windows)]
    {
        windows::capture(adapterGuid, addressFamily, cancelled)
    }
    #[cfg(not(windows))]
    {
        let _ = (adapterGuid, addressFamily, cancelled);
        Err("Native MTU capture requires Windows".into())
    }
}

pub fn inventory(cancelled: &AtomicBool) -> ServiceResult<Vec<CaptureEntry>> {
    #[cfg(windows)]
    {
        windows::inventory(cancelled)
    }
    #[cfg(not(windows))]
    {
        let _ = cancelled;
        Err("Native MTU capture requires Windows".into())
    }
}

pub fn captureMany(
    adapterGuids: &[Uuid],
    cancelled: &AtomicBool,
) -> ServiceResult<Vec<CaptureEntry>> {
    let unique: std::collections::BTreeSet<_> = adapterGuids.iter().collect();
    if adapterGuids.len() > 256
        || unique.len() != adapterGuids.len()
        || adapterGuids.iter().any(Uuid::is_nil)
    {
        return Err(
            "Native MTU capture requires up to 256 distinct, nonempty adapter GUIDs".into(),
        );
    }
    #[cfg(windows)]
    {
        windows::captureMany(adapterGuids, cancelled)
    }
    #[cfg(not(windows))]
    {
        let _ = cancelled;
        Err("Native MTU capture requires Windows".into())
    }
}
