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

impl Snapshot {
    pub fn journalContext(&self) -> ServiceResult<crate::journal::AdapterContext> {
        let luid = self
            .interfaceLuid
            .parse::<u64>()
            .map_err(|_| "Native snapshot LUID is invalid")?;
        if self.schemaVersion != 1
            || self.adapterGuid.is_nil()
            || self.interfaceIndex == 0
            || luid == 0
            || luid.to_string() != self.interfaceLuid
            || self.capturedAtUnixMs == 0
            || self.capturedAtUnixMs > i64::MAX as u64
            || self.os.major < 10
            || self.os.build == 0
            || !matches!(self.os.nativeArchitecture, 9 | 12)
        {
            return Err("Native checkpoint identity or OS context is incomplete".into());
        }
        let DriverContext::Captured { identity } = &self.driver else {
            return Err("Native checkpoint requires a verified driver identity".into());
        };
        for (value, maximum) in [
            (&identity.version, 256),
            (&identity.infPath, 4096),
            (&identity.infSection, 4096),
            (&identity.deviceInstanceId, 4096),
        ] {
            if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
                return Err("Native checkpoint driver identity is malformed".into());
            }
        }
        let minimum = match self.addressFamily {
            AddressFamily::Ipv4 => 68,
            AddressFamily::Ipv6 => 1280,
        };
        if self.settings.nlMtu < minimum
            || self.linkMtu < self.settings.nlMtu
            || self.alias.len() > 2048
            || self.description.len() > 2048
        {
            return Err("Native checkpoint MTU capability or interface metadata is invalid".into());
        }
        Ok(crate::journal::AdapterContext {
            adapterGuid: self.adapterGuid,
            osBuild: format!(
                "{}.{}.{}.{};arch={}",
                self.os.major,
                self.os.minor,
                self.os.build,
                self.os.updateRevision,
                self.os.nativeArchitecture
            ),
            driverVersion: identity.version.clone(),
        })
    }

    pub(crate) fn validateMtuIdentity(&self, original: &Self) -> ServiceResult<()> {
        if self.journalContext()? != original.journalContext()?
            || self.addressFamily != original.addressFamily
            || self.os != original.os
            || self.driver != original.driver
            || self.linkMtu != original.linkMtu
            || self.interfaceType != original.interfaceType
            || self.tunnelType != original.tunnelType
        {
            return Err("Native adapter, OS, driver, family, or MTU capability changed".into());
        }
        Ok(())
    }

    pub(crate) fn validateMtuObservation(&self, original: &Self) -> ServiceResult<()> {
        self.validateMtuIdentity(original)?;
        let mut settings = self.settings.clone();
        settings.nlMtu = original.settings.nlMtu;
        if settings != original.settings {
            let current = serde_json::to_value(&settings)?;
            let expected = serde_json::to_value(&original.settings)?;
            let changed = current
                .as_object()
                .ok_or("Native interface settings must serialize as an object")?
                .iter()
                .filter(|(name, value)| expected.get(name.as_str()) != Some(*value))
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "Unrelated native interface settings changed ({changed}); refusing an unsafe MTU transition"
            ).into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn driftDiagnosticsNameUnrelatedFieldsWithoutChangingEvidence() {
        let original = crate::recovery::tests::nativeFixture();
        let mut observed = original.clone();
        observed.settings.nlMtu = 1400;
        observed.settings.metric += 1;
        observed.settings.sitePrefixLength = 64;
        let before = observed.clone();
        let error = observed
            .validateMtuObservation(&original)
            .unwrap_err()
            .to_string();
        assert!(error.contains("metric"));
        assert!(error.contains("sitePrefixLength"));
        assert!(!error.contains("nlMtu"));
        assert_eq!(observed, before);
        observed.settings.metric = original.settings.metric;
        observed.settings.sitePrefixLength = original.settings.sitePrefixLength;
        observed.validateMtuObservation(&original).unwrap();
    }
}

#[cfg(all(windows, feature = "native-mtu-lab"))]
pub(crate) fn ensureLabCommandStopped() -> ServiceResult<()> {
    windows::ensureLabCommandStopped()
}

#[cfg(all(windows, feature = "native-mtu-lab"))]
pub(crate) fn waitForLabMutator(identity: &crate::journal::MutatorIdentity) -> ServiceResult<()> {
    windows::waitForLabMutator(identity)
}

#[cfg(all(windows, feature = "native-mtu-lab"))]
pub(crate) fn writeLabMtu(
    permit: &crate::mtu_lab::ServicePermit,
    original: &Snapshot,
    expected: &Snapshot,
    value: u32,
    deadline: std::time::Instant,
    authorize: Option<&mut dyn FnMut() -> ServiceResult<()>>,
    register: &mut crate::recovery::MutatorRegistrar<'_>,
) -> ServiceResult<()> {
    windows::writeLabMtu(
        permit, original, expected, value, deadline, authorize, register,
    )
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
