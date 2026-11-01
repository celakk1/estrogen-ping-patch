mod context;
#[cfg(feature = "native-mtu-lab")]
mod write;
use super::{CaptureEntry, InterfaceSettings, Snapshot};
use crate::{ServiceResult, journal::AddressFamily};
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;
use windows_sys::{
    Win32::{
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToGuid, FreeMibTable, GetIfEntry2,
                GetIpInterfaceEntry, GetIpInterfaceTable, MIB_IF_ROW2, MIB_IPINTERFACE_ROW,
                MIB_IPINTERFACE_TABLE,
            },
            Ndis::NET_LUID_LH,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
    },
    core::GUID,
};
#[cfg(feature = "native-mtu-lab")]
pub(super) use write::{ensureLabCommandStopped, waitForLabMutator, writeLabMtu};

fn checkCancellation(cancelled: &AtomicBool) -> ServiceResult<()> {
    if cancelled.load(Ordering::SeqCst) {
        Err("Native MTU capture cancelled; no partial capture is published".into())
    } else {
        Ok(())
    }
}

fn nativeGuid(value: Uuid) -> GUID {
    let (data1, data2, data3, data4) = value.as_fields();
    GUID {
        data1,
        data2,
        data3,
        data4: *data4,
    }
}

fn uuid(value: GUID) -> Uuid {
    Uuid::from_fields(value.data1, value.data2, value.data3, &value.data4)
}

fn errorCode(operation: &str, code: u32) -> ServiceResult<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{operation} failed: Windows {code}: {}",
            std::io::Error::from_raw_os_error(code as i32)
        )
        .into())
    }
}

fn fixedText(value: &[u16]) -> ServiceResult<String> {
    let length = value
        .iter()
        .position(|value| *value == 0)
        .ok_or("Native interface text has no terminator")?;
    Ok(String::from_utf16(&value[..length])?)
}

fn settings(row: &MIB_IPINTERFACE_ROW) -> InterfaceSettings {
    InterfaceSettings {
        advertisingEnabled: row.AdvertisingEnabled,
        forwardingEnabled: row.ForwardingEnabled,
        weakHostSend: row.WeakHostSend,
        weakHostReceive: row.WeakHostReceive,
        useAutomaticMetric: row.UseAutomaticMetric,
        useNeighborUnreachabilityDetection: row.UseNeighborUnreachabilityDetection,
        managedAddressConfigurationSupported: row.ManagedAddressConfigurationSupported,
        otherStatefulConfigurationSupported: row.OtherStatefulConfigurationSupported,
        advertiseDefaultRoute: row.AdvertiseDefaultRoute,
        routerDiscoveryBehavior: row.RouterDiscoveryBehavior,
        dadTransmits: row.DadTransmits,
        baseReachableTime: row.BaseReachableTime,
        retransmitTime: row.RetransmitTime,
        pathMtuDiscoveryTimeout: row.PathMtuDiscoveryTimeout,
        linkLocalAddressBehavior: row.LinkLocalAddressBehavior,
        linkLocalAddressTimeout: row.LinkLocalAddressTimeout,
        zoneIndices: row.ZoneIndices,
        sitePrefixLength: row.SitePrefixLength,
        metric: row.Metric,
        nlMtu: row.NlMtu,
        disableDefaultRoutes: row.DisableDefaultRoutes,
    }
}

fn family(value: AddressFamily) -> u16 {
    match value {
        AddressFamily::Ipv4 => AF_INET,
        AddressFamily::Ipv6 => AF_INET6,
    }
}

fn read(
    adapterGuid: Uuid,
    addressFamily: AddressFamily,
    os: &super::OsContext,
    drivers: &context::Drivers,
    cancelled: &AtomicBool,
) -> ServiceResult<Snapshot> {
    checkCancellation(cancelled)?;
    if adapterGuid.is_nil() {
        return Err("MTU capture requires a nonempty adapter GUID".into());
    }
    let mut luid = NET_LUID_LH::default();
    errorCode("ConvertInterfaceGuidToLuid", unsafe {
        ConvertInterfaceGuidToLuid(&nativeGuid(adapterGuid), &mut luid)
    })?;
    let mut roundTrip = GUID::from_u128(0);
    errorCode("ConvertInterfaceLuidToGuid", unsafe {
        ConvertInterfaceLuidToGuid(&luid, &mut roundTrip)
    })?;
    if uuid(roundTrip) != adapterGuid {
        return Err("Adapter GUID to LUID mapping did not round trip".into());
    }
    let mut link = MIB_IF_ROW2 {
        InterfaceLuid: luid,
        ..Default::default()
    };
    errorCode("GetIfEntry2", unsafe { GetIfEntry2(&mut link) })?;
    if uuid(link.InterfaceGuid) != adapterGuid
        || unsafe { link.InterfaceLuid.Value } != unsafe { luid.Value }
    {
        return Err("Link identity changed during native MTU capture".into());
    }
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family(addressFamily),
        InterfaceLuid: luid,
        ..Default::default()
    };
    errorCode("GetIpInterfaceEntry", unsafe {
        GetIpInterfaceEntry(&mut row)
    })?;
    if row.Family != family(addressFamily)
        || row.InterfaceIndex != link.InterfaceIndex
        || unsafe { row.InterfaceLuid.Value } != unsafe { luid.Value }
    {
        return Err("IP interface identity changed during native MTU capture".into());
    }
    checkCancellation(cancelled)?;
    Ok(Snapshot {
        schemaVersion: 1,
        capturedAtUnixMs: crate::transport::nowUnixMs()?,
        adapterGuid,
        addressFamily,
        interfaceLuid: unsafe { luid.Value }.to_string(),
        interfaceIndex: row.InterfaceIndex,
        alias: fixedText(&link.Alias)?,
        description: fixedText(&link.Description)?,
        linkMtu: link.Mtu,
        interfaceType: link.Type,
        tunnelType: link.TunnelType,
        operationalStatus: link.OperStatus,
        mediaConnectState: link.MediaConnectState,
        interfaceStatusFlags: link.InterfaceAndOperStatusFlags._bitfield,
        os: os.clone(),
        driver: drivers.get(adapterGuid),
        settings: settings(&row),
    })
}

pub(super) fn capture(
    adapterGuid: Uuid,
    addressFamily: AddressFamily,
    cancelled: &AtomicBool,
) -> ServiceResult<Snapshot> {
    checkCancellation(cancelled)?;
    let os = context::os()?;
    let drivers = context::Drivers::capture(cancelled)?;
    read(adapterGuid, addressFamily, &os, &drivers, cancelled)
}

pub(super) fn captureMany(
    adapterGuids: &[Uuid],
    cancelled: &AtomicBool,
) -> ServiceResult<Vec<CaptureEntry>> {
    checkCancellation(cancelled)?;
    if adapterGuids.is_empty() {
        return Ok(Vec::new());
    }
    let os = context::os()?;
    let drivers = context::Drivers::capture(cancelled)?;
    let mut entries = Vec::with_capacity(adapterGuids.len() * 2);
    for adapterGuid in adapterGuids {
        for addressFamily in [AddressFamily::Ipv4, AddressFamily::Ipv6] {
            let result = read(*adapterGuid, addressFamily, &os, &drivers, cancelled);
            checkCancellation(cancelled)?;
            let (snapshot, error) = match result {
                Ok(snapshot) => (Some(snapshot), None),
                Err(error) => (None, Some(error.to_string().chars().take(512).collect())),
            };
            entries.push(CaptureEntry {
                interfaceIndex: snapshot
                    .as_ref()
                    .map_or(0, |snapshot| snapshot.interfaceIndex),
                adapterGuid: Some(*adapterGuid),
                addressFamily,
                snapshot,
                error,
            });
        }
    }
    Ok(entries)
}

struct InterfaceTable(*mut MIB_IPINTERFACE_TABLE);
impl Drop for InterfaceTable {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.0.cast()) };
    }
}

pub(super) fn inventory(cancelled: &AtomicBool) -> ServiceResult<Vec<CaptureEntry>> {
    checkCancellation(cancelled)?;
    let os = context::os()?;
    let drivers = context::Drivers::capture(cancelled)?;
    let mut table = std::ptr::null_mut();
    errorCode("GetIpInterfaceTable", unsafe {
        GetIpInterfaceTable(AF_UNSPEC, &mut table)
    })?;
    if table.is_null() {
        return Err("GetIpInterfaceTable returned no allocation".into());
    }
    let table = InterfaceTable(table);
    let count = unsafe { (*table.0).NumEntries } as usize;
    if count > 4096 {
        return Err("Native IP interface count exceeds 4096".into());
    }
    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table.0).Table).cast::<MIB_IPINTERFACE_ROW>(),
            count,
        )
    };
    let mut entries = Vec::with_capacity(count);
    for row in rows {
        checkCancellation(cancelled)?;
        let addressFamily = match row.Family {
            AF_INET => AddressFamily::Ipv4,
            AF_INET6 => AddressFamily::Ipv6,
            _ => return Err("Native IP interface table contains an unsupported family".into()),
        };
        let mut guid = GUID::from_u128(0);
        let code = unsafe { ConvertInterfaceLuidToGuid(&row.InterfaceLuid, &mut guid) };
        let adapterGuid = (code == 0)
            .then(|| uuid(guid))
            .filter(|guid| !guid.is_nil());
        let result = match adapterGuid {
            Some(guid) => {
                read(guid, addressFamily, &os, &drivers, cancelled).and_then(|snapshot| {
                    if snapshot.interfaceIndex != row.InterfaceIndex
                        || snapshot.interfaceLuid != unsafe { row.InterfaceLuid.Value }.to_string()
                    {
                        return Err("Native table identity changed during capture".into());
                    }
                    Ok(snapshot)
                })
            }
            None => Err(format!(
                "Interface {} has no stable adapter GUID (Windows {code})",
                row.InterfaceIndex
            )
            .into()),
        };
        checkCancellation(cancelled)?;
        let (snapshot, error) = match result {
            Ok(snapshot) => (Some(snapshot), None),
            Err(error) => (None, Some(error.to_string().chars().take(512).collect())),
        };
        entries.push(CaptureEntry {
            interfaceIndex: row.InterfaceIndex,
            adapterGuid,
            addressFamily,
            snapshot,
            error,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests;
