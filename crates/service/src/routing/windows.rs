use super::{Address, LinkStatistics, Snapshot};
use crate::ServiceResult;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr::null,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use windows_sys::{
    Win32::{
        NetworkManagement::IpHelper::{
            ConvertInterfaceGuidToLuid, ConvertInterfaceLuidToGuid, GetBestRoute2, GetIfEntry2,
            MIB_IF_ROW2, MIB_IPFORWARD_ROW2,
        },
        NetworkManagement::Ndis::NET_LUID_LH,
        Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET},
    },
    core::GUID,
};

fn checked(operation: &str, code: u32) -> ServiceResult<()> {
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

fn sockaddr(address: &Address) -> SOCKADDR_INET {
    match address.ip {
        IpAddr::V4(ip) => {
            let mut native = SOCKADDR_IN {
                sin_family: AF_INET,
                ..Default::default()
            };
            native.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
            SOCKADDR_INET { Ipv4: native }
        }
        IpAddr::V6(ip) => {
            let mut native = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                ..Default::default()
            };
            native.sin6_addr.u.Byte = ip.octets();
            native.Anonymous.sin6_scope_id = address.scopeId;
            SOCKADDR_INET { Ipv6: native }
        }
    }
}

fn address(native: &SOCKADDR_INET) -> ServiceResult<Address> {
    match unsafe { native.si_family } {
        AF_INET => Ok(Address {
            ip: IpAddr::V4(Ipv4Addr::from(
                unsafe { native.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
            )),
            scopeId: 0,
        }),
        AF_INET6 => Ok(Address {
            ip: IpAddr::V6(Ipv6Addr::from(unsafe { native.Ipv6.sin6_addr.u.Byte })),
            scopeId: unsafe { native.Ipv6.Anonymous.sin6_scope_id },
        }),
        _ => Err("Windows returned an unsupported route address family".into()),
    }
}

pub(super) fn capture(destination: &Address) -> ServiceResult<Snapshot> {
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    checked("GetBestRoute2", unsafe {
        GetBestRoute2(
            null(),
            0,
            null(),
            &sockaddr(destination),
            0,
            &mut route,
            &mut source,
        )
    })?;
    let mut guid = GUID::from_u128(0);
    checked("ConvertInterfaceLuidToGuid", unsafe {
        ConvertInterfaceLuidToGuid(&route.InterfaceLuid, &mut guid)
    })?;
    let mut roundTrip = NET_LUID_LH::default();
    checked("ConvertInterfaceGuidToLuid", unsafe {
        ConvertInterfaceGuidToLuid(&guid, &mut roundTrip)
    })?;
    let mut link = MIB_IF_ROW2 {
        InterfaceLuid: route.InterfaceLuid,
        ..Default::default()
    };
    let queryStartedAtUnixMs = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let queryStarted = Instant::now();
    checked("GetIfEntry2", unsafe { GetIfEntry2(&mut link) })?;
    let queryElapsedNs = u64::try_from(queryStarted.elapsed().as_nanos())?.to_string();
    let queryFinishedAtUnixMs = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?;
    let adapterGuid = uuid::Uuid::from_fields(guid.data1, guid.data2, guid.data3, &guid.data4);
    if unsafe { roundTrip.Value } != unsafe { route.InterfaceLuid.Value }
        || unsafe { link.InterfaceLuid.Value } != unsafe { route.InterfaceLuid.Value }
        || link.InterfaceIndex != route.InterfaceIndex
        || uuid::Uuid::from_fields(
            link.InterfaceGuid.data1,
            link.InterfaceGuid.data2,
            link.InterfaceGuid.data3,
            &link.InterfaceGuid.data4,
        ) != adapterGuid
    {
        return Err("Selected route adapter identity changed during capture".into());
    }
    let snapshot = Snapshot {
        schemaVersion: 1,
        capturedAtUnixMs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
            .try_into()?,
        destination: destination.clone(),
        adapterGuid,
        interfaceLuid: unsafe { route.InterfaceLuid.Value }.to_string(),
        interfaceIndex: route.InterfaceIndex,
        source: address(&source)?,
        destinationPrefix: address(&route.DestinationPrefix.Prefix)?,
        prefixLength: route.DestinationPrefix.PrefixLength,
        nextHop: address(&route.NextHop)?,
        routeMetric: route.Metric,
        protocol: route.Protocol,
        origin: route.Origin,
        sitePrefixLength: route.SitePrefixLength,
        loopback: route.Loopback,
        autoconfigureAddress: route.AutoconfigureAddress,
        publish: route.Publish,
        immortal: route.Immortal,
        validLifetimeSeconds: route.ValidLifetime,
        preferredLifetimeSeconds: route.PreferredLifetime,
        ageSeconds: route.Age,
        linkStatistics: Some(Box::new(LinkStatistics {
            schemaVersion: 1,
            queryStartedAtUnixMs,
            queryFinishedAtUnixMs,
            queryElapsedNs,
            interfaceType: link.Type,
            operStatus: link.OperStatus,
            adminStatus: link.AdminStatus,
            mediaConnectState: link.MediaConnectState,
            receiveLinkSpeedBps: link.ReceiveLinkSpeed.to_string(),
            transmitLinkSpeedBps: link.TransmitLinkSpeed.to_string(),
            receivedOctets: link.InOctets.to_string(),
            sentOctets: link.OutOctets.to_string(),
            receivedUnicastPackets: link.InUcastPkts.to_string(),
            receivedNonUnicastPackets: link.InNUcastPkts.to_string(),
            sentUnicastPackets: link.OutUcastPkts.to_string(),
            sentNonUnicastPackets: link.OutNUcastPkts.to_string(),
            receivedDiscards: link.InDiscards.to_string(),
            receivedErrors: link.InErrors.to_string(),
            receivedUnknownProtocols: link.InUnknownProtos.to_string(),
            sentDiscards: link.OutDiscards.to_string(),
            sentErrors: link.OutErrors.to_string(),
        })),
    };
    snapshot.validate()?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nativeSocketAddressesPreserveByteOrderFamilyAndIpv6Scope() {
        for value in [
            Address {
                ip: "1.2.3.4".parse().unwrap(),
                scopeId: 0,
            },
            Address {
                ip: "fe80::1234:abcd".parse().unwrap(),
                scopeId: 12,
            },
        ] {
            let native = sockaddr(&value);
            assert_eq!(address(&native).unwrap(), value);
            if value.ip.is_ipv4() {
                assert_eq!(
                    unsafe { native.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
                    [1, 2, 3, 4]
                );
            }
        }
        assert!(address(&SOCKADDR_INET::default()).is_err());
    }
}
