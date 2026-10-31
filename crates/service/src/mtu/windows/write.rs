use super::*;
use crate::mtu_lab::ServicePermit;
use std::{
    ffi::OsString,
    os::windows::{ffi::OsStringExt, process::CommandExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use windows_sys::Win32::System::{
    SystemInformation::GetSystemDirectoryW, Threading::CREATE_NO_WINDOW,
};

fn validateRow(row: &MIB_IPINTERFACE_ROW, expected: &Snapshot) -> ServiceResult<()> {
    if row.Family != family(expected.addressFamily)
        || row.InterfaceIndex != expected.interfaceIndex
        || unsafe { row.InterfaceLuid.Value }.to_string() != expected.interfaceLuid
    {
        return Err("Native interface identity changed immediately before MTU write".into());
    }
    if settings(row) != expected.settings {
        return Err("Native interface settings changed immediately before MTU write".into());
    }
    Ok(())
}

fn arguments(original: &Snapshot, value: u32) -> [String; 7] {
    [
        "interface".into(),
        match original.addressFamily {
            AddressFamily::Ipv4 => "ipv4".into(),
            AddressFamily::Ipv6 => "ipv6".into(),
        },
        "set".into(),
        "subinterface".into(),
        format!("interface=epp-mtu-lab-{}", original.adapterGuid),
        format!("mtu={value}"),
        "store=active".into(),
    ]
}

fn executable() -> ServiceResult<PathBuf> {
    let mut buffer = [0u16; 260];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 || length >= buffer.len() {
        return Err("Cannot resolve the protected Windows system directory".into());
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])).join("netsh.exe"))
}

fn finishCommand(
    mut child: Child,
    mut check: impl FnMut() -> ServiceResult<()>,
) -> ServiceResult<()> {
    let outcome = loop {
        if let Err(error) = check() {
            break Err(error);
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break Ok(()),
            Ok(Some(status)) => break Err(format!("Windows MTU command failed: {status}").into()),
            Err(error) => break Err(error.into()),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    if outcome.is_err() && child.try_wait()?.is_none() {
        child.kill()?;
        child.wait()?;
    }
    outcome
}

pub(crate) fn writeLabMtu(
    permit: &ServicePermit,
    original: &Snapshot,
    expected: &Snapshot,
    value: u32,
    deadline: Instant,
    applyLease: Option<(u64, &AtomicBool)>,
) -> ServiceResult<()> {
    permit.validateTarget(original)?;
    if value != original.settings.nlMtu && value != 1400 {
        return Err("Native lab permits only its fixed candidate or exact original MTU".into());
    }
    let check = || -> ServiceResult<()> {
        if Instant::now() >= deadline {
            return Err("Windows MTU command deadline expired".into());
        }
        if let Some((expires, cancelled)) = applyLease
            && (cancelled.load(Ordering::SeqCst) || crate::transport::nowUnixMs()? >= expires)
        {
            return Err("Native lab apply authorization was revoked or expired".into());
        }
        Ok(())
    };
    check()?;
    let fresh = capture(
        original.adapterGuid,
        original.addressFamily,
        &AtomicBool::new(false),
    )?;
    permit.validateTarget(&fresh)?;
    fresh.validateMtuIdentity(original)?;
    if fresh.settings != expected.settings {
        return Err("Native interface settings drifted before the MTU write".into());
    }
    let mut luid = NET_LUID_LH::default();
    errorCode("ConvertInterfaceGuidToLuid", unsafe {
        ConvertInterfaceGuidToLuid(&nativeGuid(original.adapterGuid), &mut luid)
    })?;
    let mut roundTrip = GUID::from_u128(0);
    errorCode("ConvertInterfaceLuidToGuid", unsafe {
        ConvertInterfaceLuidToGuid(&luid, &mut roundTrip)
    })?;
    if uuid(roundTrip) != original.adapterGuid
        || unsafe { luid.Value }.to_string() != fresh.interfaceLuid
    {
        return Err("Native GUID/LUID identity changed immediately before MTU write".into());
    }
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family(original.addressFamily),
        InterfaceLuid: luid,
        ..Default::default()
    };
    errorCode("GetIpInterfaceEntry", unsafe {
        GetIpInterfaceEntry(&mut row)
    })?;
    validateRow(&row, &fresh)?;
    check()?;
    let child = Command::new(executable()?)
        .args(arguments(original, value))
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    finishCommand(child, check)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtuArgumentsHaveNoCallerSelectedProgramTargetOrPolicyStore() {
        let mut original = crate::recovery::tests::nativeFixture();
        for (family, name) in [(AddressFamily::Ipv4, "ipv4"), (AddressFamily::Ipv6, "ipv6")] {
            original.addressFamily = family;
            let args = arguments(&original, 1400);
            assert_eq!(args[0], "interface");
            assert_eq!(args[1], name);
            assert_eq!(&args[2..4], &["set", "subinterface"]);
            assert_eq!(
                args[4],
                format!("interface=epp-mtu-lab-{}", original.adapterGuid)
            );
            assert_eq!(&args[5..], &["mtu=1400", "store=active"]);
        }
        let path = executable().unwrap();
        assert!(path.is_absolute());
        assert!(path.ends_with("netsh.exe"));
        assert!(path.is_file());
    }

    #[test]
    fn nativeRowValidationPreservesReturnedPrefixAndRejectsDrift() {
        let mut expected = crate::recovery::tests::nativeFixture();
        let mut row = MIB_IPINTERFACE_ROW {
            Family: AF_INET,
            InterfaceIndex: expected.interfaceIndex,
            InterfaceLuid: NET_LUID_LH {
                Value: expected.interfaceLuid.parse().unwrap(),
            },
            SitePrefixLength: 64,
            ..Default::default()
        };
        expected.settings = settings(&row);
        validateRow(&row, &expected).unwrap();
        assert_eq!(row.SitePrefixLength, 64);
        for drift in 0..5 {
            let mut changed = row;
            match drift {
                0 => changed.Family = AF_INET6,
                1 => changed.InterfaceIndex += 1,
                2 => changed.InterfaceLuid = NET_LUID_LH { Value: 123 },
                3 => changed.SitePrefixLength = 0,
                4 => changed.Metric += 1,
                _ => unreachable!(),
            }
            assert!(validateRow(&changed, &expected).is_err());
        }
        row.Family = AF_INET6;
        expected.addressFamily = AddressFamily::Ipv6;
        validateRow(&row, &expected).unwrap();
        assert_eq!(row.SitePrefixLength, 64);
    }

    #[test]
    #[ignore]
    fn waitingChild() {
        std::thread::sleep(Duration::from_secs(60));
    }

    #[test]
    fn commandWaitTerminatesItsOwnChildOnDeadlineOrRevocation() {
        for revoked in [false, true] {
            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "mtu::windows::write::tests::waitingChild",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let started = Instant::now();
            let error = finishCommand(child, || {
                if revoked || started.elapsed() > Duration::from_millis(80) {
                    Err("test revocation or deadline".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
            assert!(error.to_string().contains("revocation or deadline"));
            assert!(started.elapsed() < Duration::from_secs(5));
        }
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--list"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        finishCommand(child, || Ok(())).unwrap();
    }
}
