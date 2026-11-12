mod command;
use super::*;
use crate::mtu::write_scope::{TargetGuard, WriteScope};
use command::CommandJob;
use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf, time::Instant};
use windows_sys::Win32::{
    Foundation::ERROR_INVALID_PARAMETER,
    NetworkManagement::IpHelper::{
        ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToNameW, ConvertInterfaceNameToLuidW,
    },
    System::SystemInformation::GetSystemDirectoryW,
};

#[derive(PartialEq, Eq)]
struct InterfaceTarget {
    name: String,
}

fn validateAliasTarget(code: u32, aliasLuid: u64, expectedLuid: u64) -> ServiceResult<()> {
    match code {
        0 if aliasLuid == expectedLuid => Ok(()),
        0 => Err("Native command target is also another adapter's alias".into()),
        // a validated native name need not exist in the separate alias namespace.
        ERROR_INVALID_PARAMETER if aliasLuid == 0 => Ok(()),
        _ => errorCode("ConvertInterfaceAliasToLuid", code),
    }
}

impl InterfaceTarget {
    fn capture(adapterGuid: Uuid, expectedLuid: &NET_LUID_LH) -> ServiceResult<Self> {
        let mut luid = NET_LUID_LH::default();
        errorCode("ConvertInterfaceGuidToLuid", unsafe {
            ConvertInterfaceGuidToLuid(&nativeGuid(adapterGuid), &mut luid)
        })?;
        if unsafe { luid.Value != expectedLuid.Value } {
            return Err(
                "Native command target no longer has the expected GUID/LUID mapping".into(),
            );
        }
        let mut buffer = [0u16; 257];
        errorCode("ConvertInterfaceLuidToNameW", unsafe {
            ConvertInterfaceLuidToNameW(&luid, buffer.as_mut_ptr(), buffer.len())
        })?;
        let name = fixedText(&buffer)?;
        if name.is_empty() {
            return Err("Native command target has an empty interface name".into());
        }
        let mut roundTripLuid = NET_LUID_LH::default();
        errorCode("ConvertInterfaceNameToLuidW", unsafe {
            ConvertInterfaceNameToLuidW(buffer.as_ptr(), &mut roundTripLuid)
        })?;
        let mut roundTripGuid = GUID::from_u128(0);
        errorCode("ConvertInterfaceLuidToGuid", unsafe {
            ConvertInterfaceLuidToGuid(&roundTripLuid, &mut roundTripGuid)
        })?;
        if unsafe { roundTripLuid.Value != expectedLuid.Value }
            || uuid(roundTripGuid) != adapterGuid
        {
            return Err("Native command target failed its name/LUID/GUID round trip".into());
        }
        let mut aliasLuid = NET_LUID_LH::default();
        let aliasCode = unsafe { ConvertInterfaceAliasToLuid(buffer.as_ptr(), &mut aliasLuid) };
        validateAliasTarget(aliasCode, unsafe { aliasLuid.Value }, unsafe {
            expectedLuid.Value
        })?;
        Ok(Self { name })
    }
}

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

fn arguments(original: &Snapshot, value: u32, target: &InterfaceTarget) -> [String; 7] {
    [
        "interface".into(),
        match original.addressFamily {
            AddressFamily::Ipv4 => "ipv4".into(),
            AddressFamily::Ipv6 => "ipv6".into(),
        },
        "set".into(),
        "subinterface".into(),
        format!("interface={}", target.name),
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

pub(crate) fn ensureLabCommandStopped() -> ServiceResult<()> {
    command::ensureStopped()
}

pub(crate) fn waitForLabMutator(identity: &crate::journal::MutatorIdentity) -> ServiceResult<()> {
    command::waitForIdentity(identity, std::time::Duration::from_secs(5))
}

fn validateBeforeWrite(
    permit: &dyn TargetGuard,
    original: &Snapshot,
    expected: &Snapshot,
) -> ServiceResult<InterfaceTarget> {
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
    if matches!(
        expected.registryOrigins,
        Some(crate::mtu::origins::OriginCapture::Captured { .. })
    ) && fresh.registryOrigins != expected.registryOrigins
    {
        return Err("Network registry origins drifted before the MTU write".into());
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
    InterfaceTarget::capture(original.adapterGuid, &luid)
}

pub(crate) fn writeScopedMtu(
    permit: &dyn TargetGuard,
    scope: &WriteScope<'_>,
    expected: &Snapshot,
    deadline: Instant,
    mut authorize: Option<&mut dyn FnMut() -> ServiceResult<()>>,
    register: &mut crate::recovery::MutatorRegistrar<'_>,
) -> ServiceResult<()> {
    ensureLabCommandStopped()?;
    scope.validateAuthorization(authorize.is_some())?;
    let original = scope.original();
    let value = scope.value();
    permit.validateTarget(original)?;
    let mut check = || -> ServiceResult<()> {
        if Instant::now() >= deadline {
            return Err("Windows MTU command deadline expired".into());
        }
        if let Some(validate) = authorize.as_mut() {
            validate()?;
        }
        Ok(())
    };
    check()?;
    let target = validateBeforeWrite(permit, original, expected)?;
    check()?;
    CommandJob::spawn(&executable()?, &arguments(original, value, &target))?.finish(
        register,
        &mut || {
            if validateBeforeWrite(permit, original, expected)? != target {
                return Err("Native command target changed before process resume".into());
            }
            Ok(())
        },
        check,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::windows::process::CommandExt,
        process::{Child, Command, Stdio},
        time::Duration,
    };
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    fn ownedCommand(arguments: &[&str]) -> CommandJob {
        let child = CommandJob::spawnFixture(
            &std::env::current_exe().unwrap(),
            &arguments
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(child.assigned());
        child
    }

    #[test]
    fn mtuArgumentsHaveNoCallerSelectedProgramTargetOrPolicyStore() {
        let mut original = crate::recovery::tests::nativeFixture();
        let target = InterfaceTarget {
            name: "ethernet_32768".into(),
        };
        for (family, name) in [(AddressFamily::Ipv4, "ipv4"), (AddressFamily::Ipv6, "ipv6")] {
            original.addressFamily = family;
            let args = arguments(&original, 1400, &target);
            assert_eq!(args[0], "interface");
            assert_eq!(args[1], name);
            assert_eq!(&args[2..4], &["set", "subinterface"]);
            assert_eq!(args[4], "interface=ethernet_32768");
            assert_eq!(&args[5..], &["mtu=1400", "store=active"]);
        }
        let path = executable().unwrap();
        assert!(path.is_absolute());
        assert!(path.ends_with("netsh.exe"));
        assert!(path.is_file());
    }

    #[test]
    fn nativeCommandTargetRequiresAnExactGuidLuidRoundTrip() {
        let mut table = std::ptr::null_mut();
        errorCode("GetIpInterfaceTable", unsafe {
            GetIpInterfaceTable(AF_UNSPEC, &mut table)
        })
        .unwrap();
        assert!(!table.is_null());
        let table = InterfaceTable(table);
        assert!(unsafe { (*table.0).NumEntries } > 0);
        let row = unsafe { &*std::ptr::addr_of!((*table.0).Table).cast::<MIB_IPINTERFACE_ROW>() };
        let mut guid = GUID::from_u128(0);
        errorCode("ConvertInterfaceLuidToGuid", unsafe {
            ConvertInterfaceLuidToGuid(&row.InterfaceLuid, &mut guid)
        })
        .unwrap();
        let target = InterfaceTarget::capture(uuid(guid), &row.InterfaceLuid).unwrap();
        assert!(!target.name.is_empty());
        assert!(InterfaceTarget::capture(Uuid::nil(), &row.InterfaceLuid).is_err());
        assert!(InterfaceTarget::capture(uuid(guid), &NET_LUID_LH::default()).is_err());
    }

    #[test]
    fn nativeTargetRefusesAliasCollisionsAndUncertainAliasLookups() {
        assert!(validateAliasTarget(0, 123, 123).is_ok());
        assert!(validateAliasTarget(ERROR_INVALID_PARAMETER, 0, 123).is_ok());
        assert!(validateAliasTarget(0, 456, 123).is_err());
        assert!(validateAliasTarget(0, 0, 123).is_err());
        assert!(validateAliasTarget(ERROR_INVALID_PARAMETER, 456, 123).is_err());
        assert!(validateAliasTarget(5, 0, 123).is_err());
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

    fn parseProcessIdMarker(value: &str) -> Option<u32> {
        // file creation can be observed before its complete pid has been written.
        let value = value.strip_suffix('\n')?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        value.parse().ok().filter(|pid| *pid != 0)
    }

    #[test]
    fn incompleteOrMalformedProcessIdsCannotSatisfyOwnerReadiness() {
        for value in [
            "",
            "123",
            "12\n3",
            "0\n",
            "+123\n",
            "4294967296\n",
            "123\npartial",
        ] {
            assert_eq!(parseProcessIdMarker(value), None, "{value:?}");
        }
        assert_eq!(parseProcessIdMarker("123\n"), Some(123));
    }

    #[test]
    #[ignore]
    fn waitingChild() {
        if let Some(marker) = std::env::var_os("EPP_MTU_COMMAND_TEST_MARKER") {
            let mut descendant = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "mtu::windows::write::tests::waitingDescendant",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            std::fs::write(
                PathBuf::from(marker).with_extension("ready"),
                format!("{}\n", descendant.id()),
            )
            .unwrap();
            descendant.wait().unwrap();
        }
        std::thread::sleep(Duration::from_secs(60));
    }

    #[test]
    #[ignore]
    fn waitingDescendant() {
        std::thread::sleep(Duration::from_secs(60));
    }

    #[test]
    #[ignore]
    fn commandOwner() {
        let marker = std::env::var_os("EPP_MTU_COMMAND_TEST_MARKER").unwrap();
        let child = ownedCommand(&[
            "--ignored",
            "--exact",
            "mtu::windows::write::tests::waitingChild",
        ]);
        std::fs::write(marker, format!("{}\n", child.id())).unwrap();
        if std::env::var("EPP_MTU_COMMAND_TEST_STAGE").unwrap() == "suspended" {
            std::thread::sleep(Duration::from_secs(60));
        }
        child
            .finish(&mut |_| Ok(()), &mut || Ok(()), || Ok(()))
            .unwrap();
    }

    #[test]
    fn commandCannotOutliveItsOwner() {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::{
            Foundation::WAIT_OBJECT_0,
            System::Threading::{
                OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, TerminateProcess,
                WaitForSingleObject,
            },
        };

        struct Owner(Child);
        impl Drop for Owner {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        struct CommandProcess(OwnedHandle);
        impl Drop for CommandProcess {
            fn drop(&mut self) {
                if unsafe { WaitForSingleObject(self.0.as_raw_handle(), 0) } != WAIT_OBJECT_0 {
                    unsafe {
                        TerminateProcess(self.0.as_raw_handle(), 1);
                        WaitForSingleObject(self.0.as_raw_handle(), 5_000);
                    }
                }
            }
        }

        for suspended in [true, false] {
            let directory = std::env::temp_dir().join(format!("epp-command-{}", Uuid::new_v4()));
            std::fs::create_dir(&directory).unwrap();
            let marker = directory.join("child.pid");
            let mut owner = Owner(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--ignored",
                        "--exact",
                        "mtu::windows::write::tests::commandOwner",
                    ])
                    .env("EPP_MTU_COMMAND_TEST_MARKER", &marker)
                    .env(
                        "EPP_MTU_COMMAND_TEST_STAGE",
                        if suspended { "suspended" } else { "running" },
                    )
                    .creation_flags(CREATE_NO_WINDOW)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            let processIds = loop {
                if let Ok(value) = std::fs::read_to_string(&marker)
                    && let Some(pid) = parseProcessIdMarker(&value)
                {
                    if suspended {
                        break vec![pid];
                    }
                    if let Ok(value) = std::fs::read_to_string(marker.with_extension("ready"))
                        && let Some(descendant) = parseProcessIdMarker(&value)
                    {
                        break vec![pid, descendant];
                    }
                }
                assert!(
                    owner.0.try_wait().unwrap().is_none(),
                    "Command owner exited early"
                );
                assert!(
                    Instant::now() < deadline,
                    "Command owner did not publish its child"
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            let children: Vec<_> = processIds
                .into_iter()
                .map(|childId| {
                    let handle =
                        unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, 0, childId) };
                    assert!(
                        !handle.is_null(),
                        "Cannot open the exact test command process"
                    );
                    let child = CommandProcess(unsafe { OwnedHandle::from_raw_handle(handle) });
                    assert_ne!(
                        unsafe { WaitForSingleObject(child.0.as_raw_handle(), 0) },
                        WAIT_OBJECT_0
                    );
                    child
                })
                .collect();
            owner.0.kill().unwrap();
            owner.0.wait().unwrap();
            let stopped: Vec<_> = children
                .iter()
                .map(|child| unsafe { WaitForSingleObject(child.0.as_raw_handle(), 2_000) })
                .collect();
            drop(children);
            drop(owner);
            std::fs::remove_file(marker).unwrap();
            if !suspended {
                std::fs::remove_file(directory.join("child.ready")).unwrap();
            }
            std::fs::remove_dir(directory).unwrap();
            assert_eq!(
                stopped,
                if suspended {
                    vec![WAIT_OBJECT_0]
                } else {
                    vec![WAIT_OBJECT_0, WAIT_OBJECT_0]
                },
                "Command survived the death of its owner"
            );
        }
    }

    #[test]
    fn commandWaitTerminatesItsOwnChildOnDeadlineOrRevocation() {
        for revoked in [false, true] {
            let child = ownedCommand(&[
                "--ignored",
                "--exact",
                "mtu::windows::write::tests::waitingChild",
            ]);
            let started = Instant::now();
            let error = child
                .finish(&mut |_| Ok(()), &mut || Ok(()), || {
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
        let child = ownedCommand(&["--list"]);
        child
            .finish(&mut |_| Ok(()), &mut || Ok(()), || Ok(()))
            .unwrap();
    }
}
