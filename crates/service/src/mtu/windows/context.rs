use super::{checkCancellation, errorCode};
use crate::{
    ServiceResult,
    mtu::{DriverContext, DriverIdentity, OsContext},
};
use std::{collections::BTreeMap, sync::atomic::AtomicBool};
use uuid::Uuid;
use windows_sys::{
    Wdk::System::SystemServices::RtlGetVersion,
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            DICS_FLAG_GLOBAL, DIGCF_PRESENT, DIREG_DRV, GUID_DEVCLASS_NET, HDEVINFO,
            SP_DEVINFO_DATA, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
            SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW, SetupDiOpenDevRegKey,
        },
        Foundation::{ERROR_NO_MORE_ITEMS, INVALID_HANDLE_VALUE},
        System::{
            Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
                RRF_SUBKEY_WOW6464KEY, RRF_ZEROONFAILURE, RegCloseKey, RegGetValueW,
            },
            SystemInformation::{GetNativeSystemInfo, OSVERSIONINFOW, SYSTEM_INFO},
        },
    },
};

struct DeviceSet(HDEVINFO);
impl Drop for DeviceSet {
    fn drop(&mut self) {
        unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}
struct RegistryKey(HKEY);
impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn text(buffer: &[u16], byteCount: u32) -> ServiceResult<String> {
    if byteCount < 2 || !byteCount.is_multiple_of(2) || byteCount as usize > buffer.len() * 2 {
        return Err("Native driver text length is malformed".into());
    }
    let length = byteCount as usize / 2;
    if buffer[length - 1] != 0 || buffer[..length - 1].contains(&0) {
        return Err("Native driver text has an invalid terminator".into());
    }
    let value = String::from_utf16(&buffer[..length - 1])?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err("Native driver identity is empty or contains control characters".into());
    }
    Ok(value)
}

fn registryText(key: HKEY, name: &str) -> ServiceResult<String> {
    let mut buffer = [0u16; 1024];
    let mut byteCount = (buffer.len() * 2) as u32;
    errorCode("RegGetValueW driver identity", unsafe {
        RegGetValueW(
            key,
            std::ptr::null(),
            wide(name).as_ptr(),
            RRF_RT_REG_SZ | RRF_ZEROONFAILURE,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut byteCount,
        )
    })?;
    text(&buffer, byteCount)
}

pub(super) fn os() -> ServiceResult<OsContext> {
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: std::mem::size_of::<OSVERSIONINFOW>() as u32,
        ..Default::default()
    };
    let status = unsafe { RtlGetVersion(&mut version) };
    if status < 0 {
        return Err(format!("RtlGetVersion failed: NTSTATUS {status:#x}").into());
    }
    let mut updateRevision = 0u32;
    let mut byteCount = 4;
    errorCode("RegGetValueW OS update revision", unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            wide(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").as_ptr(),
            wide("UBR").as_ptr(),
            RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY | RRF_ZEROONFAILURE,
            std::ptr::null_mut(),
            (&mut updateRevision as *mut u32).cast(),
            &mut byteCount,
        )
    })?;
    if byteCount != 4 {
        return Err("OS update revision has an invalid native size".into());
    }
    let mut system = SYSTEM_INFO::default();
    unsafe { GetNativeSystemInfo(&mut system) };
    Ok(OsContext {
        major: version.dwMajorVersion,
        minor: version.dwMinorVersion,
        build: version.dwBuildNumber,
        updateRevision,
        nativeArchitecture: unsafe { system.Anonymous.Anonymous.wProcessorArchitecture },
    })
}

fn deviceIdentity(
    set: HDEVINFO,
    device: &SP_DEVINFO_DATA,
    key: HKEY,
) -> ServiceResult<DriverIdentity> {
    let version = registryText(key, "DriverVersion")?;
    if version.len() > 256 {
        return Err("Native driver version exceeds 256 bytes".into());
    }
    let infPath = registryText(key, "InfPath")?;
    let infSection = registryText(key, "InfSection")?;
    let mut buffer = [0u16; 1024];
    let mut size = 0;
    if unsafe {
        SetupDiGetDeviceInstanceIdW(
            set,
            device,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut size,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let deviceInstanceId = text(
        &buffer,
        size.checked_mul(2)
            .ok_or("Native device identity length overflow")?,
    )?;
    Ok(DriverIdentity {
        version,
        infPath,
        infSection,
        deviceInstanceId,
    })
}

pub(super) struct Drivers {
    entries: BTreeMap<Uuid, DriverContext>,
    unavailable: Option<String>,
}

impl Drivers {
    pub(super) fn capture(cancelled: &AtomicBool) -> ServiceResult<Self> {
        checkCancellation(cancelled)?;
        let handle = unsafe {
            SetupDiGetClassDevsW(
                &GUID_DEVCLASS_NET,
                std::ptr::null(),
                std::ptr::null_mut(),
                DIGCF_PRESENT,
            )
        };
        if handle == -1 {
            return Ok(Self {
                entries: BTreeMap::new(),
                unavailable: Some(format!(
                    "Cannot enumerate native network driver context: {}",
                    std::io::Error::last_os_error()
                )),
            });
        }
        let set = DeviceSet(handle);
        let mut entries = BTreeMap::new();
        let mut complete = false;
        for index in 0..4096 {
            checkCancellation(cancelled)?;
            let mut device = SP_DEVINFO_DATA {
                cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            if unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut device) } == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                    complete = true;
                    break;
                }
                return Err(format!("Native driver enumeration failed: {error}").into());
            }
            let key = unsafe {
                SetupDiOpenDevRegKey(
                    set.0,
                    &device,
                    DICS_FLAG_GLOBAL,
                    0,
                    DIREG_DRV,
                    KEY_QUERY_VALUE,
                )
            };
            if key == INVALID_HANDLE_VALUE {
                continue;
            }
            let key = RegistryKey(key);
            let Ok(value) = registryText(key.0, "NetCfgInstanceId") else {
                continue;
            };
            let Ok(guid) = Uuid::parse_str(&value) else {
                continue;
            };
            if guid.is_nil() {
                continue;
            }
            let context = match deviceIdentity(set.0, &device, key.0) {
                Ok(identity) => DriverContext::Captured { identity },
                Err(error) => DriverContext::Unavailable {
                    error: error.to_string().chars().take(512).collect(),
                },
            };
            if entries.insert(guid, context).is_some() {
                entries.insert(guid,DriverContext::Unavailable {error:"Multiple present PnP devices share the adapter GUID; native driver identity is ambiguous".into()});
            }
        }
        if !complete {
            return Err("Native network driver count exceeds 4096".into());
        }
        checkCancellation(cancelled)?;
        Ok(Self {
            entries,
            unavailable: None,
        })
    }

    pub(super) fn get(&self, guid: Uuid) -> DriverContext {
        self.entries
            .get(&guid)
            .cloned()
            .unwrap_or_else(|| DriverContext::Unavailable {
                error: self.unavailable.clone().unwrap_or_else(|| {
                    "No unique readable present PnP driver identity matched the adapter GUID".into()
                }),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nativeDriverTextCannotSilentlyNormalizeMalformedIdentity() {
        assert_eq!(text(&[b'1' as u16, 0], 4).unwrap(), "1");
        for (buffer, bytes) in [
            (vec![0], 2),
            (vec![1, 0], 3),
            (vec![1], 4),
            (vec![1], 2),
            (vec![1, 0, 0], 6),
            (vec![0xd800, 0], 4),
            (vec![10, 0], 4),
        ] {
            assert!(text(&buffer, bytes).is_err());
        }
    }
}
