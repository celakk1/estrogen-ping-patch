use crate::AppResult;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) fn captureSections(inventory: &Value, cancelled: &AtomicBool) -> AppResult<Vec<Value>> {
    let adapters = inventory["adapters"]
        .as_array()
        .ok_or("Snapshot adapter inventory must be an array")?;
    #[cfg(windows)]
    let api = windows::DnsApi::load();
    let mut sections = Vec::with_capacity(adapters.len());
    for adapter in adapters {
        if cancelled.load(Ordering::Relaxed) {
            return Err("Configuration capture was cancelled".into());
        }
        let adapterId = adapter["id"].as_str().unwrap_or_default();
        #[cfg(windows)]
        let result = match &api {
            Ok(api) => api.readSettings(adapterId),
            Err(error) => Err(error.to_string().into()),
        };
        #[cfg(not(windows))]
        let result: AppResult<Value> = Err("Native DNS configuration requires Windows".into());
        sections.push(match result {
            Ok(value) => json!({"name":"nativeInterfaceDns","adapterId":adapterId,"status":"captured","values":[value],"error":null}),
            Err(error) => json!({"name":"nativeInterfaceDns","adapterId":adapterId,"status":"unavailable","values":[],"error":error.to_string()}),
        });
    }
    if cancelled.load(Ordering::Relaxed) {
        return Err("Configuration capture was cancelled".into());
    }
    Ok(sections)
}

#[cfg(windows)]
mod windows {
    use super::*;
    use windows_sys::{
        Win32::{
            Foundation::{FreeLibrary, HMODULE},
            NetworkManagement::IpHelper::{
                DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1,
            },
            System::LibraryLoader::{GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW},
        },
        core::GUID,
    };

    type GetSettings = unsafe extern "system" fn(GUID, *mut DNS_INTERFACE_SETTINGS) -> u32;
    type FreeSettings = unsafe extern "system" fn(*mut DNS_INTERFACE_SETTINGS);

    struct Library(HMODULE);

    impl Drop for Library {
        fn drop(&mut self) {
            unsafe { FreeLibrary(self.0) };
        }
    }

    pub(super) struct DnsApi {
        _library: Library,
        getSettings: GetSettings,
        freeSettings: FreeSettings,
    }

    struct OwnedSettings<'a> {
        settings: DNS_INTERFACE_SETTINGS,
        api: &'a DnsApi,
    }

    impl Drop for OwnedSettings<'_> {
        fn drop(&mut self) {
            unsafe { (self.api.freeSettings)(&mut self.settings) };
        }
    }

    impl DnsApi {
        pub(super) fn load() -> AppResult<Self> {
            let libraryName: Vec<u16> = "iphlpapi.dll\0".encode_utf16().collect();
            let handle = unsafe {
                LoadLibraryExW(
                    libraryName.as_ptr(),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            if handle.is_null() {
                return Err(format!(
                    "Cannot load Windows DNS reader: {}",
                    std::io::Error::last_os_error()
                )
                .into());
            }
            let library = Library(handle);
            let getAddress = unsafe { GetProcAddress(handle, c"GetInterfaceDnsSettings".as_ptr().cast()) }
                .ok_or("GetInterfaceDnsSettings is unavailable; Windows 10 build 19041 or newer is required")?;
            let freeAddress =
                unsafe { GetProcAddress(handle, c"FreeInterfaceDnsSettings".as_ptr().cast()) }
                    .ok_or(
                        "FreeInterfaceDnsSettings is unavailable; native DNS capture is disabled",
                    )?;
            // resolve both exports before allocating settings; keep their library alive until cleanup.
            Ok(Self {
                _library: library,
                getSettings: unsafe {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, GetSettings>(
                        getAddress,
                    )
                },
                freeSettings: unsafe {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, FreeSettings>(
                        freeAddress,
                    )
                },
            })
        }

        pub(super) fn readSettings(&self, adapterId: &str) -> AppResult<Value> {
            let guid = parseGuid(adapterId)?;
            // the getter requires only version; setting an ipv6 flag here violates its input contract.
            let mut settings = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                ..Default::default()
            };
            let result = unsafe { (self.getSettings)(guid, &mut settings) };
            if result != 0 {
                return Err(format!(
                    "GetInterfaceDnsSettings failed with Windows error {result}: {}",
                    std::io::Error::from_raw_os_error(result as i32)
                )
                .into());
            }
            let owned = OwnedSettings {
                settings,
                api: self,
            };
            unsafe { settingsValue(&owned.settings) }
        }
    }

    fn parseGuid(value: &str) -> AppResult<GUID> {
        let value = value
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
            .unwrap_or(value);
        if value.len() != 36
            || value.bytes().enumerate().any(|(index, byte)| {
                if [8, 13, 18, 23].contains(&index) {
                    byte != b'-'
                } else {
                    !byte.is_ascii_hexdigit()
                }
            })
        {
            return Err("Adapter identity is not a canonical GUID".into());
        }
        Ok(GUID::from_u128(u128::from_str_radix(
            &value.replace('-', ""),
            16,
        )?))
    }

    unsafe fn readString(value: *const u16) -> AppResult<Option<String>> {
        if value.is_null() {
            return Ok(None);
        }
        for length in 0..32_768 {
            if unsafe { *value.add(length) } == 0 {
                let text = unsafe { std::slice::from_raw_parts(value, length) };
                return Ok(Some(String::from_utf16(text)?));
            }
        }
        Err("Native DNS string exceeded the 32768 UTF-16 unit capture limit".into())
    }

    unsafe fn settingsValue(settings: &DNS_INTERFACE_SETTINGS) -> AppResult<Value> {
        Ok(json!({
            "api": "GetInterfaceDnsSettings",
            "version": settings.Version,
            "flagsHex": format!("0x{:016x}", settings.Flags),
            "domain": unsafe { readString(settings.Domain)? },
            "nameServer": unsafe { readString(settings.NameServer)? },
            "searchList": unsafe { readString(settings.SearchList)? },
            "profileNameServer": unsafe { readString(settings.ProfileNameServer)? },
            "registrationEnabled": settings.RegistrationEnabled,
            "registerAdapterName": settings.RegisterAdapterName,
            "enableLlmnr": settings.EnableLLMNR,
            "queryAdapterName": settings.QueryAdapterName,
            "unavailableFields": []
        }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::AtomicUsize;

        static FREED_SETTINGS: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "system" fn fakeFreeSettings(_: *mut DNS_INTERFACE_SETTINGS) {
            FREED_SETTINGS.fetch_add(1, Ordering::SeqCst);
        }

        unsafe extern "system" fn fakeGetSettings(
            _: GUID,
            settings: *mut DNS_INTERFACE_SETTINGS,
        ) -> u32 {
            let settings = unsafe { &mut *settings };
            assert_eq!(settings.Version, DNS_INTERFACE_SETTINGS_VERSION1);
            assert_eq!(settings.Flags, 0);
            static INVALID: [u16; 2] = [0xd800, 0];
            settings.NameServer = INVALID.as_ptr().cast_mut();
            0
        }

        #[test]
        fn settingsPreserveNullEmptyTextFlagsAndNativeIntegers() {
            let mut empty = [0];
            let mut text: Vec<u16> = "zażółć.example\0".encode_utf16().collect();
            let settings = DNS_INTERFACE_SETTINGS {
                Version: 1,
                Flags: u64::MAX,
                NameServer: empty.as_mut_ptr(),
                Domain: text.as_mut_ptr(),
                RegistrationEnabled: u32::MAX,
                ..Default::default()
            };
            let value = unsafe { settingsValue(&settings) }.unwrap();
            assert!(value["profileNameServer"].is_null());
            assert_eq!(value["nameServer"], "");
            assert_eq!(value["domain"], "zażółć.example");
            assert_eq!(value["flagsHex"], "0xffffffffffffffff");
            assert_eq!(value["registrationEnabled"], u32::MAX);
        }

        #[test]
        fn malformedNativeStringsCannotBecomeLossyRestoreValues() {
            let invalid = [0xd800, 0];
            assert!(unsafe { readString(invalid.as_ptr()) }.is_err());
            let unterminated = [65; 32_768];
            assert!(unsafe { readString(unterminated.as_ptr()) }.is_err());
        }

        #[test]
        fn adapterGuidUsesWindowsByteLayoutAndRejectsMalformedIdentity() {
            let guid = parseGuid("{00112233-4455-6677-8899-aabbccddeeff}").unwrap();
            assert_eq!(guid.data1, 0x00112233);
            assert_eq!(guid.data2, 0x4455);
            assert_eq!(guid.data3, 0x6677);
            assert_eq!(guid.data4, [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            for invalid in [
                "",
                "00112233445566778899aabbccddeeff",
                "{00112233-4455-6677-8899-aabbccddeeff",
                "00112233-4455-6677-8899-aabbccddeefg",
            ] {
                assert!(parseGuid(invalid).is_err());
            }
        }

        #[test]
        fn nativeAllocationIsFreedWhenSerializationFails() {
            let handle = unsafe {
                LoadLibraryExW(
                    windows_sys::core::w!("iphlpapi.dll"),
                    std::ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_SYSTEM32,
                )
            };
            assert!(!handle.is_null());
            let api = DnsApi {
                _library: Library(handle),
                getSettings: fakeGetSettings,
                freeSettings: fakeFreeSettings,
            };
            assert!(
                api.readSettings("00112233-4455-6677-8899-aabbccddeeff")
                    .is_err()
            );
            assert_eq!(FREED_SETTINGS.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn nativeReaderCapturesActualAdapterOrReportsExplicitWindowsError() {
            let inventory = crate::discovery::inventory().unwrap();
            let sections = captureSections(&inventory, &AtomicBool::new(false)).unwrap();
            assert_eq!(
                sections.len(),
                inventory["adapters"].as_array().unwrap().len()
            );
            for section in sections {
                match section["status"].as_str().unwrap() {
                    "captured" => {
                        assert_eq!(section["values"][0]["api"], "GetInterfaceDnsSettings");
                        assert_eq!(section["values"][0]["version"], 1);
                        assert!(section["values"][0]["flagsHex"].is_string());
                    }
                    "unavailable" => assert!(section["error"].is_string()),
                    status => panic!("Unexpected capture status: {status}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellationCannotPublishPartialNativeDnsSections() {
        let inventory = json!({"adapters":[{"id":"00112233-4455-6677-8899-aabbccddeeff"}]});
        assert!(captureSections(&inventory, &AtomicBool::new(true)).is_err());
    }
}
