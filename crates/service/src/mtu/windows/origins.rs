use super::{checkCancellation, errorCode};
use crate::{
    ServiceResult,
    mtu::origins::{MAX_DATA_BYTES, NamedValue, RawValue, RegistryOrigins, Stack, VALUE_NAMES},
};
use std::{ptr::null, sync::atomic::AtomicBool};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_PATH_NOT_FOUND},
    System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_WOW64_64KEY, RegCloseKey, RegOpenKeyExW,
        RegQueryValueExW,
    },
};

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn readValue(key: HKEY, name: &str, remaining: &mut usize) -> ServiceResult<Option<RawValue>> {
    let mut valueType = 0;
    let mut buffer = vec![0u8; (*remaining).max(1)];
    let mut size = *remaining as u32;
    let status = unsafe {
        RegQueryValueExW(
            key,
            wide(name).as_ptr(),
            null(),
            &mut valueType,
            buffer.as_mut_ptr(),
            &mut size,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status == ERROR_MORE_DATA {
        return Err(format!("Network registry origin value {name} exceeds the remaining {remaining}-byte capture allowance").into());
    }
    errorCode(
        &format!("Read fixed network registry origin value {name}"),
        status,
    )?;
    if size as usize > *remaining {
        return Err("Network registry origin data exceeded its capture allowance".into());
    }
    *remaining -= size as usize;
    Ok(Some(RawValue {
        valueType,
        dataHex: buffer[..size as usize]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }))
}

fn readOnce(adapterGuid: Uuid, cancelled: &AtomicBool) -> ServiceResult<RegistryOrigins> {
    let mut stacks = Vec::with_capacity(2);
    let mut remaining = MAX_DATA_BYTES;
    for name in ["Tcpip", "Tcpip6"] {
        checkCancellation(cancelled)?;
        let path = format!(
            "SYSTEM\\CurrentControlSet\\Services\\{name}\\Parameters\\Interfaces\\{{{adapterGuid}}}"
        );
        let mut handle = std::ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(&path).as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                &mut handle,
            )
        };
        let key = if matches!(status, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
            None
        } else {
            errorCode("Open fixed adapter registry origin key", status)?;
            Some(Key(handle))
        };
        let mut values = Vec::with_capacity(VALUE_NAMES.len());
        for valueName in VALUE_NAMES {
            checkCancellation(cancelled)?;
            values.push(NamedValue {
                name: valueName.into(),
                value: match &key {
                    Some(key) => readValue(key.0, valueName, &mut remaining)?,
                    None => None,
                },
            });
        }
        stacks.push(Stack {
            name: name.into(),
            keyPresent: key.is_some(),
            values,
        });
    }
    let evidence = RegistryOrigins {
        schemaVersion: 1,
        adapterGuid,
        stacks,
    };
    evidence.validate(adapterGuid)?;
    Ok(evidence)
}

pub(super) fn capture(adapterGuid: Uuid, cancelled: &AtomicBool) -> ServiceResult<RegistryOrigins> {
    let first = readOnce(adapterGuid, cancelled)?;
    let second = readOnce(adapterGuid, cancelled)?;
    if first != second {
        return Err("Network registry origin values changed during capture".into());
    }
    Ok(second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missingAdapterKeysRemainExplicitAndCancellationCannotReturnPartialEvidence() {
        let adapterGuid = Uuid::new_v4();
        let evidence = capture(adapterGuid, &AtomicBool::new(false)).unwrap();
        evidence.validate(adapterGuid).unwrap();
        assert!(evidence.stacks.iter().all(
            |stack| !stack.keyPresent && stack.values.iter().all(|entry| entry.value.is_none())
        ));
        assert!(capture(adapterGuid, &AtomicBool::new(true)).is_err());
        assert!(capture(Uuid::nil(), &AtomicBool::new(false)).is_err());
    }

    #[test]
    fn rawRegistryReadsPreserveTypeAndBytesAndRefuseInsufficientAllowance() {
        let mut handle = std::ptr::null_mut();
        errorCode("Open read-only OS context fixture", unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").as_ptr(),
                0,
                KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                &mut handle,
            )
        })
        .unwrap();
        let key = Key(handle);
        let mut remaining = 4;
        let value = readValue(key.0, "UBR", &mut remaining).unwrap().unwrap();
        assert_eq!(value.valueType, 4);
        assert_eq!(remaining, 0);
        let revision = super::super::context::os().unwrap().updateRevision;
        let expected: String = revision
            .to_le_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(value.dataHex, expected);
        assert!(readValue(key.0, "UBR", &mut 3).is_err());
        assert!(
            readValue(key.0, &format!("epp-missing-{}", Uuid::new_v4()), &mut 0)
                .unwrap()
                .is_none()
        );
    }
}
