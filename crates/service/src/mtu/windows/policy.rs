use super::{Capture, FIELDS, Row, Value};
use crate::{ServiceResult, journal::AddressFamily, mtu};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use uuid::Uuid;
use windows::{
    Win32::System::{
        Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoSetProxyBlanket, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
        },
        Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE},
        Variant::{VARIANT, VT_I4, VT_NULL, VT_UI1, VT_UI2, VT_UI4},
        Wmi::{
            IWbemClassObject, IWbemContext, IWbemLocator, IWbemServices,
            WBEM_FLAG_CONNECT_USE_MAX_WAIT, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
            WBEM_S_FALSE, WBEM_S_TIMEDOUT, WbemContext, WbemLocator,
        },
    },
    core::{BSTR, PCWSTR, w},
};

struct Apartment(bool);
impl Apartment {
    fn enter() -> ServiceResult<Self> {
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result.0 == 0x80010106u32 as i32 {
            return Ok(Self(false));
        }
        result.ok()?;
        Ok(Self(true))
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}

fn check(cancelled: &AtomicBool, deadline: Instant) -> ServiceResult<()> {
    if cancelled.load(Ordering::SeqCst) || Instant::now() >= deadline {
        return Err("IP policy query cancelled or its enumeration allowance expired".into());
    }
    Ok(())
}

fn scalar(value: &VARIANT, cimType: i32) -> ServiceResult<Value> {
    let maximum = match cimType {
        17 => u8::MAX as u32,
        18 => u16::MAX as u32,
        19 => u32::MAX,
        _ => return Err("IP policy property has an unsupported CIM type".into()),
    };
    let data = unsafe { &value.Anonymous.Anonymous };
    let number = match data.vt {
        VT_NULL => None,
        VT_I4 if cimType == 19 => Some(unsafe { data.Anonymous.lVal } as u32),
        VT_I4 => Some(u32::try_from(unsafe { data.Anonymous.lVal })?),
        VT_UI1 => Some(unsafe { data.Anonymous.bVal } as u32),
        VT_UI2 => Some(unsafe { data.Anonymous.uiVal } as u32),
        VT_UI4 => Some(unsafe { data.Anonymous.ulVal }),
        _ => return Err("IP policy property has an unexpected VARIANT representation".into()),
    };
    if number.is_some_and(|number| number > maximum) {
        return Err("IP policy property exceeds its CIM type".into());
    }
    Ok(Value {
        cimType: cimType as u32,
        value: number,
    })
}

fn property(row: &IWbemClassObject, name: &str) -> ServiceResult<Value> {
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut value = VARIANT::default();
    let mut cimType = 0;
    unsafe {
        row.Get(
            PCWSTR(name.as_ptr()),
            0,
            &mut value,
            Some(&mut cimType),
            None,
        )
    }?;
    scalar(&value, cimType)
}

fn required(row: &IWbemClassObject, name: &str) -> ServiceResult<u32> {
    property(row, name)?
        .value
        .ok_or_else(|| format!("IP policy identity property {name} is null").into())
}

fn query(
    services: &IWbemServices,
    index: u32,
    family: AddressFamily,
    store: &str,
    cancelled: &AtomicBool,
    deadline: Instant,
) -> ServiceResult<Option<Row>> {
    check(cancelled, deadline)?;
    let context: IWbemContext =
        unsafe { CoCreateInstance(&WbemContext, None, CLSCTX_INPROC_SERVER) }?;
    unsafe { context.SetValue(w!("PolicyStore"), 0, &VARIANT::from(store)) }?;
    let family = match family {
        AddressFamily::Ipv4 => 2,
        AddressFamily::Ipv6 => 23,
    };
    let query = format!(
        "SELECT InterfaceIndex,AddressFamily,Store,CompartmentId,{} FROM MSFT_NetIPInterface WHERE InterfaceIndex={index} AND AddressFamily={family}",
        FIELDS.join(",")
    );
    let rows = unsafe {
        services.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from(query),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            &context,
        )
    }?;
    let mut found = None;
    loop {
        check(cancelled, deadline)?;
        let mut row = [None];
        let mut count = 0;
        let status = unsafe { rows.Next(100, &mut row, &mut count) };
        status.ok()?;
        if count > 1 {
            return Err("IP policy enumeration returned an invalid row count".into());
        }
        if let Some(row) = row[0].take() {
            if found.is_some() {
                return Err("IP policy query returned ambiguous interface rows".into());
            }
            found = Some(Row {
                interfaceIndex: required(&row, "InterfaceIndex")?,
                addressFamily: required(&row, "AddressFamily")?,
                store: required(&row, "Store")?,
                compartmentId: property(&row, "CompartmentId")?,
                values: FIELDS
                    .iter()
                    .map(|name| Ok(((*name).into(), property(&row, name)?)))
                    .collect::<ServiceResult<_>>()?,
            });
        } else if count != 0 || status.0 == 0 {
            return Err("IP policy enumeration omitted its reported row".into());
        }
        if status.0 == WBEM_S_FALSE.0 {
            break;
        }
        if status.0 != 0 && status.0 != WBEM_S_TIMEDOUT.0 {
            return Err("IP policy enumeration returned an unexpected success status".into());
        }
    }
    Ok(found)
}

pub(super) fn capture(
    adapterGuid: Uuid,
    family: AddressFamily,
    cancelled: &AtomicBool,
) -> ServiceResult<Capture> {
    let deadline = Instant::now() + Duration::from_secs(4);
    check(cancelled, deadline)?;
    let before = mtu::capture(adapterGuid, family, cancelled)?;
    before.journalContext()?;
    before.requireOriginalOrigins()?;
    let _apartment = Apartment::enter()?;
    let locator: IWbemLocator =
        unsafe { CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER) }?;
    let services = unsafe {
        locator.ConnectServer(
            &BSTR::from("ROOT\\StandardCimv2"),
            &BSTR::new(),
            &BSTR::new(),
            &BSTR::new(),
            WBEM_FLAG_CONNECT_USE_MAX_WAIT.0,
            &BSTR::new(),
            None,
        )
    }?;
    unsafe {
        CoSetProxyBlanket(
            &services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    }?;
    let active = query(
        &services,
        before.interfaceIndex,
        family,
        "ActiveStore",
        cancelled,
        deadline,
    )?
    .ok_or("Active IP policy row is unavailable")?;
    let persistent = query(
        &services,
        before.interfaceIndex,
        family,
        "PersistentStore",
        cancelled,
        deadline,
    )?;
    check(cancelled, deadline)?;
    let native = mtu::capture(adapterGuid, family, cancelled)?;
    native.validateMtuObservation(&before)?;
    if native.interfaceLuid != before.interfaceLuid
        || native.interfaceIndex != before.interfaceIndex
        || native.settings != before.settings
    {
        return Err(
            "Native interface identity or settings changed during IP policy capture".into(),
        );
    }
    let capture = Capture {
        schemaVersion: 1,
        native,
        active,
        persistent,
    };
    capture.validate()?;
    check(cancelled, deadline)?;
    Ok(capture)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::System::Variant::VT_EMPTY;

    #[test]
    fn unsignedCimWordsNullsAndUnexpectedVariantTypesStayDistinct() {
        assert_eq!(
            scalar(&VARIANT::from(-1i32), 19).unwrap().value,
            Some(u32::MAX)
        );
        assert_eq!(
            scalar(&VARIANT::from(u32::MAX), 19).unwrap().value,
            Some(u32::MAX)
        );
        assert!(scalar(&VARIANT::from(-1i32), 18).is_err());
        assert!(scalar(&VARIANT::from(65536u32), 18).is_err());
        assert!(scalar(&VARIANT::from("1500"), 19).is_err());
        let mut null = VARIANT::default();
        assert_eq!(null.vt(), VT_EMPTY);
        assert!(scalar(&null, 19).is_err());
        unsafe {
            (*null.Anonymous.Anonymous).vt = VT_NULL;
        }
        assert_eq!(scalar(&null, 19).unwrap().value, None);
        assert!(scalar(&null, 0).is_err());
    }

    #[test]
    fn cancelledOrUnknownPolicyTargetsAreRefusedBeforeProviderEnumeration() {
        assert!(capture(Uuid::nil(), AddressFamily::Ipv4, &AtomicBool::new(true)).is_err());
        assert!(capture(Uuid::nil(), AddressFamily::Ipv4, &AtomicBool::new(false)).is_err());
        assert!(capture(Uuid::new_v4(), AddressFamily::Ipv6, &AtomicBool::new(false)).is_err());
    }
}
