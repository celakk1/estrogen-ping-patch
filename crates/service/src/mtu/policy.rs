use super::Snapshot;
use crate::ServiceResult;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::atomic::AtomicBool};

#[cfg(windows)]
#[path = "windows/policy.rs"]
mod windows;

pub(crate) const FIELDS: [&str; 11] = [
    "NlMtu",
    "InterfaceMetric",
    "AutomaticMetric",
    "Dhcp",
    "RouterDiscovery",
    "Forwarding",
    "WeakHostSend",
    "WeakHostReceive",
    "Advertising",
    "ManagedAddressConfiguration",
    "OtherStatefulConfiguration",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Value {
    pub cimType: u32,
    pub value: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Row {
    pub interfaceIndex: u32,
    pub addressFamily: u32,
    pub store: u32,
    pub compartmentId: Value,
    pub values: BTreeMap<String, Value>,
}

impl Value {
    fn validate(&self) -> ServiceResult<()> {
        let maximum = match self.cimType {
            17 => u8::MAX as u32,
            18 => u16::MAX as u32,
            19 => u32::MAX,
            _ => return Err("Policy evidence contains an unsupported CIM scalar type".into()),
        };
        if self.value.is_some_and(|value| value > maximum) {
            return Err("Policy evidence value exceeds its declared CIM scalar type".into());
        }
        Ok(())
    }
}

impl Row {
    fn validate(&self, native: &Snapshot, store: u32) -> ServiceResult<()> {
        let family = match native.addressFamily {
            crate::journal::AddressFamily::Ipv4 => 2,
            crate::journal::AddressFamily::Ipv6 => 23,
        };
        if self.interfaceIndex != native.interfaceIndex
            || self.addressFamily != family
            || self.store != store
        {
            return Err(
                "Policy provider returned a different interface, family, or policy store".into(),
            );
        }
        self.compartmentId.validate()?;
        if self.compartmentId.value.is_some_and(|value| value != 1)
            || (store == 1 && self.compartmentId.value != Some(1))
        {
            return Err("Policy evidence is restricted to the default network compartment".into());
        }
        if self.values.len() != FIELDS.len()
            || FIELDS.iter().any(|name| !self.values.contains_key(*name))
        {
            return Err("Policy evidence has missing or substituted fields".into());
        }
        for value in self.values.values() {
            value.validate()?;
        }
        if store == 1 && self.values["NlMtu"].value != Some(native.settings.nlMtu) {
            return Err("Active policy MTU does not match native effective-value readback".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capture {
    pub schemaVersion: u32,
    pub native: Snapshot,
    pub active: Row,
    pub persistent: Option<Row>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    pub active: Row,
    pub persistent: Option<Row>,
}

impl Evidence {
    pub(crate) fn validate(&self, native: &Snapshot) -> ServiceResult<()> {
        if native.schemaVersion != 2 {
            return Err("IP policy originals require native schema-two context".into());
        }
        native.journalContext()?;
        native.requireOriginalOrigins()?;
        self.active.validate(native, 1)?;
        if let Some(row) = &self.persistent {
            row.validate(native, 0)?;
        }
        Ok(())
    }

    pub(crate) fn validateMtuObservation(
        &self,
        original: &Snapshot,
        current: &Capture,
    ) -> ServiceResult<()> {
        self.validate(original)?;
        current.validate()?;
        current.native.validateMtuObservation(original)?;
        let mut observed = current.evidence();
        observed.active.interfaceIndex = self.active.interfaceIndex;
        observed.active.values.get_mut("NlMtu").unwrap().value = self.active.values["NlMtu"].value;
        if let (Some(expected), Some(actual)) = (&self.persistent, &mut observed.persistent) {
            actual.interfaceIndex = expected.interfaceIndex;
        }
        if &observed != self {
            return Err(
                "Active or persistent IP policy changed from the exact checkpoint original".into(),
            );
        }
        Ok(())
    }
}

impl Capture {
    pub fn evidence(&self) -> Evidence {
        Evidence {
            active: self.active.clone(),
            persistent: self.persistent.clone(),
        }
    }

    pub fn validate(&self) -> ServiceResult<()> {
        if self.schemaVersion != 1 || self.native.schemaVersion != 2 {
            return Err("Unsupported IP policy evidence schema".into());
        }
        self.native.journalContext()?;
        self.native.requireOriginalOrigins()?;
        self.active.validate(&self.native, 1)?;
        if let Some(row) = &self.persistent {
            row.validate(&self.native, 0)?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;

// com calls can block; invoke this reader only in an isolated worker process.
pub fn inspectWorker(
    adapterGuid: uuid::Uuid,
    family: crate::journal::AddressFamily,
    cancelled: &AtomicBool,
) -> ServiceResult<Capture> {
    #[cfg(windows)]
    {
        windows::capture(adapterGuid, family, cancelled)
    }
    #[cfg(not(windows))]
    {
        let _ = (adapterGuid, family, cancelled);
        Err("IP policy evidence requires Windows".into())
    }
}

#[cfg(windows)]
fn decode(
    bytes: &[u8],
    adapterGuid: uuid::Uuid,
    family: crate::journal::AddressFamily,
) -> ServiceResult<Capture> {
    let capture: Capture = serde_json::from_slice(bytes)?;
    capture.validate()?;
    if capture.native.adapterGuid != adapterGuid || capture.native.addressFamily != family {
        return Err("IP policy worker returned a different adapter or family".into());
    }
    Ok(capture)
}

pub fn inspect(
    adapterGuid: uuid::Uuid,
    family: crate::journal::AddressFamily,
    cancelled: &AtomicBool,
) -> ServiceResult<Capture> {
    #[cfg(windows)]
    {
        use std::{
            sync::atomic::Ordering,
            time::{Duration, Instant},
        };
        let deadline = Instant::now() + Duration::from_secs(15);
        let check = || -> ServiceResult<()> {
            if cancelled.load(Ordering::SeqCst) || Instant::now() >= deadline {
                Err(
                    "IP policy worker cancelled or its fifteen-second process allowance expired"
                        .into(),
                )
            } else {
                Ok(())
            }
        };
        check()?;
        let executable = std::env::current_exe()?;
        if !executable
            .file_name()
            .is_some_and(|name| name.eq_ignore_ascii_case("epp-network-service.exe"))
        {
            return Err("IP policy isolation requires the dedicated service executable".into());
        }
        let arguments = [
            "--ip-policy-worker".into(),
            adapterGuid.to_string(),
            match family {
                crate::journal::AddressFamily::Ipv4 => "ipv4".into(),
                crate::journal::AddressFamily::Ipv6 => "ipv6".into(),
            },
        ];
        let bytes = crate::owned_process::CommandJob::spawnReader(&executable, &arguments)?
            .collect(65536, check)?;
        check()?;
        let capture = decode(&bytes, adapterGuid, family)?;
        check()?;
        Ok(capture)
    }
    #[cfg(not(windows))]
    {
        let _ = (adapterGuid, family, cancelled);
        Err("IP policy evidence requires Windows".into())
    }
}
