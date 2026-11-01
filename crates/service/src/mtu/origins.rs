use crate::ServiceResult;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) const VALUE_NAMES: [&str; 9] = [
    "MTU",
    "EnableDHCP",
    "IPAddress",
    "SubnetMask",
    "DefaultGateway",
    "NameServer",
    "DhcpNameServer",
    "ProfileNameServer",
    "Dhcpv6DNSServers",
];
pub(crate) const MAX_DATA_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawValue {
    pub valueType: u32,
    pub dataHex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NamedValue {
    pub name: String,
    pub value: Option<RawValue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Stack {
    pub name: String,
    pub keyPresent: bool,
    pub values: Vec<NamedValue>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryOrigins {
    pub schemaVersion: u32,
    pub adapterGuid: Uuid,
    pub stacks: Vec<Stack>,
}

impl RegistryOrigins {
    pub fn validate(&self, adapterGuid: Uuid) -> ServiceResult<()> {
        if self.schemaVersion != 1 || adapterGuid.is_nil() || self.adapterGuid != adapterGuid {
            return Err("Registry origin evidence does not identify the expected adapter".into());
        }
        if self.stacks.len() != 2 {
            return Err("Registry origin evidence requires both fixed address-family keys".into());
        }
        let mut bytes = 0usize;
        for (stack, name) in self.stacks.iter().zip(["Tcpip", "Tcpip6"]) {
            if stack.name != name || stack.values.len() != VALUE_NAMES.len() {
                return Err("Registry origin evidence has missing or substituted fields".into());
            }
            for (entry, name) in stack.values.iter().zip(VALUE_NAMES) {
                if entry.name != name || (!stack.keyPresent && entry.value.is_some()) {
                    return Err("Registry origin value presence is inconsistent".into());
                }
                if let Some(value) = &entry.value {
                    if !value.dataHex.len().is_multiple_of(2)
                        || !value
                            .dataHex
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        return Err(
                            "Registry origin bytes must use lossless lowercase hexadecimal".into(),
                        );
                    }
                    bytes = bytes
                        .checked_add(value.dataHex.len() / 2)
                        .ok_or("Registry origin evidence size overflow")?;
                    if bytes > MAX_DATA_BYTES {
                        return Err(
                            "Registry origin evidence exceeds its four-KiB raw data bound".into(),
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum OriginCapture {
    Captured { evidence: RegistryOrigins },
    Unavailable { error: String },
}

impl OriginCapture {
    pub(super) fn validate(&self, adapterGuid: Uuid) -> ServiceResult<()> {
        match self {
            Self::Captured { evidence } => evidence.validate(adapterGuid),
            Self::Unavailable { error } if !error.is_empty() && error.len() <= 2048 => Ok(()),
            _ => Err("Registry origin capture status is malformed".into()),
        }
    }

    pub(super) fn requireCaptured(&self, adapterGuid: Uuid) -> ServiceResult<()> {
        match self {
            Self::Captured { evidence } => evidence.validate(adapterGuid),
            Self::Unavailable { .. } => Err(
                "Checkpoint preparation requires service-captured fixed registry origin evidence"
                    .into(),
            ),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
