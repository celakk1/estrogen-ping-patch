use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) fn appendNativeMtu(payload: &mut Value, cancelled: &AtomicBool) -> Result<(), String> {
    if cancelled.load(Ordering::SeqCst) {
        return Err("Backup capture was cancelled".into());
    }
    let adapters = payload["inventory"]["adapters"]
        .as_array()
        .ok_or("Backup adapter inventory is malformed")?;
    let ids: Vec<_> = adapters
        .iter()
        .map(|adapter| adapter["id"].clone())
        .collect();
    let guids = ids
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("Backup adapter GUID is malformed: {error}"))?;
    let mut sections = Vec::new();
    match epp_service::mtu::captureMany(&guids, cancelled) {
        Ok(entries) => {
            for entry in entries {
                let index = guids
                    .iter()
                    .position(|guid| Some(*guid) == entry.adapterGuid)
                    .ok_or("Native MTU capture returned an unexpected adapter GUID")?;
                let (values, status, error) = match entry.snapshot {
                    Some(snapshot) => {
                        let mut value =
                            serde_json::to_value(snapshot).map_err(|error| error.to_string())?;
                        value["api"] = json!("GetIpInterfaceEntry");
                        value["linkApi"] = json!("GetIfEntry2");
                        value["restorationVerified"] = json!(false);
                        let mut unavailable = vec![
                            "persistentPolicyStore",
                            "dnsAndAddressingRestore",
                            "nativeSetterAndRecoveryValidation",
                        ];
                        if value["driver"]["status"] != "captured" {
                            unavailable.push("driverContext");
                        }
                        value["unavailableFields"] = json!(unavailable);
                        (json!([value]), "captured", Value::Null)
                    }
                    None => (
                        json!([]),
                        "unavailable",
                        json!(
                            entry
                                .error
                                .unwrap_or_else(|| "Native MTU capture was unavailable".into())
                        ),
                    ),
                };
                sections.push(json!({"name":"nativeIpInterface","adapterId":ids[index],"addressFamily":entry.addressFamily,"status":status,"values":values,"error":error}));
            }
        }
        Err(error) => {
            if cancelled.load(Ordering::SeqCst) {
                return Err("Backup capture was cancelled".into());
            }
            sections.push(json!({"name":"nativeIpInterface","adapterId":"","status":"unavailable","values":[],"error":error.to_string().chars().take(512).collect::<String>()}));
        }
    }
    if cancelled.load(Ordering::SeqCst) {
        return Err("Backup capture was cancelled".into());
    }
    payload["settings"]["sections"]
        .as_array_mut()
        .ok_or("Backup sections are malformed")?
        .extend(sections);
    payload["limitations"].as_array_mut().ok_or("Backup limitations are malformed")?.push(json!("Native interface rows preserve API-reported values and OS/driver context. Persistent policy-store origin, DNS/addressing recovery, authorization, and native restore validation are not established."));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellationCannotAppendPartialNativeMtuSections() {
        let mut value =
            json!({"inventory":{"adapters":[]},"settings":{"sections":[]},"limitations":[]});
        let original = value.clone();
        assert!(appendNativeMtu(&mut value, &AtomicBool::new(true)).is_err());
        assert_eq!(value, original);
    }
}
