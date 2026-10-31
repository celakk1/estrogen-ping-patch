use crate::{AppResult, discovery};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{sync::atomic::AtomicBool, time::Duration};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupSummary {
    pub id: i64,
    pub capturedAt: String,
    pub sha256: String,
    pub unavailableSections: usize,
    pub capturedSections: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupExport {
    pub summary: BackupSummary,
    pub payloadJson: String,
}

pub fn capture(cancelled: &AtomicBool) -> AppResult<Value> {
    let startedAt = Utc::now().to_rfc3339();
    let inventory = discovery::cancellableInventory(cancelled)?;
    let mut settings = discovery::readWindowsData(
        include_str!("backup.ps1"),
        Duration::from_secs(60),
        Some(cancelled),
    )?;
    let nativeSections = crate::native_dns::captureSections(&inventory, cancelled)?;
    settings["sections"]
        .as_array_mut()
        .ok_or("Snapshot settings sections must be an array")?
        .extend(nativeSections);
    let payload = json!({
        "schemaVersion": 1,
        "kind": "networkSettingsSnapshot",
        "appVersion": env!("CARGO_PKG_VERSION"),
        "startedAt": startedAt,
        "capturedAt": Utc::now().to_rfc3339(),
        "inventory": inventory,
        "settings": settings,
        "restoreStatus": "notImplemented",
        "modificationsPermitted": false,
        "limitations": [
            "This is a read-only settings snapshot, not a verified full-system restore point.",
            "Unavailable driver or operating-system sections are recorded explicitly.",
            "Resolved DNS addresses alone do not prove whether DNS configuration was automatic or static.",
            "Native DNS version-one fields preserve API-reported values, not a proven full-policy or dual-stack restore checkpoint.",
            "Capture is not an atomic operating-system transaction; settings may change during collection.",
            "Automatic restoration and pre-change rollback checkpoints require the privileged service and are not enabled."
        ]
    });
    validatePayload(&payload)?;
    Ok(payload)
}

pub fn validatePayload(payload: &Value) -> AppResult<(usize, usize)> {
    if payload["schemaVersion"] != 1
        || payload["kind"] != "networkSettingsSnapshot"
        || payload["modificationsPermitted"] != false
        || !payload["capturedAt"].is_string()
        || payload["restoreStatus"] != "notImplemented"
        || !payload["limitations"]
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string))
    {
        return Err("Invalid network settings snapshot format".into());
    }
    discovery::validateInventory(&payload["inventory"])?;
    let sections = payload["settings"]["sections"]
        .as_array()
        .ok_or("Snapshot settings sections must be an array")?;
    if sections.is_empty() || sections.len() > 512 {
        return Err("Snapshot section count is outside safe bounds".into());
    }
    let mut unavailable = 0;
    for section in sections {
        if !section["name"].is_string()
            || !section["adapterId"].is_string()
            || !section["values"].is_array()
        {
            return Err("Malformed snapshot section".into());
        }
        match section["status"].as_str() {
            Some("captured") => {}
            Some("unavailable") if section["error"].is_string() => unavailable += 1,
            _ => return Err("Snapshot section has an invalid capture status".into()),
        }
    }
    Ok((sections.len() - unavailable, unavailable))
}

pub fn checksum(payloadJson: &str) -> String {
    format!("{:x}", Sha256::digest(payloadJson.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn fixture() -> Value {
        json!({"schemaVersion":1,"kind":"networkSettingsSnapshot","modificationsPermitted":false,"restoreStatus":"notImplemented","limitations":[],"capturedAt":"2026-10-31T00:00:00Z","inventory":{"adapters":[],"routes":[],"interfaces":[],"dns":[],"limitations":[]},"settings":{"sections":[{"name":"dnsServers","adapterId":"","status":"captured","values":[],"error":null}]}})
    }

    #[test]
    fn unavailableSettingsAreNeverCountedAsSuccessful() {
        let mut payload = fixture();
        payload["settings"]["sections"][0] = json!({"name":"rss","adapterId":"","status":"unavailable","values":[],"error":"Unsupported adapter"});
        assert_eq!(validatePayload(&payload).unwrap(), (0, 1));
        payload["settings"]["sections"][0]["status"] = json!("unknown");
        assert!(validatePayload(&payload).is_err());
    }

    #[test]
    fn exportChecksumCoversExactUtf8Bytes() {
        assert_eq!(
            checksum("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_ne!(checksum("{}"), checksum("{}\n"));
    }

    #[test]
    fn durableBackupRoundTripAndTamperRejection() {
        let mut connection =
            crate::storage::openDatabase(std::path::Path::new(":memory:")).unwrap();
        let summary = crate::storage::saveBackup(&mut connection, &fixture()).unwrap();
        let loaded = crate::storage::loadBackup(&connection, summary.id).unwrap();
        assert_eq!(loaded.summary.sha256, checksum(&loaded.payloadJson));
        assert_eq!(crate::storage::backupHistory(&connection).unwrap().len(), 1);
        connection
            .execute(
                "UPDATE configuration_snapshots SET payload_json='{}' WHERE id=?1",
                [summary.id],
            )
            .unwrap();
        assert!(crate::storage::loadBackup(&connection, summary.id).is_err());
    }

    #[test]
    fn cancellationDoesNotStartConfigurationCapture() {
        assert!(capture(&AtomicBool::new(true)).is_err());
    }

    #[test]
    fn fullBackupStorePreservesExistingSnapshots() {
        let mut connection =
            crate::storage::openDatabase(std::path::Path::new(":memory:")).unwrap();
        for _ in 0..200 {
            crate::storage::saveBackup(&mut connection, &fixture()).unwrap();
        }
        let original = crate::storage::loadBackup(&connection, 1).unwrap();
        assert!(crate::storage::saveBackup(&mut connection, &fixture()).is_err());
        assert_eq!(
            crate::storage::backupHistory(&connection).unwrap().len(),
            200
        );
        assert_eq!(
            crate::storage::loadBackup(&connection, 1)
                .unwrap()
                .summary
                .sha256,
            original.summary.sha256
        );
    }
}
