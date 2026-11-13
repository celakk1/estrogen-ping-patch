use crate::ServiceResult;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkStatistics {
    pub schemaVersion: u32,
    pub queryStartedAtUnixMs: u64,
    pub queryFinishedAtUnixMs: u64,
    pub queryElapsedNs: String,
    pub interfaceType: u32,
    pub operStatus: i32,
    pub adminStatus: i32,
    pub mediaConnectState: i32,
    pub receiveLinkSpeedBps: String,
    pub transmitLinkSpeedBps: String,
    pub receivedOctets: String,
    pub sentOctets: String,
    pub receivedUnicastPackets: String,
    pub receivedNonUnicastPackets: String,
    pub sentUnicastPackets: String,
    pub sentNonUnicastPackets: String,
    pub receivedDiscards: String,
    pub receivedErrors: String,
    pub receivedUnknownProtocols: String,
    pub sentDiscards: String,
    pub sentErrors: String,
}

impl LinkStatistics {
    pub fn validate(&self, routeCapturedAtUnixMs: u64) -> ServiceResult<()> {
        if self.schemaVersion != 1
            || self.queryStartedAtUnixMs == 0
            || self.queryStartedAtUnixMs > self.queryFinishedAtUnixMs
            || self.queryFinishedAtUnixMs > routeCapturedAtUnixMs
        {
            return Err("Adapter statistics have invalid schema or query timestamps".into());
        }
        for value in [
            &self.queryElapsedNs,
            &self.receiveLinkSpeedBps,
            &self.transmitLinkSpeedBps,
            &self.receivedOctets,
            &self.sentOctets,
            &self.receivedUnicastPackets,
            &self.receivedNonUnicastPackets,
            &self.sentUnicastPackets,
            &self.sentNonUnicastPackets,
            &self.receivedDiscards,
            &self.receivedErrors,
            &self.receivedUnknownProtocols,
            &self.sentDiscards,
            &self.sentErrors,
        ] {
            let parsed: u64 = value.parse()?;
            if parsed.to_string() != *value {
                return Err("Adapter statistics require canonical unsigned decimal values".into());
            }
        }
        Ok(())
    }
}
