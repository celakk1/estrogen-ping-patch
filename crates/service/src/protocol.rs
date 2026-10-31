use crate::ServiceResult;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 4096;
pub const MAX_REQUEST_LIFETIME_MS: u64 = 5000;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum Operation {
    GetStatus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub schemaVersion: u32,
    pub requestId: String,
    pub issuedAtUnixMs: u64,
    pub expiresAtUnixMs: u64,
    pub operation: Operation,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceStatus {
    pub schemaVersion: u32,
    pub requestId: String,
    pub serviceVersion: String,
    pub servicePid: u32,
    pub mode: String,
    pub modificationsPermitted: bool,
    pub rollbackAvailable: bool,
}

impl Request {
    pub fn validate(&self, nowUnixMs: u64) -> ServiceResult<()> {
        if self.schemaVersion != SCHEMA_VERSION {
            return Err("Unsupported service protocol schema".into());
        }
        if !(8..=64).contains(&self.requestId.len())
            || !self
                .requestId
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("Invalid service request identifier".into());
        }
        if self.issuedAtUnixMs > nowUnixMs.saturating_add(250)
            || self.expiresAtUnixMs <= nowUnixMs
            || self.expiresAtUnixMs <= self.issuedAtUnixMs
            || self.expiresAtUnixMs - self.issuedAtUnixMs > MAX_REQUEST_LIFETIME_MS
        {
            return Err("Service request deadline expired or exceeded its bound".into());
        }
        Ok(())
    }
}

pub fn decodeRequest(frame: &[u8], nowUnixMs: u64) -> ServiceResult<Request> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err("Service frame exceeds the 4096-byte limit".into());
    }
    let request: Request = serde_json::from_slice(frame)?;
    request.validate(nowUnixMs)?;
    Ok(request)
}

pub fn response(request: &Request) -> ServiceStatus {
    ServiceStatus {
        schemaVersion: SCHEMA_VERSION,
        requestId: request.requestId.clone(),
        serviceVersion: env!("CARGO_PKG_VERSION").into(),
        servicePid: std::process::id(),
        mode: "readOnly".into(),
        modificationsPermitted: false,
        rollbackAvailable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strictAllowlistRejectsCommandsUnknownFieldsAndOversizedFrames() {
        let valid = json!({"schemaVersion":1,"requestId":"12345678","issuedAtUnixMs":1000,"expiresAtUnixMs":2000,"operation":"getStatus"});
        assert!(decodeRequest(&serde_json::to_vec(&valid).unwrap(), 1500).is_ok());
        let mut command = valid.clone();
        command["operation"] = json!("runCommand");
        assert!(decodeRequest(&serde_json::to_vec(&command).unwrap(), 1500).is_err());
        let mut unknown = valid.clone();
        unknown["command"] = json!("anything");
        assert!(decodeRequest(&serde_json::to_vec(&unknown).unwrap(), 1500).is_err());
        assert!(decodeRequest(&vec![b' '; MAX_FRAME_BYTES + 1], 1500).is_err());
        assert!(decodeRequest(br#"{"schemaVersion":1,"schemaVersion":1,"requestId":"12345678","issuedAtUnixMs":1000,"expiresAtUnixMs":2000,"operation":"getStatus"}"#, 1500).is_err());
    }

    #[test]
    fn deadlinesAndIdentifiersAreBoundedBeforeDispatch() {
        let mut request = Request {
            schemaVersion: 1,
            requestId: "12345678".into(),
            issuedAtUnixMs: 1000,
            expiresAtUnixMs: 2000,
            operation: Operation::GetStatus,
        };
        assert!(request.validate(2000).is_err());
        assert!(request.validate(500).is_err());
        request.expiresAtUnixMs = 6001;
        assert!(request.validate(1500).is_err());
        request.expiresAtUnixMs = 2000;
        request.requestId = "line\nbreak".into();
        assert!(request.validate(1500).is_err());
        request.requestId = "12345678".into();
        request.schemaVersion = 2;
        assert!(request.validate(1500).is_err());
    }

    #[test]
    fn statusNeverGrantsMutationOrClaimsRollback() {
        let request = Request {
            schemaVersion: 1,
            requestId: "12345678".into(),
            issuedAtUnixMs: 1000,
            expiresAtUnixMs: 2000,
            operation: Operation::GetStatus,
        };
        let status = response(&request);
        assert_eq!(status.requestId, request.requestId);
        assert_eq!(status.mode, "readOnly");
        assert!(!status.modificationsPermitted);
        assert!(!status.rollbackAvailable);
    }
}
