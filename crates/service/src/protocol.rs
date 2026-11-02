use crate::ServiceResult;
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 3;
pub const MAX_FRAME_BYTES: usize = 4096;
pub const MAX_REQUEST_LIFETIME_MS: u64 = 5000;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum Operation {
    GetStatus,
    StartMtuPreview(crate::preview::Proposal),
    GetMtuPreview {
        jobId: uuid::Uuid,
    },
    ApproveMtuPreview {
        jobId: uuid::Uuid,
        previewId: uuid::Uuid,
        checkpointSha256: String,
    },
    CancelMtuPreview {
        jobId: uuid::Uuid,
    },
}

impl Operation {
    fn validate(&self) -> ServiceResult<()> {
        let valid = match self {
            Self::GetStatus => true,
            Self::StartMtuPreview(proposal) => return proposal.validate(),
            Self::GetMtuPreview { jobId } | Self::CancelMtuPreview { jobId } => !jobId.is_nil(),
            Self::ApproveMtuPreview {
                jobId,
                previewId,
                checkpointSha256,
            } => {
                !jobId.is_nil()
                    && !previewId.is_nil()
                    && checkpointSha256.len() == 64
                    && checkpointSha256
                        .bytes()
                        .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
            }
        };
        if !valid {
            return Err("Invalid MTU preview identity or checkpoint hash".into());
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ReplyBody {
    Status(ServiceStatus),
    MtuPreview(crate::preview::Report),
    Rejected { detail: String },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Reply {
    pub schemaVersion: u32,
    pub requestId: String,
    pub servicePid: u32,
    pub result: ReplyBody,
}

impl Reply {
    pub fn new(request: &Request, result: ReplyBody) -> Self {
        Self {
            schemaVersion: SCHEMA_VERSION,
            requestId: request.requestId.clone(),
            servicePid: std::process::id(),
            result,
        }
    }
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
    pub checkpointStore: CheckpointStoreStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckpointStoreStatus {
    pub schemaVersion: u32,
    pub verifiedAtUnixMs: u64,
    pub pendingRecoveryCount: u32,
}

impl CheckpointStoreStatus {
    pub(crate) fn fromJournal(
        journal: &crate::journal::Journal,
        verifiedAtUnixMs: u64,
    ) -> ServiceResult<Self> {
        Ok(Self {
            schemaVersion: crate::journal::SCHEMA_VERSION,
            verifiedAtUnixMs,
            pendingRecoveryCount: (journal.pendingRecovery()?.len()
                + journal.pendingPolicyVerification()?.len())
            .try_into()?,
        })
    }
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
        self.operation.validate()
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

pub fn response(request: &Request, checkpointStore: &CheckpointStoreStatus) -> ServiceStatus {
    ServiceStatus {
        schemaVersion: SCHEMA_VERSION,
        requestId: request.requestId.clone(),
        serviceVersion: env!("CARGO_PKG_VERSION").into(),
        servicePid: std::process::id(),
        mode: "readOnly".into(),
        modificationsPermitted: false,
        rollbackAvailable: false,
        checkpointStore: checkpointStore.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn previewOperationsRejectClaimedActorsUnknownFieldsAndInvalidScope() {
        let proposal = crate::preview::Proposal {
            adapterGuid: uuid::Uuid::new_v4(),
            addressFamily: crate::journal::AddressFamily::Ipv4,
            proposedMtu: 1400,
            trialDurationMs: 120_000,
        };
        let request = Request {
            schemaVersion: SCHEMA_VERSION,
            requestId: "12345678".into(),
            issuedAtUnixMs: 1000,
            expiresAtUnixMs: 2000,
            operation: Operation::StartMtuPreview(proposal),
        };
        let valid = serde_json::to_value(&request).unwrap();
        assert!(decodeRequest(&serde_json::to_vec(&valid).unwrap(), 1500).is_ok());
        for field in [
            "actorSid",
            "ownerSid",
            "command",
            "registryPath",
            "endpoint",
        ] {
            let mut invalid = valid.clone();
            invalid["operation"]["startMtuPreview"][field] = json!("untrusted");
            assert!(
                decodeRequest(&serde_json::to_vec(&invalid).unwrap(), 1500).is_err(),
                "{field}"
            );
        }
        for (field, value) in [
            ("proposedMtu", json!(1279)),
            ("proposedMtu", json!(65536)),
            ("trialDurationMs", json!(0)),
            ("trialDurationMs", json!(300001)),
            ("adapterGuid", json!(uuid::Uuid::nil())),
        ] {
            let mut invalid = valid.clone();
            invalid["operation"]["startMtuPreview"][field] = value;
            assert!(
                decodeRequest(&serde_json::to_vec(&invalid).unwrap(), 1500).is_err(),
                "{field}"
            );
        }
        for operation in [
            Operation::GetMtuPreview {
                jobId: uuid::Uuid::nil(),
            },
            Operation::ApproveMtuPreview {
                jobId: uuid::Uuid::new_v4(),
                previewId: uuid::Uuid::new_v4(),
                checkpointSha256: "A".repeat(64),
            },
            Operation::CancelMtuPreview {
                jobId: uuid::Uuid::nil(),
            },
        ] {
            assert!(operation.validate().is_err());
        }
    }

    #[test]
    fn strictAllowlistRejectsCommandsUnknownFieldsAndOversizedFrames() {
        let valid = json!({"schemaVersion":SCHEMA_VERSION,"requestId":"12345678","issuedAtUnixMs":1000,"expiresAtUnixMs":2000,"operation":"getStatus"});
        assert!(decodeRequest(&serde_json::to_vec(&valid).unwrap(), 1500).is_ok());
        let mut command = valid.clone();
        command["operation"] = json!("runCommand");
        assert!(decodeRequest(&serde_json::to_vec(&command).unwrap(), 1500).is_err());
        let mut unknown = valid.clone();
        unknown["command"] = json!("anything");
        assert!(decodeRequest(&serde_json::to_vec(&unknown).unwrap(), 1500).is_err());
        assert!(decodeRequest(&vec![b' '; MAX_FRAME_BYTES + 1], 1500).is_err());
        assert!(decodeRequest(br#"{"schemaVersion":3,"schemaVersion":3,"requestId":"12345678","issuedAtUnixMs":1000,"expiresAtUnixMs":2000,"operation":"getStatus"}"#, 1500).is_err());
    }

    #[test]
    fn deadlinesAndIdentifiersAreBoundedBeforeDispatch() {
        let mut request = Request {
            schemaVersion: SCHEMA_VERSION,
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
        request.schemaVersion = 1;
        assert!(request.validate(1500).is_err());
        request.schemaVersion = 2;
        assert!(request.validate(1500).is_err());
    }

    #[test]
    fn statusNeverGrantsMutationOrClaimsRollback() {
        let request = Request {
            schemaVersion: SCHEMA_VERSION,
            requestId: "12345678".into(),
            issuedAtUnixMs: 1000,
            expiresAtUnixMs: 2000,
            operation: Operation::GetStatus,
        };
        let status = response(
            &request,
            &CheckpointStoreStatus {
                schemaVersion: crate::journal::SCHEMA_VERSION,
                verifiedAtUnixMs: 1000,
                pendingRecoveryCount: 1,
            },
        );
        assert_eq!(status.requestId, request.requestId);
        assert_eq!(status.mode, "readOnly");
        assert!(!status.modificationsPermitted);
        assert!(!status.rollbackAvailable);
        assert_eq!(status.checkpointStore.pendingRecoveryCount, 1);
    }
}
