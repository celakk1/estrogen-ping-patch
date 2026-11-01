#![allow(non_snake_case)]

pub mod authorization;
#[cfg(feature = "automatic-trials")]
pub mod experiment;
pub mod journal;
pub mod mtu;
#[cfg(all(windows, feature = "native-mtu-lab"))]
pub mod mtu_lab;
#[cfg(windows)]
mod owned_process;
pub mod protocol;
pub mod recovery;
pub mod routing;
#[cfg(windows)]
mod security;
#[cfg(windows)]
mod storage;
#[cfg(windows)]
mod transport;
pub mod trial;
pub mod watchdog;
#[cfg(windows)]
pub mod windows;

pub type ServiceResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub const SERVICE_NAME: &str = "EstrogenPingPatch";
pub const PIPE_NAME: &str = r"\\.\pipe\estrogen-ping-patch-service-v2";
pub const SERVICE_ACCOUNT_SID: &str = "S-1-5-19";

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceReport {
    pub state: String,
    pub detail: String,
    pub response: Option<protocol::ServiceStatus>,
}

pub fn inspectBlocking() -> ServiceReport {
    #[cfg(windows)]
    {
        match windows::inspectBlocking() {
            Ok(report) => report,
            Err(error) => ServiceReport {
                state: "unavailable".into(),
                detail: error.to_string(),
                response: None,
            },
        }
    }
    #[cfg(not(windows))]
    ServiceReport {
        state: "unsupported".into(),
        detail: "The dedicated service requires Windows".into(),
        response: None,
    }
}
