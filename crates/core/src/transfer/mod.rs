mod http;
mod provider;
pub mod session;

use crate::AppResult;
pub use provider::{Provider, ProviderInfo};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64},
    },
    time::Duration,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Direction {
    Download,
    Upload,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransferPlan {
    pub provider: Provider,
    pub direction: Direction,
    pub bytes: u64,
    pub streams: u8,
    pub timeoutMs: u64,
}

impl TransferPlan {
    pub fn validate(&self) -> AppResult<()> {
        self.provider.info()?;
        if !(1..=4).contains(&self.streams)
            || !(1024..=536_870_912).contains(&self.bytes)
            || self.bytes < u64::from(self.streams)
            || !(100..=60_000).contains(&self.timeoutMs)
        {
            return Err("Transfers require 1..4 streams, 1 KiB..512 MiB total payload, and a 100 ms..60 s deadline".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TransferStatus {
    Completed,
    Cancelled,
    TimedOut,
    HttpError,
    ProtocolError,
    NetworkError,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamResult {
    pub ordinal: u8,
    pub requestedBytes: u64,
    pub downloadBytesRead: u64,
    pub uploadBodyBytesProvided: u64,
    pub acceptedPayloadBytes: u64,
    pub elapsedMs: f64,
    pub status: TransferStatus,
    pub httpStatus: Option<u16>,
    pub remoteAddress: Option<String>,
    pub retryAfter: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferResult {
    pub plan: TransferPlan,
    pub provider: ProviderInfo,
    pub startedAt: String,
    pub finishedAt: String,
    pub elapsedMs: f64,
    pub status: TransferStatus,
    pub acceptedPayloadBytes: u64,
    pub applicationGoodputMbps: Option<f64>,
    pub streams: Vec<StreamResult>,
}

#[derive(Clone, Default)]
pub struct TransferProgress {
    pub downloadBytesRead: Arc<AtomicU64>,
    pub uploadBodyBytesProvided: Arc<AtomicU64>,
    pub activeRequests: Arc<AtomicU64>,
}

pub fn measure(
    plan: TransferPlan,
    cancelled: &AtomicBool,
    progress: &TransferProgress,
) -> AppResult<TransferResult> {
    plan.validate()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    let result = runtime.block_on(http::measure(plan, cancelled, progress));
    runtime.shutdown_timeout(Duration::from_millis(100));
    result
}

fn deadline(plan: &TransferPlan) -> Duration {
    Duration::from_millis(plan.timeoutMs)
}

#[cfg(test)]
mod tests;
