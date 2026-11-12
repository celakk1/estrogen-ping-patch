mod http;
mod provider;
pub mod session;

use crate::AppResult;
pub use provider::{Provider, ProviderInfo};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64},
    },
    time::Duration,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBinding {
    pub source: IpAddr,
    pub peer: SocketAddr,
}

impl SourceBinding {
    pub fn validate(&self, provider: &Provider) -> AppResult<()> {
        for address in [self.source, self.peer.ip()] {
            crate::icmp::EchoTarget {
                address,
                scopeId: 0,
            }
            .validate()?;
        }
        let origin = reqwest::Url::parse(&provider.info()?.origin)?;
        let literal = origin
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok());
        if self.source.is_ipv4() != self.peer.is_ipv4()
            || Some(self.peer.port()) != origin.port_or_known_default()
            || literal.is_some_and(|ip| ip != self.peer.ip())
            || matches!(self.peer, SocketAddr::V6(peer) if peer.scope_id() != 0 || peer.flowinfo() != 0)
        {
            return Err("Transfer source and peer must use the same address family and the provider's exact port and literal address, without IPv6 scope or flow overrides".into());
        }
        Ok(())
    }
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sourceBinding: Option<SourceBinding>,
}

#[derive(Default)]
#[repr(C)]
pub struct TransferCounters {
    pub downloadBytesRead: AtomicU64,
    pub uploadBodyBytesProvided: AtomicU64,
    pub activeRequests: AtomicU64,
}

pub trait TransferProgressStorage: std::any::Any + Send + Sync {
    fn counters(&self) -> &TransferCounters;
}

impl TransferProgressStorage for TransferCounters {
    fn counters(&self) -> &TransferCounters {
        self
    }
}

#[derive(Clone)]
pub struct TransferProgress {
    storage: Arc<dyn TransferProgressStorage>,
}

impl TransferProgress {
    pub fn fromStorage(storage: Arc<dyn TransferProgressStorage>) -> Self {
        Self { storage }
    }

    pub fn storage<T: TransferProgressStorage>(&self) -> Option<&T> {
        let storage: &dyn std::any::Any = self.storage.as_ref();
        storage.downcast_ref()
    }
}

impl Default for TransferProgress {
    fn default() -> Self {
        Self::fromStorage(Arc::new(TransferCounters::default()))
    }
}

impl std::ops::Deref for TransferProgress {
    type Target = TransferCounters;

    fn deref(&self) -> &Self::Target {
        self.storage.counters()
    }
}

pub fn measure(
    plan: TransferPlan,
    cancelled: &AtomicBool,
    progress: &TransferProgress,
) -> AppResult<TransferResult> {
    measureBound(plan, None, cancelled, progress)
}

pub fn measureFrom(
    plan: TransferPlan,
    binding: SourceBinding,
    cancelled: &AtomicBool,
    progress: &TransferProgress,
) -> AppResult<TransferResult> {
    binding.validate(&plan.provider)?;
    measureBound(plan, Some(binding), cancelled, progress)
}

fn measureBound(
    plan: TransferPlan,
    binding: Option<SourceBinding>,
    cancelled: &AtomicBool,
    progress: &TransferProgress,
) -> AppResult<TransferResult> {
    plan.validate()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(4)
        .enable_all()
        .build()?;
    let result = runtime.block_on(http::measure(plan, binding, cancelled, progress));
    runtime.shutdown_timeout(Duration::from_millis(100));
    result
}

fn deadline(plan: &TransferPlan) -> Duration {
    Duration::from_millis(plan.timeoutMs)
}

#[cfg(test)]
mod tests;
