mod transport;
mod wire;

use crate::AppResult;
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::atomic::AtomicBool,
    time::Duration,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    Aaaa,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueryPlan {
    pub name: String,
    pub recordType: RecordType,
}

impl QueryPlan {
    pub fn normalized(&self) -> AppResult<Self> {
        let name = self.name.strip_suffix('.').unwrap_or(&self.name);
        if name.is_empty() || name.len() > 253 || !name.is_ascii() {
            return Err("DNS query names require 1..253 ASCII characters; use punycode for international names".into());
        }
        for label in name.split('.') {
            if label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err("DNS query names require valid hostname labels without spaces, wildcards, or empty labels".into());
            }
        }
        Ok(Self {
            name: format!("{}.", name.to_ascii_lowercase()),
            recordType: self.recordType,
        })
    }
}

pub fn parseResolver(value: &str) -> AppResult<SocketAddr> {
    let address = match value.parse::<SocketAddr>() {
        Ok(address) => address,
        Err(_) => {
            let Some((ipAndScope, port)) = value
                .strip_prefix('[')
                .and_then(|value| value.split_once("]:"))
            else {
                return Err(
                    "DNS resolvers require a numeric IP:port, such as 1.1.1.1:53 or [::1]:53"
                        .into(),
                );
            };
            let Some((ip, scope)) = ipAndScope.split_once('%') else {
                return Err("Invalid IPv6 DNS resolver address".into());
            };
            SocketAddrV6::new(ip.parse()?, port.parse()?, 0, scope.parse()?).into()
        }
    };
    if address.port() == 0
        || address.ip().is_unspecified()
        || address.ip().is_multicast()
        || matches!(address.ip(), IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err("DNS resolvers require a numeric unicast address and nonzero port".into());
    }
    if let SocketAddr::V6(address) = address
        && (address.ip().to_ipv4_mapped().is_some()
            || (address.ip().is_unicast_link_local() && address.scope_id() == 0))
    {
        return Err(
            "Use plain IPv4 for mapped addresses; link-local IPv6 requires a numeric scope ID"
                .into(),
        );
    }
    Ok(address)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DnsStatus {
    Resolved,
    NoData,
    NxDomain,
    DnsError,
    TimedOut,
    InvalidResponse,
    OsError,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Transport {
    Udp,
    TcpFallback,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum CacheMode {
    DirectResolverCacheUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Answer {
    pub owner: String,
    pub address: IpAddr,
    pub ttlSeconds: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Alias {
    pub name: String,
    pub target: String,
    pub ttlSeconds: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DnsOutcome {
    pub query: QueryPlan,
    pub cacheMode: CacheMode,
    pub status: DnsStatus,
    pub transport: Transport,
    pub lookupMs: Option<f64>,
    pub responseMs: Option<f64>,
    pub responseCode: Option<u16>,
    pub authenticatedDataReported: Option<bool>,
    pub recursionAvailable: Option<bool>,
    pub answers: Vec<Answer>,
    pub aliases: Vec<Alias>,
    pub rejectedResponses: u32,
    pub requestBytes: u32,
    pub responseBytes: u32,
    pub error: Option<String>,
}

impl DnsOutcome {
    fn empty(query: QueryPlan) -> Self {
        Self {
            query,
            cacheMode: CacheMode::DirectResolverCacheUnknown,
            status: DnsStatus::Cancelled,
            transport: Transport::Udp,
            lookupMs: None,
            responseMs: None,
            responseCode: None,
            authenticatedDataReported: None,
            recursionAvailable: None,
            answers: Vec::new(),
            aliases: Vec::new(),
            rejectedResponses: 0,
            requestBytes: 0,
            responseBytes: 0,
            error: None,
        }
    }
}

pub fn measure(
    resolver: SocketAddr,
    query: &QueryPlan,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> AppResult<DnsOutcome> {
    parseResolver(&resolver.to_string())?;
    let query = query.normalized()?;
    if !(1..=5000).contains(&timeout.as_millis()) {
        return Err("DNS timeout must be between 1 and 5000 milliseconds".into());
    }
    transport::measure(resolver, query, timeout, cancelled)
}

#[cfg(test)]
mod tests;
