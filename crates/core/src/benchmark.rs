use crate::{
    AppResult,
    config::Config,
    dns::{self, DnsOutcome, DnsStatus, QueryPlan},
    icmp::{EchoOutcome, EchoProbe, EchoStatus, EchoTarget},
    statistics::{Summary, summarize},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    net::{SocketAddr, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub id: String,
    pub address: String,
    #[serde(default)]
    pub protocol: ProbeProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnsQuery: Option<QueryPlan>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProbeProtocol {
    #[default]
    TcpConnect,
    IcmpEcho,
    DnsLookup,
}

impl ProbeProtocol {
    fn name(self) -> &'static str {
        match self {
            Self::TcpConnect => "tcpConnect",
            Self::IcmpEcho => "icmpEcho",
            Self::DnsLookup => "dnsLookup",
        }
    }
}

#[derive(Eq, PartialEq)]
enum ParsedTarget {
    Tcp(SocketAddr),
    Echo(EchoTarget),
    Dns(SocketAddr),
}

impl Endpoint {
    pub fn destinationAddress(&self) -> AppResult<(std::net::IpAddr, u32)> {
        match self.target()? {
            ParsedTarget::Tcp(address) | ParsedTarget::Dns(address) => Ok((
                address.ip(),
                match address {
                    std::net::SocketAddr::V4(_) => 0,
                    std::net::SocketAddr::V6(address) => address.scope_id(),
                },
            )),
            ParsedTarget::Echo(address) => Ok((address.address, address.scopeId)),
        }
    }

    fn target(&self) -> AppResult<ParsedTarget> {
        match self.protocol {
            ProbeProtocol::TcpConnect => {
                let address: SocketAddr = self.address.parse().map_err(|_| "TCP targets require a numeric IP:port, such as 1.1.1.1:53 or [::1]:443")?;
                if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
                    return Err("TCP endpoint address or port is invalid".into());
                }
                Ok(ParsedTarget::Tcp(address))
            }
            ProbeProtocol::IcmpEcho => Ok(ParsedTarget::Echo(EchoTarget::parse(&self.address).map_err(|error| format!("ICMP targets require a numeric IP without a port; link-local IPv6 requires %scopeId: {error}"))?)),
            ProbeProtocol::DnsLookup => Ok(ParsedTarget::Dns(dns::parseResolver(&self.address)?)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sample {
    pub endpointId: String,
    pub address: String,
    pub timestamp: String,
    pub connectMs: Option<f64>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub echo: Option<EchoOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsOutcome>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointResult {
    pub endpoint: Endpoint,
    pub summary: Summary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub echoCounts: Option<EchoCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnsCounts: Option<DnsCounts>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsCounts {
    pub resolved: usize,
    pub noData: usize,
    pub nxDomain: usize,
    pub dnsErrors: usize,
    pub timeouts: usize,
    pub invalidResponses: usize,
    pub osErrors: usize,
    pub tcpFallbacks: usize,
    pub addressSetChanges: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EchoCounts {
    pub replies: usize,
    pub timeouts: usize,
    pub ipErrors: usize,
    pub osErrors: usize,
    pub invalidReplies: usize,
    pub unsupported: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BenchmarkRun {
    pub id: i64,
    pub startedAt: String,
    pub finishedAt: String,
    pub status: String,
    pub protocol: String,
    pub appVersion: String,
    pub config: Config,
    pub results: Vec<EndpointResult>,
    pub samples: Vec<Sample>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<RoutingEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sourceBindings: Option<Vec<SourceBinding>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBinding {
    pub endpointId: String,
    pub source: EchoTarget,
}

#[cfg(test)]
#[path = "benchmark/source_bound_tests.rs"]
mod source_bound_tests;

pub(crate) fn validateSourceBindings(
    endpoints: &[Endpoint],
    bindings: &[SourceBinding],
) -> AppResult<()> {
    validateEndpoints(endpoints)?;
    if endpoints.len() != bindings.len() {
        return Err(
            "Every source-bound echo endpoint needs exactly one ordered source binding".into(),
        );
    }
    for (endpoint, binding) in endpoints.iter().zip(bindings) {
        if endpoint.protocol != ProbeProtocol::IcmpEcho || endpoint.id != binding.endpointId {
            return Err(
                "Source bindings must match the complete ordered ICMP endpoint cohort".into(),
            );
        }
        crate::icmp::validateSource(&binding.source, &EchoTarget::parse(&endpoint.address)?)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RoutingStatus {
    Unchanged,
    Changed,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingEvidence {
    pub schemaVersion: u32,
    pub status: RoutingStatus,
    pub beforeFingerprint: Option<String>,
    pub afterFingerprint: Option<String>,
    pub before: serde_json::Value,
    pub after: serde_json::Value,
}

fn probeTarget(
    endpoint: &Endpoint,
    target: &ParsedTarget,
    timeout: Duration,
    cancelled: &AtomicBool,
    echoProbe: &mut EchoProbe,
    source: Option<&EchoTarget>,
) -> AppResult<Option<Sample>> {
    let start = Instant::now();
    let (connectMs, error, echo, dns) = match target {
        ParsedTarget::Tcp(address) => match TcpStream::connect_timeout(address, timeout) {
            Ok(stream) => {
                let duration = start.elapsed().as_secs_f64() * 1000.0;
                drop(stream);
                (Some(duration), None, None, None)
            }
            Err(error) => (None, Some(error.to_string()), None, None),
        },
        ParsedTarget::Echo(target) => {
            let result = if let Some(source) = source {
                echoProbe.measureFrom(source, target, timeout, cancelled)?
            } else {
                echoProbe.measure(target, timeout, cancelled)?
            };
            if result.status == EchoStatus::Cancelled {
                return Ok(None);
            }
            let error = if result.status == EchoStatus::Reply {
                None
            } else {
                Some(format!(
                    "ICMP {:?}; native status {:?}",
                    result.status, result.nativeCode
                ))
            };
            (None, error, Some(result), None)
        }
        ParsedTarget::Dns(resolver) => {
            let query = endpoint.dnsQuery.as_ref().expect("validated DNS query");
            let result = dns::measure(*resolver, query, timeout, cancelled)?;
            if result.status == DnsStatus::Cancelled {
                return Ok(None);
            }
            let error = if result.status == DnsStatus::Resolved {
                None
            } else {
                Some(result.error.clone().unwrap_or_else(|| {
                    format!(
                        "DNS {:?}; response code {:?}",
                        result.status, result.responseCode
                    )
                }))
            };
            (None, error, None, Some(result))
        }
    };
    let sample = Sample {
        endpointId: endpoint.id.clone(),
        address: endpoint.address.clone(),
        timestamp: Utc::now().to_rfc3339(),
        connectMs,
        error,
        echo,
        dns,
    };

    Ok(Some(sample))
}

pub(crate) fn measureOnce(
    endpoint: &Endpoint,
    timeout: Duration,
    cancelled: &AtomicBool,
    echoProbe: &mut EchoProbe,
    source: Option<&EchoTarget>,
) -> AppResult<Option<Sample>> {
    if source.is_some() && endpoint.protocol != ProbeProtocol::IcmpEcho {
        return Err("Source-bound latency samples require ICMP echo".into());
    }
    if cancelled.load(Ordering::SeqCst) {
        return Ok(None);
    }
    probeTarget(
        endpoint,
        &endpoint.target()?,
        timeout,
        cancelled,
        echoProbe,
        source,
    )
}
pub fn validateEndpoints(endpoints: &[Endpoint]) -> AppResult<()> {
    if !(2..=8).contains(&endpoints.len()) {
        return Err("Select between 2 and 8 independent endpoints".into());
    }
    for (index, endpoint) in endpoints.iter().enumerate() {
        if endpoint.id.is_empty()
            || endpoint.id.len() > 80
            || endpoint.id.chars().any(char::is_control)
            || endpoint.address.len() > 160
        {
            return Err("Endpoint identifier or address is invalid".into());
        }
        let target = endpoint.target()?;
        if endpoint.protocol == ProbeProtocol::DnsLookup {
            let query = endpoint
                .dnsQuery
                .as_ref()
                .ok_or("DNS benchmarks require a query name and record type")?
                .normalized()?;
            let firstQuery = endpoints[0]
                .dnsQuery
                .as_ref()
                .ok_or("DNS benchmarks require a query name and record type")?
                .normalized()?;
            if query != firstQuery {
                return Err(
                    "Compare DNS resolvers with the same query name and record type".into(),
                );
            }
        } else if endpoint.dnsQuery.is_some() {
            return Err("DNS query options are only valid for a DNS benchmark".into());
        }
        if endpoint.protocol != endpoints[0].protocol {
            return Err("A baseline cohort must use one protocol; run separate matched TCP, ICMP, and DNS baselines".into());
        }
        for previous in &endpoints[..index] {
            if previous.id == endpoint.id || previous.target()? == target {
                return Err("Endpoints must have distinct identifiers and addresses".into());
            }
        }
    }
    Ok(())
}

pub fn runBenchmark(
    config: Config,
    endpoints: Vec<Endpoint>,
    cancelled: &AtomicBool,
    onSample: impl FnMut(&Sample, usize, usize),
) -> AppResult<BenchmarkRun> {
    runBenchmarkInternal(config, endpoints, None, cancelled, onSample)
}

pub fn runSourceBoundEchoBenchmark(
    config: Config,
    endpoints: Vec<Endpoint>,
    bindings: Vec<SourceBinding>,
    cancelled: &AtomicBool,
    onSample: impl FnMut(&Sample, usize, usize),
) -> AppResult<BenchmarkRun> {
    validateSourceBindings(&endpoints, &bindings)?;
    runBenchmarkInternal(config, endpoints, Some(bindings), cancelled, onSample)
}

fn runBenchmarkInternal(
    config: Config,
    endpoints: Vec<Endpoint>,
    sourceBindings: Option<Vec<SourceBinding>>,
    cancelled: &AtomicBool,
    mut onSample: impl FnMut(&Sample, usize, usize),
) -> AppResult<BenchmarkRun> {
    config.validate()?;
    validateEndpoints(&endpoints)?;
    let startedAt = Utc::now().to_rfc3339();
    let deadline = Instant::now() + Duration::from_secs(u64::from(config.sessionMinutes) * 60);
    let mut samples = Vec::with_capacity(config.sampleCount as usize * endpoints.len());
    let total = config.sampleCount as usize * endpoints.len();
    let targets = endpoints
        .iter()
        .map(Endpoint::target)
        .collect::<AppResult<Vec<_>>>()?;
    let protocol = endpoints[0].protocol;
    let mut echoProbe = EchoProbe::default();
    'measurements: for _ in 0..config.sampleCount {
        for (index, (endpoint, target)) in endpoints.iter().zip(&targets).enumerate() {
            if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
                break 'measurements;
            }
            let start = Instant::now();
            let timeout = Duration::from_millis(config.timeoutMs)
                .min(deadline.saturating_duration_since(start));
            if timeout.as_millis() == 0 {
                break 'measurements;
            }
            let source = sourceBindings
                .as_ref()
                .map(|bindings| &bindings[index].source);
            let Some(sample) =
                probeTarget(endpoint, target, timeout, cancelled, &mut echoProbe, source)?
            else {
                break 'measurements;
            };
            samples.push(sample);
            onSample(
                samples.last().expect("sample was just inserted"),
                samples.len(),
                total,
            );
            let delayUntil =
                (Instant::now() + Duration::from_millis(config.intervalMs)).min(deadline);
            while Instant::now() < delayUntil {
                if cancelled.load(Ordering::Relaxed) {
                    break 'measurements;
                }
                thread::sleep(
                    Duration::from_millis(50)
                        .min(delayUntil.saturating_duration_since(Instant::now())),
                );
            }
        }
    }
    let status = if cancelled.load(Ordering::Relaxed) {
        "cancelled"
    } else if samples.len() < total {
        "timeLimit"
    } else {
        "completed"
    }
    .to_string();
    let results = endpoints
        .into_iter()
        .map(|endpoint| summarizeEndpoint(endpoint, &samples))
        .collect();
    Ok(BenchmarkRun {
        id: 0,
        startedAt,
        finishedAt: Utc::now().to_rfc3339(),
        status,
        protocol: protocol.name().into(),
        appVersion: env!("CARGO_PKG_VERSION").into(),
        config,
        results,
        samples,
        routing: None,
        sourceBindings,
    })
}

pub(crate) fn summarizeEndpoint(endpoint: Endpoint, samples: &[Sample]) -> EndpointResult {
    let values: Vec<_> = samples
        .iter()
        .filter(|sample| sample.endpointId == endpoint.id)
        .map(|sample| match endpoint.protocol {
            ProbeProtocol::IcmpEcho => sample
                .echo
                .as_ref()
                .and_then(|echo| echo.rttMs.map(f64::from)),
            ProbeProtocol::DnsLookup => sample.dns.as_ref().and_then(|dns| dns.lookupMs),
            ProbeProtocol::TcpConnect => sample.connectMs,
        })
        .collect();
    let mut summary = summarize(&values);
    let echoCounts = if endpoint.protocol == ProbeProtocol::IcmpEcho {
        let mut counts = EchoCounts::default();
        for echo in samples
            .iter()
            .filter(|sample| sample.endpointId == endpoint.id)
            .filter_map(|sample| sample.echo.as_ref())
        {
            match echo.status {
                EchoStatus::Reply => counts.replies += 1,
                EchoStatus::TimedOut => counts.timeouts += 1,
                EchoStatus::IpError => counts.ipErrors += 1,
                EchoStatus::OsError => counts.osErrors += 1,
                EchoStatus::InvalidReply => counts.invalidReplies += 1,
                EchoStatus::Unsupported => counts.unsupported += 1,
                EchoStatus::Cancelled => {}
            }
        }
        summary.connectionFailurePercent = None;
        let valid = counts.replies + counts.timeouts;
        summary.echoTimeoutPercent = if valid > 0 && valid == summary.attempted {
            Some(counts.timeouts as f64 * 100.0 / valid as f64)
        } else {
            None
        };
        Some(counts)
    } else {
        None
    };
    let dnsCounts = if endpoint.protocol == ProbeProtocol::DnsLookup {
        let mut counts = DnsCounts::default();
        let mut previousAddresses = None;
        for dns in samples
            .iter()
            .filter(|sample| sample.endpointId == endpoint.id)
            .filter_map(|sample| sample.dns.as_ref())
        {
            match dns.status {
                DnsStatus::Resolved => counts.resolved += 1,
                DnsStatus::NoData => counts.noData += 1,
                DnsStatus::NxDomain => counts.nxDomain += 1,
                DnsStatus::DnsError => counts.dnsErrors += 1,
                DnsStatus::TimedOut => counts.timeouts += 1,
                DnsStatus::InvalidResponse => counts.invalidResponses += 1,
                DnsStatus::OsError => counts.osErrors += 1,
                DnsStatus::Cancelled => {}
            }
            if dns.transport == dns::Transport::TcpFallback {
                counts.tcpFallbacks += 1;
            }
            if dns.status == DnsStatus::Resolved {
                let addresses: std::collections::BTreeSet<_> =
                    dns.answers.iter().map(|answer| answer.address).collect();
                if previousAddresses
                    .as_ref()
                    .is_some_and(|previous| *previous != addresses)
                {
                    counts.addressSetChanges += 1;
                }
                previousAddresses = Some(addresses);
            }
        }
        summary.connectionFailurePercent = None;
        summary.dnsFailurePercent = if summary.attempted > 0 {
            Some((summary.attempted - counts.resolved) as f64 * 100.0 / summary.attempted as f64)
        } else {
            None
        };
        Some(counts)
    } else {
        None
    };
    EndpointResult {
        endpoint,
        summary,
        echoCounts,
        dnsCounts,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn routeDestinationsReuseProtocolParsingAndPreserveIpv6Scope() {
        for (protocol, address, ip, scope) in [
            (ProbeProtocol::TcpConnect, "127.0.0.1:443", "127.0.0.1", 0),
            (ProbeProtocol::DnsLookup, "[fe80::1%12]:53", "fe80::1", 12),
            (ProbeProtocol::IcmpEcho, "fe80::1%12", "fe80::1", 12),
        ] {
            let endpoint = Endpoint {
                id: "fixture".into(),
                address: address.into(),
                protocol,
                dnsQuery: None,
            };
            assert_eq!(
                endpoint.destinationAddress().unwrap(),
                (ip.parse::<std::net::IpAddr>().unwrap(), scope)
            );
        }
        let endpoint = Endpoint {
            id: "invalid".into(),
            address: "https://example.com".into(),
            protocol: ProbeProtocol::TcpConnect,
            dnsQuery: None,
        };
        assert!(endpoint.destinationAddress().is_err());
    }

    #[test]
    fn measureRealLocalSocketsAndPersistFailuresAsMissing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let closedAddress = closed.local_addr().unwrap();
        drop(closed);
        let config = Config {
            sampleCount: 3,
            intervalMs: 250,
            timeoutMs: 100,
            ..Config::default()
        };
        let endpoints = vec![
            Endpoint {
                id: "open".into(),
                address: listener.local_addr().unwrap().to_string(),
                protocol: ProbeProtocol::TcpConnect,
                dnsQuery: None,
            },
            Endpoint {
                id: "closed".into(),
                address: closedAddress.to_string(),
                protocol: ProbeProtocol::TcpConnect,
                dnsQuery: None,
            },
        ];
        let mut run =
            runBenchmark(config, endpoints, &AtomicBool::new(false), |_, _, _| {}).unwrap();
        assert_eq!(run.samples.len(), 6);
        assert_eq!(run.results[0].summary.successful, 3);
        assert_eq!(run.results[1].summary.connectionFailurePercent, Some(100.0));
        assert!(run.results[1].summary.medianMs.is_none());
        let legacy = serde_json::to_value(&run).unwrap();
        assert!(legacy.get("routing").is_none());
        assert!(
            serde_json::from_value::<BenchmarkRun>(legacy)
                .unwrap()
                .routing
                .is_none()
        );
        run.routing = Some(RoutingEvidence {
            schemaVersion: 1,
            status: RoutingStatus::Unavailable,
            beforeFingerprint: None,
            afterFingerprint: None,
            before: serde_json::json!({"status":"unavailable","error":"fixture unavailable"}),
            after: serde_json::json!({"status":"unavailable","error":"fixture unavailable"}),
        });
        let mut connection =
            crate::storage::openDatabase(std::path::Path::new(":memory:")).unwrap();
        crate::storage::saveRun(&mut connection, &mut run).unwrap();
        let saved = crate::storage::history(&connection, 1).unwrap().remove(0);
        assert_eq!(
            serde_json::to_value(&saved).unwrap(),
            serde_json::to_value(&run).unwrap()
        );
    }

    #[test]
    fn cancellationMakesNoNetworkRequests() {
        let endpoints = vec![
            Endpoint {
                id: "first".into(),
                address: "127.0.0.1:1".into(),
                protocol: ProbeProtocol::TcpConnect,
                dnsQuery: None,
            },
            Endpoint {
                id: "second".into(),
                address: "127.0.0.1:2".into(),
                protocol: ProbeProtocol::TcpConnect,
                dnsQuery: None,
            },
        ];
        let run = runBenchmark(
            Config::default(),
            endpoints,
            &AtomicBool::new(true),
            |_, _, _| panic!("unexpected request"),
        )
        .unwrap();
        assert_eq!(run.status, "cancelled");
        assert!(run.samples.is_empty());
    }

    #[test]
    fn rejectDuplicateAndUnboundedTargets() {
        let endpoint = Endpoint {
            id: "same".into(),
            address: "127.0.0.1:443".into(),
            protocol: ProbeProtocol::TcpConnect,
            dnsQuery: None,
        };
        assert!(validateEndpoints(&[endpoint.clone(), endpoint]).is_err());
        assert!(validateEndpoints(&[]).is_err());
    }

    fn echoEndpoint(id: &str, address: &str) -> Endpoint {
        Endpoint {
            id: id.into(),
            address: address.into(),
            protocol: ProbeProtocol::IcmpEcho,
            dnsQuery: None,
        }
    }

    #[test]
    fn cohortsRejectMixedProtocolsAndEquivalentIpv6Targets() {
        assert!(
            validateEndpoints(&[
                echoEndpoint("first", "::1"),
                echoEndpoint("second", "0:0:0:0:0:0:0:1")
            ])
            .is_err()
        );
        let tcp = Endpoint {
            id: "tcp".into(),
            address: "127.0.0.1:443".into(),
            protocol: ProbeProtocol::TcpConnect,
            dnsQuery: None,
        };
        assert!(validateEndpoints(&[tcp, echoEndpoint("echo", "127.0.0.1")]).is_err());
        for address in ["1.1.1.1:53", "127.0.0.1%0", "fe80::1", "::ffff:127.0.0.1"] {
            assert!(
                validateEndpoints(&[
                    echoEndpoint("first", address),
                    echoEndpoint("second", "::1")
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn legacyTcpEndpointsAndSamplesKeepTheirMeaning() {
        let endpoint: Endpoint =
            serde_json::from_str(r#"{"id":"legacy","address":"127.0.0.1:443"}"#).unwrap();
        assert_eq!(endpoint.protocol, ProbeProtocol::TcpConnect);
        let sample: Sample = serde_json::from_str(r#"{"endpointId":"legacy","address":"127.0.0.1:443","timestamp":"2026-10-31T00:00:00Z","connectMs":2.5,"error":null}"#).unwrap();
        assert!(sample.echo.is_none());
        assert_eq!(sample.connectMs, Some(2.5));
    }

    #[test]
    fn ipOrSystemErrorsCannotBeAdvertisedAsEchoPacketLoss() {
        let endpoint = echoEndpoint("echo", "127.0.0.1");
        let sample = |status, rttMs| Sample {
            endpointId: "echo".into(),
            address: endpoint.address.clone(),
            timestamp: Utc::now().to_rfc3339(),
            connectMs: None,
            error: None,
            dns: None,
            echo: Some(EchoOutcome {
                status,
                rttMs,
                rttUnitMs: 1,
                callDurationMs: 1.0,
                responder: None,
                responderScopeId: None,
                nativeCode: None,
            }),
        };
        let received = sample(EchoStatus::Reply, Some(0));
        let timeout = sample(EchoStatus::TimedOut, None);
        let valid = summarizeEndpoint(endpoint.clone(), &[received.clone(), timeout.clone()]);
        assert_eq!(valid.summary.medianMs, Some(0.0));
        assert_eq!(valid.summary.echoTimeoutPercent, Some(50.0));
        assert!(valid.summary.connectionFailurePercent.is_none());
        for status in [
            EchoStatus::IpError,
            EchoStatus::OsError,
            EchoStatus::InvalidReply,
            EchoStatus::Unsupported,
        ] {
            let result = summarizeEndpoint(
                endpoint.clone(),
                &[received.clone(), timeout.clone(), sample(status, None)],
            );
            assert!(result.summary.echoTimeoutPercent.is_none());
            assert_eq!(result.summary.attempted, 3);
            assert_eq!(result.summary.successful, 1);
        }
    }

    #[cfg(windows)]
    #[test]
    fn realEchoCohortPersistsRttSeparatelyFromConnectTimeAndCanCancel() {
        let config = Config {
            sampleCount: 3,
            intervalMs: 250,
            timeoutMs: 500,
            ..Config::default()
        };
        let endpoints = vec![
            echoEndpoint("ipv4", "127.0.0.1"),
            echoEndpoint("ipv6", "::1"),
        ];
        let mut run = runBenchmark(
            config.clone(),
            endpoints.clone(),
            &AtomicBool::new(false),
            |_, _, _| {},
        )
        .unwrap();
        assert_eq!(run.protocol, "icmpEcho");
        assert_eq!(run.samples.len(), 6);
        for sample in &run.samples {
            assert!(sample.connectMs.is_none());
            assert_eq!(sample.echo.as_ref().unwrap().status, EchoStatus::Reply);
        }
        for result in &run.results {
            assert_eq!(result.summary.successful, 3);
            assert!(result.summary.connectionFailurePercent.is_none());
            assert_eq!(result.summary.echoTimeoutPercent, Some(0.0));
        }
        let mut database = crate::storage::openDatabase(std::path::Path::new(":memory:")).unwrap();
        crate::storage::saveRun(&mut database, &mut run).unwrap();
        let saved = crate::storage::history(&database, 1).unwrap().remove(0);
        assert_eq!(
            serde_json::to_value(saved).unwrap(),
            serde_json::to_value(run).unwrap()
        );
        let cancelled = AtomicBool::new(false);
        let partial = runBenchmark(config, endpoints, &cancelled, |_, _, _| {
            cancelled.store(true, Ordering::SeqCst)
        })
        .unwrap();
        assert_eq!(partial.status, "cancelled");
        assert_eq!(partial.samples.len(), 1);
    }
}
