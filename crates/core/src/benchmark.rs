use crate::{
    AppResult,
    config::Config,
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
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ProbeProtocol {
    #[default]
    TcpConnect,
    IcmpEcho,
}

impl ProbeProtocol {
    fn name(self) -> &'static str {
        match self {
            Self::TcpConnect => "tcpConnect",
            Self::IcmpEcho => "icmpEcho",
        }
    }
}

#[derive(Eq, PartialEq)]
enum ParsedTarget {
    Tcp(SocketAddr),
    Echo(EchoTarget),
}

impl Endpoint {
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointResult {
    pub endpoint: Endpoint,
    pub summary: Summary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub echoCounts: Option<EchoCounts>,
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
        if endpoint.protocol != endpoints[0].protocol {
            return Err("A baseline cohort must use one protocol; run separate matched TCP and ICMP baselines".into());
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
        for (endpoint, target) in endpoints.iter().zip(&targets) {
            if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
                break 'measurements;
            }
            let start = Instant::now();
            let timeout = Duration::from_millis(config.timeoutMs)
                .min(deadline.saturating_duration_since(start));
            if timeout.as_millis() == 0 {
                break 'measurements;
            }
            let (connectMs, error, echo) = match target {
                ParsedTarget::Tcp(address) => match TcpStream::connect_timeout(address, timeout) {
                    Ok(stream) => {
                        let duration = start.elapsed().as_secs_f64() * 1000.0;
                        drop(stream);
                        (Some(duration), None, None)
                    }
                    Err(error) => (None, Some(error.to_string()), None),
                },
                ParsedTarget::Echo(target) => {
                    let result = echoProbe.measure(target, timeout, cancelled)?;
                    if result.status == EchoStatus::Cancelled {
                        break 'measurements;
                    }
                    let error = if result.status == EchoStatus::Reply {
                        None
                    } else {
                        Some(format!(
                            "ICMP {:?}; native status {:?}",
                            result.status, result.nativeCode
                        ))
                    };
                    (None, error, Some(result))
                }
            };
            let sample = Sample {
                endpointId: endpoint.id.clone(),
                address: endpoint.address.clone(),
                timestamp: Utc::now().to_rfc3339(),
                connectMs,
                error,
                echo,
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
    })
}

fn summarizeEndpoint(endpoint: Endpoint, samples: &[Sample]) -> EndpointResult {
    let values: Vec<_> = samples
        .iter()
        .filter(|sample| sample.endpointId == endpoint.id)
        .map(|sample| match &sample.echo {
            Some(echo) => echo.rttMs.map(f64::from),
            None => sample.connectMs,
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
    EndpointResult {
        endpoint,
        summary,
        echoCounts,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

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
            },
            Endpoint {
                id: "closed".into(),
                address: closedAddress.to_string(),
                protocol: ProbeProtocol::TcpConnect,
            },
        ];
        let run = runBenchmark(config, endpoints, &AtomicBool::new(false), |_, _, _| {}).unwrap();
        assert_eq!(run.samples.len(), 6);
        assert_eq!(run.results[0].summary.successful, 3);
        assert_eq!(run.results[1].summary.connectionFailurePercent, Some(100.0));
        assert!(run.results[1].summary.medianMs.is_none());
    }

    #[test]
    fn cancellationMakesNoNetworkRequests() {
        let endpoints = vec![
            Endpoint {
                id: "first".into(),
                address: "127.0.0.1:1".into(),
                protocol: ProbeProtocol::TcpConnect,
            },
            Endpoint {
                id: "second".into(),
                address: "127.0.0.1:2".into(),
                protocol: ProbeProtocol::TcpConnect,
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
        };
        assert!(validateEndpoints(&[endpoint.clone(), endpoint]).is_err());
        assert!(validateEndpoints(&[]).is_err());
    }

    fn echoEndpoint(id: &str, address: &str) -> Endpoint {
        Endpoint {
            id: id.into(),
            address: address.into(),
            protocol: ProbeProtocol::IcmpEcho,
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
