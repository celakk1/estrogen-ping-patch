use crate::{
    AppResult,
    config::Config,
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
    pub address: SocketAddr,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Sample {
    pub endpointId: String,
    pub address: SocketAddr,
    pub timestamp: String,
    pub connectMs: Option<f64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EndpointResult {
    pub endpoint: Endpoint,
    pub summary: Summary,
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
        let ip = endpoint.address.ip();
        if endpoint.id.is_empty()
            || endpoint.id.len() > 80
            || endpoint.address.port() == 0
            || ip.is_unspecified()
            || ip.is_multicast()
        {
            return Err("Endpoint identifier or address is invalid".into());
        }
        if endpoints[..index]
            .iter()
            .any(|previous| previous.id == endpoint.id || previous.address == endpoint.address)
        {
            return Err("Endpoints must have distinct identifiers and addresses".into());
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
    'measurements: for _ in 0..config.sampleCount {
        for endpoint in &endpoints {
            if cancelled.load(Ordering::Relaxed) || Instant::now() >= deadline {
                break 'measurements;
            }
            let start = Instant::now();
            let result = TcpStream::connect_timeout(
                &endpoint.address,
                Duration::from_millis(config.timeoutMs)
                    .min(deadline.saturating_duration_since(start)),
            );
            let (connectMs, error) = match result {
                Ok(stream) => {
                    let duration = start.elapsed().as_secs_f64() * 1000.0;
                    drop(stream);
                    (Some(duration), None)
                }
                Err(error) => (None, Some(error.to_string())),
            };
            let sample = Sample {
                endpointId: endpoint.id.clone(),
                address: endpoint.address,
                timestamp: Utc::now().to_rfc3339(),
                connectMs,
                error,
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
        .map(|endpoint| {
            let values: Vec<_> = samples
                .iter()
                .filter(|sample| sample.endpointId == endpoint.id)
                .map(|sample| sample.connectMs)
                .collect();
            EndpointResult {
                endpoint,
                summary: summarize(&values),
            }
        })
        .collect();
    Ok(BenchmarkRun {
        id: 0,
        startedAt,
        finishedAt: Utc::now().to_rfc3339(),
        status,
        protocol: "tcpConnect".into(),
        appVersion: env!("CARGO_PKG_VERSION").into(),
        config,
        results,
        samples,
    })
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
                address: listener.local_addr().unwrap(),
            },
            Endpoint {
                id: "closed".into(),
                address: closedAddress,
            },
        ];
        let run = runBenchmark(config, endpoints, &AtomicBool::new(false), |_, _, _| {}).unwrap();
        assert_eq!(run.samples.len(), 6);
        assert_eq!(run.results[0].summary.successful, 3);
        assert_eq!(run.results[1].summary.connectionFailurePercent, 100.0);
        assert!(run.results[1].summary.medianMs.is_none());
    }

    #[test]
    fn cancellationMakesNoNetworkRequests() {
        let endpoints = vec![
            Endpoint {
                id: "first".into(),
                address: "127.0.0.1:1".parse().unwrap(),
            },
            Endpoint {
                id: "second".into(),
                address: "127.0.0.1:2".parse().unwrap(),
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
            address: "127.0.0.1:443".parse().unwrap(),
        };
        assert!(validateEndpoints(&[endpoint.clone(), endpoint]).is_err());
        assert!(validateEndpoints(&[]).is_err());
    }
}
