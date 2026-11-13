use super::*;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, atomic::Ordering},
    thread,
    time::Instant,
};

#[path = "source_bound_tests.rs"]
mod source_bound_tests;

#[path = "source_bound_session_tests.rs"]
mod source_bound_session_tests;

#[derive(Clone, Copy)]
enum Behavior {
    Normal,
    Refused,
    Redirect,
    Encoded,
    Short,
    Slow,
    WrongAck,
}

fn fixture(behavior: Behavior, count: usize) -> (Provider, thread::JoinHandle<Vec<(String, u64)>>) {
    fixtureWithSignal(behavior, count, None)
}

fn fixtureWithSignal(
    behavior: Behavior,
    count: usize,
    signal: Option<Arc<AtomicBool>>,
) -> (Provider, thread::JoinHandle<Vec<(String, u64)>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut handlers = Vec::new();
        while handlers.len() < count {
            match listener.accept() {
                Ok((stream, _)) => {
                    let signal = signal.clone();
                    handlers.push(thread::spawn(move || respond(stream, behavior, signal)));
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("Fixture accept failed: {error}"),
            }
        }
        handlers
            .into_iter()
            .map(|handler| handler.join().unwrap())
            .collect()
    });
    (Provider::UserOwnedHttp { origin }, worker)
}

fn respond(
    mut stream: TcpStream,
    behavior: Behavior,
    signal: Option<Arc<AtomicBool>>,
) -> (String, u64) {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        headers.push(byte[0]);
        assert!(headers.len() < 8192);
    }
    let headers = String::from_utf8(headers).unwrap();
    let path = headers
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string();
    let uploaded = headers
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<u64>().unwrap())
        })
        .unwrap_or(0);
    let mut received = 0;
    let mut buffer = [0; 4096];
    while received < uploaded {
        let maximum = (uploaded - received).min(buffer.len() as u64) as usize;
        let count = stream.read(&mut buffer[..maximum]).unwrap();
        assert!(count > 0);
        received += count as u64;
    }
    if let Some(signal) = signal {
        signal.store(true, Ordering::SeqCst);
    }
    if matches!(behavior, Behavior::Slow) {
        thread::sleep(Duration::from_millis(400));
    }
    let requested: u64 = path
        .split_once("bytes=")
        .map_or(0, |(_, value)| value.parse().unwrap());
    let mut status = "200 OK";
    let mut extra = String::new();
    if matches!(behavior, Behavior::Refused) {
        status = "429 Too Many Requests";
        extra = "Retry-After: 60\r\n".into();
    }
    if matches!(behavior, Behavior::Redirect) {
        status = "302 Found";
        extra = "Location: /must-not-follow\r\n".into();
    }
    if matches!(behavior, Behavior::Encoded) {
        extra = "Content-Encoding: gzip\r\n".into();
    }
    let ack = if matches!(behavior, Behavior::WrongAck) {
        received + 1
    } else {
        received
    };
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {requested}\r\nX-Epp-Benchmark-Protocol: 1\r\nX-Epp-Received-Bytes: {ack}\r\nConnection: close\r\n{extra}\r\n"
    );
    if stream.write_all(reply.as_bytes()).is_ok() {
        let amount = if matches!(behavior, Behavior::Short) {
            requested / 2
        } else {
            requested
        };
        let mut sent = 0;
        while sent < amount {
            let bytes = (amount - sent).min(buffer.len() as u64) as usize;
            if stream.write_all(&buffer[..bytes]).is_err() {
                break;
            }
            sent += bytes as u64;
        }
    }
    (path, received)
}

fn plan(provider: Provider, direction: Direction, streams: u8) -> TransferPlan {
    TransferPlan {
        provider,
        direction,
        streams,
        bytes: 65_539,
        timeoutMs: 2000,
    }
}

#[test]
fn providerOriginsAndFixedPathsDoNotAcceptCredentialsOrRedirectDestinations() {
    for origin in [
        "http://example.com",
        "https://user:password@example.com/",
        "https://example.com/path",
        "https://example.com/?token=x",
        "https://example.com/#fragment",
        "file:///tmp",
        "http://0.0.0.0:8080/",
        "https://example.com:0/",
    ] {
        assert!(
            Provider::UserOwnedHttp {
                origin: origin.into()
            }
            .info()
            .is_err(),
            "{origin}"
        );
    }
    assert!(
        Provider::UserOwnedHttp {
            origin: "http://[::1]:8080/".into()
        }
        .info()
        .is_ok()
    );
    let url = Provider::Cloudflare
        .requestUrl(Direction::Download, 1024)
        .unwrap();
    assert_eq!(
        url.as_str(),
        "https://speed.cloudflare.com/__down?bytes=1024"
    );
    assert_eq!(
        Provider::Cloudflare
            .requestUrl(Direction::Upload, 1024)
            .unwrap()
            .as_str(),
        "https://speed.cloudflare.com/__up?bytes=1024"
    );
    let mut invalid = plan(Provider::Cloudflare, Direction::Download, 5);
    assert!(invalid.validate().is_err());
    invalid.streams = 1;
    invalid.bytes = u64::MAX;
    assert!(invalid.validate().is_err());
}

#[test]
fn customProgressStorageSharesActualTransferCountersAndOwnsTheirLifetime() {
    for direction in [Direction::Download, Direction::Upload] {
        let (provider, worker) = fixture(Behavior::Normal, 2);
        let storage = Arc::new(TransferCounters::default());
        let weak = Arc::downgrade(&storage);
        let progress = TransferProgress::fromStorage(storage.clone());
        let retained = progress.clone();
        let result = measure(
            plan(provider, direction, 2),
            &AtomicBool::new(false),
            &progress,
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(result.status, TransferStatus::Completed);
        assert_eq!(result.acceptedPayloadBytes, 65_539);
        assert_eq!(
            storage.downloadBytesRead.load(Ordering::SeqCst),
            if direction == Direction::Download {
                65_539
            } else {
                0
            }
        );
        assert_eq!(
            storage.uploadBodyBytesProvided.load(Ordering::SeqCst),
            if direction == Direction::Upload {
                65_539
            } else {
                0
            }
        );
        assert_eq!(storage.activeRequests.load(Ordering::SeqCst), 0);
        drop(storage);
        drop(progress);
        assert!(weak.upgrade().is_some());
        drop(retained);
        assert!(weak.upgrade().is_none());
    }
}

#[test]
fn parallelDownloadsShareTheTotalBudgetAndRetainRealPeerAddresses() {
    let (provider, worker) = fixture(Behavior::Normal, 4);
    let progress = TransferProgress::default();
    let result = measure(
        plan(provider, Direction::Download, 4),
        &AtomicBool::new(false),
        &progress,
    )
    .unwrap();
    let requests = worker.join().unwrap();
    assert_eq!(requests.len(), 4);
    assert_eq!(result.status, TransferStatus::Completed);
    assert_eq!(result.acceptedPayloadBytes, 65_539);
    assert_eq!(progress.downloadBytesRead.load(Ordering::SeqCst), 65_539);
    assert_eq!(progress.activeRequests.load(Ordering::SeqCst), 0);
    assert!(result.applicationGoodputMbps.unwrap() > 0.0);
    assert_eq!(
        result
            .streams
            .iter()
            .map(|stream| stream.requestedBytes)
            .sum::<u64>(),
        65_539
    );
    assert!(result.streams.iter().all(|stream| {
        stream
            .remoteAddress
            .as_ref()
            .unwrap()
            .starts_with("127.0.0.1:")
    }));
    let saved: TransferResult =
        serde_json::from_str(&serde_json::to_string(&result).unwrap()).unwrap();
    assert!(saved.workerCpu.is_none());
    assert!(
        serde_json::to_value(&result)
            .unwrap()
            .get("workerCpu")
            .is_none()
    );
    assert_eq!(
        serde_json::to_value(saved).unwrap(),
        serde_json::to_value(result).unwrap()
    );
}

#[test]
fn streamedUploadNeedsACompleteMatchingAcknowledgement() {
    let (provider, worker) = fixture(Behavior::Normal, 3);
    let progress = TransferProgress::default();
    let result = measure(
        plan(provider, Direction::Upload, 3),
        &AtomicBool::new(false),
        &progress,
    )
    .unwrap();
    let requests = worker.join().unwrap();
    assert_eq!(result.status, TransferStatus::Completed);
    assert_eq!(
        requests.iter().map(|(_, received)| *received).sum::<u64>(),
        65_539
    );
    assert_eq!(result.acceptedPayloadBytes, 65_539);
    assert_eq!(
        progress.uploadBodyBytesProvided.load(Ordering::SeqCst),
        65_539
    );
    let (provider, worker) = fixture(Behavior::WrongAck, 1);
    let result = measure(
        plan(provider, Direction::Upload, 1),
        &AtomicBool::new(false),
        &TransferProgress::default(),
    )
    .unwrap();
    worker.join().unwrap();
    assert_eq!(result.status, TransferStatus::ProtocolError);
    assert!(result.applicationGoodputMbps.is_none());
    assert_eq!(result.acceptedPayloadBytes, 0);
    assert_eq!(result.streams[0].uploadBodyBytesProvided, 65_539);
}

#[test]
fn refusalRedirectEncodingAndIncompleteBodiesCannotProduceGoodput() {
    for (behavior, expected) in [
        (Behavior::Refused, TransferStatus::HttpError),
        (Behavior::Redirect, TransferStatus::HttpError),
        (Behavior::Encoded, TransferStatus::ProtocolError),
        (Behavior::Short, TransferStatus::NetworkError),
    ] {
        let (provider, worker) = fixture(behavior, 1);
        let progress = TransferProgress::default();
        let result = measure(
            plan(provider, Direction::Download, 1),
            &AtomicBool::new(false),
            &progress,
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(result.status, expected);
        assert!(result.applicationGoodputMbps.is_none());
        assert_eq!(result.acceptedPayloadBytes, 0);
        assert_eq!(progress.activeRequests.load(Ordering::SeqCst), 0);
        if matches!(behavior, Behavior::Refused) {
            assert_eq!(result.streams[0].retryAfter.as_deref(), Some("60"));
        }
    }
}

#[test]
fn cancellationAndDeadlinesCloseActiveRequestsWithoutInventingTransferRates() {
    let (provider, worker) = fixture(Behavior::Slow, 1);
    let mut request = plan(provider, Direction::Download, 1);
    request.timeoutMs = 100;
    let result = measure(
        request,
        &AtomicBool::new(false),
        &TransferProgress::default(),
    )
    .unwrap();
    worker.join().unwrap();
    assert_eq!(result.status, TransferStatus::TimedOut);
    assert!(result.applicationGoodputMbps.is_none());
    let signal = Arc::new(AtomicBool::new(false));
    let (provider, worker) = fixtureWithSignal(Behavior::Slow, 1, Some(signal.clone()));
    let cancelled = Arc::new(AtomicBool::new(false));
    let other = cancelled.clone();
    let cancellation = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        while !signal.load(Ordering::SeqCst) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(signal.load(Ordering::SeqCst));
        other.store(true, Ordering::SeqCst);
    });
    let result = measure(
        plan(provider, Direction::Download, 1),
        &cancelled,
        &TransferProgress::default(),
    )
    .unwrap();
    cancellation.join().unwrap();
    worker.join().unwrap();
    assert_eq!(result.status, TransferStatus::Cancelled);
    assert!(result.applicationGoodputMbps.is_none());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let progress = TransferProgress::default();
    let result = measure(
        plan(
            Provider::UserOwnedHttp {
                origin: format!("http://{}/", listener.local_addr().unwrap()),
            },
            Direction::Upload,
            4,
        ),
        &cancelled,
        &progress,
    )
    .unwrap();
    assert_eq!(result.status, TransferStatus::Cancelled);
    assert_eq!(progress.uploadBodyBytesProvided.load(Ordering::SeqCst), 0);
    assert!(listener.accept().is_err());
}

fn sessionPlan(providers: Vec<Provider>, listeners: &[TcpListener; 2]) -> session::SessionPlan {
    use crate::benchmark::{Endpoint, ProbeProtocol};
    session::SessionPlan {
        providers,
        downloadBytesPerProvider: 65_539,
        uploadBytesPerProvider: 65_539,
        streams: 1,
        phaseTimeoutMs: 2000,
        idleRounds: 3,
        intervalMs: 250,
        probeTimeoutMs: 100,
        latencyEndpoints: listeners
            .iter()
            .enumerate()
            .map(|(index, listener)| Endpoint {
                id: format!("latency-{index}"),
                address: listener.local_addr().unwrap().to_string(),
                protocol: ProbeProtocol::TcpConnect,
                dnsQuery: None,
            })
            .collect(),
    }
}

#[test]
fn sessionsKeepProviderCohortsAndConcurrentRequestLatencySeparate() {
    use session::{Phase, runSession};
    let (first, firstWorker) = fixture(Behavior::Slow, 2);
    let (second, secondWorker) = fixture(Behavior::Slow, 2);
    let listeners = [
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let plan = sessionPlan(vec![first, second], &listeners);
    let mut progress = Vec::new();
    let mut result = runSession(
        crate::config::Config::default(),
        plan,
        &AtomicBool::new(false),
        |event| progress.push(event),
    )
    .unwrap();
    firstWorker.join().unwrap();
    secondWorker.join().unwrap();
    assert!(
        serde_json::to_value(&result)
            .unwrap()
            .get("sourceBindings")
            .is_none()
    );
    assert_eq!(result.status, "completed");
    assert_eq!(result.transfers.len(), 4);
    assert!(
        result
            .transfers
            .iter()
            .all(|phase| phase.result.as_ref().unwrap().status == TransferStatus::Completed)
    );
    for index in 0..2 {
        for phase in [Phase::Idle, Phase::Recovery] {
            let summary = result
                .latencySummaries
                .iter()
                .find(|summary| summary.providerIndex == index && summary.phase == phase)
                .unwrap();
            assert!(summary.results.iter().all(
                |endpoint| endpoint.summary.attempted == 3 && endpoint.summary.successful == 3
            ));
        }
    }
    assert!(result.latencySamples.iter().any(|sample| matches!(
        sample.phase,
        Phase::Download | Phase::Upload
    ) && sample.inFlightRequestsAtStart > 0
        && sample.inFlightRequestsAtEnd > 0));
    assert!(progress.iter().any(|event| event.phase == Phase::Recovery));
    let mut database = crate::storage::openDatabase(std::path::Path::new(":memory:")).unwrap();
    for (index, transfer) in result.transfers.iter_mut().enumerate() {
        let evidence = if index % 2 == 0 {
            WorkerCpuEvidence::Measured {
                usage: WorkerCpu {
                    schemaVersion: 1,
                    creationTime100ns: "134000000000000001".into(),
                    exitTime100ns: "134000000010000001".into(),
                    kernelTime100ns: "0".into(),
                    userTime100ns: "125000".into(),
                },
            }
        } else {
            WorkerCpuEvidence::Unavailable {
                reason: "fixture query unavailable".into(),
            }
        };
        evidence.validate().unwrap();
        transfer.result.as_mut().unwrap().workerCpu = Some(evidence);
    }
    crate::storage::saveLoadSession(&mut database, &mut result).unwrap();
    let history = crate::storage::loadSessionHistory(&database, 10).unwrap();
    assert_eq!(
        serde_json::to_value(&history[0]).unwrap(),
        serde_json::to_value(&result).unwrap()
    );
    let saved: session::SessionRun =
        serde_json::from_str(&serde_json::to_string(&result).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(saved).unwrap(),
        serde_json::to_value(result).unwrap()
    );
}

#[test]
fn sessionBudgetsDuplicateProvidersAndEarlyCancellationAreEnforced() {
    use session::runSession;
    let listeners = [
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let mut plan = sessionPlan(vec![Provider::Cloudflare, Provider::Cloudflare], &listeners);
    assert!(plan.validate(&crate::config::Config::default()).is_err());
    plan.providers.pop();
    let config = crate::config::Config {
        maxDownloadBytes: 1024,
        ..crate::config::Config::default()
    };
    assert!(plan.validate(&config).is_err());
    let run = runSession(
        crate::config::Config::default(),
        plan,
        &AtomicBool::new(true),
        |_| {},
    )
    .unwrap();
    assert_eq!(run.status, "cancelled");
    assert!(run.transfers.is_empty() && run.latencySamples.is_empty());
}

#[test]
fn cancellingDuringAConcurrentProbeStopsTheTransferAndSkipsUpload() {
    let (provider, worker) = fixture(Behavior::Slow, 1);
    let listeners = [
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let cancelled = AtomicBool::new(false);
    let result = session::runSession(
        crate::config::Config::default(),
        sessionPlan(vec![provider], &listeners),
        &cancelled,
        |event| {
            if event.phase == session::Phase::Download
                && event
                    .sample
                    .as_ref()
                    .is_some_and(|sample| sample.inFlightRequestsAtStart > 0)
            {
                cancelled.store(true, Ordering::SeqCst);
            }
        },
    )
    .unwrap();
    worker.join().unwrap();
    assert_eq!(result.status, "cancelled");
    assert_eq!(result.transfers.len(), 1);
    assert_eq!(
        result.transfers[0].result.as_ref().unwrap().status,
        TransferStatus::Cancelled
    );
    assert!(
        result.transfers[0]
            .result
            .as_ref()
            .unwrap()
            .applicationGoodputMbps
            .is_none()
    );
}
