use super::*;
use std::net::{IpAddr, SocketAddr};

#[cfg(feature = "isolated-tls")]
#[test]
fn cancelledOwnedTransfersPreserveUnavailableSocketEvidenceWithoutConnecting() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let peer = listener.local_addr().unwrap();
    let result = measureIsolatedFrom(
        plan(
            Provider::UserOwnedHttp {
                origin: format!("http://{peer}/"),
            },
            Direction::Download,
            2,
        ),
        SourceBinding {
            source: peer.ip(),
            peer,
        },
        &AtomicBool::new(true),
        &TransferProgress::default(),
    )
    .unwrap();
    assert_eq!(result.status, TransferStatus::Cancelled);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    for stream in result.streams {
        assert!(matches!(
            stream.tcpInfo,
            Some(TcpInfoEvidence::Unavailable { .. })
        ));
    }
}

#[cfg(feature = "isolated-tls")]
#[test]
fn ownedHttpTransportRetainsBoundStreamsAndProtocolRefusals() {
    for (behavior, direction, expected) in [
        (
            Behavior::Normal,
            Direction::Download,
            TransferStatus::Completed,
        ),
        (
            Behavior::Normal,
            Direction::Upload,
            TransferStatus::Completed,
        ),
        (
            Behavior::Refused,
            Direction::Download,
            TransferStatus::HttpError,
        ),
        (
            Behavior::Redirect,
            Direction::Download,
            TransferStatus::HttpError,
        ),
        (
            Behavior::Encoded,
            Direction::Download,
            TransferStatus::ProtocolError,
        ),
        (
            Behavior::Short,
            Direction::Download,
            TransferStatus::NetworkError,
        ),
        (
            Behavior::WrongAck,
            Direction::Upload,
            TransferStatus::ProtocolError,
        ),
    ] {
        let (provider, worker) = fixture(behavior, 2);
        let peer: SocketAddr = provider
            .info()
            .unwrap()
            .origin
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .parse()
            .unwrap();
        let binding = SourceBinding {
            source: peer.ip(),
            peer,
        };
        let progress = TransferProgress::default();
        let result = measureIsolatedFrom(
            plan(provider, direction, 2),
            binding,
            &AtomicBool::new(false),
            &progress,
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(result.status, expected, "{result:?}");
        assert_eq!(progress.activeRequests.load(Ordering::SeqCst), 0);
        for stream in &result.streams {
            let evidence = stream
                .tcpInfo
                .as_ref()
                .expect("owned transport omitted TCP evidence");
            evidence
                .validateFor(binding, &result.startedAt, &result.finishedAt)
                .unwrap();
            #[cfg(windows)]
            assert!(
                matches!(evidence, TcpInfoEvidence::Measured { .. }),
                "{evidence:?}"
            );
        }
        if expected != TransferStatus::Completed {
            assert!(result.applicationGoodputMbps.is_none());
        }
    }
}

fn server(
    address: IpAddr,
    count: usize,
    allowance: Duration,
) -> (Provider, SocketAddr, thread::JoinHandle<Vec<SocketAddr>>) {
    let listener = TcpListener::bind(SocketAddr::new(address, 0)).unwrap();
    let peer = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + allowance;
        let mut peers = Vec::new();
        let mut handlers = Vec::new();
        while peers.len() < count && Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, source)) => {
                    peers.push(source);
                    handlers.push(thread::spawn(move || {
                        respond(stream, Behavior::Normal, None)
                    }));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(error) => panic!("Bound fixture accept failed: {error}"),
            }
        }
        for handler in handlers {
            handler.join().unwrap();
        }
        peers
    });
    (
        Provider::UserOwnedHttp {
            origin: format!("http://{peer}/"),
        },
        peer,
        worker,
    )
}

#[test]
fn transfersBindEveryUploadAndDownloadStreamAndPreserveExactProvenance() {
    for source in [
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        "::1".parse().unwrap(),
    ] {
        for direction in [Direction::Download, Direction::Upload] {
            let (provider, peer, worker) = server(source, 2, Duration::from_secs(3));
            let binding = SourceBinding { source, peer };
            let mut plan = plan(provider, direction, 2);
            plan.bytes = 4096;
            let result = measureFrom(
                plan,
                binding,
                &AtomicBool::new(false),
                &TransferProgress::default(),
            )
            .unwrap();
            assert_eq!(result.status, TransferStatus::Completed);
            assert_eq!(result.acceptedPayloadBytes, 4096);
            assert_eq!(result.sourceBinding, Some(binding));
            assert!(
                result.streams.iter().all(
                    |stream| stream.remoteAddress.as_deref() == Some(peer.to_string().as_str())
                )
            );
            let peers = worker.join().unwrap();
            assert_eq!(peers.len(), 2);
            assert!(peers.iter().all(|peer| peer.ip() == source));
            let saved: TransferResult =
                serde_json::from_str(&serde_json::to_string(&result).unwrap()).unwrap();
            assert_eq!(saved.sourceBinding, Some(binding));
        }
    }
}

#[test]
fn unavailableTransferSourceCannotFallBackToTheWorkingDefaultConnection() {
    let (provider, peer, worker) =
        server("127.0.0.1".parse().unwrap(), 1, Duration::from_millis(600));
    let mut plan = plan(provider, Direction::Download, 1);
    plan.timeoutMs = 250;
    let binding = SourceBinding {
        source: "192.0.2.254".parse().unwrap(),
        peer,
    };
    let result = measureFrom(
        plan,
        binding,
        &AtomicBool::new(false),
        &TransferProgress::default(),
    )
    .unwrap();
    assert_eq!(result.status, TransferStatus::NetworkError);
    assert_eq!(result.acceptedPayloadBytes, 0);
    assert!(result.applicationGoodputMbps.is_none());
    assert!(worker.join().unwrap().is_empty());
}

#[test]
fn transferBindingRejectsWrongFamilyPortLiteralAndScopedOrNonUnicastAddresses() {
    let provider = Provider::UserOwnedHttp {
        origin: "http://127.0.0.1:43210/".into(),
    };
    let good = SourceBinding {
        source: "127.0.0.1".parse().unwrap(),
        peer: "127.0.0.1:43210".parse().unwrap(),
    };
    good.validate(&provider).unwrap();
    for source in [
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "::1",
        "::ffff:127.0.0.1",
        "fe80::1",
    ] {
        assert!(
            SourceBinding {
                source: source.parse().unwrap(),
                ..good
            }
            .validate(&provider)
            .is_err(),
            "source {source}"
        );
    }
    for peer in [
        "127.0.0.1:0",
        "127.0.0.1:43211",
        "127.0.0.2:43210",
        "[::1]:43210",
    ] {
        assert!(
            SourceBinding {
                peer: peer.parse().unwrap(),
                ..good
            }
            .validate(&provider)
            .is_err(),
            "peer {peer}"
        );
    }
    let provider = Provider::UserOwnedHttp {
        origin: "http://[::1]:43210/".into(),
    };
    for peer in [
        SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            43210,
            1,
            0,
        )),
        SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            43210,
            0,
            1,
        )),
    ] {
        assert!(
            SourceBinding {
                source: "::1".parse().unwrap(),
                peer
            }
            .validate(&provider)
            .is_err()
        );
    }
}

#[test]
fn pinnedHttpsHostnameConnectsToTheRecordedPeerAndRejectsFailedTls() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((stream, source)) => {
                    drop(stream);
                    return Some(source);
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return None,
                Err(error) => panic!("Pinned HTTPS fixture failed: {error}"),
            }
        }
    });
    let provider = Provider::UserOwnedHttp {
        origin: format!("https://epp-unresolved-benchmark.invalid:{}/", peer.port()),
    };
    let binding = SourceBinding {
        source: "127.0.0.1".parse().unwrap(),
        peer,
    };
    let mut plan = plan(provider, Direction::Download, 1);
    plan.timeoutMs = 1000;
    let result = measureFrom(
        plan,
        binding,
        &AtomicBool::new(false),
        &TransferProgress::default(),
    )
    .unwrap();
    assert_eq!(worker.join().unwrap().unwrap().ip(), binding.source);
    assert_eq!(result.status, TransferStatus::NetworkError);
    assert!(result.applicationGoodputMbps.is_none());
    assert_eq!(result.acceptedPayloadBytes, 0);
}

#[test]
fn defaultTransfersKeepLegacyMetadataAndCancelledBoundRequestsSendNothing() {
    let (provider, worker) = fixture(Behavior::Normal, 1);
    let result = measure(
        plan(provider, Direction::Download, 1),
        &AtomicBool::new(false),
        &TransferProgress::default(),
    )
    .unwrap();
    worker.join().unwrap();
    let json = serde_json::to_value(&result).unwrap();
    assert!(json.get("sourceBinding").is_none());
    assert!(
        serde_json::from_value::<TransferResult>(json)
            .unwrap()
            .sourceBinding
            .is_none()
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let peer = listener.local_addr().unwrap();
    let provider = Provider::UserOwnedHttp {
        origin: format!("http://{peer}/"),
    };
    let result = measureFrom(
        plan(provider, Direction::Upload, 1),
        SourceBinding {
            source: peer.ip(),
            peer,
        },
        &AtomicBool::new(true),
        &TransferProgress::default(),
    )
    .unwrap();
    assert_eq!(result.status, TransferStatus::Cancelled);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
