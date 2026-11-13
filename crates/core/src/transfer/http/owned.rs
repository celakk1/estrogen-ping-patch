use super::*;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Empty, StreamBody, combinators::UnsyncBoxBody};
use hyper::{Request, body::Frame, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustls_platform_verifier::BuilderVerifierExt;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpSocket, TcpStream},
};

trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Transport for T {}

struct Driver(tokio::task::JoinHandle<Result<(), hyper::Error>>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn network(error: impl std::fmt::Display) -> Failure {
    Failure(
        TransferStatus::NetworkError,
        error
            .to_string()
            .chars()
            .take(512)
            .map(|value| if value.is_control() { ' ' } else { value })
            .collect(),
    )
}

pub(super) fn tlsConfig(plan: &TransferPlan) -> AppResult<Option<Arc<rustls::ClientConfig>>> {
    if reqwest::Url::parse(&plan.provider.info()?.origin)?.scheme() != "https" {
        return Ok(None);
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_platform_verifier()?
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Some(Arc::new(config)))
}

pub(super) async fn exchange(
    context: &RequestContext<'_>,
    result: &mut StreamResult,
    download: &AtomicU64,
    upload: &Arc<AtomicU64>,
    progress: &TransferProgress,
    payload: Bytes,
    trace: &super::super::tcp_info::Slot,
) -> Result<(), Failure> {
    let plan = context.plan;
    let binding = context.binding.ok_or_else(|| {
        protocolFailure("Owned transfers require an exact source and peer binding")
    })?;
    let url = plan
        .provider
        .requestUrl(plan.direction, result.requestedBytes)
        .map_err(network)?;
    if (url.scheme() == "https") != context.tlsConfig.is_some() {
        return Err(protocolFailure(
            "Owned transfer TLS policy does not match the provider scheme",
        ));
    }
    let socket = if binding.source.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .map_err(network)?;
    socket
        .bind(std::net::SocketAddr::new(binding.source, 0))
        .map_err(network)?;
    let stream = socket.connect(binding.peer).await.map_err(network)?;
    stream.set_nodelay(true).map_err(network)?;
    if stream.local_addr().map_err(network)?.ip() != binding.source
        || stream.peer_addr().map_err(network)? != binding.peer
    {
        return Err(protocolFailure(
            "Owned transfer socket does not match its frozen binding",
        ));
    }
    result.remoteAddress = Some(binding.peer.to_string());
    let stream = stream.into_std().map_err(network)?;
    trace.attach(&stream);
    let stream = TcpStream::from_std(stream).map_err(network)?;
    let transport: Box<dyn Transport> = if let Some(config) = &context.tlsConfig {
        let host = url
            .host_str()
            .ok_or_else(|| protocolFailure("Missing provider hostname"))?
            .trim_matches(['[', ']'])
            .to_owned();
        let name = rustls::pki_types::ServerName::try_from(host).map_err(network)?;
        Box::new(
            tokio_rustls::TlsConnector::from(config.clone())
                .connect(name, stream)
                .await
                .map_err(network)?,
        )
    } else {
        Box::new(stream)
    };
    let (mut sender, connection) = http1::Builder::new()
        .max_headers(64)
        .max_buf_size(64 * 1024)
        .handshake::<_, UnsyncBoxBody<Bytes, io::Error>>(TokioIo::new(transport))
        .await
        .map_err(network)?;
    let _driver = Driver(tokio::spawn(connection));
    let body = if plan.direction == Direction::Upload {
        let stream = uploadStream(
            result.requestedBytes,
            upload.clone(),
            progress.clone(),
            payload,
        )
        .map(|chunk| chunk.map(Frame::data));
        StreamBody::new(stream).boxed_unsync()
    } else {
        Empty::<Bytes>::new()
            .map_err(|value| match value {})
            .boxed_unsync()
    };
    let host = url
        .host_str()
        .ok_or_else(|| protocolFailure("Missing provider hostname"))?;
    let authority = url
        .port()
        .map_or_else(|| host.to_owned(), |port| format!("{host}:{port}"));
    let path = url.query().map_or_else(
        || url.path().to_owned(),
        |query| format!("{}?{query}", url.path()),
    );
    let mut request = Request::builder()
        .method(if plan.direction == Direction::Download {
            "GET"
        } else {
            "POST"
        })
        .uri(path)
        .header(header::HOST, authority)
        .header(header::ACCEPT_ENCODING, "identity")
        .header(header::CACHE_CONTROL, "no-store")
        .header(
            header::USER_AGENT,
            concat!("estrogen-ping-patch/", env!("CARGO_PKG_VERSION")),
        );
    if plan.direction == Direction::Upload {
        request = request
            .header(header::CONTENT_LENGTH, result.requestedBytes)
            .header(header::CONTENT_TYPE, "application/octet-stream");
    }
    let mut response = sender
        .send_request(request.body(body).map_err(network)?)
        .await
        .map_err(network)?;
    validateResponse(response.status().as_u16(), response.headers(), plan, result)?;
    if plan.direction == Direction::Download
        && (response.status().as_u16() != 200
            || hyper::body::Body::size_hint(response.body()).exact() != Some(result.requestedBytes))
    {
        return Err(protocolFailure(
            "Download requires HTTP 200 and the exact requested Content-Length",
        ));
    }
    if plan.direction == Direction::Upload {
        if upload.load(Ordering::SeqCst) != result.requestedBytes {
            return Err(protocolFailure(
                "Server answered before the full upload body was provided",
            ));
        }
        if matches!(plan.provider, Provider::UserOwnedHttp { .. })
            && response
                .headers()
                .get("x-epp-received-bytes")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                != Some(result.requestedBytes)
        {
            return Err(protocolFailure(
                "Upload acknowledgement does not match the requested payload length",
            ));
        }
    }
    let mut acknowledged = 0usize;
    while let Some(frame) = response.body_mut().frame().await {
        let frame = frame.map_err(network)?;
        if let Ok(chunk) = frame.into_data() {
            tokio::task::yield_now().await;
            if plan.direction == Direction::Download {
                download.fetch_add(chunk.len() as u64, Ordering::SeqCst);
                progress
                    .downloadBytesRead
                    .fetch_add(chunk.len() as u64, Ordering::SeqCst);
                if download.load(Ordering::SeqCst) > result.requestedBytes {
                    return Err(protocolFailure(
                        "Download exceeded its declared payload length",
                    ));
                }
            } else {
                acknowledged = acknowledged
                    .checked_add(chunk.len())
                    .ok_or_else(|| protocolFailure("Upload acknowledgement size overflow"))?;
                if acknowledged > ACK_LIMIT {
                    return Err(protocolFailure("Upload acknowledgement exceeds 4096 bytes"));
                }
            }
        }
    }
    if plan.direction == Direction::Download
        && download.load(Ordering::SeqCst) != result.requestedBytes
    {
        return Err(protocolFailure(
            "Download ended before its declared payload length",
        ));
    }
    result.acceptedPayloadBytes = result.requestedBytes;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn ownedTlsVerifiesTrustAndHostnameBeforeAcceptingPayload() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let identity = rcgen::generate_simple_self_signed(vec!["epp-test.invalid".into()])
                .unwrap();
            let certificate = identity.cert.der().clone();
            let serverConfig = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(serverConfig));
            let mut roots = rustls::RootCertStore::empty();
            roots.add(certificate).unwrap();
            let trusted = Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
            );
            for case in 0..3 {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let peer = listener.local_addr().unwrap();
                let acceptor = acceptor.clone();
                let server = tokio::spawn(async move {
                    tokio::time::timeout(Duration::from_secs(5), async move {
                        let (stream, _) = listener.accept().await.unwrap();
                        let Ok(mut stream) = acceptor.accept(stream).await else {
                            return false;
                        };
                        let mut request = Vec::new();
                        let mut byte = [0u8; 1];
                        while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                            if stream.read_exact(&mut byte).await.is_err() {
                                return false;
                            }
                            request.push(byte[0]);
                        }
                        assert!(String::from_utf8(request).unwrap().starts_with("GET /"));
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nx-epp-benchmark-protocol: 1\r\nConnection: close\r\n\r\ndata").await.unwrap();
                        stream.flush().await.unwrap();
                        true
                    })
                    .await
                    .unwrap()
                });
                let host = if case == 2 { "wrong-test.invalid" } else { "epp-test.invalid" };
                let plan = TransferPlan {
                    provider: Provider::UserOwnedHttp { origin: format!("https://{host}:{}/", peer.port()) },
                    direction: Direction::Download,
                    bytes: 4,
                    streams: 1,
                    timeoutMs: 2000,
                };
                let binding = SourceBinding { source: peer.ip(), peer };
                let context = RequestContext {
                    client: None,
                    plan: &plan,
                    binding: Some(&binding),
                    tlsConfig: if case == 0 { tlsConfig(&plan).unwrap() } else { Some(trusted.clone()) },
                };
                let progress = TransferProgress::default();
                let result = measureStream(&context, 0, Instant::now(), &AtomicBool::new(false), &progress, Bytes::new()).await;
                assert_eq!(progress.activeRequests.load(Ordering::SeqCst), 0);
                let completed = case == 1;
                assert_eq!(server.await.unwrap(), completed);
                assert_eq!(result.status, if completed { TransferStatus::Completed } else { TransferStatus::NetworkError }, "{result:?}");
                assert_eq!(result.acceptedPayloadBytes, if completed { 4 } else { 0 });
                assert_eq!(result.downloadBytesRead, if completed { 4 } else { 0 });
                if !completed {
                    assert!(result.error.as_ref().unwrap().to_lowercase().contains("certificate"), "{result:?}");
                }
                result.tcpInfo.unwrap().validate().unwrap();
            }
        });
    }
}
