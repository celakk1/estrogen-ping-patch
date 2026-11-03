use super::*;
use epp_core::transfer::{Provider, StreamResult};
use std::{
    io::{BufRead, BufReader, Read},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    thread,
};

fn input(peer: SocketAddr, direction: Direction) -> Request {
    Request {
        schemaVersion: SCHEMA_VERSION,
        plan: TransferPlan {
            provider: Provider::UserOwnedHttp {
                origin: format!("http://{peer}/"),
            },
            direction,
            bytes: 4097,
            streams: 2,
            timeoutMs: 3000,
        },
        binding: SourceBinding {
            source: peer.ip(),
            peer,
        },
    }
}

fn response(input: &Request) -> Response {
    Response {
        schemaVersion: SCHEMA_VERSION,
        result: TransferResult {
            plan: input.plan.clone(),
            provider: input.plan.provider.info().unwrap(),
            startedAt: "2026-11-03T12:00:00Z".into(),
            finishedAt: "2026-11-03T12:00:01Z".into(),
            elapsedMs: 1000.0,
            status: TransferStatus::Completed,
            acceptedPayloadBytes: 4097,
            applicationGoodputMbps: Some(4097.0 * 8.0 / 1_000_000.0),
            sourceBinding: Some(input.binding),
            streams: (0..2)
                .map(|ordinal| {
                    let requestedBytes = if ordinal == 0 { 2049 } else { 2048 };
                    StreamResult {
                        ordinal,
                        requestedBytes,
                        downloadBytesRead: requestedBytes,
                        uploadBodyBytesProvided: 0,
                        acceptedPayloadBytes: requestedBytes,
                        elapsedMs: 999.0,
                        status: TransferStatus::Completed,
                        httpStatus: Some(200),
                        remoteAddress: Some(input.binding.peer.to_string()),
                        retryAfter: None,
                        error: None,
                    }
                })
                .collect(),
        },
    }
}

#[test]
fn rejectsUnrestrictedEntryAndInvalidRequestsBeforeLaunch() {
    assert!(
        run("not-a-length")
            .unwrap_err()
            .to_string()
            .contains("restricted token")
    );
    assert!(Input::new(&[]).is_err());
    assert!(Input::new(&vec![0; request::MAX_BYTES + 1]).is_err());
    let mut request = input("127.0.0.1:8080".parse().unwrap(), Direction::Download);
    request.schemaVersion += 1;
    assert!(request.validate().is_err());
    request.schemaVersion = SCHEMA_VERSION;
    request.binding.peer.set_port(8081);
    assert!(request.validate().is_err());
    let cancelled = AtomicBool::new(true);
    let request = input("127.0.0.1:8080".parse().unwrap(), Direction::Download);
    assert!(
        measureUsing(
            Path::new("C:/unavailable-worker.exe"),
            request.plan,
            request.binding,
            &cancelled
        )
        .unwrap_err()
        .to_string()
        .contains("cancelled")
    );
}

#[test]
fn rejectsResultIdentityCountersStreamsAndSummaryDrift() {
    let request = input("127.0.0.1:8080".parse().unwrap(), Direction::Download);
    let result = response(&request);
    validateResult(&request, &result).unwrap();
    let mut changes: Vec<Response> = (0..15)
        .map(|_| serde_json::from_slice(&serde_json::to_vec(&result).unwrap()).unwrap())
        .collect();
    changes[0].schemaVersion += 1;
    changes[1].result.plan.bytes += 1;
    changes[2].result.provider.origin = "http://127.0.0.1:8081/".into();
    changes[3].result.sourceBinding = None;
    changes[4].result.streams.pop();
    changes[5].result.streams[0].ordinal = 1;
    changes[6].result.streams[0].requestedBytes += 1;
    changes[7].result.streams[0].downloadBytesRead += 1;
    changes[8].result.streams[0].uploadBodyBytesProvided = 1;
    changes[9].result.streams[0].acceptedPayloadBytes -= 1;
    changes[10].result.streams[0].remoteAddress = Some("127.0.0.1:8081".into());
    changes[11].result.streams[0].httpStatus = Some(206);
    changes[12].result.streams[0].elapsedMs = f64::NAN;
    changes[13].result.applicationGoodputMbps = Some(99.0);
    changes[14].result.acceptedPayloadBytes += 1;
    for (index, result) in changes.iter().enumerate() {
        assert!(
            validateResult(&request, result).is_err(),
            "accepted drift {index}"
        );
    }
}

#[test]
fn rejectsUnknownMissingTrailingAndInvalidResultData() {
    let request = input("127.0.0.1:8080".parse().unwrap(), Direction::Download);
    let response = response(&request);
    let original = serde_json::to_value(response).unwrap();
    parseResult(&request, &serde_json::to_vec(&original).unwrap()).unwrap();
    let mut value = original.clone();
    value["result"]["streams"][0]["extra"] = true.into();
    assert!(parseResult(&request, &serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = original.clone();
    value["result"]["streams"][0]
        .as_object_mut()
        .unwrap()
        .remove("retryAfter");
    assert!(parseResult(&request, &serde_json::to_vec(&value).unwrap()).is_err());
    for finished in ["not-a-date", "2026-11-03T11:59:59Z", "2026-11-03T12:01:00Z"] {
        let mut value = original.clone();
        value["result"]["finishedAt"] = finished.into();
        assert!(parseResult(&request, &serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut bytes = serde_json::to_vec(&original).unwrap();
    bytes.extend_from_slice(b"{}");
    assert!(parseResult(&request, &bytes).is_err());
    assert!(parseResult(&request, &vec![b' '; RESULT_BYTES + 1]).is_err());
}

struct Image(PathBuf);

impl Image {
    fn configured() -> Self {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::{
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW,
        };
        let source = PathBuf::from(std::env::var_os("EPP_TRANSFER_WORKER_IMAGE").expect(
            "set EPP_TRANSFER_WORKER_IMAGE to the separately built automatic-trials service image",
        ));
        assert!(
            source.is_absolute()
                && source
                    .file_name()
                    .unwrap()
                    .eq_ignore_ascii_case("epp-network-service.exe")
        );
        let directory = std::env::temp_dir().join(format!("epp worker {}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let image = directory.join("epp-network-service.exe");
        std::fs::copy(source, &image).unwrap();
        let owner = crate::security::currentSid().unwrap();
        let descriptor = crate::security::Descriptor::testObject(&format!(
            "D:P(A;;FA;;;{owner})(A;;FRFX;;;AU)(A;;RC;;;OW)"
        ))
        .unwrap();
        for path in [&directory, &image] {
            let path: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            assert_ne!(
                unsafe {
                    SetFileSecurityW(
                        path.as_ptr(),
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        descriptor.attributes().lpSecurityDescriptor,
                    )
                },
                0
            );
        }
        Self(image)
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_dir(self.0.parent().unwrap());
    }
}

fn accept(listener: &TcpListener) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                return stream;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5))
            }
            Err(error) => panic!("worker did not connect: {error}"),
        }
    }
}

fn serve(listener: TcpListener, direction: Direction) -> thread::JoinHandle<u64> {
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let mut total = 0;
        for _ in 0..2 {
            let stream = accept(&listener);
            assert_eq!(
                stream.peer_addr().unwrap().ip(),
                listener.local_addr().unwrap().ip()
            );
            let mut reader = BufReader::new(stream);
            let mut headers = String::new();
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                headers.push_str(&line);
                assert!(headers.len() <= 8192);
                if line == "\r\n" {
                    break;
                }
            }
            let bytes = if direction == Direction::Download {
                assert!(headers.starts_with("GET /epp/v1/download?bytes="));
                headers
                    .split("bytes=")
                    .nth(1)
                    .unwrap()
                    .split(' ')
                    .next()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
            } else {
                assert!(headers.starts_with("POST /epp/v1/upload "));
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .map(str::to_owned)
                    })
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                assert!(length <= 4097);
                reader.read_exact(&mut vec![0; length]).unwrap();
                length
            };
            assert!(bytes == 2048 || bytes == 2049);
            let stream = reader.get_mut();
            let length = if direction == Direction::Download {
                bytes
            } else {
                0
            };
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nX-Epp-Benchmark-Protocol: 1\r\nX-Epp-Received-Bytes: {bytes}\r\nConnection: close\r\n\r\n").unwrap();
            if length > 0 {
                stream.write_all(&vec![b'X'; length]).unwrap();
            }
            total += bytes as u64;
        }
        total
    })
}

#[test]
#[ignore = "requires a separately built automatic-trials service executable"]
fn isolatedWorkerTransfersOverIpv4AndIpv6WithoutAServiceInstall() {
    let image = Image::configured();
    for address in ["127.0.0.1:0", "[::1]:0"] {
        for direction in [Direction::Download, Direction::Upload] {
            let listener = TcpListener::bind(address).unwrap();
            let request = input(listener.local_addr().unwrap(), direction);
            let server = serve(listener, direction);
            let result = measureUsing(
                &image.0,
                request.plan,
                request.binding,
                &AtomicBool::new(false),
            )
            .unwrap();
            assert_eq!(result.status, TransferStatus::Completed);
            assert_eq!(result.acceptedPayloadBytes, 4097);
            assert_eq!(server.join().unwrap(), 4097);
        }
    }
}

#[test]
#[ignore = "requires a separately built automatic-trials service executable"]
fn isolatedWorkerStopsStalledTrafficOnDeadlineAndCancellation() {
    let image = Image::configured();
    for cancel in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut request = input(listener.local_addr().unwrap(), Direction::Download);
        request.plan.streams = 1;
        request.plan.timeoutMs = if cancel { 3000 } else { 500 };
        let cancelled = AtomicBool::new(false);
        thread::scope(|scope| {
            let cancelledRef = &cancelled;
            let server = scope.spawn(move || {
                let mut stream = accept(&listener);
                let mut bytes = [0; 4096];
                let mut received = 0;
                loop {
                    let count = match stream.read(&mut bytes) {
                        Ok(count) => count,
                        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                        Err(error) => panic!("stalled worker socket did not close: {error}"),
                    };
                    if count == 0 {
                        break;
                    }
                    received += count;
                    if cancel {
                        cancelledRef.store(true, Ordering::SeqCst);
                    }
                    assert!(received < 8192);
                }
                assert!(received > 0);
            });
            let start = Instant::now();
            let error = measureUsing(&image.0, request.plan, request.binding, &cancelled)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(if cancel { "cancelled" } else { "deadline" }),
                "{error}"
            );
            assert!(start.elapsed() < Duration::from_secs(4));
            server.join().unwrap();
        });
    }
}
