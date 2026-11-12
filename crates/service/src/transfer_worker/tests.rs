use super::*;
use epp_core::transfer::{Provider, StreamResult};
use std::{
    io::{BufRead, BufReader, Read},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    thread,
};

pub(super) fn input(peer: SocketAddr, direction: Direction) -> Request {
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

pub(super) fn response(input: &Request) -> Response {
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
fn isolatedRunnerRefusesOrdinaryProgressAndNeverReusesCompletedCounters() {
    use epp_core::transfer::session::BoundTransferRunner;
    let runner = IsolatedTransferRunner::default();
    assert!(runner.snapshot(&TransferProgress::default()).is_err());
    let first = runner.createProgress().unwrap();
    let second = runner.createProgress().unwrap();
    first.downloadBytesRead.store(1, Ordering::SeqCst);
    assert_eq!(runner.snapshot(&first).unwrap().downloadBytesRead, 1);
    assert_eq!(runner.snapshot(&second).unwrap().downloadBytesRead, 0);
    let request = input("127.0.0.1:8080".parse().unwrap(), Direction::Download);
    let error = measureUsingStorage(
        Path::new("not-an-executable"),
        request,
        &AtomicBool::new(false),
        first.storage::<shared::SharedProgress>().unwrap(),
        Instant::now(),
        |_| Ok(()),
    )
    .unwrap_err();
    assert!(error.to_string().contains("cannot be reused"));
}

#[test]
fn rejectsUnrestrictedEntryAndInvalidRequestsBeforeLaunch() {
    assert!(
        run("not-a-length", "not-a-parent", "not-a-progress-handle")
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
        for name in ["owner.pid", "owner.log"] {
            let _ = std::fs::remove_file(self.0.parent().unwrap().join(name));
        }
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_dir(self.0.parent().unwrap());
    }
}

#[test]
#[ignore]
fn parentDeathFixture() {
    let image = PathBuf::from(std::env::var_os("EPP_TRANSFER_WORKER_IMAGE").unwrap());
    assert!(
        image.is_absolute()
            && image
                .file_name()
                .unwrap()
                .eq_ignore_ascii_case("epp-network-service.exe")
    );
    let peer: SocketAddr = std::env::var("EPP_TRANSFER_OWNER_PEER")
        .unwrap()
        .parse()
        .unwrap();
    assert!(peer.ip().is_loopback());
    let mut request = input(peer, Direction::Download);
    request.plan.streams = 1;
    request.plan.timeoutMs = 60_000;
    let mapping = Input::new(&serde_json::to_vec(&request).unwrap()).unwrap();
    let shared = shared::SharedProgress::new().unwrap();
    let progressHandle = shared.inherit().unwrap();
    let child = CommandJob::spawnRestrictedReader(
        &image,
        &[
            "--transfer-worker".into(),
            mapping.length.to_string(),
            std::process::id().to_string(),
            {
                use std::os::windows::io::AsRawHandle;
                (progressHandle.as_raw_handle() as usize).to_string()
            },
        ],
        Some(&mapping.handle),
        Some(&progressHandle),
    )
    .unwrap();
    std::fs::write(
        std::env::var_os("EPP_TRANSFER_OWNER_MARKER").unwrap(),
        child.id().to_string(),
    )
    .unwrap();
    if std::env::var("EPP_TRANSFER_OWNER_STAGE").unwrap() == "running" {
        let result = child.collect(RESULT_BYTES, || Ok(()));
        panic!("restricted worker owner should have been terminated: {result:?}");
    } else {
        thread::sleep(Duration::from_secs(60));
        drop(child);
    }
}

#[test]
#[ignore = "requires a separately built automatic-trials service executable"]
fn isolatedWorkerCannotOutliveItsParentBeforeOrAfterResume() {
    use std::{
        os::windows::{
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
            process::CommandExt,
        },
        process::{Child, Command, Stdio},
    };
    use windows_sys::Win32::{
        Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{
            CREATE_NO_WINDOW, OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        },
    };

    struct Owner(Child);
    impl Drop for Owner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let image = Image::configured();
    let marker = image.0.parent().unwrap().join("owner.pid");
    let diagnostic = image.0.parent().unwrap().join("owner.log");
    for stage in ["suspended", "running"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let output = std::fs::File::create(&diagnostic).unwrap();
        let mut owner = Owner(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "transfer_worker::tests::parentDeathFixture",
                    "--nocapture",
                ])
                .env("EPP_TRANSFER_WORKER_IMAGE", &image.0)
                .env("EPP_TRANSFER_OWNER_MARKER", &marker)
                .env(
                    "EPP_TRANSFER_OWNER_PEER",
                    listener.local_addr().unwrap().to_string(),
                )
                .env("EPP_TRANSFER_OWNER_STAGE", stage)
                .creation_flags(CREATE_NO_WINDOW)
                .stdout(Stdio::from(output.try_clone().unwrap()))
                .stderr(Stdio::from(output))
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let id = loop {
            if let Ok(value) = std::fs::read_to_string(&marker)
                && let Ok(id) = value.parse::<u32>()
            {
                break id;
            }
            assert!(
                Instant::now() < deadline,
                "restricted parent did not become ready"
            );
            let status = owner.0.try_wait().unwrap();
            assert!(
                status.is_none(),
                "restricted parent exited early: {status:?}: {}",
                std::fs::read_to_string(&diagnostic)
                    .unwrap_or_default()
                    .chars()
                    .take(4096)
                    .collect::<String>()
            );
            thread::sleep(Duration::from_millis(10));
        };
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, id) };
        assert!(!handle.is_null());
        let child = unsafe { OwnedHandle::from_raw_handle(handle) };
        assert_eq!(
            unsafe { WaitForSingleObject(child.as_raw_handle(), 0) },
            WAIT_TIMEOUT
        );
        let mut connection = if stage == "running" {
            let mut connection = accept(&listener);
            let mut bytes = [0; 4096];
            let count = connection.read(&mut bytes).unwrap();
            assert!(count > 0 && bytes[..count].starts_with(b"GET "));
            Some(connection)
        } else {
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            None
        };
        owner.0.kill().unwrap();
        owner.0.wait().unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(child.as_raw_handle(), 5000) },
            WAIT_OBJECT_0,
            "{stage}"
        );
        if let Some(connection) = &mut connection {
            let mut bytes = [0; 4096];
            match connection.read(&mut bytes) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                outcome => panic!("restricted orphan socket remained active: {outcome:?}"),
            }
        }
        std::fs::remove_file(&marker).unwrap();
        std::fs::remove_file(&diagnostic).unwrap();
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
    serveControlled(listener, direction, None)
}

fn serveControlled(
    listener: TcpListener,
    direction: Direction,
    gate: Option<std::sync::mpsc::Receiver<()>>,
) -> thread::JoinHandle<u64> {
    listener.set_nonblocking(true).unwrap();
    thread::spawn(move || {
        let mut total = 0;
        for index in 0..2 {
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
            if index == 0
                && direction == Direction::Upload
                && let Some(gate) = &gate
            {
                gate.recv_timeout(Duration::from_secs(2)).unwrap();
            }
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nX-Epp-Benchmark-Protocol: 1\r\nX-Epp-Received-Bytes: {bytes}\r\nConnection: close\r\n\r\n").unwrap();
            if length > 0 {
                let prefix = if index == 0 && gate.is_some() {
                    1024
                } else {
                    length
                };
                stream.write_all(&vec![b'X'; prefix]).unwrap();
                stream.flush().unwrap();
                if prefix < length {
                    gate.as_ref()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(2))
                        .unwrap();
                    stream.write_all(&vec![b'X'; length - prefix]).unwrap();
                }
            }
            total += bytes as u64;
        }
        total
    })
}

#[test]
#[ignore = "requires a separately built automatic-trials service executable"]
fn isolatedWorkerSharedCountersAdvanceWhileFrameConsumerIsBlocked() {
    let image = Image::configured();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let request = input(listener.local_addr().unwrap(), Direction::Download);
    let shared = shared::SharedProgress::new().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let server = serveControlled(listener, Direction::Download, Some(receiver));
    let mut blocked = false;
    let result = measureUsingStorage(
        &image.0,
        request,
        &AtomicBool::new(false),
        &shared,
        Instant::now(),
        |update| {
            if !blocked
                && update.observation.counters.downloadBytesRead > 0
                && update.observation.counters.downloadBytesRead < 4097
            {
                blocked = true;
                sender.send(()).unwrap();
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    let counters = shared.read()?;
                    if counters.downloadBytesRead == 4097 && counters.activeRequests == 0 {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "shared counters depended on pipe consumption"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
                assert!(
                    update.observation.counters.downloadBytesRead
                        < shared.read()?.downloadBytesRead
                );
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(blocked);
    assert_eq!(result.status, TransferStatus::Completed);
    assert_eq!(server.join().unwrap(), 4097);
}

#[test]
#[ignore = "requires a separately built automatic-trials service executable"]
fn isolatedWorkerSessionReadsLiveCountersAtProbeBoundaries() {
    use epp_core::{
        benchmark::{Endpoint, ProbeProtocol, SourceBinding as EchoBinding},
        config::Config,
        icmp::EchoTarget,
        transfer::session::{self, Phase, SessionPlan, SourceBindings, TransferExecution},
    };
    let image = Image::configured();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let request = input(listener.local_addr().unwrap(), Direction::Download);
    let (downloadSender, downloadReceiver) = std::sync::mpsc::channel();
    let (uploadSender, uploadReceiver) = std::sync::mpsc::channel();
    let server = thread::spawn(move || {
        for (direction, receiver) in [
            (Direction::Download, downloadReceiver),
            (Direction::Upload, uploadReceiver),
        ] {
            assert_eq!(
                serveControlled(listener.try_clone().unwrap(), direction, Some(receiver))
                    .join()
                    .unwrap(),
                4097
            );
        }
    });
    let runner = IsolatedTransferRunner {
        image: Some(image.0.clone()),
    };
    let mut released = [false; 2];
    let run = session::runSourceBoundSessionWithRunner(
        Config::default(),
        SessionPlan {
            providers: vec![request.plan.provider],
            downloadBytesPerProvider: 4097,
            uploadBytesPerProvider: 4097,
            streams: 2,
            phaseTimeoutMs: 3000,
            idleRounds: 3,
            intervalMs: 250,
            probeTimeoutMs: 100,
            latencyEndpoints: ["127.0.0.1", "::1"]
                .into_iter()
                .enumerate()
                .map(|(index, address)| Endpoint {
                    id: format!("loopback-{index}"),
                    address: address.into(),
                    protocol: ProbeProtocol::IcmpEcho,
                    dnsQuery: None,
                })
                .collect(),
        },
        SourceBindings {
            transfers: vec![request.binding],
            latency: ["127.0.0.1", "::1"]
                .into_iter()
                .enumerate()
                .map(|(index, address)| EchoBinding {
                    endpointId: format!("loopback-{index}"),
                    source: EchoTarget::parse(address).unwrap(),
                })
                .collect(),
        },
        &AtomicBool::new(false),
        |update| {
            if let Some(sample) = update.sample
                && matches!(sample.phase, Phase::Download | Phase::Upload)
                && sample.inFlightRequestsAtStart > 0
                && sample.inFlightRequestsAtEnd > 0
            {
                let index = usize::from(sample.phase == Phase::Upload);
                if !released[index] {
                    released[index] = true;
                    if index == 0 {
                        downloadSender.send(()).unwrap();
                    } else {
                        uploadSender.send(()).unwrap();
                    }
                }
            }
        },
        &runner,
    )
    .unwrap();
    server.join().unwrap();
    assert_eq!(run.status, "completed", "{:?}", run.transfers);
    assert_eq!(released, [true, true]);
    assert_eq!(
        run.transferExecution,
        Some(TransferExecution::RestrictedWorkerV1)
    );
    for phase in [Phase::Download, Phase::Upload] {
        assert!(run.latencySamples.iter().any(|sample| sample.phase == phase
            && sample.inFlightRequestsAtStart > 0
            && sample.inFlightRequestsAtEnd > 0));
    }
    let restored: session::SessionRun =
        serde_json::from_str(&serde_json::to_string(&run).unwrap()).unwrap();
    assert_eq!(restored.transferExecution, run.transferExecution);
}

#[test]
#[ignore = "requires a separately built automatic-trials service executable"]
fn isolatedWorkerReportsChangedCountersBeforeTransferCompletion() {
    let image = Image::configured();
    for direction in [Direction::Download, Direction::Upload] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let request = input(listener.local_addr().unwrap(), direction);
        let (sender, receiver) = std::sync::mpsc::channel();
        let server = serveControlled(listener, direction, Some(receiver));
        let mut live = false;
        let started = Instant::now();
        let result = measureUsingProgress(
            &image.0,
            request.plan,
            request.binding,
            &AtomicBool::new(false),
            |update| {
                assert!(update.receivedAt >= started);
                let counters = update.observation.counters;
                let bytes = if direction == Direction::Download {
                    counters.downloadBytesRead
                } else {
                    counters.uploadBodyBytesProvided
                };
                if !live && counters.activeRequests > 0 && bytes > 0 {
                    if direction == Direction::Download {
                        assert!(bytes < 4097);
                    }
                    live = true;
                    sender.send(()).unwrap();
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(live, "worker reported no live {direction:?} counters");
        assert_eq!(result.status, TransferStatus::Completed);
        assert_eq!(server.join().unwrap(), 4097);
    }
}

#[test]
#[ignore = "requires a separately built automatic-trials service executable"]
fn isolatedWorkerStopsBeforeReturningARefusedOrPanickingProgressConsumer() {
    let image = Image::configured();
    for panic in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut request = input(listener.local_addr().unwrap(), Direction::Download);
        request.plan.streams = 1;
        let server = thread::spawn(move || {
            let mut stream = accept(&listener);
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut size = 0;
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                size += line.len();
                assert!(size <= 8192);
                if line == "\r\n" {
                    break;
                }
            }
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4097\r\nX-Epp-Benchmark-Protocol: 1\r\nConnection: close\r\n\r\n").unwrap();
            stream.write_all(&[b'X'; 1024]).unwrap();
            stream.flush().unwrap();
            match stream.read(&mut [0; 1]) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                outcome => panic!("refused consumer left worker traffic alive: {outcome:?}"),
            }
        });
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            measureUsingProgress(
                &image.0,
                request.plan,
                request.binding,
                &AtomicBool::new(false),
                |update| {
                    if update.observation.counters.activeRequests > 0
                        && update.observation.counters.downloadBytesRead > 0
                    {
                        assert!(!panic, "fixture progress consumer panic");
                        return Err("fixture progress consumer refused".into());
                    }
                    Ok(())
                },
            )
        }));
        if panic {
            assert!(outcome.is_err());
        } else {
            assert!(
                outcome
                    .unwrap()
                    .unwrap_err()
                    .to_string()
                    .contains("consumer refused")
            );
        }
        server.join().unwrap();
    }
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
