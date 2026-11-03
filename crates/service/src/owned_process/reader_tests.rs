use super::*;
use std::io::Write;

fn fixture(name: &str) -> CommandJob {
    let child = CommandJob::spawnReader(
        &std::env::current_exe().unwrap(),
        &[
            "--ignored".into(),
            "--exact".into(),
            format!("owned_process::reader_tests::{name}"),
            "--nocapture".into(),
        ],
    )
    .unwrap();
    assert!(child.assigned());
    assert!(child.id() > 0);
    child
}

#[test]
fn unexpectedResumeCountReportsTheObservedProcessAndThreadState() {
    let child = fixture("waits");
    child.resume("test initial resume").unwrap();
    let error = child
        .resume("test repeated resume")
        .unwrap_err()
        .to_string();
    assert!(error.contains("previous suspend count 0"), "{error}");
    assert!(error.contains("process exit true:0x00000103"), "{error}");
    assert!(error.contains("thread exit true:"), "{error}");
}

fn within(deadline: Instant) -> ServiceResult<()> {
    if Instant::now() >= deadline {
        Err("test worker deadline".into())
    } else {
        Ok(())
    }
}

#[test]
#[ignore]
fn writesOutput() {
    std::io::stdout().write_all(&vec![b'Q'; 6000]).unwrap();
    println!("bounded-worker-output");
}

#[test]
#[ignore]
fn writesLargeReport() {
    std::io::stdout()
        .write_all(&vec![0xa5; 2 * 1024 * 1024])
        .unwrap();
}

#[test]
#[ignore]
fn streamsBeforeWaiting() {
    println!("streaming-progress-before-exit");
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(60));
}

#[test]
fn streamingDeliversProgressBeforeWorkerExitAndStopsOnConsumerRefusal() {
    let child = fixture("streamsBeforeWaiting");
    let process = child.process.try_clone().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut received = Vec::new();
    let result = child.stream(
        8192,
        || within(deadline),
        |chunk| {
            received.extend_from_slice(chunk);
            if String::from_utf8_lossy(&received).contains("streaming-progress-before-exit") {
                assert_eq!(
                    unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
                    WAIT_TIMEOUT
                );
                return Err("test consumer stopped after real progress".into());
            }
            Ok(())
        },
    );
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("consumer stopped after real progress")
    );
    assert_eq!(
        unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
        WAIT_OBJECT_0
    );
}

#[test]
fn streamingDrainsLargeReportsInBoundedChunksAndConfirmsWorkerExit() {
    let child = fixture("writesLargeReport");
    let process = child.process.try_clone().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut bytes = 0;
    let mut payloadBytes = 0;
    child
        .stream(
            3 * 1024 * 1024,
            || within(deadline),
            |chunk| {
                assert!(!chunk.is_empty() && chunk.len() <= 4096);
                bytes += chunk.len();
                payloadBytes += chunk.iter().filter(|byte| **byte == 0xa5).count();
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(payloadBytes, 2 * 1024 * 1024);
    assert!((payloadBytes..payloadBytes + 4096).contains(&bytes));
    assert_eq!(
        unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
        WAIT_OBJECT_0
    );
}

#[test]
fn streamingBoundsAndCancellationTerminateTheWorkerBeforeReturning() {
    for (name, limit, expected) in [
        ("floodsOutput", 8192, "byte allowance"),
        ("waits", 0, "byte allowance"),
        ("waits", 4 * 1024 * 1024 + 1, "byte allowance"),
        ("waits", 4 * 1024 * 1024, "deadline"),
    ] {
        let child = fixture(name);
        let process = child.process.try_clone().unwrap();
        let deadline =
            Instant::now() + Duration::from_millis(if name == "waits" { 150 } else { 5000 });
        let error = child
            .stream(limit, || within(deadline), |_| Ok(()))
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{name}: {error}");
        assert_eq!(
            unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
            WAIT_OBJECT_0
        );
    }
}

#[test]
fn streamingConsumerPanicsStillStopTheOwnedWorker() {
    let child = fixture("streamsBeforeWaiting");
    let process = child.process.try_clone().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        child.stream(8192, || within(deadline), |_| panic!("test consumer panic"))
    }));
    assert!(result.is_err());
    assert_eq!(
        unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
        WAIT_OBJECT_0
    );
}

#[test]
#[ignore]
fn floodsOutput() {
    loop {
        std::io::stdout().write_all(&[b'X'; 4096]).unwrap();
    }
}

#[test]
#[ignore]
fn waits() {
    std::thread::sleep(Duration::from_secs(60));
}

#[test]
#[ignore]
fn exitsWithFailure() {
    eprintln!("policy-fixture-readable-error");
    std::process::exit(23);
}

#[test]
#[ignore]
fn refusesDescendants() {
    let error = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--list")
        .spawn()
        .unwrap_err();
    assert_eq!(
        error.raw_os_error(),
        Some(windows_sys::Win32::Foundation::ERROR_NOT_ENOUGH_QUOTA as i32)
    );
    println!("descendant-refused");
}

#[test]
fn readerCannotCreateOrdinaryDescendants() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let bytes = fixture("refusesDescendants")
        .collect(8192, || within(deadline))
        .unwrap();
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .contains("descendant-refused")
    );
}

#[test]
#[ignore]
fn readerUncertaintyFixture() {
    let child = fixture("waits");
    child.recordTerminationFailure();
    drop(child);
    assert!(
        CommandJob::spawnReader(&std::env::current_exe().unwrap(), &["--list".into()]).is_err()
    );
    ensureStopped().unwrap();
    #[cfg(feature = "native-mtu-lab")]
    CommandJob::spawn(&std::env::current_exe().unwrap(), &["--list".into()])
        .unwrap()
        .finish(&mut |_| Ok(()), &mut || Ok(()), || Ok(()))
        .unwrap();
}

#[test]
fn uncertainReaderBlocksMoreReadsWithoutBlockingTheRecoveryCommandPath() {
    use std::os::windows::process::CommandExt;
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "owned_process::reader_tests::readerUncertaintyFixture",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    ensureStopped().unwrap();
}

#[test]
#[ignore]
fn readerOwnerFixture() {
    let marker = std::env::var_os("EPP_READER_OWNER_MARKER").unwrap();
    let child = fixture("waits");
    if std::env::var("EPP_READER_OWNER_STAGE").unwrap() == "running" {
        child
            .resume("Cannot resume the reader owner fixture")
            .unwrap();
    }
    std::fs::write(marker, child.id().to_string()).unwrap();
    std::thread::sleep(Duration::from_secs(60));
    drop(child);
}

#[test]
fn readerCannotOutliveItsOwnerEvenBeforeResume() {
    use std::{
        os::windows::process::CommandExt,
        process::{Child, Command, Stdio},
    };
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};

    struct Owner(Child);
    impl Drop for Owner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    for stage in ["suspended", "running"] {
        let directory =
            std::env::temp_dir().join(format!("epp-reader-owner-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let marker = directory.join("reader.pid");
        let diagnostic = directory.join("owner.log");
        let output = std::fs::File::create(&diagnostic).unwrap();
        let mut owner = Owner(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "owned_process::reader_tests::readerOwnerFixture",
                ])
                .env("EPP_READER_OWNER_MARKER", &marker)
                .env("EPP_READER_OWNER_STAGE", stage)
                .creation_flags(CREATE_NO_WINDOW)
                .stdout(Stdio::from(output.try_clone().unwrap()))
                .stderr(Stdio::from(output))
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let processId = loop {
            if let Ok(value) = std::fs::read_to_string(&marker)
                && let Ok(id) = value.parse::<u32>()
            {
                break id;
            }
            assert!(
                Instant::now() < deadline,
                "reader owner did not become ready"
            );
            let status = owner.0.try_wait().unwrap();
            if status.is_some() {
                let detail: String = std::fs::read_to_string(&diagnostic)
                    .unwrap()
                    .chars()
                    .take(4096)
                    .collect();
                panic!("reader owner exited before readiness: {status:?}: {detail}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, processId) };
        assert!(!handle.is_null());
        let reader = unsafe { OwnedHandle::from_raw_handle(handle) };
        assert_eq!(
            unsafe { WaitForSingleObject(reader.as_raw_handle(), 0) },
            WAIT_TIMEOUT
        );
        owner.0.kill().unwrap();
        owner.0.wait().unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(reader.as_raw_handle(), 5000) },
            WAIT_OBJECT_0,
            "{stage}"
        );
        std::fs::remove_file(marker).unwrap();
        std::fs::remove_file(diagnostic).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}

#[test]
fn readerDrainsBeyondThePipeBufferAndConfirmsExitBeforeReturning() {
    let child = fixture("writesOutput");
    let process = child.process.try_clone().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let bytes = child.collect(8192, || within(deadline)).unwrap();
    assert!(bytes.len() >= 6000 && bytes.len() <= 8192);
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .contains("bounded-worker-output")
    );
    assert_eq!(
        unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
        WAIT_OBJECT_0
    );
}

#[test]
fn overflowTimeoutFailureAndInvalidLimitsEndTheOwnedReader() {
    for (name, limit, expected) in [
        ("floodsOutput", 8192, "byte allowance"),
        ("waits", 8192, "deadline"),
        ("exitsWithFailure", 8192, "exit code 23"),
        ("waits", 0, "byte allowance"),
        ("waits", 65537, "byte allowance"),
    ] {
        let child = fixture(name);
        let process = child.process.try_clone().unwrap();
        let deadline =
            Instant::now() + Duration::from_millis(if name == "waits" { 150 } else { 5000 });
        let error = child
            .collect(limit, || within(deadline))
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{name}: {error}");
        if name == "exitsWithFailure" {
            assert!(error.contains("policy-fixture-readable-error"));
        }
        assert_eq!(
            unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
            WAIT_OBJECT_0,
            "{name}"
        );
    }
    ensureStopped().unwrap();
}

#[test]
fn cancellationAfterResumeStopsTheOwnedReaderBeforeReturning() {
    let child = fixture("waits");
    let process = child.process.try_clone().unwrap();
    let cancelled = std::sync::Arc::new(AtomicBool::new(false));
    let request = cancelled.clone();
    let cancellation = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        request.store(true, Ordering::SeqCst);
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = child.collect(65536, || {
        within(deadline)?;
        if cancelled.load(Ordering::SeqCst) {
            Err("test worker cancellation".into())
        } else {
            Ok(())
        }
    });
    cancellation.join().unwrap();
    assert!(result.unwrap_err().to_string().contains("cancellation"));
    assert_eq!(
        unsafe { WaitForSingleObject(process.as_raw_handle(), 0) },
        WAIT_OBJECT_0
    );
    ensureStopped().unwrap();
}
