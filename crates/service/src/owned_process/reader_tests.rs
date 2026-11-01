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
fn readerOwnerFixture() {
    let marker = std::env::var_os("EPP_READER_OWNER_MARKER").unwrap();
    let child = fixture("waits");
    if std::env::var("EPP_READER_OWNER_STAGE").unwrap() == "running" {
        assert_eq!(unsafe { ResumeThread(child.thread.as_raw_handle()) }, 1);
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
                .stdout(Stdio::null())
                .stderr(Stdio::null())
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
            assert!(
                owner.0.try_wait().unwrap().is_none(),
                "reader owner exited before readiness"
            );
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
