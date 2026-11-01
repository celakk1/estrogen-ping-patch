pub(super) use crate::owned_process::{CommandJob, ensureStopped, waitForIdentity};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owned_process::{QUIESCENCE_UNKNOWN, commandLine, processIdentity};
    use std::{
        os::windows::io::AsRawHandle,
        path::Path,
        sync::atomic::Ordering,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::WAIT_TIMEOUT,
        System::Threading::{CREATE_NO_WINDOW, WaitForSingleObject},
    };

    #[test]
    fn predecessorWaitUsesCreationTimeAndNeverTerminatesAReusedPid() {
        let child =
            CommandJob::spawn(&std::env::current_exe().unwrap(), &["--list".into()]).unwrap();
        let identity = processIdentity(child.process.as_raw_handle(), child.processId).unwrap();
        assert!(waitForIdentity(&identity, Duration::from_millis(10)).is_err());
        let mut reused = identity.clone();
        reused.creationTime100ns =
            (identity.creationTime100ns.parse::<u64>().unwrap() + 1).to_string();
        waitForIdentity(&reused, Duration::from_millis(10)).unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(child.process.as_raw_handle(), 0) },
            WAIT_TIMEOUT
        );
        drop(child);
        waitForIdentity(&identity, Duration::from_millis(10)).unwrap();
    }

    #[test]
    #[ignore]
    fn jobProcessLimitFixture() {
        let error = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .spawn()
            .unwrap_err();
        assert_eq!(
            error.raw_os_error(),
            Some(windows_sys::Win32::Foundation::ERROR_NOT_ENOUGH_QUOTA as i32)
        );
    }

    #[test]
    fn settingCommandCannotCreateOrdinaryDescendants() {
        let child = CommandJob::spawn(
            &std::env::current_exe().unwrap(),
            &[
                "--ignored".into(),
                "--exact".into(),
                "mtu::windows::write::command::tests::jobProcessLimitFixture".into(),
            ],
        )
        .unwrap();
        let mut registered = None;
        child
            .finish(
                &mut |identity| {
                    registered = Some(identity);
                    Ok(())
                },
                &mut || Ok(()),
                || Ok(()),
            )
            .unwrap();
        registered.unwrap().validate().unwrap();
    }

    #[test]
    fn singleProcessCommandCanReadInterfaceStatus() {
        let child = CommandJob::spawn(
            &super::super::executable().unwrap(),
            &[
                "interface".into(),
                "ipv4".into(),
                "show".into(),
                "subinterfaces".into(),
            ],
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        child
            .finish(&mut |_| Ok(()), &mut || Ok(()), || {
                if Instant::now() < deadline {
                    Ok(())
                } else {
                    Err("test read-only command deadline".into())
                }
            })
            .unwrap();
    }

    #[test]
    #[ignore]
    fn writesExecutionMarker() {
        std::fs::write(
            std::env::var_os("EPP_MUTATOR_START_MARKER").unwrap(),
            "started",
        )
        .unwrap();
    }

    #[test]
    #[ignore]
    fn preExecutionFailureFixture() {
        let marker = Path::new(&std::env::var_os("EPP_MUTATOR_START_MARKER").unwrap()).to_owned();
        for failure in ["registration", "target", "none"] {
            let child = CommandJob::spawn(
                &std::env::current_exe().unwrap(),
                &[
                    "--ignored".into(),
                    "--exact".into(),
                    "mtu::windows::write::command::tests::writesExecutionMarker".into(),
                ],
            )
            .unwrap();
            let mut registered = false;
            let result = child.finish(
                &mut |_| {
                    if failure == "registration" {
                        return Err("test registration commit failed".into());
                    }
                    registered = true;
                    Ok(())
                },
                &mut || {
                    if failure == "target" {
                        Err("test target changed".into())
                    } else {
                        Ok(())
                    }
                },
                || Ok(()),
            );
            if failure == "none" {
                result.unwrap();
                assert!(registered && marker.is_file());
                std::fs::remove_file(&marker).unwrap();
            } else {
                assert!(result.unwrap_err().to_string().contains(failure));
                assert_eq!(registered, failure == "target");
                assert!(!marker.exists());
            }
        }
    }

    #[test]
    fn preExecutionFailuresNeverResumeTheSettingProcess() {
        use std::os::windows::process::CommandExt;
        let directory =
            std::env::temp_dir().join(format!("epp-mutator-start-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let marker = directory.join("started");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "mtu::windows::write::command::tests::preExecutionFailureFixture",
            ])
            .env("EPP_MUTATOR_START_MARKER", &marker)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .unwrap();
        let started = marker.exists();
        if started {
            std::fs::remove_file(marker).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!started);
    }

    #[test]
    fn generatedCommandLineQuotesOnlyTheExecutableAndRejectsUnstructuredArguments() {
        let executable = Path::new("C:\\Windows tools\\System32\\netsh.exe");
        let (application, line) =
            commandLine(executable, &["interface".into(), "mtu=1400".into()]).unwrap();
        assert_eq!(application.last(), Some(&0));
        assert_eq!(line.last(), Some(&0));
        assert_eq!(
            String::from_utf16(&line[..line.len() - 1]).unwrap(),
            "\"C:\\Windows tools\\System32\\netsh.exe\" interface mtu=1400"
        );
        for argument in [
            "x y", "x\ty", "x\ny", "x&y", "x|y", "x;y", "x\"y", "x\0y", "", "\\",
        ] {
            assert!(commandLine(executable, &[argument.into()]).is_err());
        }
        for executable in [
            "netsh.exe",
            "C:\\Windows\\netsh.cmd",
            "C:\\Windows\\bad\"name.exe",
            "C:\\Windows\\bad\0name.exe",
        ] {
            assert!(commandLine(Path::new(executable), &["interface".into()]).is_err());
        }
    }

    #[test]
    #[ignore]
    fn quiescenceFailureFixture() {
        QUIESCENCE_UNKNOWN.store(true, Ordering::SeqCst);
        assert!(crate::mtu::ensureLabCommandStopped().is_err());
        let error = CommandJob::spawn(&std::env::current_exe().unwrap(), &["--list".into()])
            .err()
            .unwrap();
        assert!(
            error
                .to_string()
                .contains("termination could not be verified")
        );
    }

    #[test]
    fn terminationUncertaintyBlocksNewCommandsForTheWholeServiceInstance() {
        use std::os::windows::process::CommandExt;
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "mtu::windows::write::command::tests::quiescenceFailureFixture",
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        ensureStopped().unwrap();
    }
}
