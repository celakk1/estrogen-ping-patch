use crate::ServiceResult;
use std::{
    ffi::c_void,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr::{null, null_mut},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::{
        JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        },
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList,
            EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList,
            LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, ResumeThread,
            STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

static QUIESCENCE_UNKNOWN: AtomicBool = AtomicBool::new(false);

pub(super) fn ensureStopped() -> ServiceResult<()> {
    if QUIESCENCE_UNKNOWN.load(Ordering::SeqCst) {
        Err("Command termination could not be verified; preserve the checkpoint and restart the lab service before recovery".into())
    } else {
        Ok(())
    }
}

fn succeeded(operation: &str, value: i32) -> ServiceResult<()> {
    if value == 0 {
        Err(format!("{operation} failed: {}", std::io::Error::last_os_error()).into())
    } else {
        Ok(())
    }
}

struct Attributes {
    buffer: Vec<usize>,
    initialized: bool,
}

impl Attributes {
    fn new() -> ServiceResult<Self> {
        let mut bytes = 0;
        let sized = unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes) };
        let error = std::io::Error::last_os_error();
        if sized != 0
            || error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || bytes == 0
            || bytes > 65536
        {
            return Err(format!("Cannot size the command attribute list: {error}").into());
        }
        let mut attributes = Self {
            buffer: vec![0; bytes.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        if unsafe { InitializeProcThreadAttributeList(attributes.pointer(), 2, 0, &mut bytes) } == 0
        {
            let error = std::io::Error::last_os_error();
            return Err(format!("Cannot initialize the command attribute list: {error}").into());
        }
        attributes.initialized = true;
        Ok(attributes)
    }

    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_mut_ptr().cast()
    }

    fn update(
        &mut self,
        attribute: u32,
        values: &[windows_sys::Win32::Foundation::HANDLE],
    ) -> ServiceResult<()> {
        succeeded("UpdateProcThreadAttribute", unsafe {
            UpdateProcThreadAttribute(
                self.pointer(),
                0,
                attribute as usize,
                values.as_ptr().cast(),
                std::mem::size_of_val(values),
                null_mut(),
                null(),
            )
        })
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { DeleteProcThreadAttributeList(self.pointer()) };
        }
    }
}

fn commandLine(executable: &Path, arguments: &[String]) -> ServiceResult<(Vec<u16>, Vec<u16>)> {
    let application: Vec<u16> = executable.as_os_str().encode_wide().collect();
    if !executable.is_absolute()
        || application.contains(&0)
        || application.contains(&(b'"' as u16))
        || !executable
            .extension()
            .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
        || arguments.len() > 16
        || arguments.iter().any(|argument| {
            argument.is_empty()
                || argument.len() > 200
                || !argument
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_=:.".contains(&byte))
        })
    {
        return Err("Command path or generated argument is outside the fixed lab grammar".into());
    }
    let mut line = vec![b'"' as u16];
    line.extend_from_slice(&application);
    line.push(b'"' as u16);
    for argument in arguments {
        line.push(b' ' as u16);
        line.extend(argument.encode_utf16());
    }
    if line.len() >= 32767 {
        return Err("Command line exceeds the Windows limit".into());
    }
    line.push(0);
    let mut application = application;
    application.push(0);
    Ok((application, line))
}

pub(super) struct CommandJob {
    job: OwnedHandle,
    process: OwnedHandle,
    thread: OwnedHandle,
    #[cfg(test)]
    processId: u32,
    cleanupAttempted: bool,
}

impl CommandJob {
    pub(super) fn spawn(executable: &Path, arguments: &[String]) -> ServiceResult<Self> {
        ensureStopped()?;
        let (application, mut line) = commandLine(executable, arguments)?;
        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let job = unsafe { OwnedHandle::from_raw_handle(job) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        succeeded("SetInformationJobObject", unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        })?;
        let inheritable = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1,
        };
        let nullFile = unsafe {
            CreateFileW(
                windows_sys::core::w!("\\\\.\\NUL"),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &inheritable,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if nullFile == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }
        let nullFile = unsafe { OwnedHandle::from_raw_handle(nullFile) };
        let jobs = [job.as_raw_handle()];
        let inherited = [nullFile.as_raw_handle()];
        let mut attributes = Attributes::new()?;
        // assigning the job after spawning would leave a service-crash window.
        attributes.update(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
        // inheriting the job handle would keep it alive after the service exits.
        attributes.update(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = nullFile.as_raw_handle();
        startup.StartupInfo.hStdOutput = nullFile.as_raw_handle();
        startup.StartupInfo.hStdError = nullFile.as_raw_handle();
        startup.lpAttributeList = attributes.pointer();
        let mut created = PROCESS_INFORMATION::default();
        succeeded("CreateProcessW", unsafe {
            CreateProcessW(
                application.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                1,
                CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                null(),
                null(),
                &startup.StartupInfo,
                &mut created,
            )
        })?;
        Ok(Self {
            job,
            process: unsafe { OwnedHandle::from_raw_handle(created.hProcess) },
            thread: unsafe { OwnedHandle::from_raw_handle(created.hThread) },
            #[cfg(test)]
            processId: created.dwProcessId,
            cleanupAttempted: false,
        })
    }

    #[cfg(test)]
    pub(super) fn id(&self) -> u32 {
        self.processId
    }

    #[cfg(test)]
    pub(super) fn assigned(&self) -> bool {
        let mut assigned = 0;
        unsafe {
            windows_sys::Win32::System::JobObjects::IsProcessInJob(
                self.process.as_raw_handle(),
                self.job.as_raw_handle(),
                &mut assigned,
            ) != 0
                && assigned != 0
        }
    }

    fn terminate(&mut self) -> ServiceResult<()> {
        self.cleanupAttempted = true;
        let result = (|| {
            let terminated = unsafe { TerminateJobObject(self.job.as_raw_handle(), 1) };
            let terminateError = std::io::Error::last_os_error();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
                succeeded("QueryInformationJobObject", unsafe {
                    QueryInformationJobObject(
                        self.job.as_raw_handle(),
                        JobObjectBasicAccountingInformation,
                        (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)
                            .cast::<c_void>(),
                        size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                        null_mut(),
                    )
                })?;
                // process signaling also confirms that pending process io has finished or canceled.
                let processState = unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) };
                if processState != WAIT_OBJECT_0 && processState != WAIT_TIMEOUT {
                    return Err(std::io::Error::last_os_error().into());
                }
                if accounting.ActiveProcesses == 0 && processState == WAIT_OBJECT_0 {
                    return Ok(());
                }
                if terminated == 0 {
                    return Err(format!("Cannot stop command job: {terminateError}").into());
                }
                if Instant::now() >= deadline {
                    return Err(
                        "Command job termination was not confirmed within five seconds".into(),
                    );
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        if result.is_err() {
            QUIESCENCE_UNKNOWN.store(true, Ordering::SeqCst);
        }
        result
    }

    pub(super) fn finish(
        mut self,
        mut check: impl FnMut() -> ServiceResult<()>,
    ) -> ServiceResult<()> {
        let outcome = (|| {
            check()?;
            if unsafe { ResumeThread(self.thread.as_raw_handle()) } != 1 {
                return Err("Cannot resume the owned command thread exactly once".into());
            }
            loop {
                check()?;
                match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 20) } {
                    WAIT_TIMEOUT => continue,
                    WAIT_OBJECT_0 => {
                        let mut exitCode = 0;
                        succeeded("GetExitCodeProcess", unsafe {
                            GetExitCodeProcess(self.process.as_raw_handle(), &mut exitCode)
                        })?;
                        return if exitCode == 0 {
                            Ok(())
                        } else {
                            Err(format!("Windows MTU command failed: exit code {exitCode}").into())
                        };
                    }
                    _ => return Err(std::io::Error::last_os_error().into()),
                }
            }
        })();
        self.terminate()?;
        outcome
    }
}

impl Drop for CommandJob {
    fn drop(&mut self) {
        if !self.cleanupAttempted {
            let _ = self.terminate();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
