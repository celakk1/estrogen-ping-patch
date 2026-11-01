use crate::ServiceResult;
#[cfg(feature = "native-mtu-lab")]
use crate::journal::MutatorIdentity;
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
        ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, GENERIC_READ, GENERIC_WRITE,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        ReadFile,
    },
    System::{
        JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
            QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        },
        Pipes::{CreatePipe, PeekNamedPipe},
        Threading::{
            CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList,
            EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, InitializeProcThreadAttributeList,
            LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION, ResumeThread,
            STARTF_USESTDHANDLES, STARTUPINFOEXW, UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};
#[cfg(feature = "native-mtu-lab")]
use windows_sys::Win32::{
    Foundation::{ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, FILETIME},
    System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    },
};

pub(crate) static QUIESCENCE_UNKNOWN: AtomicBool = AtomicBool::new(false);
static READER_QUIESCENCE_UNKNOWN: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, PartialEq)]
enum ProcessRole {
    ReadOnly,
    #[cfg(feature = "native-mtu-lab")]
    Setting,
}

pub(crate) fn ensureStopped() -> ServiceResult<()> {
    if QUIESCENCE_UNKNOWN.load(Ordering::SeqCst) {
        Err("Owned process termination could not be verified; preserve the checkpoint and restart the service before recovery".into())
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
    fn new(count: u32) -> ServiceResult<Self> {
        let mut bytes = 0;
        let sized = unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut bytes) };
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
        if unsafe { InitializeProcThreadAttributeList(attributes.pointer(), count, 0, &mut bytes) }
            == 0
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

    fn update<T>(&mut self, attribute: u32, values: &[T]) -> ServiceResult<()> {
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

pub(crate) fn commandLine(
    executable: &Path,
    arguments: &[String],
) -> ServiceResult<(Vec<u16>, Vec<u16>)> {
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
        return Err(
            "Command path or generated argument is outside the fixed process grammar".into(),
        );
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

pub(crate) struct CommandJob {
    job: OwnedHandle,
    pub(crate) process: OwnedHandle,
    thread: OwnedHandle,
    pub(crate) processId: u32,
    output: Option<OwnedHandle>,
    role: ProcessRole,
    cleanupAttempted: bool,
}

impl CommandJob {
    #[cfg(feature = "native-mtu-lab")]
    pub(crate) fn spawn(executable: &Path, arguments: &[String]) -> ServiceResult<Self> {
        Self::create(executable, arguments, false, ProcessRole::Setting)
    }

    pub(crate) fn spawnReader(executable: &Path, arguments: &[String]) -> ServiceResult<Self> {
        Self::create(executable, arguments, false, ProcessRole::ReadOnly)
    }

    #[cfg(all(test, feature = "native-mtu-lab"))]
    pub(crate) fn spawnFixture(executable: &Path, arguments: &[String]) -> ServiceResult<Self> {
        Self::create(executable, arguments, true, ProcessRole::Setting)
    }

    fn create(
        executable: &Path,
        arguments: &[String],
        allowChildren: bool,
        role: ProcessRole,
    ) -> ServiceResult<Self> {
        ensureStopped()?;
        if role == ProcessRole::ReadOnly && READER_QUIESCENCE_UNKNOWN.load(Ordering::SeqCst) {
            return Err("Reader termination could not be verified; further policy reads require a service restart, while MTU recovery remains available".into());
        }
        let (application, mut line) = commandLine(executable, arguments)?;
        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let job = unsafe { OwnedHandle::from_raw_handle(job) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if !allowChildren {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = 1;
        }
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
        let (output, writer) = if role == ProcessRole::ReadOnly {
            let mut reader = null_mut();
            let mut writer = null_mut();
            succeeded("CreatePipe", unsafe {
                CreatePipe(&mut reader, &mut writer, &inheritable, 4096)
            })?;
            (
                Some(unsafe { OwnedHandle::from_raw_handle(reader) }),
                Some(unsafe { OwnedHandle::from_raw_handle(writer) }),
            )
        } else {
            (None, None)
        };
        let stdout = writer.as_ref().unwrap_or(&nullFile).as_raw_handle();
        let jobs = [job.as_raw_handle()];
        let mut inherited = vec![nullFile.as_raw_handle()];
        if writer.is_some() {
            inherited.push(stdout);
        }
        let mut attributes = Attributes::new(2)?;
        // assigning the job after spawning would leave a service-crash window.
        attributes.update(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
        // inheriting the job handle would keep it alive after the service exits.
        attributes.update(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &inherited)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = nullFile.as_raw_handle();
        startup.StartupInfo.hStdOutput = stdout;
        startup.StartupInfo.hStdError = if role == ProcessRole::ReadOnly {
            stdout
        } else {
            nullFile.as_raw_handle()
        };
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
            processId: created.dwProcessId,
            output,
            role,
            cleanupAttempted: false,
        })
    }

    fn readAvailable(&self, bytes: &mut Vec<u8>, limit: usize) -> ServiceResult<bool> {
        let reader = self
            .output
            .as_ref()
            .ok_or("Owned reader has no output pipe")?;
        let mut available = 0;
        if unsafe {
            PeekNamedPipe(
                reader.as_raw_handle(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        } == 0
        {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                Ok(false)
            } else {
                Err(error.into())
            };
        }
        if available == 0 {
            return Ok(false);
        }
        if available as usize > limit.saturating_sub(bytes.len()) {
            return Err("Owned reader output exceeded its fixed byte allowance".into());
        }
        let mut buffer = [0u8; 4096];
        let mut read = 0;
        let requested = available.min(buffer.len() as u32);
        succeeded("ReadFile", unsafe {
            ReadFile(
                reader.as_raw_handle(),
                buffer.as_mut_ptr(),
                requested,
                &mut read,
                null_mut(),
            )
        })?;
        if read == 0 || read > requested {
            return Err("Owned reader returned an invalid pipe read length".into());
        }
        bytes.extend_from_slice(&buffer[..read as usize]);
        Ok(true)
    }

    pub(crate) fn collect(
        mut self,
        limit: usize,
        mut check: impl FnMut() -> ServiceResult<()>,
    ) -> ServiceResult<Vec<u8>> {
        let outcome = (|| {
            if limit == 0 || limit > 65536 {
                return Err("Owned reader byte allowance must be between one and 65536".into());
            }
            check()?;
            if unsafe { ResumeThread(self.thread.as_raw_handle()) } != 1 {
                return Err("Cannot resume the owned reader exactly once".into());
            }
            let mut bytes = Vec::new();
            loop {
                check()?;
                self.readAvailable(&mut bytes, limit)?;
                match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 10) } {
                    WAIT_TIMEOUT => continue,
                    WAIT_OBJECT_0 => {
                        loop {
                            check()?;
                            if !self.readAvailable(&mut bytes, limit)? {
                                break;
                            }
                        }
                        let mut exitCode = 0;
                        succeeded("GetExitCodeProcess", unsafe {
                            GetExitCodeProcess(self.process.as_raw_handle(), &mut exitCode)
                        })?;
                        if exitCode != 0 {
                            let detail: String =
                                String::from_utf8_lossy(&bytes).chars().take(1024).collect();
                            return Err(format!(
                                "Owned reader failed: exit code {exitCode}: {detail}"
                            )
                            .into());
                        }
                        check()?;
                        return Ok(bytes);
                    }
                    _ => return Err(std::io::Error::last_os_error().into()),
                }
            }
        })();
        self.terminate()?;
        outcome
    }

    #[cfg(test)]
    pub(crate) fn id(&self) -> u32 {
        self.processId
    }

    #[cfg(test)]
    pub(crate) fn assigned(&self) -> bool {
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
                    return Err(format!(
                        "Owned process {} job termination was not confirmed within five seconds",
                        self.processId
                    )
                    .into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        if result.is_err() {
            self.recordTerminationFailure();
        }
        result
    }

    fn recordTerminationFailure(&self) {
        match self.role {
            ProcessRole::ReadOnly => READER_QUIESCENCE_UNKNOWN.store(true, Ordering::SeqCst),
            #[cfg(feature = "native-mtu-lab")]
            ProcessRole::Setting => QUIESCENCE_UNKNOWN.store(true, Ordering::SeqCst),
        }
    }

    #[cfg(feature = "native-mtu-lab")]
    pub(crate) fn finish(
        mut self,
        register: &mut crate::recovery::MutatorRegistrar<'_>,
        beforeResume: &mut dyn FnMut() -> ServiceResult<()>,
        mut check: impl FnMut() -> ServiceResult<()>,
    ) -> ServiceResult<()> {
        let outcome = (|| {
            check()?;
            register(processIdentity(
                self.process.as_raw_handle(),
                self.processId,
            )?)?;
            check()?;
            beforeResume()?;
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

#[cfg(feature = "native-mtu-lab")]
pub(crate) fn processIdentity(
    handle: windows_sys::Win32::Foundation::HANDLE,
    processId: u32,
) -> ServiceResult<MutatorIdentity> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    succeeded("GetProcessTimes", unsafe {
        GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user)
    })?;
    let identity = MutatorIdentity {
        processId,
        creationTime100ns: ((u64::from(creation.dwHighDateTime) << 32)
            | u64::from(creation.dwLowDateTime))
        .to_string(),
    };
    identity.validate()?;
    Ok(identity)
}

#[cfg(feature = "native-mtu-lab")]
pub(crate) fn waitForIdentity(identity: &MutatorIdentity, timeout: Duration) -> ServiceResult<()> {
    identity.validate()?;
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            identity.processId,
        )
    };
    if handle.is_null() {
        let error = std::io::Error::last_os_error();
        return if matches!(error.raw_os_error(), Some(value) if value == ERROR_INVALID_PARAMETER as i32 || value == ERROR_NOT_FOUND as i32)
        {
            Ok(())
        } else {
            Err(format!("Cannot verify predecessor mutator: {error}").into())
        };
    }
    let process = unsafe { OwnedHandle::from_raw_handle(handle) };
    if processIdentity(process.as_raw_handle(), identity.processId)? != *identity {
        return Ok(());
    }
    let timeoutMs = timeout.as_millis().min(5_000) as u32;
    match unsafe { WaitForSingleObject(process.as_raw_handle(), timeoutMs) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(
            "Predecessor mutator has not exited; readback and restoration remain blocked".into(),
        ),
        _ => Err(std::io::Error::last_os_error().into()),
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
mod reader_tests;
