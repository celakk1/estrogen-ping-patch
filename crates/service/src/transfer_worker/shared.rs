use super::*;
use epp_core::transfer::{TransferCounters, TransferProgressStorage};
use std::{
    mem::{align_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
    sync::{Arc, atomic::AtomicU64},
};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, ERROR_ACCESS_DENIED, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE,
    },
    Storage::FileSystem::{WRITE_DAC, WRITE_OWNER},
    System::{
        Memory::{
            CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS,
            MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
        },
        Threading::GetCurrentProcess,
    },
};

const MAGIC: u64 = 0x4550505052470001;

#[repr(C)]
struct Layout {
    magic: AtomicU64,
    counters: TransferCounters,
}

pub(super) struct SharedProgress {
    view: MEMORY_MAPPED_VIEW_ADDRESS,
    handle: OwnedHandle,
}

// both processes retain writable views and access only aligned, initialized atomics.
unsafe impl Send for SharedProgress {}
unsafe impl Sync for SharedProgress {}

impl SharedProgress {
    pub(super) fn new() -> ServiceResult<Arc<Self>> {
        let descriptor = crate::security::Descriptor::workerProgress()?;
        let handle = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                &descriptor.attributes(),
                PAGE_READWRITE,
                0,
                size_of::<Layout>() as u32,
                null(),
            )
        };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let storage = Self::map(unsafe { OwnedHandle::from_raw_handle(handle) })?;
        unsafe {
            storage.view.Value.cast::<Layout>().write(Layout {
                magic: AtomicU64::new(MAGIC),
                counters: TransferCounters::default(),
            });
        }
        Ok(Arc::new(storage))
    }

    fn map(handle: OwnedHandle) -> ServiceResult<Self> {
        let view = unsafe {
            MapViewOfFile(
                handle.as_raw_handle(),
                FILE_MAP_READ | FILE_MAP_WRITE,
                0,
                0,
                size_of::<Layout>(),
            )
        };
        if view.Value.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let storage = Self { view, handle };
        if !(storage.view.Value as usize).is_multiple_of(align_of::<Layout>()) {
            return Err("Benchmark progress mapping is not aligned".into());
        }
        Ok(storage)
    }

    pub(super) fn inherit(&self) -> ServiceResult<OwnedHandle> {
        let mut handle = null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.handle.as_raw_handle(),
                GetCurrentProcess(),
                &mut handle,
                FILE_MAP_READ | FILE_MAP_WRITE,
                1,
                0,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    pub(super) fn open(value: &str) -> ServiceResult<Arc<Self>> {
        let handle = value.parse::<usize>()? as HANDLE;
        let mut flags = 0;
        if handle.is_null()
            || handle == INVALID_HANDLE_VALUE
            || unsafe { GetHandleInformation(handle, &mut flags) } == 0
            || flags & HANDLE_FLAG_INHERIT == 0
        {
            return Err("Benchmark progress capability is missing or not inherited".into());
        }
        for rights in [WRITE_DAC, WRITE_OWNER] {
            let mut upgraded = null_mut();
            if unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle,
                    GetCurrentProcess(),
                    &mut upgraded,
                    rights,
                    0,
                    0,
                )
            } != 0
            {
                drop(unsafe { OwnedHandle::from_raw_handle(upgraded) });
                return Err("Benchmark progress capability permits descriptor escalation".into());
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
                return Err("Cannot verify benchmark progress descriptor refusal".into());
            }
        }
        let storage = Self::map(unsafe { OwnedHandle::from_raw_handle(handle) })?;
        if storage.read()? != Counters::default() {
            return Err("Benchmark progress capability was not initialized to zero".into());
        }
        Ok(Arc::new(storage))
    }

    pub(super) fn read(&self) -> ServiceResult<Counters> {
        if unsafe { &*self.view.Value.cast::<Layout>() }
            .magic
            .load(Ordering::SeqCst)
            != MAGIC
        {
            return Err("Benchmark progress capability schema changed".into());
        }
        let counters = self.counters();
        Ok(Counters {
            downloadBytesRead: counters.downloadBytesRead.load(Ordering::SeqCst),
            uploadBodyBytesProvided: counters.uploadBodyBytesProvided.load(Ordering::SeqCst),
            activeRequests: counters.activeRequests.load(Ordering::SeqCst),
        })
    }
}

impl TransferProgressStorage for SharedProgress {
    fn counters(&self) -> &TransferCounters {
        unsafe { &(*self.view.Value.cast::<Layout>()).counters }
    }
}

impl Drop for SharedProgress {
    fn drop(&mut self) {
        unsafe { UnmapViewOfFile(self.view) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separateViewsShareInitializedAtomicsAndRejectSchemaDrift() {
        let shared = SharedProgress::new().unwrap();
        assert_eq!(size_of::<Layout>(), 32);
        assert_eq!(shared.read().unwrap(), Counters::default());
        let other = SharedProgress::map(shared.inherit().unwrap()).unwrap();
        let progress = TransferProgress::fromStorage(shared.clone());
        drop(shared);
        progress.downloadBytesRead.store(1024, Ordering::SeqCst);
        progress.activeRequests.store(1, Ordering::SeqCst);
        assert_eq!(
            other.read().unwrap(),
            Counters {
                downloadBytesRead: 1024,
                uploadBodyBytesProvided: 0,
                activeRequests: 1
            }
        );
        unsafe { &*other.view.Value.cast::<Layout>() }
            .magic
            .store(0, Ordering::SeqCst);
        assert!(other.read().is_err());
    }

    #[test]
    fn invalidProgressCapabilitiesAreRefused() {
        for value in ["", "not-a-handle", "0", &usize::MAX.to_string()] {
            assert!(SharedProgress::open(value).is_err());
        }
        let shared = SharedProgress::new().unwrap();
        assert!(
            SharedProgress::open(&(shared.handle.as_raw_handle() as usize).to_string()).is_err()
        );
        assert_eq!(shared.read().unwrap(), Counters::default());
    }
}
