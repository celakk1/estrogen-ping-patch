use super::*;
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, ERROR_ACCESS_DENIED},
    Storage::FileSystem::{WRITE_DAC, WRITE_OWNER},
    System::{
        Console::{GetStdHandle, STD_INPUT_HANDLE},
        Memory::{
            CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS,
            MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
        },
        Threading::GetCurrentProcess,
    },
};

pub(crate) const MAX_BYTES: usize = 8192;

struct View(Option<MEMORY_MAPPED_VIEW_ADDRESS>);

impl View {
    fn new(handle: HANDLE, access: u32, length: usize) -> ServiceResult<Self> {
        let address = unsafe { MapViewOfFile(handle, access, 0, 0, length) };
        if address.Value.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(Some(address)))
    }

    fn close(mut self) -> ServiceResult<()> {
        succeeded("Unmap benchmark request", unsafe {
            UnmapViewOfFile(self.0.unwrap())
        })?;
        self.0 = None;
        Ok(())
    }
}

impl Drop for View {
    fn drop(&mut self) {
        if let Some(address) = self.0 {
            unsafe { UnmapViewOfFile(address) };
        }
    }
}

pub(crate) struct Input {
    pub(crate) handle: OwnedHandle,
    pub(crate) length: usize,
}

impl Input {
    pub(crate) fn new(bytes: &[u8]) -> ServiceResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err("Benchmark request must contain one to 8192 bytes".into());
        }
        let descriptor = crate::security::Descriptor::workerRequest()?;
        let handle = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                &descriptor.attributes(),
                PAGE_READWRITE,
                0,
                bytes.len() as u32,
                null(),
            )
        };
        if handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let original = unsafe { OwnedHandle::from_raw_handle(handle) };
        let view = View::new(original.as_raw_handle(), FILE_MAP_WRITE, bytes.len())?;
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), view.0.unwrap().Value.cast(), bytes.len())
        };
        view.close()?;
        let mut reader = null_mut();
        succeeded("Duplicate read-only benchmark request", unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                original.as_raw_handle(),
                GetCurrentProcess(),
                &mut reader,
                FILE_MAP_READ,
                1,
                0,
            )
        })?;
        drop(original);
        Ok(Self {
            handle: unsafe { OwnedHandle::from_raw_handle(reader) },
            length: bytes.len(),
        })
    }
}

pub(crate) fn read(length: &str, parentId: &str) -> ServiceResult<Vec<u8>> {
    restricted::validateCurrent()?;
    readVerified(length, parentId)
}

#[cfg(feature = "automatic-trials")]
pub(crate) fn readPacket(length: &str, parentId: &str) -> ServiceResult<Vec<u8>> {
    restricted::validateCurrentPacketReader()?;
    readVerified(length, parentId)
}

fn readVerified(length: &str, parentId: &str) -> ServiceResult<Vec<u8>> {
    restricted::verifyParent(parentId)?;
    let length: usize = length.parse()?;
    if length == 0 || length > MAX_BYTES {
        return Err("Benchmark request length is outside its fixed bound".into());
    }
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err("Benchmark request capability is missing".into());
    }
    match View::new(handle, FILE_MAP_WRITE, length) {
        Ok(view) => {
            view.close()?;
            return Err("Benchmark request unexpectedly permits writes".into());
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error)
                == Some(ERROR_ACCESS_DENIED as i32) => {}
        Err(error) => {
            return Err(format!("Cannot verify benchmark request write refusal: {error}").into());
        }
    }
    for rights in [FILE_MAP_WRITE, WRITE_DAC, WRITE_OWNER] {
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
            return Err("Benchmark request permits capability escalation".into());
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
            return Err("Cannot verify benchmark request capability refusal".into());
        }
    }
    let view = View::new(handle, FILE_MAP_READ, length)?;
    let bytes =
        unsafe { std::slice::from_raw_parts(view.0.unwrap().Value.cast::<u8>(), length) }.to_vec();
    view.close()?;
    Ok(bytes)
}
