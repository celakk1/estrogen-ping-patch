use crate::{ServiceResult, journal::Journal, protocol::CheckpointStoreStatus, security};
use std::{
    fs::{File, OpenOptions},
    os::windows::{ffi::OsStringExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFileInformationByHandle,
    },
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath},
};

pub(crate) struct OwnedJournal {
    pub(crate) status: CheckpointStoreStatus,
    _journal: Journal,
    _directory: File,
    _parent: File,
}

fn programData() -> ServiceResult<PathBuf> {
    let mut path = std::ptr::null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut path) };
    if result < 0 {
        return Err(format!("Cannot resolve machine recovery storage: HRESULT {result:#x}").into());
    }
    let result = (|| {
        for length in 0..32_768 {
            if unsafe { *path.add(length) } == 0 {
                return Ok(PathBuf::from(std::ffi::OsString::from_wide(unsafe {
                    std::slice::from_raw_parts(path, length)
                })));
            }
        }
        Err("Machine recovery storage path exceeded its Windows bound".into())
    })();
    unsafe { CoTaskMemFree(path.cast()) };
    result
}

fn openProtectedPath(path: &Path, directory: bool) -> ServiceResult<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err("Recovery storage must use ordinary directories and single-link files".into());
    }
    Ok(file)
}

pub(crate) fn open(serviceSid: &str) -> ServiceResult<OwnedJournal> {
    security::requireServiceMembership(serviceSid)?;
    let parent = programData()?;
    let parentGuard = openProtectedPath(&parent, true)?;
    let directory = parent.join("estrogen-ping-patch-service");
    let directoryGuard = openProtectedPath(&directory, true)?;
    security::verifyStorageHandle(directoryGuard.as_raw_handle(), serviceSid, true)?;
    verifyFiles(&directory, serviceSid)?;
    let journal = Journal::open(&directory.join("recovery.sqlite3"))?;
    verifyFiles(&directory, serviceSid)?;
    let pending = journal.pendingRecovery()?.len().try_into()?;
    Ok(OwnedJournal {
        status: CheckpointStoreStatus {
            schemaVersion: crate::journal::SCHEMA_VERSION,
            verifiedAtUnixMs: crate::transport::nowUnixMs()?,
            pendingRecoveryCount: pending,
        },
        _journal: journal,
        _directory: directoryGuard,
        _parent: parentGuard,
    })
}

fn verifyFiles(directory: &Path, serviceSid: &str) -> ServiceResult<()> {
    for name in [
        "recovery.sqlite3",
        "recovery.sqlite3-wal",
        "recovery.sqlite3-shm",
    ] {
        let path = directory.join(name);
        match openProtectedPath(&path, false) {
            Ok(file) => security::verifyStorageHandle(file.as_raw_handle(), serviceSid, false)?,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recoveryFilesCannotUseHardLinksOrInterchangeFilesAndDirectories() {
        let folder = std::env::temp_dir().join(format!(
            "epp-storage-{}-{}",
            std::process::id(),
            crate::transport::nowUnixMs().unwrap()
        ));
        std::fs::create_dir(&folder).unwrap();
        let file = folder.join("original");
        let link = folder.join("linked");
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0.join("linked"));
                let _ = std::fs::remove_file(self.0.join("original"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let _cleanup = Cleanup(folder.clone());
        std::fs::write(&file, b"fixture").unwrap();
        assert!(openProtectedPath(&folder, true).is_ok());
        assert!(openProtectedPath(&file, false).is_ok());
        assert!(openProtectedPath(&folder, false).is_err());
        assert!(openProtectedPath(&file, true).is_err());
        std::fs::hard_link(&file, &link).unwrap();
        assert!(openProtectedPath(&file, false).is_err());
        assert!(openProtectedPath(&link, false).is_err());
    }
}
