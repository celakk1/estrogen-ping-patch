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
    directoryPath: PathBuf,
    serviceSid: String,
}

pub(crate) struct OwnedAuthorization {
    pub(crate) store: crate::authorization::AuthorizationStore,
    _directory: File,
    _parent: File,
}

#[cfg(feature = "native-mtu-lab")]
pub(crate) struct OwnedExperiments {
    pub(crate) store: epp_core::experiment::Store,
    pub(crate) measurements: rusqlite::Connection,
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
    openNamed(serviceSid, "estrogen-ping-patch-service")
}

fn openNamed(serviceSid: &str, directoryName: &str) -> ServiceResult<OwnedJournal> {
    security::requireServiceMembership(serviceSid)?;
    let parent = programData()?;
    let parentGuard = openProtectedPath(&parent, true)?;
    let directory = parent.join(directoryName);
    let directoryGuard = openProtectedPath(&directory, true)?;
    security::verifyStorageHandle(directoryGuard.as_raw_handle(), serviceSid, true)?;
    verifyFiles(&directory, serviceSid)?;
    let journal = Journal::open(&directory.join("recovery.sqlite3"))?;
    verifyFiles(&directory, serviceSid)?;
    Ok(OwnedJournal {
        status: CheckpointStoreStatus::fromJournal(&journal, crate::transport::nowUnixMs()?)?,
        _journal: journal,
        _directory: directoryGuard,
        _parent: parentGuard,
        directoryPath: directory,
        serviceSid: serviceSid.into(),
    })
}

#[cfg(feature = "native-mtu-lab")]
pub(crate) fn openMtuLab(serviceSid: &str) -> ServiceResult<OwnedJournal> {
    openNamed(serviceSid, "estrogen-ping-patch-mtu-lab")
}

impl OwnedJournal {
    pub(crate) fn hasPendingWork(&self) -> ServiceResult<bool> {
        Ok(!self._journal.pendingRecovery()?.is_empty()
            || !self._journal.pendingPolicyVerification()?.is_empty())
    }
    #[cfg(any(feature = "native-mtu-lab", feature = "native-recovery"))]
    pub(crate) fn journal(&mut self) -> &mut Journal {
        &mut self._journal
    }

    pub(crate) fn authorization(&self) -> ServiceResult<OwnedAuthorization> {
        let names = [
            "authorization.sqlite3",
            "authorization.sqlite3-wal",
            "authorization.sqlite3-shm",
        ];
        verifyStateFiles(&self.directoryPath, &self.serviceSid, &names)?;
        let store =
            crate::authorization::AuthorizationStore::open(&self.directoryPath.join(names[0]))?;
        verifyStateFiles(&self.directoryPath, &self.serviceSid, &names)?;
        Ok(OwnedAuthorization {
            store,
            _directory: self._directory.try_clone()?,
            _parent: self._parent.try_clone()?,
        })
    }

    #[cfg(feature = "native-mtu-lab")]
    pub(crate) fn experiments(&self) -> ServiceResult<OwnedExperiments> {
        let names = [
            "experiments.sqlite3",
            "experiments.sqlite3-wal",
            "experiments.sqlite3-shm",
            "experiments.sqlite3-journal",
            "measurements.sqlite3",
            "measurements.sqlite3-wal",
            "measurements.sqlite3-shm",
            "measurements.sqlite3-journal",
        ];
        verifyStateFiles(&self.directoryPath, &self.serviceSid, &names)?;
        let store = epp_core::experiment::Store::open(&self.directoryPath.join(names[0]))?;
        let measurements = epp_core::storage::openDatabase(&self.directoryPath.join(names[4]))?;
        measurements.execute_batch("CREATE TABLE IF NOT EXISTS native_measurements(run_id INTEGER PRIMARY KEY REFERENCES benchmark_runs(id), experiment_id TEXT NOT NULL, payload_json TEXT NOT NULL, sha256 TEXT NOT NULL)")?;
        verifyStateFiles(&self.directoryPath, &self.serviceSid, &names)?;
        Ok(OwnedExperiments {
            store,
            measurements,
            _directory: self._directory.try_clone()?,
            _parent: self._parent.try_clone()?,
        })
    }
}

fn verifyFiles(directory: &Path, serviceSid: &str) -> ServiceResult<()> {
    verifyStateFiles(
        directory,
        serviceSid,
        &[
            "recovery.sqlite3",
            "recovery.sqlite3-wal",
            "recovery.sqlite3-shm",
        ],
    )
}

fn verifyStateFiles(directory: &Path, serviceSid: &str, names: &[&str]) -> ServiceResult<()> {
    for name in names {
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
