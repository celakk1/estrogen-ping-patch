#![allow(non_snake_case)]

pub mod backups;
pub mod benchmark;
pub mod config;
pub mod discovery;
pub mod mcp;
mod native_dns;
pub mod statistics;
pub mod storage;

use std::path::PathBuf;

pub type AppResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub fn dataDirectory() -> AppResult<PathBuf> {
    if let Some(directory) = std::env::var_os("EPP_DATA_DIR") {
        let directory = PathBuf::from(directory);
        if !directory.is_absolute() {
            return Err("EPP_DATA_DIR must be an absolute path".into());
        }
        return Ok(directory);
    }
    Ok(dirs::data_local_dir()
        .ok_or("Windows local application data directory is unavailable")?
        .join("estrogen-ping-patch"))
}
