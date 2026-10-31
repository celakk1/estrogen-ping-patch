use crate::AppResult;
use serde_json::Value;
use std::{
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub fn inventory() -> AppResult<Value> {
    if !cfg!(windows) {
        return Err("Network discovery currently requires Windows 10/11".into());
    }
    let systemRoot = std::env::var_os("SystemRoot").ok_or("SystemRoot is unavailable")?;
    let powershellPath =
        std::path::PathBuf::from(systemRoot).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let mut command = Command::new(powershellPath);
    command.env_remove("PSModulePath");
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("discovery.ps1"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().ok_or("Missing inventory output")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("Missing inventory error output")?;
    let outputThread = thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .take(2_000_001)
            .read_to_end(&mut output)
            .map(|_| output)
    });
    let errorThread = thread::spawn(move || {
        let mut output = Vec::new();
        stderr.take(16_384).read_to_end(&mut output).map(|_| output)
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = outputThread.join();
            let _ = errorThread.join();
            return Err("Windows discovery timed out after 30 seconds; check NetAdapter and NetTCPIP availability".into());
        }
        thread::sleep(Duration::from_millis(50));
    };
    let output = outputThread
        .join()
        .map_err(|_| "Inventory reader failed")??;
    let error = errorThread
        .join()
        .map_err(|_| "Inventory error reader failed")??;
    if !status.success() {
        return Err(format!(
            "Windows discovery failed: {}",
            String::from_utf8_lossy(&error)
        )
        .into());
    }
    if output.len() > 2_000_000 {
        return Err("Inventory exceeded the 2 MB safety limit".into());
    }
    let result: Value = serde_json::from_slice(&output)?;
    validateInventory(&result)?;
    Ok(result)
}

pub fn validateInventory(inventory: &Value) -> AppResult<()> {
    for field in ["adapters", "routes", "interfaces", "dns", "limitations"] {
        if !inventory[field].is_array() {
            return Err(format!("Windows inventory field '{field}' is not an array").into());
        }
    }
    for entry in inventory["dns"].as_array().ok_or("Missing DNS inventory")? {
        let servers = entry["servers"]
            .as_array()
            .ok_or("Windows DNS servers were not serialized as an array")?;
        if servers.iter().any(|server| !server.is_string()) {
            return Err("Windows DNS server addresses must be strings".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejectPowerShellArrayWrappersBeforeTheyReachTheGui() {
        let mut inventory = json!({"adapters":[],"routes":[],"interfaces":[],"dns":[{"interfaceIndex":1,"servers":{"value":["127.0.0.1"],"Count":1}}],"limitations":[]});
        assert!(validateInventory(&inventory).is_err());
        inventory["dns"][0]["servers"] = json!(["127.0.0.1"]);
        assert!(validateInventory(&inventory).is_ok());
    }

    #[test]
    #[cfg(windows)]
    fn windowsDiscoveryHonorsTheFrontendArrayContract() {
        let inventory = inventory().expect("read-only Windows discovery failed");
        validateInventory(&inventory).unwrap();
        assert!(inventory["os"]["version"].is_string());
    }
}
