#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(non_snake_case)]

mod backups;
mod routing;

use epp_core::{
    backups::{BackupExport, BackupSummary},
    benchmark::{BenchmarkRun, Endpoint, Sample},
    config::Config,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tauri::{Emitter, Manager, State};

struct LocalService {
    directory: PathBuf,
    busy: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
}

struct JobGuard(Arc<AtomicBool>);

impl Drop for JobGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn beginJob(service: &LocalService) -> Result<JobGuard, String> {
    service
        .busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .map_err(|_| "A network task is already running".to_string())?;
    service.cancelled.store(false, Ordering::SeqCst);
    Ok(JobGuard(service.busy.clone()))
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Progress {
    sample: Sample,
    completed: usize,
    total: usize,
    remainingLowSeconds: u64,
    remainingHighSeconds: u64,
}

#[tauri::command]
fn status(service: State<'_, LocalService>) -> Result<Value, String> {
    let config =
        epp_core::config::loadConfig(&service.directory).map_err(|error| error.to_string())?;
    Ok(
        json!({"version": env!("CARGO_PKG_VERSION"), "service": "ready", "privilegedService": "checkServiceStatus", "mcp": "readOnly", "busy": service.busy.load(Ordering::SeqCst), "config": config, "dataDirectory": service.directory}),
    )
}

#[tauri::command]
async fn getPrivilegedService() -> Result<epp_service::ServiceReport, String> {
    tauri::async_runtime::spawn_blocking(epp_service::inspectBlocking)
        .await
        .map_err(|error| error.to_string())
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum ServiceAction {
    Install,
    Start,
    Stop,
    Uninstall,
}

#[tauri::command]
async fn manageService(app: tauri::AppHandle, action: ServiceAction) -> Result<(), String> {
    let scriptPath = if cfg!(debug_assertions) {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../scripts/manage-service.ps1")
    } else {
        app.path()
            .resource_dir()
            .map_err(|error| error.to_string())?
            .join("service/manage-service.ps1")
    };
    let action = match action {
        ServiceAction::Install => "install",
        ServiceAction::Start => "start",
        ServiceAction::Stop => "stop",
        ServiceAction::Uninstall => "uninstall",
    };
    tauri::async_runtime::spawn_blocking(move || {
        if !scriptPath.is_file() { return Err("Service management resources are missing. Use build.bat or install the packaged application.".to_string()); }
        let powershell = PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot is unavailable")?).join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let mut command = std::process::Command::new(powershell);
        command.env_remove("PSModulePath").args(["-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"]).arg(scriptPath).args(["-action", action]);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let output = command.output().map_err(|error| error.to_string())?;
        if !output.status.success() { return Err(format!("Service management failed (exit {:?}): {} {}", output.status.code(), String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))); }
        Ok(())
    }).await.map_err(|error| error.to_string())?
}

#[tauri::command]
async fn getInventory() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| {
        epp_core::discovery::inventory().map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn getHistory(service: State<'_, LocalService>) -> Result<Vec<BenchmarkRun>, String> {
    let directory = service.directory.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let connection = epp_core::storage::openDatabase(&directory.join("experiments.sqlite3"))
            .map_err(|error| error.to_string())?;
        epp_core::storage::history(&connection, 30).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn getBackups(service: State<'_, LocalService>) -> Result<Vec<BackupSummary>, String> {
    let directory = service.directory.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let connection = epp_core::storage::openDatabase(&directory.join("experiments.sqlite3"))
            .map_err(|error| error.to_string())?;
        epp_core::storage::backupHistory(&connection).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn captureBackup(service: State<'_, LocalService>) -> Result<BackupSummary, String> {
    let guard = beginJob(&service)?;
    let directory = service.directory.clone();
    let cancelled = service.cancelled.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let mut payload =
            epp_core::backups::capture(&cancelled).map_err(|error| error.to_string())?;
        backups::appendNativeMtu(&mut payload, &cancelled)?;
        epp_core::backups::finalizeCapture(&mut payload, &cancelled)
            .map_err(|error| error.to_string())?;
        if cancelled.load(Ordering::SeqCst) {
            return Err("Backup capture was cancelled".to_string());
        }
        let mut connection =
            epp_core::storage::openDatabase(&directory.join("experiments.sqlite3"))
                .map_err(|error| error.to_string())?;
        epp_core::storage::saveBackup(&mut connection, &payload).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn exportBackup(service: State<'_, LocalService>, id: i64) -> Result<BackupExport, String> {
    let directory = service.directory.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let connection = epp_core::storage::openDatabase(&directory.join("experiments.sqlite3"))
            .map_err(|error| error.to_string())?;
        epp_core::storage::loadBackup(&connection, id).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn runBaseline(
    app: tauri::AppHandle,
    service: State<'_, LocalService>,
    config: Config,
    endpoints: Vec<Endpoint>,
) -> Result<BenchmarkRun, String> {
    config.validate().map_err(|error| error.to_string())?;
    epp_core::benchmark::validateEndpoints(&endpoints).map_err(|error| error.to_string())?;
    let destinations = routing::destinations(&endpoints)?;
    let guard = beginJob(&service)?;
    let cancelled = service.cancelled.clone();
    let directory = service.directory.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let routesBefore = routing::capture(&destinations, &cancelled);
        let start = std::time::Instant::now();
        let timeoutMs = config.timeoutMs;
        let intervalMs = config.intervalMs;
        let mut run = epp_core::benchmark::runBenchmark(
            config,
            endpoints,
            &cancelled,
            |sample, completed, total| {
                let observedSeconds = start.elapsed().as_secs_f64() / completed as f64;
                let remaining = (total - completed) as f64;
                let progress = Progress {
                    sample: sample.clone(),
                    completed,
                    total,
                    remainingLowSeconds: (remaining * observedSeconds * 0.8).floor() as u64,
                    remainingHighSeconds: (remaining
                        * observedSeconds.max((timeoutMs + intervalMs) as f64 / 1000.0))
                    .ceil() as u64,
                };
                let _ = app.emit("benchmark-progress", progress);
            },
        )
        .map_err(|error| error.to_string())?;
        run.routing = Some(routing::evidence(
            routesBefore,
            routing::capture(&destinations, &cancelled),
        ));
        let mut connection = epp_core::storage::openDatabase(
            &directory.join("experiments.sqlite3"),
        )
        .map_err(|error| format!("Measurements finished but storage could not open: {error}"))?;
        epp_core::storage::saveRun(&mut connection, &mut run)
            .map_err(|error| format!("Measurements finished but saving failed: {error}"))?;
        Ok(run)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn getLoadHistory(
    service: State<'_, LocalService>,
) -> Result<Vec<epp_core::transfer::session::SessionRun>, String> {
    let directory = service.directory.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let connection = epp_core::storage::openDatabase(&directory.join("experiments.sqlite3"))
            .map_err(|error| error.to_string())?;
        epp_core::storage::loadSessionHistory(&connection, 50).map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
async fn runLoadSession(
    app: tauri::AppHandle,
    service: State<'_, LocalService>,
    config: Config,
    plan: epp_core::transfer::session::SessionPlan,
) -> Result<epp_core::transfer::session::SessionRun, String> {
    plan.validate(&config).map_err(|error| error.to_string())?;
    let guard = beginJob(&service)?;
    let cancelled = service.cancelled.clone();
    let directory = service.directory.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _guard = guard;
        let mut run =
            epp_core::transfer::session::runSession(config, plan, &cancelled, |progress| {
                let _ = app.emit("load-progress", progress);
            })
            .map_err(|error| error.to_string())?;
        let mut connection =
            epp_core::storage::openDatabase(&directory.join("experiments.sqlite3")).map_err(
                |error| format!("Load measurements finished but storage could not open: {error}"),
            )?;
        epp_core::storage::saveLoadSession(&mut connection, &mut run)
            .map_err(|error| format!("Load measurements finished but saving failed: {error}"))?;
        Ok(run)
    })
    .await
    .map_err(|error| error.to_string())?
}

#[tauri::command]
fn cancelBaseline(service: State<'_, LocalService>) {
    service.cancelled.store(true, Ordering::SeqCst);
}

fn startupFailure(error: impl std::fmt::Display) -> ! {
    let message = format!(
        "estrogen ping patch could not start.\n\n{error}\n\nRun setup.bat in the source checkout and verify local data permissions and WebView2. Your network settings have not been changed."
    );
    eprintln!("{message}");
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        let message: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
        let title: Vec<u16> = "estrogen ping patch - startup failed"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // both buffers remain alive and null-terminated for the synchronous dialog.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
    std::process::exit(1);
}

fn main() {
    if std::env::args().skip(1).any(|argument| argument == "--mcp") {
        if let Err(error) = epp_core::mcp::serve(std::io::stdin().lock(), std::io::stdout().lock())
        {
            eprintln!("MCP stopped: {error}");
            std::process::exit(1);
        }
        return;
    }
    let app = tauri::Builder::default()
        .setup(|app| {
            let directory = epp_core::dataDirectory().map_err(|error| -> Box<dyn std::error::Error> { error })?;
            epp_core::config::loadConfig(&directory).map_err(|error| -> Box<dyn std::error::Error> { error })?;
            let connection = epp_core::storage::openDatabase(&directory.join("experiments.sqlite3")).map_err(|error| -> Box<dyn std::error::Error> { error })?;
            connection.execute("INSERT INTO application_events(kind,detail) VALUES('startup','Read-only local service initialized; modifications disabled')", [])?;
            app.manage(LocalService { directory, busy: Arc::new(AtomicBool::new(false)), cancelled: Arc::new(AtomicBool::new(false)) });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![status, getPrivilegedService, manageService, getInventory, getHistory, getBackups, captureBackup, exportBackup, runBaseline, cancelBaseline, getLoadHistory, runLoadSession])
        .build(tauri::generate_context!());
    let app = match app {
        Ok(app) => app,
        Err(error) => startupFailure(error),
    };
    app.run(|handle, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            let service = handle.state::<LocalService>();
            if service.busy.load(Ordering::SeqCst) {
                service.cancelled.store(true, Ordering::SeqCst);
                api.prevent_exit();
                let busy = service.busy.clone();
                let handle = handle.clone();
                std::thread::spawn(move || {
                    while busy.load(Ordering::SeqCst) {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    handle.exit(0);
                });
            }
        }
    });
}
