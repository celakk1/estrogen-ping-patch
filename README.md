# estrogen ping patch

A local Windows network experimentation application built with Rust, Tauri 2, React, and TypeScript. Measure, experiment, validate, retain or revert. Lower ping is an experimental outcome, never a promise.

## Development status

This is an early development build. It provides read-only network discovery, bounded TCP connection baselines across multiple destinations, cancellation, live progress, local SQLite history, JSON/HTML reports, local network settings snapshots with SHA-256-verified JSON exports, and a read-only MCP stdio interface. It preserves the existing network configuration. Automatic snapshot restoration is not implemented.

A separate Windows service provides authenticated local status reporting, with optional installation and management from **Safety & policy**. It runs as LocalService, accepts no network setters, and is not needed for diagnostics or backups. The read-only SCM lifecycle passed disposable Windows CI. The next milestone adds protected service-owned recovery journal storage and startup detection of incomplete checkpoints; its extended lab checks are under validation. Automatic network modifications, operation authorization, controlled optimization, native crash rollback, throughput providers, scheduling, and optional inference providers remain under development. See [implementation plan](docs/development.md) and the [full specification](docs/specification.md).

## Quick start

Supported development platform: Windows 10/11 x64, Rust stable MSVC, Node.js 24 LTS with npm 11 or 12, Visual Studio 2022 C++ Build Tools with a Windows SDK, and Microsoft Edge WebView2 Runtime.

1. Clone this private repository into a local directory. Spaces in the path are supported.
2. Double-click `setup.bat` once. It validates the toolchain, installs locked JavaScript dependencies, fetches Rust dependencies, checks TypeScript, and validates local storage and MCP initialization.
3. Double-click `launch.bat` whenever you want to work on the application. It starts Vite and the Tauri desktop application, which owns the local application-service lifecycle. Close the GUI to stop it; Tauri stops its development server.

No manual terminal commands are needed for these normal workflows. If a system prerequisite is missing, the script provides the official installation link and required component. System prerequisite installers remain a separate, explicit step. The launchers never elevate themselves or change network settings.

| Script | Behavior | Output |
| --- | --- | --- |
| `setup.bat` | Validate prerequisites and install project dependencies | Local toolchain ready |
| `launch.bat` | Preflight, Vite, Tauri development GUI | Development desktop window |
| `test.bat` | TypeScript, frontend tests, Rust formatting/tests/Clippy, launcher tests | Automated verification |
| `build.bat` | Build optimized desktop application | `target/release/estrogen-ping-patch.exe` |
| `package.bat` | Build a per-user NSIS installer | `target/release/bundle/nsis/*-setup.exe` |
| `clean.bat` | Remove allowlisted build artifacts | Preserves source, dependencies, application data |

Scripts retain output for double-click users and return the failing command's exit code. Set `EPP_NO_PAUSE=1` for unattended execution; CI also skips pauses. Project dependencies are reinstalled only when missing, invalid, or inconsistent with the lockfile. Each checkout runs one script task at a time; close development mode before testing, building, packaging, or refreshing dependencies.

The installed application launches from its Start menu shortcut without a terminal. Development scripts are not part of its runtime requirements. Installers are unsigned until a signing identity is configured; no release is published automatically.

The optional service has separate `install-service.bat` and `uninstall-service.bat` helpers. Service management requests its own Windows administrator approval; `launch.bat` and the desktop remain unelevated. Uninstall the service through **Safety & policy** before uninstalling the desktop. See [service management and trust boundaries](docs/service.md).

## Privacy and safety

- No telemetry, advertising, or automatic cloud inference.
- No network measurement traffic until the user starts a baseline.
- AI is disabled with a zero cloud budget. MCP exposes an explicit read-only tool allowlist.
- Inventory and raw measurements are stored in `%LOCALAPPDATA%/estrogen-ping-patch`, outside the source checkout.
- Use `.env.example` as documentation only. No `.env` loader is installed and no credentials are required.
- JSON and HTML exports may contain endpoint addresses; review them before sharing.

## Documentation

- [Setup and troubleshooting](docs/setup.md)
- [Architecture and feasibility](docs/architecture.md)
- [Security and threat model](docs/security.md)
- [Development and acceptance tracking](docs/development.md)
- [Candidate registry](docs/candidates.md)
- [Network settings backups and recovery requirements](docs/backups.md)
- [Dedicated Windows service](docs/service.md)
- [Research sources](docs/research.md)

## License

MIT, selected by the project owner. See [LICENSE](LICENSE). Private repository visibility and software licensing are independent.
