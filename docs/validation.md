# Validation record

Checked on 2026-10-31 on the current Windows x64 development machine. This verifies a read-only development milestone, not the full optimization acceptance criteria.

| Check | Observed result | Limits |
| --- | --- | --- |
| `setup.bat` | Successful toolchain validation, locked dependency installation, TypeScript check, storage/config/MCP preflight; subsequent invocation reused installed packages | System prerequisites were already installed; missing Rust path tested separately |
| `launch.bat` | Vite and the actual Tauri desktop started from a repository path containing spaces | No clean external machine tested yet |
| `test.bat` | Formatting, TypeScript, 2 frontend tests, 56 Rust tests, workspace Clippy, 4 Windows launcher tests, 2 WebView readiness tests, and a service-build selection regression | The two ignored Rust functions are explicit subprocess/lab helpers. No native setters, restoration, inference, or throughput tested |
| Launcher coordination | A second setup command was rejected while packaging held the checkout lock; isolated lock regression test preserved active artifacts | Direct Cargo/npm commands bypass the batch coordination lock |
| Cleanup | Actual `clean.bat` in a temporary checkout removed generated artifacts and preserved dependencies/private data; junction target was rejected | Main checkout was not cleaned during active builds |
| `build.bat` | Produced optimized `target/release/estrogen-ping-patch.exe` | Compilation alone is not gameplay/network improvement or recovery proof |
| `package.bat` | Produced `target/release/bundle/nsis/estrogen ping patch_0.1.0_x64-setup.exe` | Installer is unsigned |
| Development and production desktop smoke | Read real Windows inventory; completed six connections against two local TCP listeners; displayed successful measurements, persisted history, and explicit safety boundary without JavaScript exceptions | Loopback probes verify the execution path; they do not establish internet performance or provider accuracy |
| Packaged MCP | Release executable over stdio initialized, listed two read-only tools, rejected arbitrary command tool, and exited cleanly | MCP protocol subset only; no AI inference integration |
| Backup GUI and actual JSON download | Isolated packaged GUI saved snapshot, reopened history, matched adapter GUIDs, verified downloaded bytes against SHA-256, and cancelled capture without adding a partial record | This machine exposed 18 captured and 23 unavailable sections; automatic restoration remains unavailable |
| Native DNS reader | Six tests cover real Windows reads/explicit errors, canonical GUID byte layout, exact null/empty/text/flag/integer values, invalid/oversized text rejection, cancellation, and cleanup after serialization failure; packaged capture succeeded on 4/7 adapters | Three adapters returned Windows error 2 and were reported unavailable. Read-only version-one fields; automatic/static restoration and policy/DoH/dual-stack semantics require lab validation |
| Temporary installer lifecycle | Per-user silent install, GUI PE subsystem, Start menu shortcut, desktop window, exact hashes of all optional service resources, and uninstallation checked | No upgrade/reboot or separate-user/OS matrix yet |
| Dedicated service protocol and original SCM lifecycle | Real pipe tests exercise ACL allow/deny, denied pipe-instance creation, token rejection/reversion, server PID mismatch, malformed frames, five-second timeout recovery, and stop cancellation. Focused and full Windows CI at `9ac3055` passed actual installation, protected binary checks, LocalService identity, repeated status requests, stop/restart, and removal | No service was installed on the development machine. The new service SID/journal integration needs its extended lab run |
| Recovery journal library | Independent connections and reopen checks verify original checkpoint persistence, state/observation gates, lease expiry, backward clock correction, stale-writer rejection, failed commits, corrupt hashes, missing events, foreign-key errors, and schema refusal. A real subprocess-termination test passed for simulated apply and restore interruptions | The changed value is a temporary text file, never a Windows adapter. Does not prove native restore, reboot, physical power-loss, or disk-full recovery |
| Recovery storage validation | Local tests reject incorrect ACL/owner rules and actual hard links; temporary Windows files confirmed OWNER RIGHTS and service SID ACL inheritance | Actual LocalService token/storage behavior and corruption refusal await the extended disposable SCM check |
| npm audit | No reported vulnerabilities at the time of the check | Not a complete application security audit |
| Staged secret scan and diff | Pattern-based scan passed; generated/runtime files excluded and staged whitespace checked | Pattern scanning cannot prove absence of every possible secret |

## Corrected defects found by validation

- Windows PowerShell strips nested native argument quotes; Node major-version detection now uses a quote-free expression.
- `cmd` can propagate incompatible PowerShell 7 module paths into Windows PowerShell 5.1; scripts isolate module lookup, and the discovery child resets it.
- Windows PowerShell serialized a selected DNS array as `{value, Count}`. Discovery now constructs plain typed arrays, validates the output contract before returning it, and has both malformed-wrapper and live Windows regression coverage.
- npm cannot replace a loaded native Tauri CLI on Windows. Batch tasks now hold a per-checkout named mutex across the lifecycle, preventing concurrent cleanup, builds, or dependency refreshes.
- Fresh Windows checkouts require explicit LF rules for CSS and JavaScript modules to match the formatter. A new clone passed the same formatting check after the attributes correction.
- Vite's default root watcher also traversed locked Cargo artifacts. The development watcher now excludes generated Cargo and application output directories.
- The cross-process mutex regression fixture must normalize Windows short paths with the same Windows path API as the launcher. A local 8.3 temporary-path reproduction failed before the correction and passed afterward.
- Pipe handles cannot be recycled with the resolved Mio version: stale read completion state caused the second connection to fail. Fresh instances with a listener retained across clients pass the real pipe tests. Client ACLs also need read-attribute access; omitting that bit rejected the authorized user at `CreateFileW`, while adding it preserves denial of pipe-instance creation.
- CI exposed that a WebView debugging endpoint can appear before the application page is available. Desktop/backup smoke checks now wait for the expected page with a deadline and URL diagnostics; the delayed-page regression and full hosted GUI/backup checks passed.
- Windows PowerShell disposes the ServiceController emitted by New-Service. Service management now discards that controller and uses a fresh one; hosted installation, stop/restart, and removal passed afterward.
- The source helper always preferred a release service binary, including after development mode built a newer debug binary. A process-level fixture reproduced selection of the stale release build. The correction selects the newest checkout build while preserving adjacent packaged resources; the same fixture exercises all three choices without installing a service.

The complete Windows verification run at `9ac3055` passed setup, automated checks, production build, NSIS packaging, packaged MCP, GUI/backup downloads, installer install/shortcut/GUI/uninstall, and the original SCM service lifecycle: [Windows verification](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41207730485). The focused [service lifecycle run](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41207730403) passed separately. These runs predate the new checkpoint-storage integration and do not validate its native recovery gates.

## Reproducing optional GUI and installer smoke checks

`scripts/gui-smoke.ps1` starts the production executable with a unique temporary application/WebView2 profile and loopback debugging port, runs the desktop and backup UI/download checks, then closes that exact process. It leaves the isolated test data for inspection and restores the caller's environment. CI runs this after packaging. The underlying Node scripts also verify that the attached desktop uses the expected isolated data directory.

For an explicitly managed test instance, `scripts/desktop-smoke.mjs` and `scripts/backup-smoke.mjs` attach only to the loopback WebView2 debugging endpoint supplied through `EPP_CDP_URL`. Start a test instance with `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=PORT` and an isolated absolute `EPP_DATA_DIR`. Run the smoke scripts, then close that instance. Normal launchers and production configuration do not enable the debugging port.

`node scripts/mcp-smoke.mjs` verifies the packaged executable's stdio mode. `scripts/installer-smoke.ps1 -installerPath PATH` installs into a unique temporary directory, verifies its shortcut and GUI, and uninstalls it. It refuses to overwrite an existing Start menu installation. Use a disposable Windows account for repeated installer or future upgrade testing. CI runs the packaged MCP and installer lifecycle checks on an isolated hosted runner.

Public internet measurements, destructive failure injection, changes to this machine's network configuration, production signing, and full optimization recovery were not performed.
