# Validation record

Checked on 2026-10-31 on the current Windows x64 development machine. This verifies a read-only development milestone, not the full optimization acceptance criteria.

| Check | Observed result | Limits |
| --- | --- | --- |
| `setup.bat` | Successful toolchain validation, locked dependency installation, TypeScript check, storage/config/MCP preflight; subsequent invocation reused installed packages | System prerequisites were already installed; missing Rust path tested separately |
| `launch.bat` | Vite and the actual Tauri desktop started from a repository path containing spaces | No clean external machine tested yet |
| `test.bat` | Formatting, TypeScript, 2 frontend tests, 16 Rust tests, workspace Clippy, and 4 Windows launcher tests | Does not validate unimplemented service, setters, inference, or throughput |
| Launcher coordination | A second setup command was rejected while packaging held the checkout lock; isolated lock regression test preserved active artifacts | Direct Cargo/npm commands bypass the batch coordination lock |
| Cleanup | Actual `clean.bat` in a temporary checkout removed generated artifacts and preserved dependencies/private data; junction target was rejected | Main checkout was not cleaned during active builds |
| `build.bat` | Produced optimized `target/release/estrogen-ping-patch.exe` | Compilation alone is not gameplay/network improvement or recovery proof |
| `package.bat` | Produced `target/release/bundle/nsis/estrogen ping patch_0.1.0_x64-setup.exe` | Installer is unsigned |
| Development and production desktop smoke | Read real Windows inventory; completed six connections against two local TCP listeners; displayed successful measurements, persisted history, and explicit safety boundary without JavaScript exceptions | Loopback probes verify the execution path; they do not establish internet performance or provider accuracy |
| Packaged MCP | Release executable over stdio initialized, listed two read-only tools, rejected arbitrary command tool, and exited cleanly | MCP protocol subset only; no AI inference integration |
| Temporary installer lifecycle | Per-user silent install, GUI PE subsystem, Start menu shortcut target, actual desktop window, and uninstallation checked | No upgrade/reboot or separate-user/OS matrix yet |
| npm audit | No reported vulnerabilities at the time of the check | Not a complete application security audit |
| Staged secret scan and diff | Pattern-based scan passed; generated/runtime files excluded and staged whitespace checked | Pattern scanning cannot prove absence of every possible secret |

## Corrected defects found by validation

- Windows PowerShell strips nested native argument quotes; Node major-version detection now uses a quote-free expression.
- `cmd` can propagate incompatible PowerShell 7 module paths into Windows PowerShell 5.1; scripts isolate module lookup, and the discovery child resets it.
- Windows PowerShell serialized a selected DNS array as `{value, Count}`. Discovery now constructs plain typed arrays, validates the output contract before returning it, and has both malformed-wrapper and live Windows regression coverage.
- npm cannot replace a loaded native Tauri CLI on Windows. Batch tasks now hold a per-checkout named mutex across the lifecycle, preventing concurrent cleanup, builds, or dependency refreshes.

## Reproducing optional GUI and installer smoke checks

`scripts/desktop-smoke.mjs` attaches only to an explicitly selected loopback WebView2 debugging endpoint supplied through `EPP_CDP_URL`. Start a test instance with `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=PORT` and an isolated absolute `EPP_DATA_DIR`. Run the smoke script, then close that instance. Normal launchers and production configuration do not enable the debugging port.

`node scripts/mcp-smoke.mjs` verifies the packaged executable's stdio mode. `scripts/installer-smoke.ps1 -installerPath PATH` installs into a unique temporary directory, verifies its shortcut and GUI, and uninstalls it. It refuses to overwrite an existing Start menu installation. Use a disposable Windows account for repeated installer or future upgrade testing. CI runs the packaged MCP and installer lifecycle checks on an isolated hosted runner.

Public internet measurements, destructive failure injection, changes to this machine's network configuration, production signing, and full optimization recovery were not performed.
