# Setup and execution

## Prerequisites

Install these once, then reopen the launcher so PATH updates are visible:

- [Rust stable](https://rustup.rs), default host `x86_64-pc-windows-msvc`. Include rustfmt and Clippy.
- [Node.js 24 LTS](https://nodejs.org) with its bundled npm, version 11 or 12. npm is the selected package manager; do not substitute another lockfile.
- [Visual Studio 2022 Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/), with Desktop development with C++, MSVC x64/x86, and a current Windows 10/11 SDK.
- [WebView2 Evergreen Runtime](https://developer.microsoft.com/microsoft-edge/webview2/).
- [Git for Windows](https://git-scm.com/download/win) for cloning and version control.

`setup.bat` validates these prerequisites. It does not silently install system-wide software or request elevation. It uses `npm ci` with the committed lockfile and `cargo fetch --locked`; network access to npm and crates.io is required on a fresh machine. Later launches reuse installed packages and Cargo's build cache.

## Normal workflows

Run `setup.bat` once after cloning, then `launch.bat` to open the desktop in development mode. These scripts work regardless of the caller's current directory. The launcher resolves the project directory from its own location, including paths containing spaces.

Use `test.bat` before committing. Use `build.bat` for an optimized executable and `package.bat` for an installable Windows build. NSIS is fetched by Tauri when first required. Its per-user installer creates the Start menu entry. No terminal is needed to run the installed app. WebView2 may be downloaded during installation if missing.

`clean.bat` removes only `target`, `dist`, `coverage`, `.cache`, and `src-tauri/gen`. It rejects reparse points and paths outside the checkout. It leaves `node_modules`, private configuration, and benchmark history intact. Stop active development/build processes before cleaning.

## Your first tests

For your first measurement, open **Connection test**, keep **Response time (ping)** selected, and press **Start test**. The defaults already contain two test servers. Results explain response times and successful checks; **Save report** downloads a readable report. Server addresses, sample counts, and technical options are under **Advanced settings**.

For a separate test during traffic, open **Speed & load**, review the test size and data limit, then press **Start load test**. This can temporarily slow other network activity. Compare the response-time table across before, download, upload, and after phases. These tests measure your connection; automatic settings optimization remains unavailable.

## Failure recovery

| Error | Action |
| --- | --- |
| Missing Rust, Cargo, Node, npm | Install the prerequisite above, close the launcher, and reopen it |
| Missing C++ tools or Windows SDK | Modify Visual Studio Build Tools and select the C++ desktop workload |
| WebView2 unavailable | Install the Evergreen Runtime for your account |
| npm download failure | Check connectivity/proxy settings, then rerun setup; do not delete the lockfile |
| Port 1420 in use | Close the earlier development instance or the application using that port |
| Another development task is running | Close the GUI and its launcher, or wait for build/test/setup to finish, then retry. Each checkout runs one batch task at a time so npm cannot replace a loaded Tauri CLI |
| Unsupported config schema | Preserve the file and use a compatible application version; no downgrade is attempted |
| Database cannot be opened | Check permissions/free disk space in the data directory; preserve the database for recovery |
| Reparse point rejected during clean | Remove that specific link manually after confirming its target |

Application data defaults to `%LOCALAPPDATA%/estrogen-ping-patch`. `EPP_DATA_DIR` may specify an absolute private storage directory for testing. The development scripts do not parse `.env` files. Do not point application data at the repository or share diagnostic data publicly without review.

Run scripts from a terminal with `EPP_NO_PAUSE=1` to suppress the end-of-task prompt. Each script returns zero on success or a nonzero failure code. An error is never converted into a successful launch.
