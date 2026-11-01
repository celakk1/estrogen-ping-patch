# estrogen ping patch

A local Windows network experimentation application built with Rust, Tauri 2, React, and TypeScript. Measure, experiment, validate, retain or revert. Lower ping is an experimental outcome, never a promise.

## Development status

This is an early development build. It provides read-only network discovery, bounded TCP connection, IPv4/IPv6 ICMP echo, and direct DNS A/AAAA baselines across multiple destinations, plus bounded HTTP download/upload sessions with concurrent latency and recovery probes. It includes cancellation, live progress, local SQLite history, JSON/HTML reports, local network settings snapshots with SHA-256-verified JSON exports, and a read-only MCP stdio interface. It preserves the existing network configuration. Automatic snapshot restoration is not implemented.

A separate Windows service provides authenticated local status reporting, with optional installation and management from **Safety & privacy**. It runs as LocalService, accepts no network setters, and is not needed for diagnostics or backups. Protected service-owned recovery journal storage verifies checkpoint integrity and detects incomplete work at startup. Disposable Windows CI passed storage permissions, simulated pending-checkpoint detection, corrupted-storage refusal, restart, and journal preservation across service removal/reinstallation. Automatic network modifications, operation authorization, controlled optimization, native crash rollback, broader provider support, scheduling, and optional inference providers remain under development. See [implementation plan](docs/development.md) and the [full specification](docs/specification.md).

Backup exports additionally preserve native IPv4/IPv6 interface fields with GUID/LUID checks and OS/PnP-driver context. Missing context and persistent-store/restore limits remain explicit. These diagnostic snapshots do not enable automatic restoration or settings changes.

The service recovery library now coordinates native-evidence MTU checkpoints, write intent, readback, and exact-value recovery through a typed backend contract. Simulated-adapter tests cover interrupted writes, authorization revocation, outside changes, and failed journal writes. The running service has no native setter/backend or recovery watchdog yet; these tests do not establish native adapter restoration.

A separate, disabled-by-default [native MTU lab](docs/native-mtu-lab.md) passed ten owned-loopback trials on a disposable hosted Windows runner: normal apply/restore, process termination after apply/restore, revoked permission, and unavailable authorization storage, for IPv4 and IPv6. Exact original MTU, unrelated fields, persistent policy, and DNS origin values were verified afterward. The lab is excluded from ordinary launch/build/package workflows and does not enable optimization in the application.

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

The optional service has separate `install-service.bat` and `uninstall-service.bat` helpers. Service management requests its own Windows administrator approval; `launch.bat` and the desktop remain unelevated. Uninstall the service through **Safety & privacy** before uninstalling the desktop. See [service management and trust boundaries](docs/service.md).

## Networking baselines

Open **Network tests**, select **Connection test**, and choose what to check: **Ping (response time)**, **Opening a connection**, or **Finding a website (DNS)**. Ping is selected initially: review the named servers and time allowance, then press **Start test**. No traffic runs until you start. The results explain each measurement and show successful checks per server; expand **Technical details** for raw statistics. Use **Save report** for a readable HTML report or **Export raw data (JSON)** for the raw data.

**Advanced settings** contains sample counts, time limits, and custom destinations. TCP/DNS targets use numeric `IP:port` addresses; ICMP targets use numeric IP addresses without a port. IPv6 link-local echo targets require a numeric interface scope, such as `fe80::1%12`. Starting a baseline sends only the selected bounded probes. Default public resolver addresses do not represent every internet route. TCP and ICMP do not measure DNS lookup performance.

ICMP reports Windows' whole-millisecond RTT separately from TCP connect time and API call duration. Raw zero RTT is displayed as `<1 ms`. Timeouts, IP errors, system errors, and invalid replies remain distinct; timeout percentage is unavailable if non-timeout errors prevent a clean estimate. ICMP may be filtered or rate-limited and is not application packet loss. Automatic optimization remains unfinished. No game selection, game launch, or in-game telemetry is required.

DNS benchmarks send the chosen query name directly to each resolver over UDP with TCP fallback. Successful lookup timing, negative answers, timeouts, and system errors remain separate. Resolver cache state is unknown, and AD is resolver-reported rather than independently validated DNSSEC. Windows DNS settings stay unchanged. See [DNS behavior and limitations](docs/dns.md).

Under **Network tests**, choose **Speed test**, review **Test size**, the providers and data limit, then press **Start speed test**. The default Quick test requests 16 MiB down and 4 MiB up per provider, about 21 MB of payload in total. The four stages measure responsiveness before downloading, during download, during upload, and afterward. Results show download/upload speed in Mbps and a side-by-side response-time table in ms. **Advanced settings** exposes custom providers, exact payload sizes, parallel streams, and probe targets.

The form supports Cloudflare's documented transfer endpoints plus an optional user-owned server, with one to four parallel HTTP/1.1 streams. Starting explicitly sends synthetic traffic and shares your IP with selected providers. Payload and time limits are enforced, and raw stream outcomes, peer addresses, and concurrent TCP/ICMP samples are saved separately from unloaded baselines. Goodput includes connection setup and server time; it is not a link-capacity estimate or the provider website score. Short transfers may provide insufficient concurrent samples, and saturation is not guaranteed. See [providers and methodology](docs/providers.md) and the [owned-server protocol](docs/transfer-protocol.md). Independent public discovery, NDT7/iperf3, sustained/bidirectional testing, utilization, and repeated-session comparisons remain unfinished.

Application database version five supports protocol-specific reports and separate load sessions while retaining earlier baseline history and configuration snapshots. Older previews refuse this newer database. Use the current application to read it; do not downgrade the database version manually. The dedicated service journal has its own independent schema.

## Privacy and safety

- No telemetry, advertising, or automatic cloud inference.
- No network measurement traffic until the user starts a baseline or load session.
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
- [Operation authorization](docs/authorization.md)
- [Research sources](docs/research.md)
- [Direct DNS benchmarks](docs/dns.md)
- [Transfer providers and methodology](docs/providers.md)
- [User-owned transfer protocol](docs/transfer-protocol.md)

## License

MIT, selected by the project owner. See [LICENSE](LICENSE). Private repository visibility and software licensing are independent.
