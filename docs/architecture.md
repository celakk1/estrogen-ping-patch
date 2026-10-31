# Architecture and feasibility

## Design

The target architecture has four trust domains: the unelevated Tauri desktop, a bounded benchmark/experiment worker, a dedicated privileged Windows service, and an unprivileged MCP/inference component. SQLite records raw evidence separately from decisions. The GUI and inference component cannot execute arbitrary commands or mutate system settings.

The current implementation includes the desktop, a local read-only application service owned by Tauri, a cancellable worker, and a standalone MCP stdio mode. These are useful running components, but they do not substitute for the privileged service. Network modifications remain unavailable until the service's authorization, authenticated named pipes, durable checkpoints, verification, watchdog, and recovery tests exist.

## Runtime paths

`launch.bat -> scripts/dev.ps1 -> epp-check -> tauri dev -> Vite + desktop`

On desktop startup, the local service validates configuration, opens the SQLite database, records a startup event, and registers bounded application commands. Network discovery executes a fixed, embedded, read-only PowerShell script through the Windows system executable. No caller input is interpolated into that script. Discovery has a 30-second deadline and bounded output. The worker performs real timed TCP connects to user-confirmed endpoints, emits live progress, supports cancellation, and saves results transactionally. Closing the desktop cancels an active run and waits for it to save before exiting.

`estrogen-ping-patch.exe --mcp` runs JSON-RPC over stdio without opening the GUI. The MCP client owns that subprocess and its lifecycle. No TCP listener or privileged access is granted to it. The desktop and preflight initialize the same MCP handler; inference remains disabled.

## Component choices

| Component | Choice and reason | Constraint |
| --- | --- | --- |
| Desktop | Tauri 2 with React and TypeScript; native WebView2 host | Windows development needs MSVC/SDK/WebView2 |
| Styling/chart | Local CSS and SVG; no remote fonts, chart SDK, or analytics | Current plots cover TCP connect latency only |
| Core | Rust; same measurement, statistics, validation, and persistence code in tests and desktop | Blocking OS work is kept off the GUI thread |
| Database | Bundled SQLite through rusqlite; transactions, WAL, FULL synchronous mode | End-of-run sample persistence currently loses an unfinished run on a process crash |
| Configuration | Versioned JSON, strict known-field validation with preservation of unknown fields | Future schemas are rejected rather than silently downgraded |
| IPC | Tauri commands now; authenticated named pipes required for privileged service | No privileged IPC implementation yet |
| MCP | Small explicit JSON-RPC stdio allowlist with 64 KiB frame bound | Read-only subset; no inference or proposal execution |
| Packaging | Per-user Tauri NSIS installer | Unsigned; service installation remains separate future work |

## Privileged service feasibility gate

Implement only allowlisted typed operations, never a shell/registry escape hatch. Each request must carry schema version, target adapter GUID, bounded authorization, operation deadline, and request identifier. The service must verify caller identity and explicit pipe ACLs; default pipe security is insufficient. Remote pipe clients must be rejected. User authorization must be scoped, expiring, recorded, and revocable.

Before any setter is enabled: capture the effective original value, fsync a durable intent/checkpoint, apply the supported operation, read it back, check connectivity, and either retain after confirmation or restore and verify. A recovery path must work without the desktop, inference, or internet. Automatic adapter restarts require separate authorization and must account for VPN and remote administration. No mutation is feasible to enable safely before this gate is tested.

## Measurement validity

TCP connect time includes operating-system and handshake effects. Failure percentages refer only to attempted TCP connections. They do not establish ICMP loss, application packet loss, sustained throughput, loaded RTT, or DNS lookup time. Each run records configuration, application version, endpoints, timestamps, raw samples, errors, median, p95, p99, IQR, and successive connection-time variation. No confidence or improvement is inferred from one run.

Future comparisons must use repeated sessions as independent units, stable endpoint cohorts, practical significance thresholds, baseline drift checks, and hard regression constraints. Server tuning recommendations are hypotheses, not consumer Windows defaults.
