# Architecture and feasibility

## Design

The target architecture has four trust domains: the unelevated Tauri desktop, a bounded benchmark/experiment worker, a dedicated privileged Windows service, and an unprivileged MCP/inference component. SQLite records raw evidence separately from decisions. The GUI and inference component cannot execute arbitrary commands or mutate system settings.

The product optimizes the machine's shared networking configuration. Its main workflow is inspect, measure, experiment, verify, then retain or restore. Gaming responsiveness, stability, and reasonable throughput are constraints throughout; users must not select a game to activate optimization. Do not build a game-selection or game-boosting flow. Measure the network directly through protocol-aware benchmarks across gateway, regional/external, DNS, and supported transfer endpoints, including unloaded and loaded latency. Do not require game launches, in-game ping, hooks, or gameplay telemetry. Benchmark results describe their tested routes/protocols rather than every game server. Validation targets must remain stable across matched experiments.

The current implementation includes the desktop, a local read-only application service owned by Tauri, a cancellable worker, a standalone MCP stdio mode, and an optional dedicated Windows service with authenticated status requests. The Windows service runs as LocalService and currently exposes no settings writes. Network modifications remain unavailable until scoped operation authorization, durable checkpoints, verified setters, watchdog, and recovery tests exist.

The transfer worker runs a bounded per-phase asynchronous HTTP client on a separate thread while the session observer reuses native TCP/ICMP probes. One to four HTTP/1.1 streams share a per-direction payload budget and deadline. Samples record request overlap and actual application payload progress; summaries do not infer saturation. Provider adapters construct fixed protocol paths from validated server origins. Transfer sessions use their own version-five database table and desktop history/report flow; DNS and unloaded baseline semantics remain unchanged. See [providers](providers.md).

Connection tests additionally capture [native local route evidence](routing.md) around measurement. The unelevated desktop uses the existing service library's read-only Windows APIs, preserving GUID/LUID/source/prefix/next-hop evidence in optional baseline metadata. This does not add a service pipe operation or establish complete environment/configuration coverage for the experiment engine.

The separate [IPv4 packet-size diagnostic](packet-size.md) binds do-not-fragment requests to the source chosen by Windows, saves native route/adapter evidence before and after, and requires controlled explicit size errors before confirming a boundary. It adds no privileged operation or enabled optimization candidate.

## Runtime paths

`launch.bat -> scripts/dev.ps1 -> epp-check -> tauri dev -> Vite + desktop`

On desktop startup, the local service validates configuration, opens the SQLite database, records a startup event, and registers bounded application commands. Network discovery executes a fixed, embedded, read-only PowerShell script through the Windows system executable. No caller input is interpolated into that script. Discovery has a 30-second deadline and bounded output. The worker performs real timed TCP connects or native IPv4/IPv6 ICMP echo requests to user-confirmed numeric endpoints, emits live progress, supports cancellation, and saves results transactionally. A baseline cohort uses a single protocol; mixed protocols and equivalent duplicate targets are rejected. Native echo handles are reused within a run and closed independently of the optional Windows service. Cancellation is checked before each probe and during pacing; an in-flight synchronous probe is bounded by its at-most-five-second timeout. Closing the desktop cancels an active run and waits for it to save before exiting.

The manual backup workflow captures inventory and supported settings, commits an immutable document and SHA-256 transactionally, and verifies the exact document bytes before export. Settings capture has a 60-second deadline, bounded output, and cancellation. Database schema version two adds snapshots without altering existing benchmark history. These snapshots expose unavailable sections and do not enable restoration. See [backup gates and limitations](backups.md).

The dedicated service independently opens `%ProgramData%\estrogen-ping-patch-service\recovery.sqlite3` before reporting Running. Its service-specific token SID, protected directory, exact file ACLs, and journal integrity must validate first. Status exposes startup verification time and pending checkpoint count; no checkpoint mutation or network operation is available through IPC. The separate journal library persists original MTU plans and verified transition history for future recovery. Native operation semantics, authorization grants, and an independent restore/watchdog backend remain required before any setter can be enabled.

`estrogen-ping-patch.exe --mcp` runs JSON-RPC over stdio without opening the GUI. The MCP client owns that subprocess and its lifecycle. No TCP listener or privileged access is granted to it. The desktop and preflight initialize the same MCP handler; inference remains disabled.

## Component choices

| Component | Choice and reason | Constraint |
| --- | --- | --- |
| Desktop | Tauri 2 with React and TypeScript; native WebView2 host | Windows development needs MSVC/SDK/WebView2 |
| Styling/chart | Local CSS and SVG; no remote fonts, chart SDK, or analytics | Baseline plots cover TCP, ICMP, and DNS; transfer reports keep per-phase measurements separate |
| Core | Rust; same measurement, statistics, validation, and persistence code in tests and desktop | Blocking OS work is kept off the GUI thread |
| Database | Bundled SQLite through rusqlite; transactions, WAL, FULL synchronous mode | End-of-run sample persistence currently loses an unfinished run on a process crash |
| Configuration | Versioned JSON, strict known-field validation with preservation of unknown fields | Future schemas are rejected rather than silently downgraded |
| IPC | Tauri commands and a local named pipe with explicit user/service ACLs, token identity checks, SCM PID/session checks, bounded messages and deadlines | Dedicated service protocol currently permits status only |
| MCP | Small explicit JSON-RPC stdio allowlist with 64 KiB frame bound | Read-only subset; no inference or proposal execution |
| Packaging | Per-user Tauri NSIS installer with separate optional service helper | Unsigned; service installation requests its own approval and must be removed separately |

## Privileged service feasibility gate

Implement only allowlisted typed operations, never a shell/registry escape hatch. Each request must carry schema version, target adapter GUID, bounded authorization, operation deadline, and request identifier. The service must verify caller identity and explicit pipe ACLs; default pipe security is insufficient. Remote pipe clients must be rejected. User authorization must be scoped, expiring, recorded, and revocable.

Before any setter is enabled: capture the effective original value, fsync a durable intent/checkpoint, apply the supported operation, read it back, check connectivity, and either retain after confirmation or restore and verify. A recovery path must work without the desktop, inference, or internet. Automatic adapter restarts require separate authorization and must account for VPN and remote administration. No mutation is feasible to enable safely before this gate is tested.

## Measurement validity

TCP connect time includes operating-system and handshake effects. Failure percentages refer only to attempted TCP connections. They do not establish ICMP loss, application packet loss, sustained throughput, loaded RTT, or DNS lookup time. Each run records configuration, application version, endpoints, timestamps, raw samples, errors, median, p95, p99, IQR, and successive connection-time variation. No confidence or improvement is inferred from one run.

ICMP uses synchronous Windows echo APIs with a fixed application-owned payload and bounded reply buffers. IPv6 link-local targets require an explicit numeric interface scope. Native RTT is recorded in whole milliseconds, independently of wall-clock API call duration. The GUI and HTML export display raw zero as `<1 ms`; this reporting unit is not a guarantee about clock accuracy. Reply, timeout, IP status, OS failure, unsupported operation, and invalid responder outcomes are separate. A timeout percentage is computed only when every attempted echo ended in a valid reply or timeout; other errors make it unavailable. These values do not establish application packet loss, loaded latency, or game-server performance. ICMP rate limiting and filtering must be considered before interpreting missing replies.

Direct DNS uses a bounded codec and connected UDP sockets, with one TCP fallback when a matching response is truncated. Each resolver receives the same explicit A/AAAA question. Only validated address resolution contributes to `lookupMs`; negative response arrival time remains separate. Answer TTLs, CNAME chains, response codes, transport, and resolver-reported AD are retained. Resolver cache state is unknown, and address-set changes are informational. See [DNS behavior](dns.md) for limits and remaining cache/DNSSEC validation gates.

Report database version six prevents older previews from misreading newer data and retains separate load-session and packet-check tables. New endpoint protocol metadata defaults to TCP when reading older records, and legacy socket address strings and TCP timing fields retain their meaning. ICMP and DNS records never populate `connectMs` or a TCP connection-failure percentage.

The [comparison library](comparisons.md) analyzes repeated matched session blocks with stable cohort/context binding, explicit practical and regression limits, baseline drift refusal, and paired resampling. Its reports are exploratory and cannot retain a setting. A separate [repeated-trial runner](repeated-trials.md) coordinates bounded matched sessions through a trusted host. Complete trusted environment capture, production experiment integration, load-session conversion, independent confirmation, and production policies remain unfinished. Server tuning recommendations are hypotheses, not consumer Windows defaults.

## Source-bound benchmark collection

The core now offers a separate source-bound ICMP collection path for future optimization sessions. It requires one ordered, explicit unicast source per endpoint and refuses wrong families, missing/reordered bindings, incompatible link-local scopes, and TCP/DNS cohorts. The ordinary manual benchmark path retains its existing Windows-selected-source behavior. This path records optional source bindings in raw benchmark payloads and includes them in a domain-separated comparison cohort hash; legacy payloads keep their original hash and serialization. Application database schema six is unchanged.

IPv4 uses the explicit source parameter of [IcmpSendEcho2Ex](https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2ex); IPv6 supplies the source sockaddr to [Icmp6SendEcho2](https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmp6sendecho2). Missing or unusable sources produce an error outcome rather than falling back to a different source. The source address alone does not prove adapter traversal, stable internet routing, or performance benefit. Optional internal [echo and load collectors](repeated-trials.md#service-host-contract) now bind before/after native policy and route evidence to raw sessions and exact candidate checkpoints. Loaded HTTP streams pin both their local source and numeric peer while retaining the provider origin for TLS. Production service storage/session/worker integration, complete profile guards, and physical-adapter validation remain unfinished.
