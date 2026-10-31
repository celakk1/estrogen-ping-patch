# Development plan and acceptance tracking

The complete product scope is [the supplied master specification](specification.md), plus the Windows execution and private-repository requirements described in the README. A working baseline preview is a milestone, not completion of the optimizer.

The owner's clarified product direction is system-wide networking optimization with gaming responsiveness as a core constraint. There must be no required game selector or "boost this game" workflow. Use actual networking benchmarks rather than measuring ping inside games: unloaded RTT, jitter, protocol-specific loss, DNS, throughput, and loaded responsiveness across multiple benchmark endpoints. Do not require game integration or gameplay telemetry. Improvements must be demonstrated across the stable benchmark cohort, with regressions checked before retention; no universal improvement across every game or route may be assumed.

## Milestones

| Stage | Deliverables | State |
| --- | --- | --- |
| 1. Research and feasibility | Architecture, initial threat model, source verification, candidate registry | Initial documents written; mutation/provider feasibility gates remain open |
| 2. Application foundation | Tauri GUI, logical local service, config, SQLite, restricted MCP, launch/build/test/setup/clean/package | Implemented; validation evidence recorded separately |
| 3. Read-only diagnostics | OS, adapter identity, drivers, default routes, DNS, interface MTU/metrics | Basic discovery implemented; workload/policy/VPN/power/advanced capabilities remain |
| 4. Benchmarking | Multiple independent destinations, raw samples, quantiles, cancellation, progress, reports | TCP-connect and native IPv4/IPv6 ICMP echo paths implemented. Protocol-specific history/reports and error categories passed current packaged desktop checks. DNS, load, throughput, and provider discovery remain |
| 5. Safe optimization | Privileged Windows service, authenticated pipe protocol, allowlisted setters, checkpoints, verification, watchdog, restore | Manual snapshots/export, authenticated read-only LocalService process, durable checkpoint library, and protected service storage implemented. Simulated process-termination tests and extended service journal lab checks passed. Native setters/restoration, scoped authorization, and watchdog remain pending; system changes disabled |
| 6. Autonomous optimization | Repeated controlled sessions, confidence, practical thresholds, drift checks, bounded search, persistent schedules, ETA | Pending; baseline-only ETA implemented |
| 7. AI/MCP | Restricted read-only/proposal tools, optional local/cloud providers, secure credentials, budgets, deterministic fallback | Read-only MCP subset implemented; inference/proposals pending |
| 8. Production hardening | Lab failure matrix, recovery, performance, installer/upgrade validation, signing if available | Basic installer install/shortcut/GUI/uninstall smoke tested; lab recovery, upgrade testing, and signing remain pending |

## Acceptance evidence required

1. Read-only inventory: compare Windows cmdlets and GUI data on Ethernet, Wi-Fi, virtual adapters, VPN, IPv4-only, dual-stack, and multiple-interface machines.
2. Measurements: deterministic adapter tests plus permitted live checks for latency, jitter, loss, loaded responsiveness, throughput, and errors across independent providers. Protocol labels must match actual measurements.
3. Optimization: real supported candidate application, effective-value readback, repeated matched sessions, baseline drift rejection, statistically and practically justified retention, and exact verified rollback.
4. Recovery: service and desktop crash injection, service restart, reboot, connectivity failure, disk-full and locked-database cases, operation deadlines, and manual offline restore.
5. AI: invalid proposal rejection, no arbitrary commands/files/endpoints, expiring authorization, disabled/local/cloud/automatic modes, secure secrets, budget/rate limits, and deterministic continuation on provider failure.
6. Scheduling: persistent immediate, timed, recurring, idle/AC-only sessions, stop time, metered/cellular safeguards, resource-aware pauses, and byte/bandwidth/provider budgets.
7. UX: all three profiles, configurable duration, actual live progress and adaptive ETA, experiment explorer, settings, reports, JSON/HTML exports, and honest inconclusive/no-improvement outcomes.
8. Delivery: six functional batch files, clean-clone setup and launch, release executable and installer, shortcut-based terminal-free launch, safe cleanup, automated CI, private GitHub main with verified expected files, and a staged secret scan before commits.

## Contributor workflow

Use camelCase variables, functions, and fields except externally mandated names. Preserve Rust type/module/constant conventions and serialize public JSON as camelCase. Comments must be minimal and lowercase. No emojis in workspace files or commit messages. Preserve unrelated changes and avoid broad formatting/refactoring.

Current measured evidence and its limits are recorded in [validation](validation.md).

Run `test.bat`, `build.bat`, and `package.bat` as appropriate. Inspect the complete staged diff and run `node scripts/scan-staged.mjs` before a meaningful validated milestone commit. Never commit secrets or private runtime data. Do not mark unfinished requirements complete because compilation or unit tests pass. Do not publish releases automatically.
