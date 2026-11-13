# Incremental load recordings

The disabled-by-default adapter-bound load collector saves a durable header before traffic and appends each session progress callback to SQLite. This closes the gap between starting measurement and saving its final raw report. It does not enable application optimization, resume interrupted work, or restore settings.

## Evidence and lifecycle

The header freezes the experiment, selected configuration, source bindings, providers, latency destinations, metric selections, native policy/routes, application version, and candidate checkpoint reference. The owner identity includes its PID and Windows creation time. Starting another recording requires a valid durable application database and no unfinished recording with a live or unverifiable owner.

Each committed event contains its sequence, parent capture time, phase, counters, and optional raw probe. Typed JSON, SHA-256 chains, exact readback, monotonic phase/time/counter checks, and frozen traffic ceilings detect accidental changes and incomplete writes. These hashes are integrity checks, not authentication against someone who can rewrite the database. The future production caller must supply protected storage.

The extension uses `adapter_load_recordings` and `adapter_load_recording_events` in the version-six application database. Writes require WAL, full synchronous commits, and foreign keys. It does not share or modify the service-owned recovery checkpoint schema. History reads use one transaction so a concurrent append cannot mix different committed states.

On normal return, the final raw report and recording completion commit in one transaction. The report must match the frozen context and every previously saved probe. A cancelled or failed report may preserve additional samples collected after recording failed, but cannot alter or remove the saved prefix. A completed report must have exactly the recorded samples. Finalization means the report was saved; native receipts and comparison admission remain separate checks.

On initialization, an unfinished recording is validated before its owner is inspected. An exact live identity or uncertain access blocks new recording. A dead owner or reused PID marks the record interrupted, preserving the committed prefix. It issues no grant, setting command, traffic, or recovery claim. An uncommitted SQLite tail is discarded by SQLite; the application does not reconstruct it.

## Limits and measurement context

- Header: 1 MiB; event: 16 KiB; at most 4096 events.
- Header plus event payloads: at most 8 MiB; final raw report: at most 8 MiB.
- At most 2000 recordings; no automatic deletion or capacity bypass.
- History: at most 100 recordings and 32 MiB of header, metadata, and event payloads per request. An oversized request fails with instructions to request fewer records.
- Bounded failure details contain at most 512 characters with control characters removed.

Appending validates only the next event and cached state, then verifies its committed bytes. It does not reread the entire chain for every probe; full-chain verification happens on history reads and closure. Disk commits happen synchronously after sampling and can change pacing. The collector uses `recordedRestrictedWorkerV4` in its comparison cohort, including the five [reported adapter count guards](comparisons.md#reported-adapter-count-guards) and frozen reported link context. The underlying worker retains parent-owned [system CPU boundary snapshots](benchmark-worker.md#system-cpu-boundary-evidence), and now uses an [owned HTTP/1.1 transport with per-socket TCP evidence](benchmark-worker.md#owned-http-and-socket-tcp-evidence). Unrecorded worker runs cannot be mixed into that cohort. Earlier version-one/two/three recordings remain readable with their original execution/cohort identity, while current trial admission requires version four.

The journal stores session callbacks, not every packet or counter change. A process crash can lose observations since the last committed callback and the unsaved final report. An event's old active-request count does not establish current worker liveness. Recorded diagnostics are not sufficient overlap, saturation, accepted throughput, stable-path, or optimization evidence.

## Validation and remaining work

Local tests exercise close/reopen, live-owner refusal, PID reuse, malformed or altered chains, storage durability refusal, bounds, atomic final-report failure, changed/missing probes, and final raw corruption. Synthetic writer processes are killed after committed progress and while holding an uncommitted tail; reopening preserves exactly the committed prefix and marks the recording interrupted without resuming it.

These are storage and process-owner tests. They do not establish installed-service crash recovery during a physical-adapter experiment, LocalService/System behavior, power-loss durability, disk hardware guarantees, or measured performance. Separate restricted-worker loopback tests cover actual traffic and termination. Production consent, service lifecycle, recovery, and optimization integration remain unfinished.
