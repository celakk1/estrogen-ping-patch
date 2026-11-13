# Incremental diagnostic recordings

The optional `experiment::candidate::diagnosis::recording::collect` entry point records the bounded multi-destination packet diagnostic in a supplied durable application database. It reuses the existing collector, native policy reader, and isolated route/packet workers. The normal service pipe and desktop do not expose it. No setting, grant, recovery command, or automatic optimization is enabled.

## Evidence and lifecycle

A checked header commits before native collection. It freezes the adapter GUID, destinations, shared duration/probe/IPv4-byte allowance, application version, execution method, recording UUID, and actual owner PID plus Windows process creation time. The original native policy and selected routes commit before the first target can start. Each target then commits its exact source-bound plan and remaining resource limits before its worker starts.

Validated samples append synchronously as they arrive. Each target's terminal report must exactly match its recorded samples and plan. Sequence, timestamps, DF/control/size semantics, fixed cohort and sources, per-target limits, and total requested traffic are checked. Recording failures cancel further collection; already checked raw observations may remain in the returned stopped result.

The final collection, including final native/routes evidence and an optional proposal summary, commits atomically with finalization. A completed collection requires every terminal report to have been recorded. A stopped collection may contain additional checked samples from the failed append, but it cannot remove or change the committed prefix. If a backend fails without returning a terminal report, its previously committed sample events remain available. Finalization means evidence was saved, not that a performance problem was demonstrated or that a setting can change.

Readback exposes `SavedCollection`, whose proposal is only a `Summary`. Runtime `MtuProposal` state cannot be deserialized from history. Reopened results issue no permission, setting operation, resumed traffic, or optimization decision. Raw completed evidence and its summary are checked again during readback.

Starting a recording checks unfinished work first. A live exact owner or uncertain owner lookup blocks another recording. A dead owner or reused PID permits marking the old recording interrupted after its full committed prefix validates. It does not recreate missing observations or resume work. A panic in a still-running owner can therefore leave work unfinished until the owner exits.

## Storage and limits

The extension uses `diagnostic_recordings` and `diagnostic_recording_events` in the version-six application database, separate from load recordings and the protected recovery journal. It requires WAL, full synchronous commits, and foreign keys. Only one unfinished diagnosis is allowed per database. The production caller must supply protected storage; the library's database handle does not authenticate the caller or storage owner.

- Header: 16 KiB; event: 128 KiB; at most 1200 events.
- Header plus event payloads: at most 4 MiB; final collection: at most 4 MiB.
- At most 500 recordings, with no automatic deletion or capacity bypass.
- History: one to fifty records and at most 32 MiB of payloads per request, read from one SQLite snapshot.
- Failure details: at most 512 characters, with control characters removed.

SHA-256 chains, strict typed JSON, compare-and-swap metadata, exact committed readback, and full replay detect changed or incomplete evidence. These checks are not authentication against someone who can rewrite the database and hashes. Append checks the new observation and cached state; full historical-chain verification happens on read and closure. A failed append cannot be retried through that recorder.

Synchronous disk commits can change pacing. Headers use the separate `recordedDiagnosticWorkerV1` execution method; recorded diagnosis is not timing evidence interchangeable with a manual or unrecorded run. A process crash can lose observations since the last successful commit and the final result. SQLite durability settings and killed-process tests do not establish power-loss or hardware guarantees.

## Validation and remaining work

Tests cover close/reopen, exact shared traffic limits, observer/write refusal, atomic final-commit failure, live-owner refusal, malformed and altered evidence, and read-only proposal summaries. Altered final proposals, samples, and byte counts are refused even when their storage checksums are recomputed. Synthetic owners are killed after committed samples and with an open uncommitted transaction; reopening keeps the committed prefix and discards the tail without issuing traffic or settings commands.

These are storage tests with simulated native capture/probe backends. They do not establish installed-service crash behavior during real public-path diagnosis, LocalService/System access, physical/client-OS compatibility, power-loss behavior, or networking benefit. Protected production storage, service lifecycle and review/session integration, complete problem/profile admission, matched confirmation, and production recovery/optimization remain unfinished.
