# Operation authorization

The service library records expiring MTU grants for one exact native checkpoint, Windows user SID, adapter GUID, OS/driver context, address family, and candidate value. The installed service can now record or revoke temporary grants through authenticated MTU preview operations. It exposes no setting mutation operation or AI permission tool. Normal application builds still permit no setting changes.

Its [MTU consent controller](consent.md) binds a single-use, expiring preview to the exact checkpoint hash before issuing a temporary, non-retaining grant. The normal pipe handler obtains the actor SID from Windows impersonation and feeds an asynchronous worker; the client cannot supply an original snapshot or claimed identity. The native lab separately exercises the controller after its existing SCM/target checks. Desktop command bindings exist, but a completed review UI, session-wide consent, and production execution remain unfinished.

## Grant scope and lifetime

A grant contains a random identifier and service-instance identifier, the exact checkpoint SHA-256 used by the recovery journal, the approved operation scope, an expiry, and a separate retention permission. Checkpoint preparation and apply admission are recorded. Apply requires a durable claim; claiming permission is not evidence that a setting was changed. Retention requires its own permission and remains prohibited in the native lab.

Checks reject a different caller, checkpoint, original snapshot, adapter, OS/driver context, family, value, or expiry. Wall-clock expiry, a monotonic deadline, and the highest observed timestamp prevent permission from being extended by clock changes within the issuing instance. Reopening the store creates a new instance identifier and invalidates old grants for new writes. A restart can recover existing work but requires fresh explicit approval before another experiment. A checkpoint identifier cannot receive a second grant.

The actor SID is supplied by trusted service code. The native lab uses its SCM-owned, explicitly configured owner. This is not an authenticated production consent flow: future IPC issuance must use the verified pipe caller and deterministic candidate/policy validation. Model output, a saved snapshot, or a claimed SID in JSON cannot authorize an operation.

## Storage and revocation

`authorization.sqlite3` is separate from `recovery.sqlite3`. It has its own application identifier and schema version two, WAL mode, FULL synchronization, immutable hashed grant documents, and chained audit events. Grant documents and events are limited to 4 KiB, grants to 2,000, and events to 64 per grant. Session approval records are limited to 64 KiB and 2,000 records; their trial links also remain bounded by the grant capacity. One event slot is reserved for revocation. Storage or claim failures block a new write; records are never silently overwritten or discarded.

The lab opens the fixed file through its service-owned directory capability, verifies exact file permissions and owners, rejects reparse points and hard links, and retains directory handles. Its permissions match the protected recovery storage. Hashes detect damaged records; filesystem access controls establish who can modify them.

An owner can revoke an issued or claimed grant. Revocation is committed and read back before it is reported as durable. The issuer also latches a valid revocation request in memory, so a failed commit blocks that process without pretending the record was saved. A fresh process cannot reuse the old instance's grant. Independent connections observe committed revocation, including during a running native command. Read checks do not append audit events on every polling iteration.

## Durable session audit

Authorization database version two adds session approval records and ordered grant links. The first trial atomically commits its complete reviewed scope, approval time and Windows owner, grant, initial grant event, and link. Subsequent trials must match the same immutable record and service instance. Their persisted count cannot exceed the reviewed block count. Each version-two grant names its session approval; missing, changed, misordered, over-budget, or incorrectly bound audit evidence blocks reads and authorization. Operation-level grants retain their existing version-one payload and bytes.

The approval record preserves the exact scope-hash preimage: MTU preview, complete repeated-trial plan, and maximum individual lease. The store verifies its checksum, bounded payload, basic scope/time limits, service-instance identity, and grant relationships. Full plan and trusted collector validation happens in the typed session controller before delegation. These records are audit evidence, not a restorable network backup or an authority that can resume work after restart. No session approval IPC or production setting execution is enabled.

Migration validates all existing grants/events and database integrity before committing schema two. It preserves their exact serialized bytes and creates no approval or delegation for legacy operations. Corrupt records and orphaned audit events leave the migration uncommitted. Older service builds refuse this newer authorization database; preserve it and use the current build rather than changing its version manually. Recovery journal version four and pipe protocol three are unchanged.

## Recovery independence

Restoration requires the verified original checkpoint and adapter context, not a valid apply grant. Pending recovery is selected before the lab opens authorization storage. An expired or revoked grant, a missing issuer instance, or unavailable authorization storage must not block exact-value restoration. The native writer requires a live permission callback for a candidate and permits authorization-independent recovery only to the captured original value. Stop, deadline, and permission failures terminate and reap the command before coordinator recovery continues.

Tracked version-three checkpoints also require the [registered predecessor exit barrier](mutators.md) before recovery observes or restores an adapter. This gate uses the recovery journal and exact process creation time, independently of grants. Unavailable recovery evidence or a failed restoration-process registration blocks the write and leaves the checkpoint unresolved.

## Validation status

Ten local tests cover exact journal binding, cross-user/adapter/value/original refusal, persisted claims, retention limits, revocation across connections and clock rollback, restart invalidation, checkpoint replay, wall/monotonic expiry, failed issue/claim/revocation commits, audit capacity, changed/missing events, future-schema refusal, and separation from a corrupted authorization store. The feature-enabled service tests and Clippy also passed locally.

At `e375d26`, the [disposable Windows run](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41246725980) passed 59 feature-enabled Rust tests, five safe harness tests, Clippy, and ten native trials. Revoked permission and an unavailable authorization path did not prevent exact IPv4/IPv6 restoration. The safe PowerShell fixture test verifies exact database-byte preservation, untouched sidecars, and collision refusal without running a service or changing networking.

The command-lifetime revision creates each setting process suspended inside an anonymous kill-on-close job, with only its null input/output handle inherited. Permission is checked again before resuming. Success, cancellation, and deadline paths terminate the job and require zero active processes before returning. Unconfirmed termination latches a service-instance failure that blocks new writes and coordinator observations, preserving unresolved recovery work. A local regression first demonstrated that the previous child outlived its owner; the revised process fixture verifies termination before execution and during execution, including a descendant. The [final native command run](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41262368831) at `b4b733d` passed 62 feature tests, Clippy, and all ten native trials with explicit process-exit verification. Service death during an actual in-flight native operation, independent watchdog, production consent, retention-policy, physical-adapter, and reboot validation remain separate gates.
