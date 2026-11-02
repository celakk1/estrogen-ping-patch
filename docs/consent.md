# MTU trial consent

The service library includes `MtuConsent`, a preview-and-approval controller for temporary MTU trials. The normal installed service now exposes authenticated preview, approval-recording, status, and cancellation operations through the version-three pipe. These operations can write private permission records, but cannot change Windows network settings. Desktop command bindings are present; the review screen and autonomous session workflow remain unfinished.

## Reviewed scope

A preview contains a random identifier, the exact version-four checkpoint hash, adapter GUID and OS/driver context, address family, original/proposed MTU, preview expiry, and trial expiry. Preview lifetime is at most thirty seconds and cannot exceed the trial lease. Retention permission is always false; keeping a setting requires a separate future approval flow.

Only one preview can await approval in a controller. It owns the original checkpoint; editing the returned preview cannot change that original. Approval requires the matching preview identifier and checkpoint hash from the same Windows owner. Cancelling, expiry, clock rollback, or a new controller instance makes the old identifier unusable. A monotonic deadline and the highest observed wall-clock time prevent old approval from being revived by a clock change, including after a rejected attempt to replace a pending preview.

The owner and actor SIDs are trusted service inputs, not identity evidence supplied in request JSON. The pipe handler supplies the actual Windows token SID after authenticating the caller. Request bodies accept no actor/owner SID, original snapshot, command, registry path, or endpoint. The native lab separately uses its already validated SCM owner; that fixture does not establish human consent.

## Grant and recovery boundaries

Creating a preview issues no grant. A valid approval consumes the pending preview before recording an exact, non-retaining grant through the protected authorization store. If recording fails, the same approval cannot be retried; another explicit preview and approval are required. The authorization store's unique checkpoint binding prevents silently issuing another grant when a previous commit actually succeeded.

A preview is not a durable backup. A recorded grant is permission, not proof of a setting change or successful restoration. The existing coordinator must still persist and verify the exact original and apply intent before any write, check live authorization, track the command process, and verify readback and recovery. Restoration remains independent of the approval controller and expired or revoked apply grants.

## Integration and limits

The owned-loopback lab obtains grants through preview and approval for both single and repeated trials. It immediately approves its own fixed fixture scope after SCM and target admission. The normal service instead captures a requested GUID/family itself, verifies complete native policy evidence, and waits for a matching authenticated approval request. Approval is consumed before opening grant storage; failed initialization cannot leave a reusable approval. Older grant storage remains readable; new previews admit only version-four policy-bound checkpoints.

The worker runs one job with one queued command and releases its state lock during provider/storage work. Status and cancellation remain responsive during capture. Cancelling approval either prevents grant creation or durably revokes a grant that committed while cancellation arrived. A failed revocation stays failed with its grant evidence retained. New work is refused until the current preview/approval is cancelled; unfinished recovery also blocks capture and grant issuance. The original backup is not committed by this preview path.

The CLI developer interface is `--preview-mtu GUID ipv4|ipv6 MTU LEASE_MS`, `--preview-status JOB_ID`, `--approve-mtu-preview JOB_ID PREVIEW_ID SHA256`, and `--cancel-mtu-preview JOB_ID`. Every result reports `executionAvailable: false`. Leases are bounded to 5..300 seconds and proposed MTUs to 1280..65535, strictly below the captured original. These are proposal inputs, not recommendations or enabled candidates. No setter, arbitrary command, registry path, executable, endpoint, or auto-approval path is exposed.

Tests cover exact scope and returned-data tampering, user/identifier/hash mismatch, cancellation, wall/monotonic expiry, clock rollback, restart, failed grant commits, storage initialization delay, single-use approval, and trial-lease bounds. Real-pipe tests use the actual Windows caller with simulated capture/storage fixtures. Installed-service positive capture and grant storage, desktop review, session-wide consent, deterministic candidate admission, privileged execution, retention approval, and physical-adapter recovery still require implementation or validation.

This per-checkpoint controller does not replace session-wide consent. The autonomous application still needs approval of a bounded experiment plan so it can issue permitted trial grants without asking the user to approve every measurement or repeated bracket. Keeping a winning setting requires separate retention permission. The operation-level preview must not be presented as a finished autonomous optimizer.

The service workflow additionally runs `scripts/service-preview-smoke.ps1` on its own fresh hosted Windows runner. This harness creates and removes only its owned Microsoft loopback adapter, installs the ordinary LocalService binary, and checks positive preview, exact approval, durable grant revocation, and restart invalidation for both address families. It compares native context, registry origins, and active/persistent policy before and after approval and revocation. No MTU setter is called. The harness refuses development-machine execution, pre-existing service/storage, or a pre-existing Microsoft loopback device. Results remain pending until the corresponding hosted job succeeds; this does not validate production setting changes or physical-adapter recovery.
