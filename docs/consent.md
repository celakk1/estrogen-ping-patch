# MTU trial consent

The service library includes `MtuConsent`, a preview-and-approval controller for temporary MTU trials. It does not expose a production pipe operation or enable settings changes in the desktop. The normal installed service still accepts only read-only status requests.

## Reviewed scope

A preview contains a random identifier, the exact version-four checkpoint hash, adapter GUID and OS/driver context, address family, original/proposed MTU, preview expiry, and trial expiry. Preview lifetime is at most thirty seconds and cannot exceed the trial lease. Retention permission is always false; keeping a setting requires a separate future approval flow.

Only one preview can await approval in a controller. It owns the original checkpoint; editing the returned preview cannot change that original. Approval requires the matching preview identifier and checkpoint hash from the same Windows owner. Cancelling, expiry, clock rollback, or a new controller instance makes the old identifier unusable. A monotonic deadline and the highest observed wall-clock time prevent old approval from being revived by a clock change, including after a rejected attempt to replace a pending preview.

The owner and actor SIDs are trusted service inputs, not identity evidence supplied in request JSON. Production integration must use the pipe caller authenticated by Windows. The current native lab uses its already validated SCM owner; that fixture does not establish human consent.

## Grant and recovery boundaries

Creating a preview issues no grant. A valid approval consumes the pending preview before recording an exact, non-retaining grant through the protected authorization store. If recording fails, the same approval cannot be retried; another explicit preview and approval are required. The authorization store's unique checkpoint binding prevents silently issuing another grant when a previous commit actually succeeded.

A preview is not a durable backup. A recorded grant is permission, not proof of a setting change or successful restoration. The existing coordinator must still persist and verify the exact original and apply intent before any write, check live authorization, track the command process, and verify readback and recovery. Restoration remains independent of the approval controller and expired or revoked apply grants.

## Integration and limits

The owned-loopback lab now obtains grants through preview and approval for both single and repeated trials. It immediately approves its own fixed fixture scope after SCM and target admission. There is no production auto-approval path, mutation IPC, arbitrary command, registry path, executable, or endpoint added by this change. Older grant storage remains readable; the preview controller itself admits only version-four policy-bound checkpoints.

Six focused tests cover exact scope and returned-data tampering, user/identifier/hash mismatch, cancellation, wall/monotonic expiry, clock rollback, restart, failed grant commits, single-use approval, and trial-lease bounds. Production authenticated IPC, asynchronous preview capture, desktop review, deterministic candidate admission, privileged execution, retention approval, and physical-adapter recovery remain unfinished.
