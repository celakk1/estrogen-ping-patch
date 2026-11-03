# Bounded transfer worker

## Status and purpose

This is the implementation direction for production loaded measurement isolation. The owned-process streaming primitive and the core's explicit bound-transfer runner contract are implemented. The current load collector still invokes the in-process core transfer implementation; restricted process/token/input/protocol delegation remains unfinished and production optimization remains disabled.

Native route, adapter, policy, checkpoint, watchdog, and journal ownership stay in the service. HTTP/TLS parsing must run in a separately bounded worker with no setting, authorization, journal, arbitrary-command, or path capability. The core session observer can keep its bounded source-bound echo sampling while delegating only `TransferPlan` plus its frozen `SourceBinding` to this worker. Manual desktop diagnostics retain their existing implementation.

## Required execution boundary

- The core now provides `BoundTransferRunner` and `runSourceBoundSessionWithRunner`. Existing entry points retain the direct runner and raw serialization. The new entry point validates all bindings before invoking a runner, forwards the exact plan/source/peer and cancellation/progress objects, and rejects returned plan/provider/binding drift. Runner errors remain phase errors in the returned raw run without a direct-HTTP fallback. This contract is not itself a process boundary or a complete untrusted-result validator.
- Launch only the known service worker image and fixed typed mode. Job assignment must remain atomic at process creation, with kill-on-close, one active process, no breakaway, and verified termination before a returned result is admissible.
- Create a restricted primary token rather than inheriting service authority. Disable administrative identities and privileges, apply a restrictive SID list and low integrity, and validate the resulting token in the worker. Fail closed without an unrestricted fallback.
- Keep recovery and authorization storage inaccessible to the restricted worker. Test actual access denial, not only token flags. Existing installed binary permissions grant authenticated users read/execute; this does not grant them access to the protected recovery directory.
- Provide a minimal environment and fixed system working directory. Do not pass the service's environment, credentials, private configuration, journal handles, job handle, or pipe-reader handle to the worker.
- Apply job UI restrictions as well as the process-count limit. No benchmark worker needs desktop handles, clipboard access, or Windows configuration controls.

Microsoft documents that [restricted tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/restricted-tokens) require both ordinary and restricting-SID access checks to succeed. [`CreateRestrictedToken`](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken) can disable SIDs and privileges; its maximum-privilege flag preserves change-notify privilege. [`CreateProcessAsUserW`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw) supports a restricted version of the caller's primary token. These API contracts do not prove this application's isolation, network compatibility, or installed-service behavior; those require actual Windows checks.

## Input and result protocol

Use one bounded, immutable typed request per process. It contains the schema, transfer plan, and exact local-source/numeric-peer binding, not a shell command or an entire application configuration. Keep request data out of command-line arguments and temporary user-owned files. Pass only the specific input capability and output writer through the existing explicit inheritance list.

An anonymous memory mapping is a possible request transport, but it needs verified read-only rights and a descriptor suitable for the restricted token. Do not treat a read-only duplicate alone as an immutable security boundary: [`DuplicateHandle`](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle) can grant additional rights for some object types. Check write mapping, rights escalation, and descriptor-change refusal in the actual child before relying on this transport. The parent retains its independent frozen request and validates the result against it.

Return bounded versioned frames for changed transfer counters and one terminal result. Validate frame order, counter monotonicity, stream/request ceilings, payload limits, result identity, and final peer/source before updating the parent observer. Polling alone must not fabricate progress; no unchanged-counter heartbeat should conceal a blocked TLS or HTTP worker. Counter delivery delay and execution-policy provenance must be represented in the trusted measurement context before a process-backed runner supplies comparison evidence; delayed counters are not automatically equivalent to the current shared atomics. Preserve incomplete raw evidence when a worker stops, while refusing it for comparisons.

The parent enforces its phase/session deadline and cancellation independently of the worker's runtime or HTTP timeout. Receiving a terminal frame is insufficient: require valid framing, zero exit, verified job quiescence, and the existing native and durable measurement admission checks. On worker failure, never retry an endpoint, bind another source, accept cached summaries, or enlarge the approved traffic budget automatically.

## Validation still required

Use bounded loopback fixtures for source-bound IPv4/IPv6 downloads and uploads, stalled requests, cancellation, malformed/flooded output, consumer failure, and parent death. Verify the restricted child cannot modify its request, access protected service files, reopen privileged parent handles, create descendants, or regain its original token. Test a genuinely successful TLS path separately; a refused self-signed certificate alone is insufficient.

Installed LocalService and recovery-account behavior, client Windows versions, TLS/ICMP compatibility, physical adapters, actual provider eligibility, and interrupted raw-data persistence remain unverified. Hosted CI currently cannot start because of the account-level billing/spending refusal recorded in [validation](validation.md); do not substitute hosted success from an earlier revision for these remaining checks. Do not install a service or change development-machine network settings to bypass those limits.
