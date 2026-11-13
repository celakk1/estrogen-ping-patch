# Owned diagnostic workers

The optional `automatic-trials` service library runs candidate-diagnosis route capture and source-bound IPv4 packet probes in owned processes. The normal installed service and desktop do not expose this collection operation. Manual desktop diagnostics and the load collector's concurrent echo sampler retain their existing implementations. No setting, grant, journal, script, or arbitrary executable capability is added.

## Fixed process policies

The parent selects its own canonical service executable and one of two fixed modes. `--network-read-worker` accepts only one to eight distinct numeric route destinations and uses the existing low-integrity restricted token. `--packet-read-worker` accepts only a validated packet plan and resource limits, and uses a separate medium-integrity restricted token. Each mode rejects the other's operation and token policy before executing a request. There is no runtime retry with a less restricted token.

The separate packet policy follows a controlled local failure: an otherwise identical low-integrity restricted token returned Windows access denied from the native echo send path, while the medium-integrity version successfully sent source-bound loopback probes. This establishes compatibility on the tested Windows installation and account, not every Windows version or service account.

Both policies retain the same restrictive SID list, disabled administrative/System identities, and removal of privileges other than change-notify. Parent-token access must be denied before request parsing. The input mapping remains immutable, including refusal of duplicate-handle write expansion, DACL changes, and ownership changes. The child receives only its explicit input/output/NUL handles, a minimal environment, and a fixed system working directory. Atomic job assignment, one-process and 256 MiB commit limits, UI restrictions, and kill-on-close remain in force. The HTTP worker's low-integrity policy is unchanged.

## Bounded input and checked results

One schema-one request is sealed in a read-only anonymous mapping of at most 8192 bytes. Strict decoding rejects missing, unknown, or duplicate fields. Packet limits retain the core's fixed maximum of 144 probes and 1,296,000 requested IPv4 bytes. The source, destination, interface MTU, pacing, timeout, and duration are frozen before launch; the child receives no endpoint-discovery or source-selection authority.

Results are schema-one JSON lines with contiguous sequence numbers. Each line is limited to 128 KiB; the entire stream is limited to 512 KiB and 145 frames. Packet samples are flushed individually. The parent checks sample order, time, DF flag, size, direction/control semantics, resource caps, and the eventual raw report. A terminal report must validate and exactly match the frozen plan and streamed samples. Route results must match the exact requested destinations and order, with validated capture identities and bounded timestamps. Trailing data is rejected.

Route workers have a three-second allowance. Packet workers use the destination's remaining diagnostic allowance. Startup consumes that allowance. The parent checks cancellation and elapsed time independently of the child's probe timeout, then terminates and verifies job quiescence before admitting a terminal result. Zero exit alone is insufficient. Callback refusal and unwind also close the owned worker before returning control.

After a packet worker fails, a living parent can return an incomplete raw report containing only samples that passed incremental validation. It records the checked requested-byte total and a bounded failure explanation, with no largest-successful size, smallest-too-big size, or confirmed boundary. It cannot become proposal evidence. A failed route worker returns an error. Sample prefixes remain in memory; this is not durable crash recovery or a restorable settings backup.

The collector reserves nineteen seconds for final route and policy capture. Progress consumers remain synchronous: a blocked callback can delay parent deadline checks. Native process creation and collector-side work are not independently preempted. These worker allowances therefore do not establish a hard deadline for every collector operation.

## Verification and remaining work

Actual executable checks cover loopback route capture and source-bound packets, deadline expiry, preservation of a refused consumer's sample, and verified child termination before callback error or unwind returns. The separate medium-integrity policy also runs protected-file/event, parent-memory/token, descendant, memory-limit, environment, and immutable-input refusal checks. Protocol fixtures reject altered evidence, mismatched terminal samples, wrong operations, malformed framing, excess bytes, and trailing data.

`test.bat` builds the optional service image in `target/transfer-worker-tests` and explicitly selects the three ignored `read_worker::tests::isolatedReadWorker` executable tests alongside the existing eight transfer-worker checks. These use loopback only and select no native setting helper. For a separate run, build the `automatic-trials` service binary, set `EPP_TRANSFER_WORKER_IMAGE` to its absolute path, and select those three tests with `--ignored`.

Installed LocalService/System behavior, client Windows versions, physical adapters and public paths, durable diagnostic progress, normal-service orchestration, complete admission/confirmation, and production optimization remain unfinished. No networking benefit or recovery guarantee follows from successful loopback checks.
