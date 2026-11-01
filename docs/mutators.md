# Settings-command recovery barrier

This library and disabled-by-default native MTU lab record each setting process before allowing its initial thread to run. The normal desktop and LocalService still expose no settings operations or rollback watchdog. This is a recovery prerequisite, not a finished optimizer.

## Durable identity and execution

The service creates the fixed system `netsh.exe` command suspended inside an anonymous kill-on-close job. Its job allows one active process and no breakaway. Only null input/output is inherited. Before resuming, the coordinator commits and reads back a record bound to the exact checkpoint bytes, write purpose, PID, and Windows process creation time. Creation time remains an exact decimal string of 100-nanosecond ticks. A PID alone is insufficient because Windows can reuse it.

The process ownership implementation is also used by the [read-only IP policy reader](backups.md#read-only-ip-policy-worker). That reader has a bounded output pipe instead of null output. Sharing job creation and verified termination does not bypass the setting command's registration, authorization, or fresh-target checks; those remain mandatory before its initial thread resumes.

Registration failure prevents execution. Permission, deadline, and fresh adapter/context/value checks run again after the commit, immediately before resume. Local process fixtures verify that failed registration or failed target revalidation cannot execute a marker-writing child; a successful control does execute it. A separate read-only test checks that the single-process limit permits the fixed system command to inspect interface status.

Handled cleanup requires both a signaled primary process handle and zero active job processes. A failure latches the instance against subsequent writes or recovery observations. After restart, the coordinator verifies all saved process identities before observing the adapter. It opens only query/synchronization rights, compares creation time, and waits up to five seconds for an exact predecessor. It never terminates a process using a saved PID. A reused PID is left untouched; access failures or an exact predecessor that remains alive block recovery observation and restoration.

The journal binds each record to its predecessor hash and a transactionally updated head/count. Missing records, changed payloads, invalid scope/order, repeated identities, and missing heads are refused. A version-three checkpoint without a registered apply cannot explain an externally changed MTU, even when that value equals its candidate; recovery refuses to overwrite it.

## Storage versions

| Component | Version | Behavior |
| --- | --- | --- |
| Service recovery SQLite | 4 | Preserves process records/heads and adds policy verification receipts; validates old history before migration |
| Tracked native checkpoint document | 3 or 4 | Requires durable process registration and exit barriers; four additionally binds exact IP policy originals |
| Legacy checkpoint document | 1 or 2 | Original bytes and event history remain unchanged; no fabricated process evidence |
| Authorization SQLite | 1 | Independent grants remain bound to exact checkpoint bytes |
| Service pipe | 2 | Status only; no new operations |
| Desktop application SQLite | 6 | Independent measurement and snapshot history |

The native lab refuses unresolved legacy checkpoints rather than inferring process proof. Older service binaries refuse the upgraded recovery database. Keep the current binary and preserve recovery storage; do not manually lower its version.

Recovery still does not require an unexpired apply grant or available authorization database. It does require readable, verified recovery evidence. If storage cannot commit a new restoration-process record, that command cannot run: the checkpoint remains unresolved and restoration is reported incomplete. Simulated failed inserts do not establish recovery on a physically full or failing disk.

## Verification and remaining gates

The local feature suite passed 76 tests, with ten explicit subprocess/lab helpers excluded from the ordinary listing. It covers migration without document rewrites, failed commits, corrupt/missing process records, exact creation-time matching, reused PIDs, live predecessors, registration-before-execution, and fresh validation before resume. Local tests do not change network settings.

At `a3ec657`, the [expanded disposable native matrix](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41266058042) passed all twelve trials and the 76 feature tests. It adds a crash after registration while the command is still suspended, for both IPv4 and IPv6. The harness independently holds the command handle, checks its exact creation time, verifies exit after service death, and requires the restarted service to verify that predecessor before completing recovery with zero setting writes. Every trial finished at the exact original MTU 1500 with its expected process-record count and unchanged unrelated settings, persistent policy, and DNS origin values. The [real LocalService lifecycle](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41266073574) also passed with recovery database version three, including corruption refusal and preserved uninstall/reinstall.

Physical adapters, Windows client OS coverage, crash during an actual in-flight native operation, reboot/power loss, independent watchdog, production consent/privileges, policy/VPN concurrency, and performance improvement remain unverified. The lab feature remains excluded from normal builds and installers.
