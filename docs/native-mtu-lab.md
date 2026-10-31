# Native MTU recovery lab

The `native-mtu-lab` Cargo feature adds a separate, narrowly scoped Windows service for testing real Windows MTU writes and recovery. Default development, build, and packaging commands do not enable it. The normal LocalService service and desktop still expose no setters and report `rollbackAvailable: false`.

The lab is not an optimization feature or a production authorization mechanism. Its purpose is to establish native MTU behavior before enabling application-owned experiments. The six-trial native matrix passed on a disposable Windows Server 2022 runner. This establishes the bounded loopback cases below, not production readiness or physical-adapter recovery.

## Isolation and authority

`scripts/native-mtu-lab.ps1 -allowNetworkChanges` is reserved for an elevated GitHub-hosted disposable Windows runner. It refuses ordinary development-machine execution before any device operation. Environment checks prevent accidental execution; they are not a security boundary against an administrator.

The harness creates one Microsoft loopback adapter through SetupAPI and the built-in `netloop.inf`, retaining its exact PnP instance ID and GUID. It assigns a unique `epp-mtu-lab-GUID` alias to its owned adapter before capturing the original. Existing loopback hardware, lab installations, and recovery storage cause refusal. It does not assign an IP address, change DNS, attach to a physical adapter, or create a default route. Cleanup removes only the device created by that process and the known lab executable; the recovery journal is retained.

The separately named `EstrogenPingPatchMtuLab` service runs as LocalSystem with an explicit service SID and a required-privilege list containing only `SeChangeNotifyPrivilege`. Its binary is copied and hash-verified in a protected Program Files directory. Its separate ProgramData journal uses the existing service-owned storage ACL and integrity checks. The production LocalService account is unchanged.

The lab entry point accepts only canonical owner SID, adapter GUID, family, interruption phase, and trial ID. It must enter through SCM, match the registered own-process LocalSystem PID in session zero, and possess the lab service SID. The mutation permit has no public constructor. Native target checks require the configured GUID/family, captured Microsoft loopback driver identity, root-enumerated network device, and Ethernet interface type. There is no mutation pipe, arbitrary executable, script, registry path, endpoint, or generic setter argument. The only candidate is MTU 1400; restoration permits the exact original value. Retention is always refused.

## Write and recovery path

The coordinator commits and reads back the native original and apply intent before calling the backend. Immediately before the write, the backend reacquires the GUID/LUID mapping and current IP row and checks the captured context, fixed alias, and every expected setting. It invokes only the protected system directory's `netsh.exe`, with a generated fixed argument list for `interface ipv4|ipv6 set subinterface`, the GUID-derived lab alias, the allowed MTU, and `store=active`. No executable, command text, policy store, script, or target name is accepted from a caller. The process has no terminal or input and a five-second deadline. Apply revocation and lease expiry terminate and reap its exact child; recovery remains independent of apply authorization. Command success is not readback evidence: the coordinator still requires the exact effective MTU and unchanged unrelated fields.

The whole-row `SetIpInterfaceEntry` approach failed the preservation gate on the disposable runner. Windows returned IPv4 `SitePrefixLength` 64, while the [setter requires zero on input](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry). Passing zero changed that unrelated field. The lab therefore uses the [documented MTU-only subinterface operation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface) instead of weakening comparisons or pretending zero restores the captured value. The complete matrix passed with this narrower operation.

Each trial has a 120-second wall-clock lease and monotonic deadline. Stopping the lab service releases an intentional pause and permits restoration. Startup processes its matching unresolved trial before considering new work, with recovery independent of an expired apply lease. A terminal trial ID cannot be replayed to apply a candidate again. Phase markers in the Application event log indicate that the native call returned; they do not themselves prove readback or durable completion. Only the verified journal and fresh observations establish the final result.

The Windows operation provides no compare-and-set transaction with the GUID validation. The unique lab alias avoids targeting a recycled numeric interface index, but checking immediately before a write and comparing afterward cannot eliminate races with an administrator renaming or replacing devices. Production policy/concurrency guards remain necessary.

## CI matrix and limits

At `91ff236`, the [native Windows run](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41243474601) passed the four safe harness tests, 49 feature-enabled Rust tests, feature Clippy, the isolated release build, and all six native trials. The original MTU was 1500 and the candidate was 1400 for both families. Each completed trial verified MTU 1500, exact unrelated settings, unchanged persistent rows and DNS origin values, a finalized restored checkpoint, and zero pending recovery work.

| Family | Interruption | Writes in final process | Final state |
| --- | --- | --- | --- |
| IPv4 | None | 2 | Restored |
| IPv4 | After apply returned | 1 | Restored |
| IPv4 | After restore returned | 0 | Restored |
| IPv6 | None | 2 | Restored |
| IPv6 | After apply returned | 1 | Restored |
| IPv6 | After restore returned | 0 | Restored |

JSON object-key order differs between the CLI snapshot and structured events. The harness compares settings after ordering their property names, preserving exact values, types, array order, and missing fields. Its safe regression test reproduces the earlier textual-order mismatch and rejects actual setting changes.

The workflow builds the feature into `target/native-mtu-lab`, outside normal packaged service output. It first runs feature tests and Clippy, then performs six owned-adapter trials: normal apply/restore, forced process termination after the apply call, and forced termination after the restore call, for both IPv4 and IPv6. Restart must verify the exact original MTU, unchanged unrelated configurable fields, a finalized restored journal state, and no pending recovery work. The harness independently checks native readback, both persistent policy rows, and DNS values including absence/type and automatic/static configuration evidence before and after trials. It refuses persistent-store drift during an interrupted trial.

This matrix does not validate other original/candidate MTU pairs, physical Ethernet or Wi-Fi, the Windows 10/11 client matrix, active traffic, VPN/policy interaction, performance improvement, native power-loss/reboot recovery, full-disk behavior, or production grants/watchdog integration. It does not justify restoring DNS/addressing from diagnostic snapshots or enabling automatic optimization. Those remain separate product gates.
