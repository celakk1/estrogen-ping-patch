# Dedicated Windows service

The optional `EstrogenPingPatch` Windows service is a read-only foundation for the future optimization service. It runs as `NT AUTHORITY\LocalService`, not as an administrator or LocalSystem. Its only protocol operation is `getStatus`; it cannot apply settings, restore snapshots, run shell commands, open arbitrary files, or accept AI proposals. Installing it does not make the optimizer complete or authorize future changes.

## Management

Build or launch the development checkout first. In **Safety & policy**, install the optional service, refresh its actual status, start/stop it, or uninstall it. The root `install-service.bat` and `uninstall-service.bat` provide the same installation/removal workflow. The packaged installer includes these helpers and the service executable. A normal development launch never requests elevation or installs a system service automatically.

Management alone requests Windows administrator approval. The original user's SID is captured before elevation and preserved if different administrator credentials are supplied. The service binary is copied to `%ProgramFiles%\estrogen ping patch service`; both the directory and executable are created with Administrators ownership and explicit ACLs allowing replacement only by administrators or SYSTEM. Ownership is established atomically at object creation rather than corrected after copying. The copied hash is checked before registration. Existing service installations/configurations and reparse points are rejected rather than overwritten. Startup is automatic; the GUI and internet are not needed to start the service. Installation trusts the build explicitly approved by the user; signing and authenticated upgrade distribution remain pending.

Use **Uninstall service** before removing the desktop application. The current per-user desktop uninstaller does not remove the separate machine-wide service automatically. Service removal stops its exact registered process, deletes its SCM entry, and removes only the known binary and an empty installation directory. It preserves user backups and measurements. Upgrades currently require explicit uninstall/reinstall; in-place service upgrade and reboot recovery are not yet validated.

## Protocol and identity

- A fixed local pipe uses a protected DACL for SYSTEM, LocalService, and the selected user's SID. User rights permit data exchange, attribute reads, and synchronization, without create-pipe-instance or security-descriptor modification rights.
- Remote clients are rejected, and the first server instance refuses an existing pipe name. Fresh instances preserve the namespace between clients; handles are not recycled after disconnect because the resolved Mio version retains stale completion state.
- The server reads the client's Windows token through identification-level pipe impersonation, compares the token user SID, and reverts before any asynchronous work. Failed reversion terminates the process. A successful ACL check alone does not dispatch a request.
- The client checks the kernel-reported pipe server PID against the running SCM service, requires session zero, verifies the registered process type/account, and rechecks the SCM PID after the response. An unregistered process imitating the pipe is rejected before receiving a request.
- Frames use a four-byte big-endian length followed by bounded UTF-8 JSON. The maximum payload is 4096 bytes. Schema, request identifier, operation, unknown fields, and a maximum five-second expiry are validated. Connection handling is bounded to five seconds, and a stop request cancels pending connection/frame work.

Read-only pipe access is not mutation authorization. Future writes need typed adapter-bound operations, expiring/revocable grants, exact service-owned checkpoints, independent recovery, and the backup gates in [backups](backups.md). No generic command, registry, executable, or endpoint escape hatch may be added.

## Verification

Local tests exercise real Windows pipes, explicit ACL denial and minimal client permissions, independent token rejection, server PID mismatch, malformed/oversized frames, repeated connections, timeout recovery, and service-stop cancellation. `scripts/service-smoke.ps1 -allowServiceInstallation` is reserved for an already elevated disposable Windows lab; CI runs it on the hosted runner. It installs the real SCM service, verifies protected binary permissions and authenticated repeated status requests, stops/restarts it, and removes it. This test never changes network settings. The developer's machine is not used for service installation testing.
