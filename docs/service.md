# Dedicated Windows service

The optional `EstrogenPingPatch` Windows service is a read-only foundation for the future optimization service. It runs as `NT AUTHORITY\LocalService`, not as an administrator or LocalSystem. Its only protocol operation is `getStatus`; it cannot apply settings, restore snapshots, run shell commands, open arbitrary files, or accept AI proposals. Installing it does not make the optimizer complete or authorize future changes.

The service library now includes native read-only interface capture reused by desktop backups. `epp-network-service.exe --mtu-inventory` prints native interface snapshots; `--inspect-mtu GUID ipv4` or `ipv6` reads a specific interface without installing a service or requiring elevation. These commands use fixed Windows APIs and fixed driver/OS registry fields, not caller-supplied registry paths. Their diagnostic output can contain adapter/device identifiers and should stay private. They expose no setter.

Microsoft documents `SetIpInterfaceEntry` as requiring administrative privileges. The current LocalService identity is therefore insufficient for that future setter. A privileged-service identity/design change, scoped authorization, durable native checkpoints, persistent-store semantics, and independent failure recovery must be validated together before enabling it. The development launcher and desktop must remain unelevated.

## Management

Build or launch the development checkout first. In **Safety & policy**, install the optional service, refresh its actual status, start/stop it, or uninstall it. The root `install-service.bat` and `uninstall-service.bat` provide the same installation/removal workflow. The packaged installer includes these helpers and the service executable. A normal development launch never requests elevation or installs a system service automatically.

The checkout helper selects the most recently built debug/release service executable. A packaged helper always uses its adjacent bundled executable, keeping those resources together. Rebuild before installation after changing service source.

Management alone requests Windows administrator approval. The original user's SID is captured before elevation and preserved if different administrator credentials are supplied. The service binary is copied to `%ProgramFiles%\estrogen ping patch service`; both the directory and executable are created with Administrators ownership and explicit ACLs allowing replacement only by administrators or SYSTEM. Ownership is established atomically at object creation rather than corrected after copying. The copied hash is checked before registration. Existing service installations/configurations and reparse points are rejected rather than overwritten. Startup is automatic; the GUI and internet are not needed to start the service. Installation trusts the build explicitly approved by the user; signing and authenticated upgrade distribution remain pending.

Use **Uninstall service** before removing the desktop application. The current per-user desktop uninstaller does not remove the separate machine-wide service automatically. Service removal stops its exact registered process, deletes its SCM entry, and removes only the known binary and an empty installation directory. It preserves user backups, measurements, and the machine recovery journal. Upgrades currently require explicit uninstall/reinstall; in-place service upgrade and reboot recovery are not yet validated.

## Recovery journal storage

Installation enables a service-specific SID and creates `%ProgramData%\estrogen-ping-patch-service` atomically with Administrators ownership and a protected DACL. SYSTEM and Administrators have full access; only `NT SERVICE\EstrogenPingPatch` receives data modification rights. Shared LocalService and interactive users receive no data access. An inheritable OWNER RIGHTS rule grants only READ_CONTROL, suppressing the implicit WRITE_DAC normally available to the shared account that owns newly created SQLite files.

The service resolves the machine data directory through Windows known folders rather than a caller-controlled data-path environment variable. Startup requires the service SID in its token, checks exact directory/file ACLs and owners, rejects reparse points and multiply linked files, and keeps directory handles open without delete sharing. It then opens and validates the local SQLite journal before reporting Running. Invalid permissions, unsupported schemas, missing original records, broken hashes, orphaned events, or corrupted storage prevent startup; existing evidence is preserved. A supported journal with unresolved work starts in read-only `recoveryRequired` mode. There is no native restore implementation to run yet.

The unelevated management path does not inspect private recovery files. Install/start checks those paths only after the separate administrator approval. Stop/uninstall can still remove the registered service when its journal is damaged; they never delete recovery data.

Status reports the journal verification time and unresolved checkpoint count as observed at service startup. No operation can create or advance a checkpoint through IPC in this build. Service removal preserves the directory, and reinstallation reuses it only if its permissions match the expected policy. The journal is separate from user-owned diagnostic snapshots. See [checkpoint guarantees and remaining recovery gates](backups.md#service-checkpoint-journal).

The journal database is now schema two, retaining validated legacy checkpoints and adding native original/readback evidence. Its version is reported separately from pipe protocol schema two. Older service binaries cannot open the upgraded journal; reinstall a current service build after upgrading the desktop. The recovery coordinator library is tested with a simulated adapter but is not wired to service startup or native setters. Status continues to report `rollbackAvailable: false`.

The feature-gated [native MTU lab](native-mtu-lab.md) has a separately named service, storage directory, and LocalSystem account for an owned-loopback verification matrix. It is excluded from normal builds and installation. It does not change this service's account or status-only contract.

## Protocol and identity

- A fixed local pipe uses a protected DACL for SYSTEM, the service-specific SID, and the selected user's SID. User rights permit data exchange, attribute reads, and synchronization, without create-pipe-instance or security-descriptor modification rights.
- Remote clients are rejected, and the first server instance refuses an existing pipe name. Fresh instances preserve the namespace between clients; handles are not recycled after disconnect because the resolved Mio version retains stale completion state.
- The server reads the client's Windows token through identification-level pipe impersonation, compares the token user SID, and reverts before any asynchronous work. Failed reversion terminates the process. A successful ACL check alone does not dispatch a request.
- The client checks the kernel-reported pipe server PID against the running SCM service, requires session zero, verifies the registered process type/account, and rechecks the SCM PID after the response. An unregistered process imitating the pipe is rejected before receiving a request.
- Frames use a four-byte big-endian length followed by bounded UTF-8 JSON. The maximum payload is 4096 bytes. Schema, request identifier, operation, unknown fields, and a maximum five-second expiry are validated. Connection handling is bounded to five seconds, and a stop request cancels pending connection/frame work.

The checkpoint-storage status contract uses protocol schema two and pipe `estrogen-ping-patch-service-v2`. It deliberately refuses schema-one peers; uninstall/reinstall an older preview service to update its binary and service SID configuration.

Read-only pipe access is not mutation authorization. Future writes need typed adapter-bound operations, expiring/revocable grants, exact service-owned checkpoints, independent recovery, and the backup gates in [backups](backups.md). No generic command, registry, executable, or endpoint escape hatch may be added.

## Verification

Local tests exercise real Windows pipes, explicit ACL denial and minimal client permissions, independent token rejection, server PID mismatch, malformed/oversized frames, repeated connections, timeout recovery, service-stop cancellation, recovery ACL validation, and actual hard-link rejection. `scripts/service-smoke.ps1 -allowServiceInstallation` is reserved for an already elevated disposable Windows lab; CI runs it on the hosted runner. The original install/status/stop/restart/removal check passed. The extended check additionally verifies journal permissions, inserts a prepared simulated checkpoint through a test-only harness while stopped, confirms it is reported after startup, cancels that unapplied fixture, injects database corruption to require startup refusal, and verifies preservation across uninstall/reinstall. These extended checks passed at `1434e8a`: [service verification](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41210675289). They never apply or restore a network setting. The developer's machine is not used for service installation testing.
