# Network settings backups and recovery

## Current snapshot workflow

Open **Configuration backups**, select **Capture backup**, and review the captured and unavailable sections. The application reads configuration, commits a new local snapshot, verifies its SHA-256 when opening/exporting it, and preserves earlier snapshots. **Export backup** downloads the exact saved JSON bytes; its filename includes the SHA-256 shown in the GUI.

Snapshots contain OS/build context, adapter GUIDs and driver versions, interface indexes, addresses and prefix origins, DHCP/IP interface settings, routes, DNS servers and client settings, TCP templates, and supported driver advanced properties/RSS/RSC/power settings. Driver properties preserve registry keywords and native values where exposed. Missing or unsupported sections retain their error instead of being reported as successfully captured.

Each settings record lists `unavailableFields` separately, preserving the distinction between a missing native property and an exposed property whose value is null. A captured section indicates that the reader returned data, not that every driver exposes every requested property.

The native DNS section reads `GetInterfaceDnsSettings` version one for each adapter GUID. It preserves the API's flags as a lossless hexadecimal string, adapter and profile nameserver strings, domain/search list, and registration/LLMNR fields. Null pointers remain JSON null; empty strings remain empty strings. Malformed UTF-16 makes the section unavailable instead of silently changing the value. Returned memory is freed even if serialization fails. Windows dynamically loads both getter and cleanup exports from the system directory; older systems or unsupported adapters record an explicit unavailable section without preventing the other snapshot sections from being saved.

Data is stored in the local application database outside the checkout. SQLite uses WAL, FULL synchronous mode, and a transaction that commits the settings document and its hash together. Snapshot records are appended, never overwritten by the capture workflow. Existing version-one application history survives the version-two database migration. The preview bounds each saved document to 2.5 MB and stops at 200 snapshots, preserving existing records. `clean.bat` does not remove the database or exported backups.

Backup history and export are local operations and remain available without internet connectivity. Exported files contain private network information and should be reviewed before sharing. A SHA-256 detects changed bytes; it does not authenticate an imported file or authorize restoring it. No backup import or settings-restore operation is enabled in this preview.

## Coverage limits

These are diagnostic settings snapshots. Automatic restoration is not implemented or tested. DNS server addresses alone do not establish whether the resolver configuration came from DHCP, static settings, enterprise policy, or VPN configuration. The native version-one fields add configuration evidence, but do not prove complete policy/DoH/IPv4/IPv6 origin or restoration semantics. The getter is initialized with only its version, as required by Microsoft; it does not set an IPv6 input flag or infer automatic DNS from IP DHCP state. Some drivers do not expose RSC, power-management, or RSS data. Collection runs over an interval and is not an atomic operating-system snapshot. These limits appear in each exported document and in the interface.

The application currently changes no Windows settings. Capturing a snapshot does not grant authorization to make changes and does not indicate that a proposed experiment is safe.

## Service checkpoint journal

The service now has a separate SQLite recovery journal library with immutable, checksummed MTU checkpoint documents and a chained event history. Each document records the exact original and proposed MTU, adapter GUID, address family, OS/driver context, authorized-user SID, creation time, and bounded lease. A SID written into a document is evidence, not an authenticated authorization grant. Only the future policy layer may authorize preparation; the current IPC protocol exposes no checkpoint writes.

Preparation commits the document and initial event in one IMMEDIATE transaction using WAL and FULL synchronization, then reads them back. An apply intent requires a matching fresh original-value observation and a verified committed checkpoint. Readback gates applied, retained, and restored states. A changed GUID, OS, driver, address family, or unexpected third-party value blocks the transition. Expired leases permit cancellation/recovery only. Event sequence supplies ordering even after a backward wall-clock correction. Unresolved work blocks another experiment, stale writers cannot advance state, and terminal history cannot be reopened.

Startup validates SQLite identity/schema, integrity, foreign keys, each saved document, and every event hash/transition. The journal retains up to 2000 documents and 128 events per document; capacity or persistence failure blocks advancement and preserves evidence. SHA-256 detects corruption, not administrator tampering. The [service storage ACLs](service.md#recovery-journal-storage) establish the local ownership boundary.

Local tests use independent connections, reopen interrupted transactions, inject failed commits and corruption, reject changed adapter context, and terminate real subprocesses after committed apply/restore intents. The subprocess test changes a simulated MTU text file; it never touches a Windows adapter. This demonstrates journal persistence under process termination, not physical power-loss durability or native restoration.

No Windows setter, rollback watchdog, effective-value/native restoration backend, persistent-versus-active MTU semantics, DNS/addressing recovery, authorization-grant lifecycle, or reboot recovery is implemented. The service only initializes this store and reports unresolved checkpoint counts; it does not claim `rollbackAvailable`. No diagnostic snapshot can substitute for these operation-specific recovery gates.

## Mandatory gate for future setting changes

Before any setter is enabled, the privileged service must perform all of these steps:

1. Match the target adapter by GUID and verify its current OS, driver, capability, management-policy, VPN, and remote-administration context.
2. Read the exact targeted original value, including absent versus present values and automatic versus manual DNS/addressing semantics. Reject the operation if required information is unavailable.
3. Commit a durable rollback checkpoint and intended operation record before making a change. Read back and verify the checkpoint. Failure to capture, persist, or verify it blocks the change.
4. Record explicit, expiring, revocable authorization for the specific allowlisted operation. A snapshot, AI proposal, or GUI session cannot grant extra permissions.
5. Apply the supported operation, read back the effective value, check connectivity, and run the matched measurements. Retain only after the required confirmation; otherwise restore the exact prior value and verify it.
6. Recover incomplete transactions through an independent service/watchdog after a GUI crash, service restart, reboot, deadline expiry, or connectivity loss. Report incomplete restoration explicitly.

Recovery must work locally, without an AI model or internet access. Provide original-configuration, last-known-good, and selected-checkpoint recovery only after the relevant operation's restore path has passed failure testing. Factory defaults and a generic adapter reset do not identify the user's original configuration.
