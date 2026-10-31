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

## Mandatory gate for future setting changes

Before any setter is enabled, the privileged service must perform all of these steps:

1. Match the target adapter by GUID and verify its current OS, driver, capability, management-policy, VPN, and remote-administration context.
2. Read the exact targeted original value, including absent versus present values and automatic versus manual DNS/addressing semantics. Reject the operation if required information is unavailable.
3. Commit a durable rollback checkpoint and intended operation record before making a change. Read back and verify the checkpoint. Failure to capture, persist, or verify it blocks the change.
4. Record explicit, expiring, revocable authorization for the specific allowlisted operation. A snapshot, AI proposal, or GUI session cannot grant extra permissions.
5. Apply the supported operation, read back the effective value, check connectivity, and run the matched measurements. Retain only after the required confirmation; otherwise restore the exact prior value and verify it.
6. Recover incomplete transactions through an independent service/watchdog after a GUI crash, service restart, reboot, deadline expiry, or connectivity loss. Report incomplete restoration explicitly.

Recovery must work locally, without an AI model or internet access. Provide original-configuration, last-known-good, and selected-checkpoint recovery only after the relevant operation's restore path has passed failure testing. Factory defaults and a generic adapter reset do not identify the user's original configuration.
