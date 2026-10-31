# Security and threat model

## Protected assets

Network connectivity, original adapter/TCP/DNS settings, authorization records, rollback checkpoints, private inventory, measurement history, provider credentials, and the integrity of statistical conclusions.

## Trust boundaries

| Source / boundary | Threat | Required control | Current state |
| --- | --- | --- | --- |
| External metadata / GUI and report | Script or markup injection | React escaping, HTML export escaping, strict CSP, no remote content | Implemented |
| MCP client / application operations | Arbitrary command execution, permission expansion | Explicit read-only tools, initialization, argument validation, bounded JSON lines | Read-only subset implemented |
| Local user / dedicated service | Unauthorized requests, pipe spoofing | Explicit user/service ACLs, impersonated token identity, remote rejection, SCM PID/session verification, bounded typed protocol | Implemented for read-only status; basic SCM lifecycle passed CI; service SID/storage changes require their extended lab run |
| Shared LocalService identity / recovery data | Checkpoint replacement or permission changes | Service-specific SID, protected machine directory, exact ACL verification, OWNER RIGHTS inheritance, reparse/hard-link refusal | Implemented; no checkpoint writes exposed through IPC; extended SCM storage checks pending |
| Worker / network | Unbounded traffic, hangs, sensitive endpoint probing | Explicit start, bounded endpoint/sample counts, connect timeouts, cancellation, session deadline | Implemented for TCP connect probes; bulk transfer budgets pending |
| Process crash / experiment | Stranded network configuration | Durable checkpoints, independent watchdog, idempotent verified recovery | Durable journal and simulated process-termination tests implemented; native recovery/watchdog pending; no mutations permitted |
| Model output / candidate execution | Prompt injection or unsafe proposals | Treat as data; deterministic registry validation; authorization cannot be granted by AI | No inference or proposals enabled |
| Repository / private data | Credential or benchmark leakage | Ignore rules, staged secret scan, no app data in checkout, no tokens in scripts | Implemented workflow |
| Installer / installed binary | Tampering or excessive privileges | Per-user installation, no launcher elevation, signing when infrastructure exists | Unsigned development installer |

The fixed Windows discovery command is application-owned and accepts no external script, command, registry path, or executable argument. Its executable comes from the Windows system directory and has a deadline and output bounds. MCP exposes no discovery shell, execution, or write tools.

## Privacy

No telemetry and no cloud inference are configured. Inventory is local and contains interface identifiers and network addresses needed for diagnosis. It does not collect browser data, unrelated documents, passwords, cookies, or application contents. Exports may contain local endpoint addresses and must be reviewed before sharing.

Future API keys must use Windows Credential Manager or equivalent protected storage, never JSON, `.env` files in Git, or logs. Future external inference must receive an explicitly authorized, redacted summary and enforce a zero-capable monetary budget.

## Development controls

Run `node scripts/scan-staged.mjs` before committing. Never commit databases, tokens, `.env` secret files, logs, binary build outputs, local configuration, or benchmark exports. Dependency lockfiles are committed. CI uses read-only repository permissions and has no publishing step or required external secrets. Free hosted-runner availability for private repositories depends on the account's included GitHub Actions minutes; no paid runner or external service is configured.

## Pending security validation

Malformed IPC, service impersonation, unauthorized local clients, reboot/crash recovery, network disconnects, locked storage, disk-full handling, mutation verification, and installer upgrades must be exercised in an isolated Windows lab before declaring a production optimizer. Existing tests cover only the currently implemented read-only subset.
