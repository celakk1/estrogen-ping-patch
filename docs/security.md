# Security and threat model

## Protected assets

Network connectivity, original adapter/TCP/DNS settings, authorization records, rollback checkpoints, private inventory, measurement history, provider credentials, and the integrity of statistical conclusions.

## Trust boundaries

| Source / boundary | Threat | Required control | Current state |
| --- | --- | --- | --- |
| External metadata / GUI and report | Script or markup injection | React escaping, HTML export escaping, strict CSP, no remote content | Implemented |
| MCP client / application operations | Arbitrary command execution, permission expansion | Explicit read-only tools, initialization, argument validation, bounded JSON lines | Read-only subset implemented |
| Local user / dedicated service | Unauthorized requests, pipe spoofing | Explicit user/service ACLs, impersonated token identity, remote rejection, SCM PID/session verification, bounded typed protocol | Implemented for read-only status; extended SCM/service SID/storage lifecycle passed CI |
| Shared LocalService identity / recovery data | Checkpoint replacement or permission changes | Service-specific SID, protected machine directory, exact ACL verification, OWNER RIGHTS inheritance, reparse/hard-link refusal | Implemented; no checkpoint writes exposed through IPC; extended storage checks passed in a disposable Windows runner |
| Worker / network | Unbounded traffic, hangs, sensitive endpoint probing | Explicit start, bounded endpoint/sample counts, probe timeouts, cancellation, session deadline | Implemented for bounded TCP/ICMP/DNS and budgeted transfer sessions; broader providers and production experiment budgets remain |
| Process crash / experiment | Stranded network configuration | Durable checkpoints, independent watchdog, idempotent verified recovery | Durable journal, tracked setting processes, scoped lab grants, watchdog, temporary controller, and repeated-trial runner implemented; twenty owned-loopback recovery cases passed. Production writes and physical/reboot recovery remain disabled/unverified |
| Model output / candidate execution | Prompt injection or unsafe proposals | Treat as data; deterministic registry validation; authorization cannot be granted by AI | No inference or proposals enabled |
| Repository / private data | Credential or benchmark leakage | Ignore rules, staged secret scan, no app data in checkout, no tokens in scripts | Implemented workflow |
| Installer / installed binary | Tampering or excessive privileges | Per-user installation, no launcher elevation, signing when infrastructure exists | Unsigned development installer |

The fixed Windows discovery command is application-owned and accepts no external script, command, registry path, or executable argument. Its executable comes from the Windows system directory and has a deadline and output bounds. MCP exposes no discovery shell, execution, or write tools.

## Privacy

No telemetry and no cloud inference are configured. Inventory is local and contains interface identifiers and network addresses needed for diagnosis. It does not collect browser data, unrelated documents, passwords, cookies, or application contents. Exports may contain local endpoint addresses and must be reviewed before sharing.

Direct DNS queries disclose the explicitly selected name to the explicitly selected resolvers. The form warns against sending private names to public resolvers. There are no automatic private-name probes, cache flushes, resolver replacements, or Windows DNS writes. UDP responses require the connected source endpoint and matching randomized ID, question, type, class, and flags. Decoding, CNAME traversal, response counts, allocations, and the total UDP/TCP deadline are bounded. This transport is unauthenticated; resolver-reported AD does not prove independent DNSSEC validation. Answer changes are not treated as malicious or automatically optimized away.

Transfer sessions start only through explicit user action, use synthetic bytes, and disclose the chosen provider's IP/traffic visibility in the form. Origin credentials, arbitrary paths, fragments, and queries are rejected. HTTPS is mandatory except for literal loopback HTTP fixtures; normal Windows TLS validation remains enabled. Redirects, application proxies, cookies, decompression, and automatic retries are disabled. Payloads, streams, deadlines, headers, acknowledgement bodies, and retained errors are bounded. Only fixed provider protocol paths are constructed. User-owned upload acknowledgements require an exact byte count. These operations run unelevated and add no privileged IPC setter or command escape hatch. Payload budgets exclude wire/control overhead; automatic metered/managed-network eligibility remains unfinished, so no unattended load tests run.

Future API keys must use Windows Credential Manager or equivalent protected storage, never JSON, `.env` files in Git, or logs. Future external inference must receive an explicitly authorized, redacted summary and enforce a zero-capable monetary budget.

## Development controls

Run `node scripts/scan-staged.mjs` before committing. Never commit databases, tokens, `.env` secret files, logs, binary build outputs, local configuration, or benchmark exports. Dependency lockfiles are committed. CI uses read-only repository permissions and has no publishing step or required external secrets. Free hosted-runner availability for private repositories depends on the account's included GitHub Actions minutes; no paid runner or external service is configured.

## Pending security validation

Malformed IPC, service impersonation, unauthorized local clients, reboot/crash recovery, network disconnects, locked storage, disk-full handling, mutation verification, and installer upgrades must be exercised in an isolated Windows lab before declaring a production optimizer. Existing evidence covers the read-only application, simulated failure paths, and the narrowly scoped owned-loopback native lab; it does not validate production optimization.
