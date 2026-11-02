# Repeated-experiment traffic reservations

New repeated experiments require explicit aggregate and provider limits for application probe attempts, provider requests, downloaded payload bytes, and uploaded payload bytes. This is a backend admission and reservation mechanism. It does not enable production optimization or unattended internet traffic.

## Admission and execution

Each fixed provider has a bounded identity, a conservative maximum cost per measurement collection, and its own limits. The trusted host declares the maximum cost of the collector it actually runs. Proposed allowances must cover every declared provider and cost; missing providers, substituted identities, and understated allowances are refused before experiment intent or measurements begin. A declaration must not perform discovery, measurements, or settings changes.

The runner reserves three collections for a complete original/candidate/original block before its first baseline. Both the global limits and every provider limit must cover that block. Reservation and phase intent commit together with checksums, revision checks, FULL synchronization, and committed readback. A failed commit prevents collection and candidate application. Reservations never decrease or refund within an experiment, including partial collection, cancellation, measurement failure, and interrupted recovery. Reported reserved amounts are conservative maxima, not measured usage or billing.

Insufficient allowance stops before another block with `budgetExhausted`; it does not reduce the configured evidence requirement, retain a candidate, or begin a change without allowance for its final baseline. Original-setting verification still runs. Ordinary measurement errors and recovery requirements retain their existing failure handling. Time spent declaring costs cannot extend the fixed monotonic deadline or create already-expired experiment intent.

Provider identities are fixed by the plan and bound to the trusted collector; they do not represent a claim of provider independence. Limits cannot change during a stored experiment. Arithmetic is checked, provider count is bounded at sixteen, and operational ceilings are one million probe/request attempts and 10 TiB per payload direction. These ceilings are not defaults: callers must supply explicit limits. The native fixture uses exactly 216 allowed TCP connection probes in total and 108 per loopback endpoint for twelve blocks, with no HTTP/provider requests or transfer payload.

## Persistence and compatibility

The experiment SQLite wrapper remains schema one. New experiment documents use payload schema two and save the number of reserved blocks alongside the immutable plan. Loading verifies that reservations agree with completed blocks, current phase, and all limits. Writes cannot reduce an existing reservation or change its schema or plan. Usage reports derive aggregate and per-provider totals from those fixed costs and reservations.

Legacy payload-schema-one documents without traffic declarations remain readable. Interrupted legacy intent can be acknowledged only after trusted original-state verification; it cannot start new unbudgeted measurements or replay a candidate. Completed legacy records retain their original meaning without invented traffic totals. Older application builds refuse the newer payload rather than silently removing its limits. These payload/traffic changes are independent of the current application database six, recovery journal four, authorization database two, and status pipe four.

## Scope and remaining work

Reservations cover one repeated experiment. A future multi-candidate search or schedule must use an additional shared cycle/period ledger rather than resetting the user's allowance for every candidate. Provider discovery, network-producing original-state checks, and watchdog connectivity traffic must be separately metered or included conservatively before those paths are enabled. Current native fixture verification reads local Windows state and sends no such auxiliary probes.

This is not an interface wire-byte meter. TCP retries, acknowledgements, TLS/control overhead, operating-system traffic, and other applications are not represented as transferred test payload. Trusted collectors must enforce their declared collection limits using their bounded workers; a provider's reported byte count cannot enlarge them. Production load-collector integration, actual usage reconciliation, bandwidth-rate limits, metered/cellular eligibility, scheduling, user-facing budget controls, and production optimization remain unfinished.

Focused tests cover aggregate/provider limits, complete-bracket admission, durable visibility before measurement, failed reservation writes, no refunds, understated/unknown collector costs, arithmetic bounds, interrupted restart, legacy read/recovery behavior, and expired cost declarations. Service integration additionally checks zero-, one-, and twelve-block allowances over actual loopback connections and a simulated setting backend. Hosted native validation of the new reservations is required separately.
