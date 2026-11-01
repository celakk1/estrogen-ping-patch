# Local route evidence

Connection tests capture Windows' selected local route before and after measurements. The desktop saves both captures with the run and displays a short route note in the results and readable HTML report. Raw JSON includes the route records and fingerprints. Old reports have no route metadata; the application does not invent it for them.

This is read-only diagnostic evidence. It does not enable settings writes, establish a complete comparison environment, or provide a rollback checkpoint. Speed/load sessions do not yet capture it.

## Capture and identity

The unelevated desktop calls the service library's native reader directly. No installed service, administrator approval, external command, DNS lookup, or probe traffic is required for route capture. Existing explicit connection-test probes still run normally.

For each numeric destination, [GetBestRoute2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2) reads the selected route and source address from Windows. The reader records destination/family/scope, adapter GUID, exact decimal-string LUID, current interface index, source address, destination prefix, next hop, route metric, protocol/origin, flags, age, and lifetime counters. GUID/LUID conversion must round-trip; the fresh link row must agree on GUID, LUID, and index. Family, source, prefix membership, and link-local scope are validated. Malformed targets are refused before capture. Each invocation is limited to eight destinations and checks cancellation between synchronous native calls.

The [route metric](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/mib-ipforward-row2) is the route's offset, not the combined interface-plus-route cost. An unspecified next hop represents an on-link or loopback route; it is not missing data. Native failures remain explicit unavailable records with bounded errors. A cancelled capture cannot return a partial success or an unchanged-route claim.

The two captures are not an atomic Windows snapshot. GetBestRoute2 reports a local IP routing decision; it does not inspect socket traffic or trace every internet hop. Filters, per-application VPN behavior, tunnels, DNS origin, management policy, wireless conditions, and configuration changes outside the selected-route fields require separate evidence. A route that changes and changes back during the test may not be detected by these boundary captures.

## Fingerprints and presentation

The `selected-route-v1` fingerprint hashes the ordered, validated route records after normalizing capture time and route age. Positive finite lifetime counters normalize to a finite category; zero and infinite lifetimes remain distinct. Ordinary countdown ticks therefore do not masquerade as a different route. Raw records retain every original counter. Changes between two positive finite durations are not distinguished by this fingerprint and must not be interpreted as verified policy stability.

| Status | Meaning |
| --- | --- |
| `unchanged` | Every destination was captured and its normalized selected-route evidence matched at both boundaries |
| `changed` | Complete captures had different fingerprints |
| `unavailable` | At least one boundary could not supply complete route evidence |

The displayed unchanged note says that Windows reported the same local route. It does not claim that the entire connection, configuration, or internet path stayed unchanged. Changed evidence asks the user to repeat the test before comparing it with earlier results. Failed route capture leaves the measurements available and reports the route check as unavailable.

The optional `routing` field is added to the existing baseline JSON. Its own schema version is one. Existing measurement fields and database version five retain their meaning; older previews ignore the additional field. The service pipe remains status-only protocol two, and recovery SQLite remains independently version three.

## Remaining comparison work

Route fingerprints are not `comparison::Plan.environmentSha256` or network-configuration hashes. Trusted OS/driver/interface configuration, policy/VPN coverage, operation-bound checkpoints, collection consistency, and automated repeated-session orchestration are still required. The [comparison library](comparisons.md) does not infer that full context from these route records. No automatic retention or optimization decision uses them in this build.

The baseline comparison adapter does enforce recorded route failures: present metadata must describe complete, consistent, unchanged route choices. Changed or unavailable records cannot be overridden by merely supplying a matching context hash. This admission check is separate from the still-required complete environment capture.

## Validation

Seven route tests cover actual IPv4/IPv6 loopback route reads without sending traffic, GUID/interface binding, exact LUID round trips, native socket byte order and scope, prefix bounds, cancellation, and changed-choice versus aging-only fingerprints. A core test covers protocol destination extraction, and a saved real TCP fixture verifies exact persistence of optional route metadata and honest legacy reads. The desktop cancellation test preserves unavailable evidence. Frontend tests distinguish unchanged, changed, unavailable, inconsistent, future-version, and absent evidence, and check readable export wording. The local packaged desktop checks passed actual IPv4/IPv6 route capture, results wording, exact JSON/HTML export, and history reload. Packaged MCP and temporary installer/shortcut/GUI/uninstall checks also passed. At `7e154ad`, the [full hosted Windows pipeline](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41302172177) and [separate service lifecycle](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41302174699) both passed. These checks do not validate complete environment binding, actual route failover during a measurement, or production optimization.
