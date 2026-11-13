# Local route evidence

Connection tests capture Windows' selected local route before and after measurements. The desktop saves both captures with the run and displays a short route note in the results and readable HTML report. Raw JSON includes the route records and fingerprints. Old reports have no route metadata; the application does not invent it for them.

This is read-only diagnostic evidence. It does not enable settings writes, establish a complete comparison environment, or provide a rollback checkpoint. The desktop speed-test flow does not yet save route evidence; optional adapter-bound service collectors do.

## Capture and identity

The unelevated desktop calls the service library's native reader directly. No installed service, administrator approval, external command, DNS lookup, or probe traffic is required for route capture. Existing explicit connection-test probes still run normally.

For each numeric destination, [GetBestRoute2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2) reads the selected route and source address from Windows. The reader records destination/family/scope, adapter GUID, exact decimal-string LUID, current interface index, source address, destination prefix, next hop, route metric, protocol/origin, flags, age, and lifetime counters. GUID/LUID conversion must round-trip; the fresh link row must agree on GUID, LUID, and index. Family, source, prefix membership, and link-local scope are validated. Malformed targets are refused before capture. The internal reader is limited to sixteen destinations and checks cancellation between synchronous native calls; desktop connection tests retain their separate eight-endpoint bound.

The optional adapter-bound service collectors use the owned route worker for initial and boundary verification. Its three-second allowance includes startup, and its frozen request covers both echo destinations and provider peers. This adds bounded process isolation to those getters; it does not establish internet-path stability or complete experiment-environment coverage.

The [route metric](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/mib-ipforward-row2) is the route's offset, not the combined interface-plus-route cost. An unspecified next hop represents an on-link or loopback route; it is not missing data. Native failures remain explicit unavailable records with bounded errors. A cancelled capture cannot return a partial success or an unchanged-route claim.

The two captures are not an atomic Windows snapshot. GetBestRoute2 reports a local IP routing decision; it does not inspect socket traffic or trace every internet hop. Filters, per-application VPN behavior, tunnels, DNS origin, management policy, wireless conditions, and configuration changes outside the selected-route fields require separate evidence. A route that changes and changes back during the test may not be detected by these boundary captures.

## Fingerprints and presentation

The `selected-route-v1` fingerprint hashes the ordered, validated route records after normalizing capture time and route age and excluding optional link statistics. Positive finite lifetime counters normalize to a finite category; zero and infinite lifetimes remain distinct. Ordinary countdown ticks and traffic-counter changes therefore do not masquerade as a different route. Raw records retain every original counter. Changes between two positive finite durations are not distinguished by this fingerprint and must not be interpreted as verified policy stability. Link state/speed changes are separate resource evidence, not selected-route identity.

| Status | Meaning |
| --- | --- |
| `unchanged` | Every destination was captured and its normalized selected-route evidence matched at both boundaries |
| `changed` | Complete captures had different fingerprints |
| `unavailable` | At least one boundary could not supply complete route evidence |

The displayed unchanged note says that Windows reported the same local route. It does not claim that the entire connection, configuration, or internet path stayed unchanged. Changed evidence asks the user to repeat the test before comparing it with earlier results. Failed route capture leaves the measurements available and reports the route check as unavailable.

The optional `routing` field remains schema one. This additive raw metadata does not change SQLite or service pipe versions; current versions are documented in [README](../README.md) and [service documentation](service.md). Older route records omit link statistics and remain readable with their original fingerprints.

## Adapter statistics

Native route records now retain optional `linkStatistics` from the existing GUID/LUID/index-checked [GetIfEntry2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2) result. No additional driver statistics query, worker mode, executable, setting operation, or public traffic is added. The reader records the query's UTC start/finish and monotonic duration, reported interface type/state, receive/transmit link speeds, octets, unicast/non-unicast packet counts, discards, errors, and unknown receive protocols. Exact 64-bit values use canonical decimal strings rather than JSON numbers.

[MIB_IF_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2) describes these interface-wide counters and reports link speed in bits per second. They include traffic from other applications. Driver reporting/update behavior and unsupported or unknown fields require separate qualification; a returned zero is not proof of zero utilization or universal packet loss. Link speed is not end-to-end available capacity. Repeated destinations can refer to the same interface and must not be summed as independent adapters.

The query window bounds the observed API call, not individual packet timestamps, counter freshness, or simultaneous driver accounting. Current reports preserve raw observations only. They do not derive utilization, detect all background workloads, normalize counter resets/wraps, attribute traffic to a process, or supply calibrated resource guards. Malformed optional statistics invalidate the route record rather than being silently discarded. Entirely missing statistics remain legacy/unavailable evidence, never fabricated zeros.

Direct connection-test history/export and optional worker/collector receipts preserve this additive data. Route identity explicitly removes the complete statistics object, keeping older fingerprint bytes unchanged. Future statistics comparisons need their own frozen policy and exact interface/driver binding. Production optimization remains disabled.

## Remaining comparison work

Route fingerprints are not `comparison::Plan.environmentSha256` or network-configuration hashes. Trusted OS/driver/interface configuration, policy/VPN coverage, operation-bound checkpoints, collection consistency, and automated repeated-session orchestration are still required. The [comparison library](comparisons.md) does not infer that full context from these route records. No automatic retention or optimization decision uses them in this build.

The baseline comparison adapter does enforce recorded route failures: present metadata must describe complete, consistent, unchanged route choices. Changed or unavailable records cannot be overridden by merely supplying a matching context hash. This admission check is separate from the still-required complete environment capture.

## Validation

Route tests cover actual IPv4/IPv6 loopback route reads without sending traffic, GUID/interface binding, exact LUID round trips, native socket byte order and scope, prefix bounds, cancellation, and changed-choice versus aging-only fingerprints. A core test covers protocol destination extraction, and a saved real TCP fixture verifies exact persistence of optional route metadata and honest legacy reads. The desktop cancellation test preserves unavailable evidence. Frontend tests distinguish unchanged, changed, unavailable, inconsistent, future-version, and absent evidence, and check readable export wording. Earlier local packaged desktop checks passed actual IPv4/IPv6 route capture, results wording, exact JSON/HTML export, and history reload. Packaged MCP and temporary installer/shortcut/GUI/uninstall checks also passed. At `7e154ad`, the [full hosted Windows pipeline](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41302172177) and [separate service lifecycle](https://github.com/celakk1/estrogen-ping-patch/actions/runs/41302174699) both passed. These historical checks predate optional link statistics and do not validate complete environment binding, actual route failover during a measurement, or production optimization.

Counter-specific checks preserve values above JavaScript's integer range through route serialization, load receipts, and a 438-rule recording across database reopen. Removing the explicit fingerprint exclusion reproduces a failing identity test; restoring it passes while retaining the changed raw counters. A native desktop history fixture preserves actual IPv4/IPv6 statistics with a cancelled benchmark and no measurement probes. Actual owned-worker tests require statistics for all sixteen requested loopback routes. Malformed schema, timestamps, decimal counters, and unknown fields are refused. These source checks do not qualify physical-driver accuracy, derive utilization, or replace installed-account and packaged validation.
