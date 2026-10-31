# Initial candidate registry

These are research candidates, not enabled setting mutations. No candidate may run until its client-OS support, adapter capability, authorization, durable rollback, and independent failure recovery have been verified. Original values must be read and restored exactly; factory reset is not rollback.

| Identifier | Mechanism and hypothesis | Support/privilege gate | Risks / restart | Verification / rollback |
| --- | --- | --- | --- | --- |
| `tcp.receiveAutoTuning` | Receive-window sizing can constrain bandwidth-delay utilization | Supported Windows client TCP settings; service-only write | Throughput regression; preserve modern defaults | Read supported TCP setting, compare repeated throughput/loaded latency, restore exact prior value and read back |
| `adapter.interruptModeration` | Driver interrupt batching trades CPU overhead for latency | Exact adapter GUID and driver-exposed supported property/value; service write | CPU increase, throughput regression, possible adapter restart | Supported property readback, repeated matched sessions, restore original property; restart only with authorization |
| `adapter.rss` | Spread receive processing when supported | Hardware/driver/OS capability and service authorization | CPU/throughput regression; driver-specific restart | Read effective RSS state and queues, match workload, restore and verify original state |
| `adapter.rsc` | Receive coalescing trades CPU work and delivery behavior | Capability per adapter and OS; service write | Workload-dependent latency/throughput trade-off | Read effective state, baseline-relative comparisons, exact verified restore |
| `dns.resolverSelection` | Resolver choice can improve lookup reliability/latency | Explicit authorization; exclude enterprise/VPN/private/split-horizon dependencies | Resolution failures and policy breakage; generally no restart | DNS-specific cached/uncached/failure tests; restore exact address list and DHCP semantics, not a guessed public resolver |
| `ip.pathMtu` | Diagnose a measured PMTU/fragmentation problem | Diagnosis first; family and interface capability; service write | Connectivity loss; family-specific behavior | Verify path and effective MTU, independent watchdog, exact prior-value rollback |

The initial enabled catalog is empty. Unsupported values, arbitrary registry paths, forced duplex, security-service changes, global Nagle tweaks, adapter disablement, and undocumented settings are not allowed. DNS performance must never be marketed as an established-session gaming RTT improvement.
