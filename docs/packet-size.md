# IPv4 packet-size diagnosis

Open **Network tests > Large packet check**, choose a numeric IPv4 destination, and press **Start packet check**. Cloudflare's `1.1.1.1` is the initial destination; `8.8.8.8` or another numeric address can be entered. Nothing runs automatically. The check is read-only and does not require the optional Windows service or administrator privileges.

## What it measures

Windows selects the local route, source address, and interface. The application captures that route and native adapter/OS/driver context, binds its requests to the selected IPv4 source, and uses `IcmpSendEcho2Ex` with the IPv4 do-not-fragment flag. Sizes include the 20-byte IPv4 header and 8-byte ICMP header. Source binding and matching before/after evidence do not prove an unchanged internet path throughout the measurement.

Three small requests establish initial responsiveness. Each tested size is checked three times, interleaved with four small control requests. A larger size passes only when all three replies match the requested destination and payload size. A size fails definitively only when all three attempts return Windows' explicit `IP_PACKET_TOO_BIG` status (11009) while the small controls still reply. Mixed outcomes, timeouts, invalid replies, and failed controls remain inconclusive.

The largest request is the smaller of the native interface MTU and 9,000 bytes. An explicit failure at that size allows a bounded search starting at 576 bytes. The adjacent successful/failing sizes are checked again before reporting a boundary. A failing 576-byte request cannot establish a lower candidate. If the largest tested size succeeds, there is no reason from this check to reduce it. Native loopback's large MTU sentinel is retained in the evidence; requests remain capped at 9,000 bytes.

The desktop limits a run to 144 probes and two minutes, with a 750 ms per-request timeout and at least 75 ms pacing. Requested IPv4 bytes cannot exceed 1,296,000. This is a conservative request allowance, including requests rejected locally; replies and wire overhead are additional. Cancellation, time exhaustion, unsupported APIs, and backward wall-clock movement preserve partial evidence without confirming a boundary.

## Interpretation and optimization

This is a diagnostic prerequisite for investigating `ip.pathMtu`, not an enabled optimizer candidate. An explicit size error can come from Windows' cached path knowledge or an intermediate router. Windows may already adapt correctly; a smaller path limit does not prove a broken connection or a gaming performance benefit. ICMP filters, rate limiting, and reply fragmentation limit what can be inferred. The check is IPv4-only and tests one destination. It does not establish a universal MTU, application packet loss, speed, or stable performance across games.

Production admission still requires a demonstrated relevant problem, fresh supported interface and environment evidence, policy/consent, exact service-owned recovery, matched original/candidate/original performance trials, regression guards, independent confirmation, and verified restoration. No result grants permission, applies a setting, bypasses the empty enabled catalog, or retains a candidate. IPv6 diagnosis and multi-destination automatic candidate generation remain unfinished.

## History and export

Application database version six adds `packet_checks`, preserving earlier baselines, load sessions, and configuration snapshots. The latest 50 packet checks can be reopened in this screen. SHA-256 is verified on load, along with schema, source/interface binding, bounded raw samples, timestamps, byte totals, and the complete controlled sequence for a confirmed conclusion. Hashes detect accidental corruption, not malicious changes by the local user or administrator. This history is not trusted authorization or recovery storage.

JSON exports contain every attempted request and raw native outcome, plus local source addresses, routes, adapter identifiers, and available OS/driver context. Review them before sharing. Older application builds refuse the newer database rather than silently changing its version. Service journal, authorization, experiment-store, and pipe schemas are unchanged.

## Native API references

- [IcmpSendEcho2Ex](https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2ex): source address, synchronous operation, and required reply buffer allowance.
- [IP_OPTION_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/ipexport/ns-ipexport-ip_option_information): IPv4 do-not-fragment flag.
- [ICMP_ECHO_REPLY32](https://learn.microsoft.com/en-us/windows/win32/api/ipexport/ns-ipexport-icmp_echo_reply32): scalar reply layout. The implementation never dereferences returned data pointers.

Focused tests cover a non-preset 1427/1428-byte simulated boundary, timeout ambiguity, failed controls, changing boundaries, cancellation/deadlines, forged stored conclusions, bounded large native MTUs, and real source-bound Windows loopback requests. The desktop smoke uses only loopback, checks route/adapter evidence, saved history and JSON export, and stops a partially completed run. These checks do not establish internet PMTU accuracy or optimization benefit on a physical network.
