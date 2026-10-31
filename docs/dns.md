# Direct DNS benchmarks

Select **Website lookup (DNS)** in **Connection test**, review **Website name to look up**, then press **Start test**. **Advanced settings** lets you enter two numeric resolver `IP:port` addresses and choose an A or AAAA record type. Both servers receive the same query name and record type. Standard DNS uses port 53. Scoped IPv6 resolver addresses use `[fe80::1%12]:53`. The core supports two to eight distinct endpoints; the current form exposes two.

The defaults are Cloudflare `1.1.1.1:53`, Google Public DNS `8.8.8.8:53`, and `example.com` A. Provider addresses were checked against their official documentation on 2026-10-31. Configured, ISP, VPN, or private resolvers can be entered explicitly; there is no automatic resolver replacement or discovery policy. A/AAAA selects the answer address family independently of the resolver's IPv4/IPv6 transport address.

Starting the benchmark sends that name to each selected resolver. Private, enterprise, and split-DNS names should only be queried against appropriate resolvers. The application does not import private names, flush any cache, change Windows DNS settings, or replace VPN/enterprise policy.

## Measurement meaning

- `lookupMs` is elapsed request-to-validated-resolution time, including a fresh UDP socket, query exchange, optional TCP connection/fallback, and answer validation. It exists only when the requested A/AAAA address is resolved.
- `responseMs` records arrival time for a validated DNS response, including negative answers. NXDOMAIN, NODATA, SERVFAIL and other response codes cannot contribute a successful lookup time.
- `cacheMode` is always `directResolverCacheUnknown`: direct queries bypass the Windows client cache, but the recursive resolver's cache is unknown. Repeated names are not proven warm or cold measurements. Controlled uncached and Windows client-cache measurements remain unfinished.
- Timeouts, DNS response errors, malformed replies, and operating-system errors have distinct counts. Unsuccessful-lookup percentage includes negative answers and errors; it is not packet loss. Timing quantiles use successful resolutions only.
- TTLs, CNAME chains, addresses, response codes, recursion availability, the resolver-reported AD bit, rejected responses, and UDP/TCP transport are retained in raw JSON/history. The dashboard and HTML show outcome totals and the last response. Byte counts cover DNS payloads and TCP length framing, excluding network/transport headers and handshakes.
- Address-set changes compare consecutive successful responses for each resolver, ignoring order and TTL changes. They are informational: CDN routing, GeoDNS, and load balancing can legitimately change answers. They are not evidence of tampering or a reason to replace a resolver.
- AD is an assertion from the selected resolver over unauthenticated DNS transport. This build performs no independent DNSSEC validation, encrypted DNS, DNSSEC failure-domain testing, or interception detection.

Each request has one shared deadline, up to five seconds, covering UDP and any TCP fallback. Connected UDP sockets filter the source endpoint; transaction IDs use operating-system entropy. Matching requires the expected ID, response/query flags, question name, record type, and class. The bounded Hickory codec handles compressed names. The application follows only the requested answer's CNAME chain, rejects loops/conflicts, and never substitutes unrelated or additional-section addresses. Limits are 256 records, 32 returned addresses, eight aliases, and 32 rejected UDP envelopes per request. Without EDNS, UDP responses are limited to 512 bytes; a matching truncated response triggers one framed TCP exchange with the same resolver. No unbounded retries or background queries run.

DNS latency affects name resolution. It does not measure or establish an improvement to an already connected game's RTT. Neither this baseline nor one fast response establishes a statistically justified optimization. Public resolver reachability, interception, managed-network behavior, and performance still require permitted live validation.

## Validation and compatibility

Unit and loopback integration tests cover name/target validation, matching, compression errors, CNAME conflicts, A/AAAA answers, unrelated records, negative responses, UDP ID rejection, TCP fallback with fragmented writes, deadlines/cancellation, protocol-specific statistics, address changes, and exact SQLite/JSON round trips. Packaged desktop smoke tests use temporary loopback fixtures for IPv4 UDP and IPv6 TCP fallback; no public resolver is queried by the automated suite.

Application database schema four introduced DNS report semantics; schema five adds separate transfer sessions. Both preserve earlier baseline history and backups. Older previews reject newer databases. The privileged recovery journal has an independent schema and is untouched by DNS measurements.
