# User-owned transfer protocol, version one

This is an application-defined protocol for explicitly selected, user-owned benchmark servers. It is not a claimed API for an unrelated public service. Native clients require HTTPS with normal certificate validation, except for literal loopback HTTP origins used for local testing. Origins cannot contain credentials, paths, queries, or fragments. Redirects, proxies, content decoding, cookies, and automatic retries are disabled.

## Server contract

`GET /epp/v1/download?bytes=N` returns HTTP 200, an exact `Content-Length: N`, uncompressed synthetic bytes, `Cache-Control: no-store`, and `X-Epp-Benchmark-Protocol: 1`. A truncated body, wrong length, encoded body, or missing protocol identifier fails the request. There are no range or arbitrary-file downloads.

`POST /epp/v1/upload` accepts an `application/octet-stream` body with an exact Content-Length. After consuming it, the server returns a successful status, `X-Epp-Benchmark-Protocol: 1`, `X-Epp-Received-Bytes: N`, and an acknowledgement body no larger than 4096 bytes. The client requires the matching byte acknowledgement. Test data must be discarded, not persisted.

Client plans cap each direction's total payload across one to four streams, with a shared deadline. The payload is split among streams; it is not multiplied by stream count. Each per-provider direction allows 1 KiB to 512 MiB and a 100 ms to 60 s deadline. Session configuration imposes an additional aggregate payload budget across all selected providers. A failed direction skips the next direction for that provider. No retries are automatic, including after HTTP 429; Retry-After is retained as evidence.

## Local reference server

With the development toolchain installed, run `node scripts/benchmark-server.mjs` to start the loopback-only reference server at `http://127.0.0.1:8088/`. An optional `--port PORT` changes its port. In **Speed test**, open **Advanced settings**, turn off Cloudflare, enter that origin, and use loopback latency targets to keep the entire test local. Stop the server with Ctrl+C.

The reference implementation accepts only fixed protocol paths, synthetic data, four active requests, a 512 MiB request limit, a two GiB process payload quota, bounded headers/connections, and timeouts. Quota reservations are not refunded after failures. It binds only literal loopback addresses and serves no user files. A remote deployment needs an independently configured HTTPS reverse proxy, access control, rate limits, and the owner's permission; this development server does not install or configure those components.

Automated GUI checks import the same server with throttled transfers. They verify exact upload/download totals, parallel streams, concurrent native IPv4/IPv6 echo, recovery samples, history, exports, and cancellation before transfer traffic begins. The fixture's counters are application-level counters, not wire-byte instrumentation.
