# Source verification and feasibility research

Research checked on 2026-10-31. These references establish design constraints; they do not prove improvements on a particular Windows client or adapter. Exact crate/npm resolutions are recorded in lockfiles.

- [Tauri Windows prerequisites](https://v2.tauri.app/start/prerequisites/): MSVC development tools and WebView2 are required. The launcher checks them before starting compilation.
- [Tauri Windows installer](https://v2.tauri.app/distribute/windows-installer/): NSIS supports Windows distribution. The configured build is per-user and does not elevate the development launcher.
- [NSIS command-line usage](https://nsis.sourceforge.io/Docs/Chapter3.html): `/D=` and `_?=` must be last and unquoted even for paths with spaces. The installer smoke test uses `_?=` so waiting for the uninstaller covers its full lifecycle rather than only its temporary-copy bootstrap.
- [Tauri process model and external binaries](https://v2.tauri.app/develop/sidecar/): lifecycle ownership must be explicit. This build uses a local logical service; the privileged service remains a separate required component.
- [Microsoft named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights): default descriptors may grant read access to Everyone/anonymous. A privileged protocol requires an explicit security descriptor and verified caller identity.
- [Get-NetAdapter](https://learn.microsoft.com/en-us/powershell/module/netadapter/get-netadapter): supports read-only adapter discovery and hidden/virtual adapter enumeration. The embedded script uses supported NetAdapter and NetTCPIP cmdlets.
- [Get-NetIPConfiguration](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipconfiguration): documents IP configuration discovery; default output alone excludes some virtual/disconnected interfaces, so discovery collects adapters, IP interfaces, routes, and resolvers separately.
- [Microsoft adapter performance tuning](https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-performance-tuning-nics): trade-offs depend on hardware and workload. This is Windows Server guidance and is not treated as proof that a setting benefits a Windows 10/11 client.
- [RFC 6349](https://www.rfc-editor.org/rfc/rfc6349.html): managed-network TCP throughput methodology. TCP connection establishment alone is not a substitute for throughput or loaded responsiveness.
- [MCP stdio transport](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports): newline-delimited UTF-8 JSON-RPC; stdout must contain protocol messages only. Implemented protocol version is explicitly pinned to 2025-06-18, rather than claiming every newer version is supported.
- [Cloudflare resolver addresses](https://developers.cloudflare.com/1.1.1.1/ip-addresses/) and [Google Public DNS addresses](https://developers.google.com/speed/public-dns/docs/using): identify independent public DNS destinations used as editable TCP port-53 defaults. These probes do not change DNS settings or claim to measure DNS resolution.

## Research gates still open

Verify official provider APIs, traffic policies, privacy terms, supported discovery, and redistribution licenses before implementing NDT7, Cloudflare throughput infrastructure, or optional Ookla/iperf3 adapters. No undocumented website endpoint is used as a speed-test API. Verify Windows 10/11 client API compatibility and driver behavior in a test lab before enabling any candidate setter. Verify supported inference APIs, credential protection, and MCP proposal validation before enabling paid or local inference.
