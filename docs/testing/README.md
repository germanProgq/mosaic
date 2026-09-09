# Earlier live connectivity tests

September 9, 2026: **live validation failed; the full connectivity gate is incomplete.** Testing used a frozen source snapshot because authenticated-session changes were being implemented concurrently. This evidence does not certify the current authenticated service.

- The original 13 Rust and 18 Python tests passed twice. Six additional preservation-guard tests also passed twice. Native macOS and static Linux binaries built successfully; the Linux binaries executed and validated their configs on both supplied hosts.
- The extra Linux node passed a real QUIC connection and echo, plus actual TLS rejection of wrong trust, server name and ALPN in about 236–239 ms.
- The Mac's valid handshake failed after 5.010 seconds. Its server identity, trust certificate and QUIC parameters matched the Linux node's, and its selected route used the existing VPN interface `utun6`. The underlying cause was not established; no egress bypass was attempted.
- The first live run stopped on a listener comparison. Its precise cause was not retained. The monitor was subsequently corrected to exclude queue occupancy and retain concrete before/after drift evidence; the historical failed result was preserved.
- A fresh node-only run passed its 300-second baseline, then correctly aborted when the relay control median increased from 1364.875 to 1648.387 ms (20.8%, +283.5 ms), crossing both documented thresholds. The full live 500-echo matrices and relay restart verification remain incomplete.
- Temporary relay/client/probe processes, binaries and test credentials were removed from both hosts. Xray service identities and restart counts were unchanged at teardown. The latest readable Mac route, DNS, proxy and listener snapshots matched; privileged Mac firewall comparison remains unavailable.

The [verification report](../../results/xray-preservation-1788974993081242000/phase1-verification.json) links the frozen source and individual runs. [The original native attempt](../../results/xray-preservation-1788974219275058000/connectivity/native-handshake.json) and [the preservation abort](../../results/xray-preservation-1788974993081242000/report.json) retain the failures. Linux builds used the documented [cargo-zigbuild cross-compilation workflow](https://github.com/rust-cross/cargo-zigbuild#usage), with no toolchain installed on either server.

The one-off deployment harness has been removed because it depended on frozen builds and private paths from this run. Stored reports and source snapshots remain under `results/`. Current diagnostics require an authenticated relay; see the [current commands](../../README.md) and [preservation tools](../../tools/xray/README.md).
