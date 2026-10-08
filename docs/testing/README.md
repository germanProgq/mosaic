# Live test records

These historical records cover diagnostic and isolated Linux behavior only. They do not establish macOS or Windows full-device VPN support. [The corrections](../../fixes.md) and [acceptance manifest](../../tests/manifest.json) require separate installed-package evidence for both desktop clients and compiled relay setup and cleanup. Those deliverables remain BLOCKED; the original PASS and FAIL results below retain their recorded scope.

## Local proxy

October 8, 2026: **proxy mode passed on the relay host; the Mac proxy was built but not run.**

- **Relay upgrade:** the relay was upgraded in place to run `--tunnel --forwarding --proxy`.
- **Test setup:** a `mosaic-client proxy` ran on the relay host and connected to the relay's public address.
- **Egress:** traffic through it left with the relay's address.
- **Requests:** 10 of 10 HTTPS requests took 16–24 ms, against 17–27 ms direct, and 30 parallel connections all succeeded.
- **Download:** 50 MB ran at 40.0 MB/s through the proxy and 39.1 MB/s direct.
- **Blocked destinations:** the relay's SSH port, cloud metadata and a loopback-only service were refused.
- **Relay restart:** after a restart, new requests worked again without restarting the proxy.
- **Memory:** about 10 MB for the client and 12 MB for the relay.
- **Xray health:** 82 representative five-second Xray samples, including a three-minute fresh baseline, showed no failures and the same Xray process.
- **What this does not measure:** client and relay shared a host, so these numbers do not measure the path from a remote client.

## Relay installation

October 8, 2026: **compiled relay installation passed on 203.0.113.76; tunnel egress from a separate client is untested.**

- **Replaced service:** the earlier fetch-only relay, launched through Python, was archived on the relay and removed.
- **Credentials:** new 30-day credentials were generated on the relay; the private key never left it.
- **Installed:** `mosaic-relay --setup` installed the hardened service with owned forwarding.
- **First install attempt:** it stopped safely before any rules were installed. Ubuntu reports `ufw.service` as active even when ufw is disabled, so the check now reads ufw's own setting.
- **Diagnostics:** session, stream echo and 1000 datagram echoes passed from the relay host.
- **Rejections:** a wrong token, an untrusted certificate and the wrong server name were rejected, and a valid session worked afterwards.
- **Restart and kill:** after a restart and after SIGKILL, the service recovered with exactly one set of forwarding rules.
- **Stop:** removed the rules and the ownership record. IPv4 forwarding kept its original value of 1.
- **Uninstall and reinstall:** uninstall left no files or rules, and reinstall passed.
- **Xray health:** 181 five-second representative samples ran across the whole window, including a 300-second baseline, with no failures. The Xray PID and restart count did not change, and the median probe time stayed near 236 ms.
- **Not yet tested:** a separate client using the tunnel. The test node rejected its recorded password after a reinstall, and the Mac's Shadowrocket VPN intercepts UDP to the relay.

## Linux TUN and cleanup

September 10, 2026: **the individual Linux checks passed across the recorded runs; the complete plan remains blocked.** The native Mac QUIC failure and privileged Mac firewall gap below remain unresolved. The second automated TUN sequence was interrupted by administrative collection failures, so its original report remains FAIL.

Both Linux kernel fixtures passed. Two fresh live tunnels each returned 20/20 ICMP replies in both directions, with 80 matching packets in each TUN capture. Each client namespace contained only `lo` and `mosaic0`, with MTU 1100, the connected /30 and no default or external IPv6 route. The inherited UDP inode remained in the host namespace under UID 65534. Direct inspection confirmed the worker's dropped capabilities, empty supplementary groups, `NoNewPrivs`, and 256 MiB address-space limit. TUN was nonpersistent, without packet-info or virtual-network headers. Outer QUIC used the Linux node's existing direct egress; no bypass route was added.

Wrong credentials, an occupied namespace and a second tunnel owner were rejected. Graceful shutdown and failed-authorization cleanup passed. After SIGKILL, cleanup correctly retained a namespace containing an unrelated process; explicit cleanup succeeded after that process ended. Malformed length/header and spoofed-source packets were rejected before TUN injection. A separate fresh monitored window repeated packet rejection twice: each relay recorded one valid packet in each direction, three rejections and zero drops, with only the valid request/reply in its capture. Valid authenticated diagnostics succeeded after wrong-token rejection.

Both earlier Linux diagnostic repetitions passed on the same production binary hashes: 500/500 byte-exact stream echoes and 1000/1000 unique 1100-byte datagrams each. That diagnostic window later failed when the kernel fixture leaked its inherited descriptor to ping. The fixture now sets close-on-exec and verifies the child descriptors; production already applied that protection.

Live testing also found an IPv6 setup-order bug: setting MTU 1100 removed the new interface's IPv6 control before it could be disabled. TUN setup now disables IPv6 first. Embedded fixture configuration allows execution without a source checkout. The monitor now measures the actual HTTPS request with curl `time_total`, records inventory cost separately, and retries a complete inventory up to twice when verified owned resources change during the snapshot. Stable drift and missed deadlines still fail. A packet-check attempt stopped on successive teardown transitions; the final workload separated lifecycle changes by six seconds so each could be inventoried. Vanished processes during `/proc` enumeration are handled as exited processes. Historical failed runs remain unchanged.

The independent observers continued through the administrative collection interruption. Their recovered histories contain 150/150 passing samples in each of four streams, including the 300-second baseline, five-second cadence and unchanged latency thresholds. The final packet window passed all 108/108 samples per stream, including its fresh baseline, workload and post-workload observations. Representative Xray checks used existing configured accounts from the peer Linux server; they do not certify a particular user's device.

All owned namespaces, TUNs, temporary processes, staged binaries and node test credentials were removed. Final inventories matched their baselines, including Xray PIDs and zero restart counts, routes, resolver state and configuration hashes. Only explicitly authorized, verified SSH-only Fail2Ban ban expirations were reconciled. Local format, lint, build and 26 Rust tests passed twice; the final 45 Python checks passed twice, with separate Linux compilation/lint and live kernel execution.

See the [combined Linux report](../../results/tun-live-1788992747026453000/report.json), [recovered control histories](../../results/tun-live-1788990903219958000/recovered-preservation.json), [original collection failure](../../results/xray-preservation-1788990934276804000/report.json), [final packet-window preservation](../../results/xray-preservation-1788992959747605000/report.json) and [final server comparison](../../results/tun-live-1788992747026453000/server-preservation-after.json). Raw captures and private artifacts remain under ignored `results/`.

## Authenticated connectivity

September 9, 2026: **the complete live checks did not pass.** Tests used committed authentication build `cfeb589d08a375130bfe6476b6046eef91310f98` in an isolated checkout while TUN development continued. Native and static Linux binaries were built from that source; 21 Rust tests and 24 Python tests passed twice.

The Linux client completed all 500 byte-exact stream echoes and 1000/1000 unique 1100-byte datagram replies. Wrong trust, server name, ALPN and token were rejected; a valid session worked afterward. The temporary relay shut down, released UDP 443, restarted and accepted a fresh Linux session.

The second Linux stream run was interrupted when the preservation monitor detected a relay inventory-plus-request median increase from 1446.653 to 1789.575 ms, exceeding both the 20% and 10 ms thresholds. Its second datagram run remains incomplete. All collected representative Xray probes passed; the latency threshold still requires the overall run to fail.

Both Mac QUIC attempts failed after approximately five seconds through the existing Shadowrocket route on `utun5`. The relay capture spans the first attempt and contains only the Linux client's QUIC packets. Shadowrocket's UDP relay was enabled, with all ports allowed and the QUIC rejection rule commented out; the cause of the failed Mac path remains unconfirmed. No VPN settings or escape routes were changed.

The capture decoder observed `mosaic-relay.internal` and `mosaic-poc/2` in the actual outer ClientHello, with no application token. The Mac passed all 140 HTTPS/egress samples, retained its connected VPN, and had unchanged DNS/proxy settings and egress at final verification. Privileged Mac firewall comparison remains unavailable.

The first baseline stopped because Xray's ephemeral outbound UDP sockets appeared in the listener inventory. The monitor now verifies process identity, executable and configuration before treating supported outbound UDP sockets as runtime traffic. Configured inbound ports and unknown owners remain strict. That failed baseline is retained.

All temporary Mosaic and Xray probe processes, binaries and node test credentials were removed. Final server inventories matched the baseline after removing the verified test-binary inventory: Xray identities, restart counts, configuration hashes, routes and firewall rules were unchanged.

See the [combined report](../../results/authentication-live-1788982590049604000/report.json), [preservation stop](../../results/xray-preservation-1788983454441825000/report.json), [Mac VPN health](../../results/authentication-live-1788982590049604000/mac-preservation.json) and [handshake capture](../../results/authentication-live-1788982590049604000/handshake-capture.json). These are private local artifacts under ignored `results/`.

## Earlier live connectivity tests

September 9, 2026: **live validation failed; the full connectivity gate is incomplete.** Testing used a frozen source snapshot because authenticated-session changes were being implemented concurrently. This evidence does not certify the current authenticated service.

- The original 13 Rust and 18 Python tests passed twice. Six additional preservation-guard tests also passed twice. Native macOS and static Linux binaries built successfully; the Linux binaries executed and validated their configs on both supplied hosts.
- The extra Linux node passed a real QUIC connection and echo, plus actual TLS rejection of wrong trust, server name and ALPN in about 236–239 ms.
- The Mac's valid handshake failed after 5.010 seconds. Its server identity, trust certificate and QUIC parameters matched the Linux node's, and its selected route used the existing VPN interface `utun6`. The underlying cause was not established; no egress bypass was attempted.
- The first live run stopped on a listener comparison. Its precise cause was not retained. The monitor was subsequently corrected to exclude queue occupancy and retain concrete before/after drift evidence; the historical failed result was preserved.
- A fresh node-only run passed its 300-second baseline, then correctly aborted when the relay inventory-plus-request median increased from 1364.875 to 1648.387 ms (20.8%, +283.5 ms), crossing both documented thresholds. The full live 500-echo matrices and relay restart verification remain incomplete.
- Temporary relay/client/probe processes, binaries and test credentials were removed from both hosts. Xray service identities and restart counts were unchanged at teardown. The latest readable Mac route, DNS, proxy and listener snapshots matched; privileged Mac firewall comparison remains unavailable.

The [verification report](../../results/xray-preservation-1788974993081242000/phase1-verification.json) links the frozen source and individual runs. [The original native attempt](../../results/xray-preservation-1788974219275058000/connectivity/native-handshake.json) and [the preservation abort](../../results/xray-preservation-1788974993081242000/report.json) retain the failures. Linux builds used the documented [cargo-zigbuild cross-compilation workflow](https://github.com/rust-cross/cargo-zigbuild#usage), with no toolchain installed on either server.

The one-off deployment harness has been removed because it depended on frozen builds and private paths from this run. Stored reports and source snapshots remain under `results/`. Current diagnostics require an authenticated relay; see the [current commands](../../README.md) and [preservation tools](../../tools/xray/README.md).
