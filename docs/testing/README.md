# Live test records

[Mosaic](../../README.md) › Docs › Live test records

Historical records of live tests on real hosts. They cover diagnostic and isolated Linux behavior only.

> [!IMPORTANT]
> These records do not establish macOS or Windows full-device VPN support. [The corrections](../../fixes.md) and [acceptance manifest](../../tests/manifest.json) require separate installed-package evidence for both desktop clients and compiled relay setup and cleanup. Those deliverables remain BLOCKED; the original PASS and FAIL results below retain their recorded scope.

Contents: [Summary](#summary) · [Remote client node](#remote-client-node) · [Full tunnel checks on the relay host](#full-tunnel-checks-on-the-relay-host) · [Local proxy](#local-proxy) · [Relay installation](#relay-installation) · [Linux TUN and cleanup](#linux-tun-and-cleanup) · [Authenticated connectivity](#authenticated-connectivity) · [Earlier live connectivity tests](#earlier-live-connectivity-tests) · [See also](#see-also)

## Summary

| Date | Record | Host | Result |
| --- | --- | --- | --- |
| October 8, 2026 | [Remote client node](#remote-client-node) | Separate client node to the relay | Passed |
| October 8, 2026 | [Full tunnel checks on the relay host](#full-tunnel-checks-on-the-relay-host) | Relay host | Passed (relay host only) |
| October 8, 2026 | [Local proxy](#local-proxy) | Relay host | Passed (relay host only); Mac proxy not run |
| October 8, 2026 | [Relay installation](#relay-installation) | Relay host | Passed; separate client tunnel egress untested |
| September 10, 2026 | [Linux TUN and cleanup](#linux-tun-and-cleanup) | Supplied Linux hosts | Blocked; individual Linux checks passed |
| September 9, 2026 | [Authenticated connectivity](#authenticated-connectivity) | Supplied Linux hosts and Mac | Failed |
| September 9, 2026 | [Earlier live connectivity tests](#earlier-live-connectivity-tests) | Supplied Linux hosts and Mac | Failed |

## Remote client node

October 8, 2026: **tests from a separate client node to the relay passed over the real network path.**

- **The node:** a production Xray (Trojan) server running nginx, ufw and fail2ban. Its systemd-resolved is inactive, so the host-mode client was not installed and its DNS was not changed.
- **Diagnostics:** `test --all --max-mbps 1` passed twice, with all 500 stream echoes and 1000/1000 datagrams each time.
- **SOCKS5 proxy:**
  - traffic left with the relay's address;
  - HTTPS took 69–75 ms through the relay, against 30–42 ms direct;
  - a 50 MB download ran at 25.2 MB/s, against 38.7 MB/s direct;
  - a 10 MB upload ran at 20.8 MB/s, against 57.0 MB/s direct;
  - 30 parallel connections all succeeded;
  - new requests worked 0.3 seconds after a relay restart.
- **Xray health:** stayed healthy on both hosts throughout: 143 node samples and 138 relay samples, no failures and no restarts.
- **Cleanup:** all temporary files were removed from both hosts afterwards.

## Full tunnel checks on the relay host

October 8, 2026: **isolation, egress, DNS, packet size, IPv6, UDP, reconnect, worker kill, regression, soak, capped download, version pairing and resolver checks passed live on the relay host.**

The isolated client ran with `--dedicated-host`, TUN `mosaic1` and test UID `nobody`. Client and relay shared one host, so these results do not measure a remote network path.

- **Isolation:** the namespace contained only `lo` and `mosaic1`, with a default route through the TUN.
- **Egress:** 10/10 HTTPS requests left with the relay's address.
- **DNS:** 10/10 lookups through the private resolver, and a capture on the relay TUN showed the queries to 1.1.1.1.
- **Packet size:** a 1100-byte don't-fragment ping returned 20/20. At 1101 bytes the ping failed with "Message too long".
- **IPv6:** an external IPv6 fetch failed, as required.
- **UDP:** echo through the tunnel returned 100/100 at 1, 64, 512, 1000 and 1072 bytes. A fragmented 1400-byte datagram reassembled 20/20. The temporary echo firewall rule was removed afterwards.
- **Reconnect:** three 20-second relay stops recovered in 5.7, 5.2 and 5.2 seconds. No request succeeded during the outages.
  - The first attempt failed: a gracefully stopped relay closes with code 0, which the client wrongly treated as permanent.
  - It now retries every close except an authorization or packet-size rejection. The local outage test uses the real shutdown code.
- **Worker kill:** SIGKILL of the worker ended the launcher, and cleanup removed the namespace and ownership records.
- **Regression:** `test --all --max-mbps 1` passed twice, 25/25 assertions each.
- **Soak:** 360/360 DNS and HTTPS cycles over 1795 seconds. Worker memory stayed at 7.9 MB and open descriptors at 12.
- **Capped download:** 2 MB at about 0.8 Mbit/s, within the test client's 1 Mbit/s cap.
- **Version pairings:** the refactored client worked with the earlier relay, and the earlier client's session, stream and datagram checks worked with the upgraded relay.
- **Linux 7.0 resolver:** this kernel refuses bind mounts of memfd files, so the private resolver files now fall back to a detached tmpfs inside the worker's private mount namespace.
- **Xray health:** 1440 representative five-second samples had no failures, and the process never changed. The final median was 256 ms against a 234 ms baseline, within the 20% limit.
- **Cleanup:** all temporary files were removed from the relay afterwards. The relay service stayed installed.

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

October 8, 2026: **compiled relay installation passed on the relay host; tunnel egress from a separate client is untested.**

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

September 10, 2026: **the individual Linux checks passed across the recorded runs; the complete plan remains blocked.**

> [!WARNING]
> The native Mac QUIC failure and privileged Mac firewall gap below remain unresolved. The second automated TUN sequence was interrupted by administrative collection failures, so its original report remains FAIL.

- **Kernel fixtures:** both Linux kernel fixtures passed.
- **Live tunnels:** two fresh live tunnels each returned 20/20 ICMP replies in both directions, with 80 matching packets in each TUN capture.
- **Namespace contents:** each client namespace contained only `lo` and `mosaic0`, with MTU 1100, the connected /30 and no default or external IPv6 route.
- **Inherited socket:** the inherited UDP inode remained in the host namespace under UID 65534.
- **Worker restrictions:** direct inspection confirmed the worker's dropped capabilities, empty supplementary groups, `NoNewPrivs`, and 256 MiB address-space limit.
- **TUN device:** nonpersistent, without packet-info or virtual-network headers.
- **Outer QUIC:** used the Linux node's existing direct egress; no bypass route was added.
- **Rejections:** wrong credentials, an occupied namespace and a second tunnel owner were rejected.
- **Cleanup:** graceful shutdown and failed-authorization cleanup passed. After SIGKILL, cleanup correctly retained a namespace containing an unrelated process; explicit cleanup succeeded after that process ended.
- **Packet rejection:** malformed length/header and spoofed-source packets were rejected before TUN injection. A separate fresh monitored window repeated packet rejection twice: each relay recorded one valid packet in each direction, three rejections and zero drops, with only the valid request/reply in its capture.
- **Authentication:** valid authenticated diagnostics succeeded after wrong-token rejection.
- **Diagnostic repetitions:** both earlier Linux diagnostic repetitions passed on the same production binary hashes: 500/500 byte-exact stream echoes and 1000/1000 unique 1100-byte datagrams each.
- **Descriptor leak:** that diagnostic window later failed when the kernel fixture leaked its inherited descriptor to ping. The fixture now sets close-on-exec and verifies the child descriptors; production already applied that protection.
- **IPv6 setup order:** live testing found a bug where setting MTU 1100 removed the new interface's IPv6 control before it could be disabled. TUN setup now disables IPv6 first.
- **Fixture configuration:** embedded fixture configuration allows execution without a source checkout.
- **Monitor changes:** the monitor now measures the actual HTTPS request with curl `time_total`, records inventory cost separately, and retries a complete inventory up to twice when verified owned resources change during the snapshot. Stable drift and missed deadlines still fail.
- **Teardown transitions:** a packet-check attempt stopped on successive teardown transitions. The final workload separated lifecycle changes by six seconds so each could be inventoried. Vanished processes during `/proc` enumeration are handled as exited processes. Historical failed runs remain unchanged.
- **Observers:** the independent observers continued through the administrative collection interruption. Their recovered histories contain 150/150 passing samples in each of four streams, including the 300-second baseline, five-second cadence and unchanged latency thresholds.
- **Final packet window:** passed all 108/108 samples per stream, including its fresh baseline, workload and post-workload observations.
- **Xray scope:** representative Xray checks used existing configured accounts from the peer Linux server; they do not certify a particular user's device.
- **Final state:** all owned namespaces, TUNs, temporary processes, staged binaries and node test credentials were removed. Final inventories matched their baselines, including Xray PIDs and zero restart counts, routes, resolver state and configuration hashes. Only explicitly authorized, verified SSH-only Fail2Ban ban expirations were reconciled.
- **Local checks:** local format, lint, build and 26 Rust tests passed twice; the final 45 Python checks passed twice, with separate Linux compilation/lint and live kernel execution.
- **Evidence:** raw captures and private artifacts remain under ignored `results/`.
  - [Combined Linux report](../../results/tun-live-1788992747026453000/report.json)
  - [Recovered control histories](../../results/tun-live-1788990903219958000/recovered-preservation.json)
  - [Original collection failure](../../results/xray-preservation-1788990934276804000/report.json)
  - [Final packet-window preservation](../../results/xray-preservation-1788992959747605000/report.json)
  - [Final server comparison](../../results/tun-live-1788992747026453000/server-preservation-after.json)

## Authenticated connectivity

September 9, 2026: **the complete live checks did not pass.**

- **Build:** tests used committed authentication build `cfeb589d08a375130bfe6476b6046eef91310f98` in an isolated checkout while TUN development continued. Native and static Linux binaries were built from that source; 21 Rust tests and 24 Python tests passed twice.
- **Linux client:** completed all 500 byte-exact stream echoes and 1000/1000 unique 1100-byte datagram replies.
- **Rejections:** wrong trust, server name, ALPN and token were rejected; a valid session worked afterward.
- **Relay restart:** the temporary relay shut down, released UDP 443, restarted and accepted a fresh Linux session.
- **Latency stop:** the second Linux stream run was interrupted when the preservation monitor detected a relay inventory-plus-request median increase from 1446.653 to 1789.575 ms, exceeding both the 20% and 10 ms thresholds. Its second datagram run remains incomplete. All collected representative Xray probes passed; the latency threshold still requires the overall run to fail.
- **Mac QUIC:** both Mac QUIC attempts failed after approximately five seconds through the existing Shadowrocket route on `utun5`. The relay capture spans the first attempt and contains only the Linux client's QUIC packets.
- **Shadowrocket settings:** UDP relay was enabled, with all ports allowed and the QUIC rejection rule commented out; the cause of the failed Mac path remains unconfirmed. No VPN settings or escape routes were changed.
- **Handshake capture:** the capture decoder observed `mosaic-relay.internal` and `mosaic-poc/2` in the actual outer ClientHello, with no application token.
- **Mac VPN health:** the Mac passed all 140 HTTPS/egress samples, retained its connected VPN, and had unchanged DNS/proxy settings and egress at final verification. Privileged Mac firewall comparison remains unavailable.
- **First baseline:** stopped because Xray's ephemeral outbound UDP sockets appeared in the listener inventory. The monitor now verifies process identity, executable and configuration before treating supported outbound UDP sockets as runtime traffic. Configured inbound ports and unknown owners remain strict. That failed baseline is retained.
- **Cleanup:** all temporary Mosaic and Xray probe processes, binaries and node test credentials were removed. Final server inventories matched the baseline after removing the verified test-binary inventory: Xray identities, restart counts, configuration hashes, routes and firewall rules were unchanged.
- **Evidence:** these are private local artifacts under ignored `results/`.
  - [Combined report](../../results/authentication-live-1788982590049604000/report.json)
  - [Preservation stop](../../results/xray-preservation-1788983454441825000/report.json)
  - [Mac VPN health](../../results/authentication-live-1788982590049604000/mac-preservation.json)
  - [Handshake capture](../../results/authentication-live-1788982590049604000/handshake-capture.json)

## Earlier live connectivity tests

September 9, 2026: **live validation failed; the full connectivity gate is incomplete.**

Testing used a frozen source snapshot because authenticated-session changes were being implemented concurrently. This evidence does not certify the current authenticated service.

- **Local tests:** the original 13 Rust and 18 Python tests passed twice. Six additional preservation-guard tests also passed twice.
- **Builds:** native macOS and static Linux binaries built successfully; the Linux binaries executed and validated their configs on both supplied hosts. Linux builds used the documented [cargo-zigbuild cross-compilation workflow](https://github.com/rust-cross/cargo-zigbuild#usage), with no toolchain installed on either server.
- **Linux node:** the extra Linux node passed a real QUIC connection and echo, plus actual TLS rejection of wrong trust, server name and ALPN in about 236–239 ms.
- **Mac handshake:** the Mac's valid handshake failed after 5.010 seconds. Its server identity, trust certificate and QUIC parameters matched the Linux node's, and its selected route used the existing VPN interface `utun6`. The underlying cause was not established; no egress bypass was attempted.
- **First live run:** stopped on a listener comparison. Its precise cause was not retained. The monitor was subsequently corrected to exclude queue occupancy and retain concrete before/after drift evidence; the historical failed result was preserved.
- **Node-only run:** a fresh node-only run passed its 300-second baseline, then correctly aborted when the relay inventory-plus-request median increased from 1364.875 to 1648.387 ms (20.8%, +283.5 ms), crossing both documented thresholds. The full live 500-echo matrices and relay restart verification remain incomplete.
- **Cleanup:** temporary relay/client/probe processes, binaries and test credentials were removed from both hosts. Xray service identities and restart counts were unchanged at teardown. The latest readable Mac route, DNS, proxy and listener snapshots matched; privileged Mac firewall comparison remains unavailable.
- **Harness:** the one-off deployment harness has been removed because it depended on frozen builds and private paths from this run. Stored reports and source snapshots remain under `results/`.
- **Evidence:**
  - [Original native attempt](../../results/xray-preservation-1788974219275058000/connectivity/native-handshake.json), which retains the failure
  - [Preservation abort](../../results/xray-preservation-1788974993081242000/report.json), which retains the failure

Current diagnostics require an authenticated relay; see the [current commands](../../README.md) and [preservation tools](../../tools/xray/README.md).

## See also

- [Xray health probes](../../tools/xray/README.md)
- [Isolated TUN checks](../isolation/README.md)
- [Internet forwarding and native HTTPS](../egress/README.md)
- [Namespace DNS and routing](../dns/README.md)
- [Relay installation](../relay/README.md)
- [Session protocol](../session/README.md)
