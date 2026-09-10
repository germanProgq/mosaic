# Isolated TUN checks

The code supports an inherited host-namespace UDP socket, Linux TUN packet forwarding and guarded cleanup. Local tests verify packet and session behavior over real QUIC. Live Linux runs verified namespace and socket ownership, two sets of bidirectional TUN traffic, packet rejection and cleanup. Independent server observers retained complete healthy control histories. An administrative collection failure interrupted the second automated cleanup; recovery and a separate packet-check window are documented in [the server test record](../testing/README.md). The complete plan is not certified.

## Local checks

```sh
python3 scripts/check.py 3 --local-only
cargo test --locked -p mosaic-core --test net_isolation
```

The packet cases cover IPv4 IHL, total length, checksum, address spoofing, unsupported versions and datagram kinds, valid options/fragments, independent bidirectional transfer and cancellation. Real QUIC cases cover custom UDP sockets, exclusive tunnel ownership and lease release, plus valid diagnostics after a rejected tunnel session. Python tests verify that the guard excludes only the exact owned namespace and socket, retaining unrelated state and rejecting changed owners, protocols or ports.

A native macOS run cannot execute the Linux namespace or TUN syscalls. Build and lint the Linux target separately. Tests must also run on Linux before deployment acceptance; cross compilation alone is not evidence of kernel behavior.

## Linux kernel fixture

On a dedicated Linux test host, run the explicit privileged fixture:

```sh
sudo cargo test --locked -p mosaic-core --test net_isolation \
  -- --ignored --exact linux_namespace_socket_and_tun_ping --nocapture
```

It starts a separate anonymous network namespace, proves an inherited loopback UDP socket survives entry, authenticates over real QUIC, creates a real TUN and requires 20 kernel ICMP replies. Malformed and spoofed incoming packets must be rejected. The child namespace disappears with its process; host links must match before and after. This fixture is excluded from ordinary unprivileged checks. Its static Linux executable passed twice on the supplied client node; the macOS test run cannot execute it. It does not certify live relay TUN, launcher cleanup or shared-node VPN preservation.

## Linux checks

Use the inventoried dedicated relay and extra client node. Follow the README’s baseline and launch commands. The existing VPN must already have representative service probes and a fresh five-minute baseline. Keep packet traffic below the configured rate and use one test flow at a time. Save bounded captures and private run reports outside the ownership directory, which cleanup removes.

1. Run the earlier authenticated diagnostic cases twice against the current relay with preservation monitoring. Record whether the observed outer path uses the existing VPN.
2. Start the dedicated relay with `--tunnel`. Start the client with `isolated-up`, the matching policy and baseline, and the preservation guard. Require the worker’s `isolation.socket` assertion, which follows a successful authenticated QUIC exchange from the isolated process using the inherited socket. The guard independently finds that socket in the original namespace’s UDP table and verifies its UID and inode.
3. Inspect `ip -n mosaic-test -j link show` and both address families’ routes. Require only `lo` and `mosaic0`, MTU 1100, the selected connected /30 and a default route through TUN. Check private DNS through `isolated-exec`; see [the DNS guide](../dns/README.md). Inspect host links and routes independently and require unchanged host state.
4. Capture ICMP on both TUN interfaces with `timeout 60 tcpdump -ni mosaic0 -c 80 -w NEW_FILE.pcap icmp`, running the client capture through `ip netns exec mosaic-test`. Keep exact capture PIDs and stop those processes before namespace cleanup. Send 20 bounded pings in each direction; require 20/20 and matching requests/replies in both captures. Run the two ping directions sequentially.
5. Exercise malformed and spoofed packet fixtures with an authenticated test peer, then a valid packet. Require the invalid packet counters to increase with no invalid packet in the receiving TUN capture. Local `net_isolation` vectors provide those packet forms; their in-memory adapter does not replace Linux capture evidence.
6. Attempt a second tunnel owner and wrong credentials. Neither may create or adopt a TUN. Diagnostic sessions must remain usable. Stop the recorded owner and establish a fresh owner.
7. Stop the exact launcher with SIGTERM. Require the socket and TUN to disappear, the namespace mount to be removed, and post-cleanup VPN verification to pass. Repeat with SIGKILL followed by `isolated-down`. Repeat interruption before authorization and with an occupied TUN/name; require nonzero results and ownership-safe cleanup. A namespace containing an unrelated process must be retained with a cleanup failure until that process exits.
8. Run the whole packet and cleanup sequence twice from fresh starts. Recheck the original baseline after both teardowns. Record each result separately, including failed or blocked assertions.

`python3 scripts/check.py 3` retains BLOCKED deployment status: it does not ingest archived server evidence, and the native connectivity and local preservation gates remain incomplete. A readiness report means only that setup reached that point; it does not certify the ping, capture, cleanup or preservation acceptance checks.

## Protocol and isolation references

The socket technique follows [WireGuard’s namespace documentation](https://www.wireguard.com/netns/), including its explicit note about userspace TUN descriptors. Quinn receives the existing socket through [Endpoint::new](https://docs.rs/quinn/0.11.11/quinn/struct.Endpoint.html#method.new). The adapter uses Linux [IFF_TUN and IFF_NO_PI](https://docs.kernel.org/networking/tuntap.html), with exclusive creation, no persistence and no offload flags. Tokio’s async descriptor wrapper drives packet reads and writes after isolation.

The adapter disables IPv6 on the new TUN before setting MTU 1100. Linux removes an interface's IPv6 state when its MTU drops below 1280, so writing the per-interface IPv6 control afterward can fail with a missing path. See the kernel's [MTU change handling](https://code.googlesource.com/linux/torvalds/linux/+/fdd041028f2294228e10610b4fca6a1a83ac683d/net/ipv6/addrconf.c). The privileged fixture embeds its configuration templates so the test executable can run on a Linux host without the source checkout.

The kernel fixture restores close-on-exec on its inherited transport descriptor before spawning ping, and checks that ping did not inherit it. The production worker applies the same descriptor protection.
