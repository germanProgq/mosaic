# Isolated TUN checks

[Mosaic](../../README.md) › Docs › Isolated TUN checks

This page explains how to run the isolated Linux tunnel and how to check it. The code supports an inherited host-namespace UDP socket, Linux TUN packet forwarding and guarded cleanup. Local tests verify packet and session behavior over real QUIC, and live Linux runs have verified the main paths.

> [!IMPORTANT]
> The complete plan is not certified. `python3 scripts/check.py 3` retains BLOCKED deployment status.

> [!NOTE]
> Live Linux runs verified namespace and socket ownership, two sets of bidirectional TUN traffic, packet rejection and cleanup. Independent server observers retained complete healthy control histories. An administrative collection failure interrupted the second automated cleanup; recovery and a separate packet-check window are documented in [the server test record](../testing/README.md).

**Contents:** [Run the isolated tunnel](#run-the-isolated-tunnel) · [Local checks](#local-checks) · [Linux kernel fixture](#linux-kernel-fixture) · [Linux checks](#linux-checks) · [Deployment status](#deployment-status) · [Implementation details](#implementation-details) · [See also](#see-also)

## Run the isolated tunnel

The Linux launcher and relay exchange IPv4 packets through exclusive nonpersistent TUN devices. The original launcher remains outside isolation, and a separate worker carries the tunnel inside a new network namespace.

### How it works

- **Socket:** the client opens an ephemeral UDP socket under the baseline policy's non-root `test_uid` in the original namespace.
- **Worker:** a separate worker inherits that descriptor, enters a new network namespace before starting Tokio, proves its socket namespace differs from the worker's, and authenticates through it.
- **TUN:** opens only after Ready. The worker then drops supplementary groups and root privileges.
- **Resolver:** the worker also receives a private mount namespace for its resolver. Applications enter it with `mosaic-client isolated-exec --namespace mosaic-test -- COMMAND`.

The worker's namespace contains only loopback and its TUN, with the configured connected /30, MTU 1100 and a default route through TUN. TUN IPv6 is disabled, and the private mount namespace supplies DNS at 1.1.1.1. Run applications through `isolated-exec` to enter both namespaces.

- **Client host changes:** no veth, host route, firewall, host forwarding or host resolver change is installed.
- **Relay with `--tunnel` alone:** likewise adds only its TUN and connected subnet.
- **Relay with `--forwarding`:** used by the installed service, adds its owned forwarding and NAT.

### Requirements

- **Software:** Python 3, the existing inventory tools, and Linux namespace-cookie and pidfd support.
- **Accounts:** root for setup and a configured non-root account.
- **Policy:** must match the relay IP, namespace and tunnel subnet.

### Start

1. Take a fresh relay and shared-node inventory, then build binaries for their Linux architecture.
2. On the dedicated relay, start the relay with TUN forwarding.

   ```sh
   ./mosaic-relay -c configs/relay.json --tunnel
   ```

3. On the extra node, record the mandatory five-minute VPN baseline. See the [shared-node baseline](../baseline/README.md).
4. Start the guarded launcher on the extra node.

   ```sh
   sudo ./mosaic-client isolated-up -c configs/client-node.json \
     --policy configs/node-baseline.json --baseline .mosaic-baseline \
     --guard tools/network/isolation.py --report results/tunnel.json
   ```

The guard verifies the baseline before setup, then checks host configuration, exact socket/namespace ownership and VPN health every five seconds. Each packet pump has bounded queues and a capped schedule.

Any of these stops the run:

- A failed probe.
- Changed egress.
- Drift.
- A missed sampling deadline.
- Excessive rolling latency.
- Worker RSS above 256 MiB.

> [!NOTE]
> These checks do not constitute a CPU reservation.

### Inspect and ping

With the default example addresses, inspect the namespace and ping the relay from another administration session.

```sh
sudo ip -n mosaic-test addr show
sudo ip -n mosaic-test route show table all
sudo ip netns exec mosaic-test ping -n -c 20 -W 2 10.77.0.1
```

On the dedicated relay, ping the client back.

```sh
ping -n -I mosaic0 -c 20 -W 2 10.77.0.2
```

Capture ICMP on both TUNs with bounded `tcpdump` runs. Both directions must return 20/20; the local packet tests do not replace these Linux assertions.

### Stop and clean up

SIGINT/SIGTERM to the exact launcher stops its worker and guard, removes the owned namespace, and verifies host/VPN controls after teardown. The kernel kills the worker if its launcher dies.

After SIGKILL or interrupted setup, remove the namespace and verify the baseline.

```sh
sudo ./mosaic-client isolated-down --namespace mosaic-test
sudo python3 tools/network/baseline.py verify --policy configs/node-baseline.json
```

- **Resolver files:** sealed anonymous memory files, bound read-only inside the worker's private mount namespace. They disappear after the last application and worker exit, including after SIGKILL.
- **Identity checks:** cleanup verifies process start times, namespace and mount identities.
- **Refusals:** cleanup refuses an active launcher, changed resources or a namespace with unrecognized processes. Stop namespace test commands before teardown.
- **Ownership records:** private under `/run/mosaic-test`. Cleanup never adopts an existing namespace or restores whole-host snapshots.

### Reconnects

When the relay connection is lost, the worker keeps the namespace and TUN and reconnects.

- **Socket:** it retries through a duplicate of the same launcher-verified host socket.
- **Backoff:** waits 1, 2, 4 and then 8 seconds between attempts, with jitter.
- **Fresh sessions:** every new session is freshly authorized, old packet pumps are cancelled, and queued packets are discarded.
- **Stop conditions:** it stops retrying on credential or configuration errors.
- **Applications:** existing application connections may fail; new ones recover.

### Dedicated relay host

> [!NOTE]
> On a dedicated relay host, where the relay and the test client share one machine, add `--dedicated-host`. The launcher accepts it only when the relay address belongs to this host.

In that mode the launcher skips the shared-node VPN guard, whose baseline cannot coexist with the relay's own `mosaic0`, and keeps every namespace isolation check. The client TUN must use a different name from the relay's (for example `mosaic1`). Monitor the host's existing services separately while it runs.

## Local checks

Run the local check script and the isolation test suite.

```sh
python3 scripts/check.py 3 --local-only
cargo test --locked -p mosaic-core --test net_isolation
```

These checks cover three areas.

- **Packet cases:** IPv4 IHL, total length, checksum, address spoofing, unsupported versions and datagram kinds, valid options/fragments, independent bidirectional transfer and cancellation.
- **Real QUIC cases:** custom UDP sockets, exclusive tunnel ownership and lease release, plus valid diagnostics after a rejected tunnel session.
- **Python tests:** the guard excludes only the exact owned namespace and socket, retaining unrelated state and rejecting changed owners, protocols or ports.

> [!WARNING]
> A native macOS run cannot execute the Linux namespace or TUN syscalls. Build and lint the Linux target separately. Tests must also run on Linux before deployment acceptance; cross compilation alone is not evidence of kernel behavior.

## Linux kernel fixture

On a dedicated Linux test host, run the explicit privileged fixture.

```sh
sudo cargo test --locked -p mosaic-core --test net_isolation \
  -- --ignored --exact linux_namespace_socket_and_tun_ping --nocapture
```

The fixture performs these steps:

- **Namespace:** starts a separate anonymous network namespace and proves an inherited loopback UDP socket survives entry.
- **Session:** authenticates over real QUIC.
- **Traffic:** creates a real TUN and requires 20 kernel ICMP replies.
- **Rejection:** malformed and spoofed incoming packets must be rejected.
- **Cleanup:** the child namespace disappears with its process; host links must match before and after.

This fixture is excluded from ordinary unprivileged checks. Its static Linux executable passed twice on the supplied client node; the macOS test run cannot execute it. It does not certify live relay TUN, launcher cleanup or shared-node VPN preservation.

## Linux checks

Use the inventoried dedicated relay and extra client node. Follow the [shared-node baseline](../baseline/README.md), [relay setup](../relay/README.md) and [native client commands](../client/README.md).

Before you start:

- **Baseline:** the existing VPN must already have representative service probes and a fresh five-minute baseline.
- **Traffic:** keep packet traffic below the configured rate and use one test flow at a time.
- **Evidence:** save bounded captures and private run reports outside the ownership directory, which cleanup removes.

Then run these checks in order:

1. Run the earlier authenticated diagnostic cases twice against the current relay with preservation monitoring. Record whether the observed outer path uses the existing VPN.
2. Start the dedicated relay with `--tunnel`. Start the client with `isolated-up`, the matching policy and baseline, and the preservation guard. Require the worker's `isolation.socket` assertion, which follows a successful authenticated QUIC exchange from the isolated process using the inherited socket. The guard independently finds that socket in the original namespace's UDP table and verifies its UID and inode.
3. Inspect `ip -n mosaic-test -j link show` and both address families' routes. Require only `lo` and `mosaic0`, MTU 1100, the selected connected /30 and a default route through TUN. Check private DNS through `isolated-exec`; see [the DNS guide](../dns/README.md). Inspect host links and routes independently and require unchanged host state.
4. Capture ICMP on both TUN interfaces with `timeout 60 tcpdump -ni mosaic0 -c 80 -w NEW_FILE.pcap icmp`, running the client capture through `ip netns exec mosaic-test`. Keep exact capture PIDs and stop those processes before namespace cleanup. Send 20 bounded pings in each direction; require 20/20 and matching requests/replies in both captures. Run the two ping directions sequentially.
5. Exercise malformed and spoofed packet fixtures with an authenticated test peer, then a valid packet. Require the invalid packet counters to increase with no invalid packet in the receiving TUN capture. Local `net_isolation` vectors provide those packet forms; their in-memory adapter does not replace Linux capture evidence.
6. Attempt a second tunnel owner and wrong credentials. Neither may create or adopt a TUN. Diagnostic sessions must remain usable. Stop the recorded owner and establish a fresh owner.
7. Stop the exact launcher with SIGTERM. Require the socket and TUN to disappear, the namespace mount to be removed, and post-cleanup VPN verification to pass. Repeat with SIGKILL followed by `isolated-down`. Repeat interruption before authorization and with an occupied TUN/name; require nonzero results and ownership-safe cleanup. A namespace containing an unrelated process must be retained with a cleanup failure until that process exits.
8. Run the whole packet and cleanup sequence twice from fresh starts. Recheck the original baseline after both teardowns. Record each result separately, including failed or blocked assertions.

## Deployment status

The full check retains BLOCKED deployment status.

```sh
python3 scripts/check.py 3
```

- **Archived evidence:** it does not ingest archived server evidence.
- **Open gates:** the native connectivity and local preservation gates remain incomplete.
- **Readiness reports:** a readiness report means only that setup reached that point. It does not certify the ping, capture, cleanup or preservation acceptance checks.

## Implementation details

### Socket and TUN

- **Socket technique:** follows [WireGuard's namespace documentation](https://www.wireguard.com/netns/), including its explicit note about userspace TUN descriptors.
- **Quinn endpoint:** Quinn receives the existing socket through [Endpoint::new](https://docs.rs/quinn/0.11.11/quinn/struct.Endpoint.html#method.new).
- **TUN flags:** the adapter uses Linux [IFF_TUN and IFF_NO_PI](https://docs.kernel.org/networking/tuntap.html), with exclusive creation, no persistence and no offload flags.
- **Async I/O:** Tokio's async descriptor wrapper drives packet reads and writes after isolation.

### IPv6 and MTU

The adapter disables IPv6 on the new TUN before setting MTU 1100. Linux removes an interface's IPv6 state when its MTU drops below 1280, so writing the per-interface IPv6 control afterward can fail with a missing path. See the kernel's [MTU change handling](https://code.googlesource.com/linux/torvalds/linux/+/fdd041028f2294228e10610b4fca6a1a83ac683d/net/ipv6/addrconf.c).

### Fixture packaging and descriptors

- **Templates:** the privileged fixture embeds its configuration templates so the test executable can run on a Linux host without the source checkout.
- **Close-on-exec:** the kernel fixture restores close-on-exec on its inherited transport descriptor before spawning ping, and checks that ping did not inherit it.
- **Production worker:** applies the same descriptor protection.

## See also

- [Server test record](../testing/README.md)
- [Namespace DNS and routing](../dns/README.md)
- [Session protocol](../session/README.md)
- [Shared-node baseline](../baseline/README.md)
- [Relay setup](../relay/README.md)
- [Native client commands](../client/README.md)
- [Mosaic README](../../README.md)

### References

- [WireGuard namespace documentation](https://www.wireguard.com/netns/)
- [Quinn `Endpoint::new`](https://docs.rs/quinn/0.11.11/quinn/struct.Endpoint.html#method.new)
- [Linux TUN/TAP: IFF_TUN and IFF_NO_PI](https://docs.kernel.org/networking/tuntap.html)
- [Linux IPv6 MTU change handling in addrconf.c](https://code.googlesource.com/linux/torvalds/linux/+/fdd041028f2294228e10610b4fca6a1a83ac683d/net/ipv6/addrconf.c)
