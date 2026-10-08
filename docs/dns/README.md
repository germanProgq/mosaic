# Namespace DNS and routing

[Mosaic](../../README.md) › Docs › Namespace DNS and routing

This page covers how the isolated Linux worker routes application traffic and resolves names inside its namespace, and how to test it. Local tests cover configuration, command boundaries, response validation and rejection of alternate routes.

> [!IMPORTANT]
> Live DNS, captures, outage behavior and VPN preservation remain required acceptance checks; earlier incomplete deployment gates still apply. The deployment check remains BLOCKED while live assertions are incomplete.

> [!WARNING]
> This is network isolation for trusted test programs, not a filesystem or hostile-program sandbox.

**Contents:** [Overview](#overview) · [Run applications](#run-applications) · [Private resolver](#private-resolver) · [Route guard](#route-guard) · [Healthy DNS and HTTPS](#healthy-dns-and-https) · [Relay outage](#relay-outage) · [Verification](#verification) · [See also](#see-also)

## Overview

The isolated Linux worker installs a default IPv4 route through its TUN and a private resolver using only 1.1.1.1.

- **Application traffic:** DNS, UDP, TCP and HTTPS use the namespace route.
- **Transport:** the inherited QUIC socket remains attached to the original host namespace.

## Run applications

Start the dedicated relay with its existing TUN forwarding configuration (see [relay setup](../relay/README.md)). Record the five-minute [shared-node VPN baseline](../baseline/README.md) and start the guarded `isolated-up` launcher (see the [native client commands](../client/README.md)).

Use `isolated-exec` to run test applications inside the namespace.

```sh
sudo ./mosaic-client isolated-exec --namespace mosaic-test -- getent ahostsv4 example.com
sudo ./mosaic-client isolated-exec --namespace mosaic-test -- dig -r @1.1.1.1 example.com A +time=2 +tries=1
sudo ./mosaic-client isolated-exec --namespace mosaic-test -- dig -r +tcp @1.1.1.1 example.com A +time=2 +tries=1
sudo ./mosaic-client isolated-exec --namespace mosaic-test -- curl -q --noproxy '*' -4fsS --max-time 20 https://api.ipify.org
```

### What `isolated-exec` does

1. Verifies the active launcher, worker, namespace identities, routing readiness and recent VPN guard sample.
2. Opens the worker's network and mount namespace descriptors before entry and checks their recorded identities.
3. Enters both namespaces.
4. Drops to the configured non-root test account.
5. Replaces itself with the application.

A failed entry returns an error without running the application. There is no inherited QUIC descriptor in these application processes.

The command supplies the verified namespace name and inode to test programs through two variables. The outage probe compares these with its actual namespace.

| Variable | Value |
| --- | --- |
| `MOSAIC_NAMESPACE` | Verified namespace name |
| `MOSAIC_NAMESPACE_INODE` | Verified namespace inode |

### Why not `ip netns exec`

The plan's application commands using `ip netns exec` are replaced by `isolated-exec` for DNS tests. `ip netns exec` alone enters the network namespace without the worker's private resolver mounts. It remains useful for administrative route inspection and packet capture.

## Private resolver

The worker creates sealed memory files and binds them read-only over `/etc/resolv.conf` and `/etc/nsswitch.conf` inside its private mount namespace.

- **Resolver:** one server and bounded retries.
- **Name service:** uses `hosts: dns`.
- **nscd:** existing nscd host-cache files and sockets are masked in that private mount namespace.
- **Host state:** host resolver files, services and caches are untouched.
- **Environment:** `LOCALDOMAIN`, `RES_OPTIONS` and `HOSTALIASES` are removed from application environments.
- **Applications:** must use ordinary DNS resolution.

The private mount approach avoids creating files under `/etc/netns` or retaining resolver files after interrupted setup. Linux documents namespace resolver mounts in [ip-netns](https://man7.org/linux/man-pages/man8/ip-netns.8.html), private mount propagation in [mount](https://man7.org/linux/man-pages/man2/mount.2.html), and anonymous sealed files in [memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html).

## Route guard

The guard checks the namespace state alongside the original host and VPN controls every five seconds.

- **Checked state:** interfaces, IPv4 routes and policy rules, absence of external IPv6 routes, worker mount identity and private DNS configuration.
- **Default route:** once routing is ready, exactly one default route must use TUN.
- **Stop conditions:** unexpected interfaces, gateways, route tables, next hops or resolver changes stop the worker.

## Healthy DNS and HTTPS

Install no tools on a shared node during the test. The existing node needs Python 3, `ip`, `nsenter`, `getent`, `dig` and `curl`.

With the guard active and the relay's independently measured public egress available, run the DNS driver.

```sh
sudo python3 tools/network/dns.py --client ./mosaic-client \
  --namespace mosaic-test --relay-egress MEASURED_RELAY_IP \
  --report results/namespace-dns.json
```

Set `--subnet` if the configured tunnel subnet differs from 10.77.0.0/30.

The driver runs ten fresh processes for each of these checks:

| Check | Notes |
| --- | --- |
| System hostname resolution | |
| UDP DNS | Automatic TCP fallback is disabled |
| TCP DNS | |
| example.com HTTPS | |
| api.ipify.org HTTPS | |

- **Limits:** requests use bounded time, output and transfer rates, with no DNS pins or proxies.
- **Answers:** DNS must return successful public IPv4 answers.
- **Egress:** every public-IP response must equal the measured relay egress.
- **Guard:** the guard is checked during each running request.
- **Reports:** record actual successful assertions with byte counts and hashes, and do not claim deployment acceptance.

### Captures

Record bounded DNS captures on the client TUN and relay TUN/WAN during the requests. Require matching UDP and TCP port-53 traffic to 1.1.1.1 and verified relay egress.

- **Client TUN scope:** capture only Mosaic DNS. Host VPN DNS traffic is outside this test's leak boundary.
- **Host evidence:** retain host resolver and VPN control evidence before, during and after each run.

## Relay outage

> [!IMPORTANT]
> Keep an independent host VPN observer running for the whole outage and recovery window, including after the launcher exits. The launcher's guard ends during teardown, so its report alone cannot prove preservation throughout this window.

Place the probe scripts in a directory readable by the configured non-root test account.

Start the probe while the relay and launcher are healthy, using a current public A record for api.ipify.org and a new report path writable by that account.

```sh
sudo ./mosaic-client isolated-exec --namespace mosaic-test -- \
  python3 /READABLE_PROJECT/tools/network/no_escape.py \
  --namespace mosaic-test --ipify-ip VERIFIED_IPIFY_IP \
  --relay-egress MEASURED_RELAY_IP --report /tmp/mosaic-outage.json
```

Then follow this procedure:

1. Wait for the probe to verify working DNS and HTTPS and print readiness.
2. Within its ten-second preparation window, stop only the recorded Mosaic relay process.
3. Keep the relay stopped until the probe finishes.
4. After the probe exits, run `isolated-down` to remove the inactive owned namespace and verify the baseline.
5. Restart only Mosaic relay, relaunch the guarded client with a fresh valid baseline if needed, and repeat the healthy DNS driver.

### What the probe checks

The probe holds its network and resolver namespaces and requires at least twenty seconds of failed lookups and requests.

- **Failing paths:** system lookups, UDP/TCP DNS, hostname HTTPS and pinned public-IP HTTPS.
- **Strictness:** unexpected exit codes and tool failures reject the run.
- **Timing:** each complete request cycle is bounded, so the observation can finish several seconds after twenty seconds.
- **Routes:** no alternate interface, next hop or IPv6 route may appear.

### Reconnect behavior

The worker now reconnects automatically and keeps its TUN while the relay is unavailable; see the [Mosaic README](../../README.md) and [Reconnects](../isolation/README.md#reconnects). Its TUN disappears when the worker exits.

The outage probe deliberately holds the namespace long enough to test the remaining failure window. Launcher cleanup then refuses this unrecognized application process and retains ownership records.

> [!WARNING]
> Do not claim automatic reconnect or preservation of existing application connections.

### Shutdown cases

Repeat normal shutdown, SIGKILL and interrupted setup with no test applications left running.

- **Resolver state:** resolver mounts and anonymous files disappear with the last process in the private mount namespace.
- **Routes:** namespace teardown removes its routes.
- **Cleanup limits:** cleanup does not restore host resolver snapshots and refuses an active launcher or a namespace containing unrecognized processes.

## Verification

Run the local and deployment checks.

```sh
python3 scripts/check.py 5 --local-only
python3 scripts/check.py 5
```

- **Local command:** repeats existing checks and the DNS/configuration, application boundary, route rejection, probe cancellation and outage-result tests.
- **Deployment command:** remains BLOCKED while live assertions are incomplete.

### Kernel fixture

An explicit kernel fixture is available on a dedicated Linux test host with root, `ip`, `getent`, `curl` and `/dev/net/tun`. Run it with a 60-second timeout.

```sh
sudo timeout 60 cargo test --locked -p mosaic-core --test net_dns \
  -- --ignored --exact linux_private_dns_and_no_escape --nocapture
```

- **Namespaces:** uses anonymous network and mount namespaces.
- **Healthy path:** answers an actual system DNS query through a real TUN.
- **Failure path:** leaves TUN unanswered and requires DNS and pinned HTTPS to fail.
- **Host files:** verifies parent resolver/name-service files and links after normal exit and SIGKILL.
- **Scope:** does not use Internet egress, relay NAT or the shared-node VPN, and is excluded from ordinary unprivileged tests.

Linux cross-compilation does not count as execution of this fixture.

## See also

- [Isolated TUN checks](../isolation/README.md)
- [Session protocol](../session/README.md)
- [Shared-node baseline](../baseline/README.md)
- [Relay setup](../relay/README.md)
- [Native client commands](../client/README.md)
- [Mosaic README](../../README.md)

### References

- [ip-netns(8)](https://man7.org/linux/man-pages/man8/ip-netns.8.html)
- [mount(2)](https://man7.org/linux/man-pages/man2/mount.2.html)
- [memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
