# Namespace DNS and routing

The isolated Linux worker installs a default IPv4 route through its TUN and a private resolver using only 1.1.1.1. Application DNS, UDP, TCP and HTTPS use the namespace route. The inherited QUIC socket remains attached to the original host namespace. Local tests cover configuration, command boundaries, response validation and rejection of alternate routes. Live DNS, captures, outage behavior and VPN preservation remain required acceptance checks; earlier incomplete deployment gates still apply.

## Run applications

Start the dedicated relay with its existing TUN forwarding configuration. Record the five-minute shared-node VPN baseline and start the guarded `isolated-up` launcher as described in the repository README. Use the new command for test applications:

```sh
sudo ./mosaic-client isolated-exec --namespace mosaic-test -- getent ahostsv4 example.com
sudo ./mosaic-client isolated-exec --namespace mosaic-test -- dig -r @1.1.1.1 example.com A +time=2 +tries=1
sudo ./mosaic-client isolated-exec --namespace mosaic-test -- dig -r +tcp @1.1.1.1 example.com A +time=2 +tries=1
sudo ./mosaic-client isolated-exec --namespace mosaic-test -- curl -q --noproxy '*' -4fsS --max-time 20 https://api.ipify.org
```

`isolated-exec` verifies the active launcher, worker, namespace identities, routing readiness and recent VPN guard sample. It opens the worker's network and mount namespace descriptors before entry, checks their recorded identities, enters both, drops to the configured non-root test account and replaces itself with the application. A failed entry returns an error without running the application. There is no inherited QUIC descriptor in these application processes. The command supplies the verified namespace name and inode to test programs through `MOSAIC_NAMESPACE` and `MOSAIC_NAMESPACE_INODE`; the outage probe compares these with its actual namespace.

The worker creates sealed memory files and binds them read-only over `/etc/resolv.conf` and `/etc/nsswitch.conf` inside its private mount namespace. The namespace resolver has one server and bounded retries. Its name-service configuration uses `hosts: dns`, and existing nscd host-cache files and sockets are masked in that private mount namespace. Host resolver files, services and caches are untouched. `LOCALDOMAIN`, `RES_OPTIONS` and `HOSTALIASES` are removed from application environments. Applications must use ordinary DNS resolution; this is network isolation for trusted test programs, not a filesystem or hostile-program sandbox.

The plan's application commands using `ip netns exec` are replaced by `isolated-exec` for DNS tests. `ip netns exec` alone enters the network namespace without the worker's private resolver mounts. It remains useful for administrative route inspection and packet capture. The private mount approach avoids creating files under `/etc/netns` or retaining resolver files after interrupted setup. Linux documents namespace resolver mounts in [ip-netns](https://man7.org/linux/man-pages/man8/ip-netns.8.html), private mount propagation in [mount](https://man7.org/linux/man-pages/man2/mount.2.html), and anonymous sealed files in [memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html).

The guard checks interfaces, IPv4 routes and policy rules, absence of external IPv6 routes, worker mount identity and private DNS configuration. Once routing is ready, exactly one default route must use TUN. Unexpected interfaces, gateways, route tables, next hops or resolver changes stop the worker. Checks still run alongside the original host and VPN controls every five seconds.

## Healthy DNS and HTTPS

Install no tools on a shared node during the test. The existing node needs Python 3, `ip`, `nsenter`, `getent`, `dig` and `curl`. With the guard active and the relay's independently measured public egress available:

```sh
sudo python3 tools/network/dns.py --client ./mosaic-client \
  --namespace mosaic-test --relay-egress MEASURED_RELAY_IP \
  --report results/namespace-dns.json
```

Set `--subnet` if the configured tunnel subnet differs from 10.77.0.0/30. The driver runs ten fresh processes for each of system hostname resolution, UDP DNS, TCP DNS, example.com HTTPS and api.ipify.org HTTPS. Requests use bounded time, output and transfer rates, with no DNS pins or proxies. UDP DNS disables automatic TCP fallback. DNS must return successful public IPv4 answers; every public-IP response must equal the measured relay egress. The guard is checked during each running request. Reports record actual successful assertions with byte counts and hashes, and do not claim deployment acceptance.

Record bounded DNS captures on the client TUN and relay TUN/WAN during the requests. Require matching UDP and TCP port-53 traffic to 1.1.1.1 and verified relay egress. Capture only Mosaic DNS on the client TUN; host VPN DNS traffic is outside this test's leak boundary. Retain host resolver and VPN control evidence before, during and after each run.

## Relay outage

Keep an independent host VPN observer running for the whole outage and recovery window, including after the launcher exits. The launcher's guard ends during teardown, so its report alone cannot prove preservation throughout this window.

Place the probe scripts in a directory readable by the configured non-root test account. Start this command while the relay and launcher are healthy, using a current public A record for api.ipify.org and a new report path writable by that account:

```sh
sudo ./mosaic-client isolated-exec --namespace mosaic-test -- \
  python3 /READABLE_PROJECT/tools/network/no_escape.py \
  --namespace mosaic-test --ipify-ip VERIFIED_IPIFY_IP \
  --relay-egress MEASURED_RELAY_IP --report /tmp/mosaic-outage.json
```

The probe verifies working DNS and HTTPS, then prints readiness. Within its ten-second preparation window, stop only the recorded Mosaic relay process. Keep it stopped until the probe finishes. The probe holds its network and resolver namespaces and requires at least twenty seconds of failed system lookups, UDP/TCP DNS, hostname HTTPS and pinned public-IP HTTPS. Unexpected exit codes and tool failures reject the run. Each complete request cycle is bounded, so the observation can finish several seconds after twenty seconds. The probe also checks that no alternate interface, next hop or IPv6 route appears.

The current transport exits on failure; automatic reconnect is still planned. Its TUN disappears when the worker exits. The outage probe deliberately holds the namespace long enough to test the remaining failure window. Launcher cleanup then refuses this unrecognized application process and retains ownership records. After the probe exits, run `isolated-down` to remove the inactive owned namespace and verify the baseline. Restart only Mosaic relay, relaunch the guarded client with a fresh valid baseline if needed, and repeat the healthy DNS driver. Do not claim automatic reconnect or preservation of existing application connections.

Repeat normal shutdown, SIGKILL and interrupted setup with no test applications left running. Resolver mounts and anonymous files disappear with the last process in the private mount namespace. Namespace teardown removes its routes. Cleanup does not restore host resolver snapshots and refuses an active launcher or a namespace containing unrecognized processes.

## Verification

```sh
python3 scripts/check.py 5 --local-only
python3 scripts/check.py 5
```

The local command repeats existing checks and the DNS/configuration, application boundary, route rejection, probe cancellation and outage-result tests. The deployment command remains BLOCKED while live assertions are incomplete.

An explicit kernel fixture is available on a dedicated Linux test host with root, `ip`, `getent`, `curl` and `/dev/net/tun`:

```sh
sudo timeout 60 cargo test --locked -p mosaic-core --test net_dns \
  -- --ignored --exact linux_private_dns_and_no_escape --nocapture
```

It uses anonymous network and mount namespaces, answers an actual system DNS query through a real TUN, then leaves TUN unanswered and requires DNS and pinned HTTPS to fail. It verifies parent resolver/name-service files and links after normal exit and SIGKILL. The fixture does not use Internet egress, relay NAT or the shared-node VPN, and is excluded from ordinary unprivileged tests. Linux cross-compilation does not count as execution of this fixture.
