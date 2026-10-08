# Mosaic prototype

The required product is a macOS and Windows VPN client that routes ordinary application traffic through Mosaic, plus a Linux relay with compiled setup and cleanup. Read [the prototype plan](Mosaic_Prototype_Plan_v2.docx) together with [the corrections](fixes.md); the corrections take precedence. The current implementation is development groundwork and is not a desktop VPN deliverable.

Native setup, authenticated QUIC diagnostics, bounded packet framing, Linux isolated TUN, native HTTPS fetch, dedicated relay forwarding, namespace default routing and private DNS are implemented. The client verifies the relay certificate before sending its token and completes SessionInit, SessionReady and ClientReady before stream or datagram echoes are accepted.

Live Linux TUN traffic, packet rejection and cleanup have been verified on both supplied servers; see [the server test record](docs/testing/README.md). Native Mac QUIC, uninterrupted automation, live egress, DNS and outage acceptance remain incomplete. Installed macOS and Windows acceptance is missing. The relay now has a compiled installer, systemd service and owned forwarding; its live acceptance is recorded separately. See [the namespace DNS guide](docs/dns/README.md) and [the forwarding and fetch guide](docs/egress/README.md). Local test results do not certify desktop VPN delivery, live deployment or VPN preservation.

## Desktop support and completion

No macOS or Windows OS version or CPU architecture is currently supported as a delivered full-device VPN. The Apple Silicon macOS binary is a diagnostic development build. Linux namespace evidence covers only isolated test applications. Windows installation and networking have not been verified. Native compilation alone does not establish platform support.

The native client now includes macOS and iOS Network Extension providers, Windows Wintun/WFP service integration, Linux TUN/nftables/systemd integration and Android VpnService integration. Shared Rust code owns authentication, packet handling and reconnect. See [native packages and test commands](native/README.md) for installation, signing, permissions, supported build targets and exact limitations.

`tests/manifest.json` keeps installed-device acceptance BLOCKED separately from implementation and compilation. macOS applications and extensions compile for Apple silicon and Intel, the iOS application and extension compile for arm64, Android builds an APK for arm64 and x64, and Linux/Windows cross-builds pass. Apple signing assets, Windows installer environment and physical platform acceptance are unavailable here. No target is certified from these builds alone. The Linux relay installs with `mosaic-relay --setup`; see [Relay installation](#relay-installation).

Installed-package reports must verify ordinary browser/application egress, system DNS, no public IPv4/IPv6 bypass, three 20-second relay outages with recovery within 45 seconds, component failures, network changes, sleep/wake, reboot, permissions, owned-state cleanup, repeated installation, upgrade/uninstall and the bounded soak. Preserve the shared Linux VPN checks. The inner tunnel remains IPv4-only with MTU 1100; native platform integration owns IPv6 protection.

## Authenticated diagnostics

On the inventoried relay, with a binary built for its OS/CPU and its existing private config:

```sh
./mosaic-relay -c relay.json --diagnostic-only
```

The unauthenticated `--echo-only` service has been removed. The diagnostic service validates its config and credentials, opens only the configured UDP listener, emits a redacted readiness report and serves until SIGINT/SIGTERM. Binding UDP 443 requires appropriate existing privileges. It cannot open TUN or destination TCP connections. Running without `--diagnostic-only`, `--fetch`, `--tunnel` or `--check-config` returns BLOCKED.

On the native client:

```sh
./dist/aarch64-apple-darwin/mosaic-client test -c configs/client.json --case session
./dist/aarch64-apple-darwin/mosaic-client test -c configs/client.json --case stream-echo
./dist/aarch64-apple-darwin/mosaic-client test -c configs/client.json --case datagram-echo --count 1000 --size 1100 --rate 50
```

All cases authenticate on a fresh connection. The TLS handshake and session exchange each have a five-second deadline. Certificate trust, SAN and prototype ALPN `mosaic-poc/2` are verified, with 0-RTT and TLS resumption disabled. The relay decodes exactly 32 token bytes and compares them with `subtle::ConstantTimeEq`. Tokens appear only inside encrypted application data and never in reports.

Control messages use a four-byte big-endian length and typed JSON bounded by the configured limit, at most 4096 bytes. Unknown fields, invalid lengths, unsupported versions/modes, early data and mismatched readiness values close the connection. A TLS exporter supplies a connection-bound identifier. Both send directions must support at least 1112 bytes before Ready. Diagnostic-only relays reject tunnel mode; the Linux `--tunnel` service accepts one authenticated tunnel owner alongside diagnostic connections. See [the session protocol](docs/session/README.md).

The stream case performs 100 byte-exact echoes at each size: 0, 1, 64, 1024 and 65536 bytes, including three concurrent streams. Each diagnostic stream carries one raw payload terminated by FIN, separate from the control stream. Stream deadlines are 15 seconds, with a four-minute connection workload limit.

The datagram case adds a 12-byte version/kind/length/sequence header, verifies every received payload and counts unique replies through three seconds after the final send. It requires 1000/1000 replies on loopback or at least 990/1000 remotely. Count is limited to 10000, payload size to 1100 bytes and rate to 50 packets/s; the capped send schedule must fit 210 seconds. Duplicate replies never increase the success count. Malformed packets and IP packet kinds are rejected by the diagnostic relay.

Tunnel packet queues hold at most 2048 packets (the examples use 512). The QUIC datagram send buffer is 512 KiB, which keeps queueing delay low. The receive buffer is 2 MiB, connection windows are 16 MiB, and QUIC uses BBR congestion control. Tunnel traffic is not rate limited unless `limits.max_mbps` is set in the client or relay configuration; without it, congestion control alone sets the speed. The limit counts both directions together, including about 96 bytes of overhead per packet. An unlimited relay lets anyone holding the token use its full uplink, so set a limit when that matters. The idle timeout may be 4 to 15 seconds and must be at least twice the 1 to 5 second keepalive; the examples use 8 and 2 seconds so lost relays are detected quickly. The relay admits eight active connection tasks, three stream tasks per connection and 512 diagnostic streams per connection. It also caps tracked QUIC connections, including closed connections awaiting removal, at 64. Diagnostic stream and datagram responses keep their own paced budget below 1 Mbit/s, and diagnostic echo queues stay at 256 packets. The client's datagram pacing also includes both directions and overhead. Loopback streams skip pacing; loopback datagrams retain their bounded schedule. These are correctness tests, not peak-throughput measurements.

`test` reports `scope: authenticated-diagnostics`. PASS covers only the requested case. Host egress uses an outbound-only ephemeral UDP socket and ordinary OS routing; the VPN/direct outer path and preservation gate V require independent live evidence. Failed TLS, authorization, size negotiation or blocked UDP returns FAIL without changing host network policy.

The local rejection tests capture an actual QUIC Initial datagram and use rustls Initial keys to recover the TLS ClientHello. They observe server name `relay.example.net` and ALPN `mosaic-poc/2`, with no application token. Their JSON evidence appears in the test log. Ordinary diagnostic runs report this visibility boundary without claiming to capture a live handshake. QUIC Initial protection does not conceal these fields; renaming an encrypted application message adds no concealment. See [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html#section-7) and [Quinn's datagram limit API](https://docs.rs/quinn/0.11.11/quinn/struct.Connection.html#method.max_datagram_size).

## Isolated Linux TUN

The Linux launcher and relay exchange IPv4 packets through exclusive nonpersistent TUN devices. The client opens an ephemeral UDP socket under the baseline policy’s non-root `test_uid` in the original namespace. A separate worker inherits that descriptor, enters a new network namespace before starting Tokio, proves its socket namespace differs from the worker’s, and authenticates through it. TUN opens only after Ready. The worker then drops supplementary groups and root privileges. The original launcher remains outside isolation. The worker also receives a private mount namespace for its resolver; applications enter it with `mosaic-client isolated-exec --namespace mosaic-test -- COMMAND`.

After fresh relay and shared-node inventory, build binaries for their Linux architecture. On the dedicated relay:

```sh
./mosaic-relay -c configs/relay.json --tunnel
```

After recording the mandatory five-minute VPN baseline on the extra node:

```sh
sudo ./mosaic-client isolated-up -c configs/client-node.json \
  --policy configs/node-baseline.json --baseline .mosaic-baseline \
  --guard tools/network/isolation.py --report results/tunnel.json
```

The launcher requires Python 3, the existing inventory tools, Linux namespace-cookie and pidfd support, root for setup, and a configured non-root account. The policy must match the relay IP, namespace and tunnel subnet. The guard verifies the baseline before setup, then checks host configuration, exact socket/namespace ownership and VPN health every five seconds. A failed probe, changed egress, drift, missed sampling deadline, excessive rolling latency or worker RSS above 256 MiB stops the run. Each packet pump has bounded queues and a capped schedule. These checks do not constitute a CPU reservation.

The worker’s namespace contains only loopback and its TUN, with the configured connected /30, MTU 1100 and a default route through TUN. TUN IPv6 is disabled. Its private mount namespace supplies DNS at 1.1.1.1. Run applications through `isolated-exec` to enter both namespaces. No veth, host route, firewall, host forwarding or host resolver change is installed. The relay started with `--tunnel` alone likewise adds only its TUN and connected subnet; `--forwarding` (used by the installed service) adds its owned forwarding and NAT.

With the default example addresses, inspect and test from another administration session:

```sh
sudo ip -n mosaic-test addr show
sudo ip -n mosaic-test route show table all
sudo ip netns exec mosaic-test ping -n -c 20 -W 2 10.77.0.1
```

On the dedicated relay, run `ping -n -I mosaic0 -c 20 -W 2 10.77.0.2`. Capture ICMP on both TUNs with bounded `tcpdump` runs. Both directions must return 20/20; the local packet tests do not replace these Linux assertions. See [the isolated TUN checks](docs/isolation/README.md).

SIGINT/SIGTERM to the exact launcher stops its worker and guard, removes the owned namespace, and verifies host/VPN controls after teardown. The kernel kills the worker if its launcher dies. After SIGKILL or interrupted setup, use:

```sh
sudo ./mosaic-client isolated-down --namespace mosaic-test
sudo python3 tools/network/baseline.py verify --policy configs/node-baseline.json
```

Resolver files are sealed anonymous memory files, bound read-only inside the worker’s private mount namespace. They disappear after the last application and worker exit, including after SIGKILL. Cleanup verifies process start times, namespace and mount identities. It refuses an active launcher, changed resources or a namespace with unrecognized processes. Stop namespace test commands before teardown. Ownership records are private under `/run/mosaic-test`; cleanup never adopts an existing namespace or restores whole-host snapshots. When the relay connection is lost, the worker keeps the namespace and TUN and reconnects. It retries through a duplicate of the same launcher-verified host socket, waiting 1, 2, 4 and then 8 seconds between attempts with jitter. Every new session is freshly authorized, old packet pumps are cancelled, and queued packets are discarded. It stops retrying on credential or configuration errors. Existing application connections may fail; new ones recover.

On a dedicated relay host, where the relay and the test client share one machine, add `--dedicated-host`. The launcher accepts it only when the relay address belongs to this host. In that mode it skips the shared-node VPN guard, whose baseline cannot coexist with the relay's own `mosaic0`, and keeps every namespace isolation check. The client TUN must use a different name from the relay's (for example `mosaic1`). Monitor the host's existing services separately while it runs.

## Native client

The diagnostic development build is `dist/aarch64-apple-darwin/mosaic-client` for macOS Apple Silicon. Its diagnostic and fetch commands need no VM, Python or sudo. It has no desktop connection mode. Examples contain documentation addresses and no credentials.

```sh
./dist/aarch64-apple-darwin/mosaic-client --version
./dist/aarch64-apple-darwin/mosaic-client check-config \
  -c configs/client.example.json --schema-only
```

After provisioning an actual relay, copy `configs/client.example.json` to `configs/client.json`, replace the relay address/name and install its trust certificate and token under `configs/secrets/`. Paths resolve relative to the config file, irrespective of the current working directory.

```sh
./dist/aarch64-apple-darwin/mosaic-client check-config -c configs/client.json
./dist/aarch64-apple-darwin/mosaic-client preflight -c configs/client.json
```

`check-config` checks the complete schema and local credentials without making network requests. `--schema-only` intentionally checks just the example/schema; it cannot validate provisioning. Certificates must contain parseable trust material and tokens must be exactly 64 hex digits (one trailing LF/CRLF is allowed). On Unix, token/key files must have owner-only permissions. Server certificate identity is verified during the QUIC handshake, not by parsing a trust-anchor file.

`preflight` validates first, then checks ordinary DNS resolution and verified HTTPS with five-second deadlines. It retains the environment's proxy and routing policy. Documentation relay addresses are blocked before networking. The relay is dialed by literal IP; its certificate DNS name need not have a public DNS record. Diagnostic, fetch and preflight commands do not change system routes, DNS or firewalls, and open no inbound service. Linux isolation commands configure only their owned namespace. Preflight HTTPS uses ordinary host egress and does not prove Mosaic connectivity.

Commands print redacted JSON. Add `--report NEW_FILE.json` to save it as an owner-only file; parent directories must exist, and existing files are never overwritten. Exit codes: `0` means assertions passed in the stated scope, `1` means FAIL, `2` means BLOCKED (also used by clap for invalid CLI usage). A local config PASS is not a deployment PASS.

## Repository layout

- `crates/` — Rust client, relay, shared protocol and Rust integration tests.
- `configs/` — tracked examples and ignored private deployment configuration.
- `scripts/` — local checks, native packaging and credential generation.
- `tools/network/` — Linux baseline, listener ownership and Fail2Ban verification.
- `tools/xray/` — representative Xray probes, staging, preservation and cleanup. Its `client/` directory contains the Go probe; `remote/` contains worker payloads.
- `tests/` — Python CLI and monitor tests, plus the acceptance manifest.
- `docs/` — session protocol and earlier live test evidence.
- `dist/`, `target/`, `results/` — ignored packages, build output and private run evidence.

## Developer checks

Rust is pinned to 1.96.0, with resolved dependencies in `Cargo.lock`. Developer scripts use Python 3 and OpenSSL already present on the machine. They do not install packages on a shared Linux node.

```sh
cargo build --workspace --locked
python3 scripts/check.py 5 --local-only
python3 scripts/check.py 5
```

The runner checks formatting, Clippy, native builds, Rust config/credential, session rejection, captured handshake and real loopback QUIC tests, plus Python CLI/monitor tests. The QUIC tests cover the full echo matrix, real TLS trust/name/ALPN rejections, silent UDP timeout, rejected streams, and fresh relay restart. Native CLI tests independently launch and stop exact child relay processes, verify reports and check UDP-port release. Tests run twice with fresh processes. Each subprocess has a deadline; output and JSON reports live in owner-only `results/checks-*/` directories. Local tests generate disposable certificates in temporary directories and remove them afterwards.

`--local-only` returns 0 only for successful local checks, with `scope: local-only` and `deployment_status: BLOCKED`. The default deployment command returns 2 while live gates are incomplete. The original plan’s `scripts/check.sh` command is now `python3 scripts/check.py`; `scripts/node-baseline.sh` is now `python3 tools/network/baseline.py`. The numeric check level selects setup (0), QUIC connectivity (1), authentication and framing (2), isolated TUN (3), Internet forwarding and native fetch (4), namespace DNS and routing (5), or planned features (6–9). Later check levels also run the shared reconnect and native bridge tests; unfinished platform acceptance remains BLOCKED; missing tests are never treated as passes. The required live assertions are listed in `tests/manifest.json`. The current runner deliberately cannot certify live deployment from hand-authored evidence files.

Build the existing diagnostic development bundle for the current macOS or Linux target (native VPN package commands are in [native/README.md](native/README.md)):

```sh
./scripts/package.sh
```

The bundle contains compiled diagnostic binaries, credential-free examples, both requirement documents, the acceptance manifest and Linux developer helpers, including their preservation dependencies. It is not a desktop installer or a completed relay installation package. Windows packaging is blocked. A Linux relay binary must be built on Linux (or with a separately verified cross-compilation setup). The macOS relay executable can validate configs and serve authenticated local fixtures; it is not a Linux deployment artifact.

## Relay preparation

Run credential generation **on the dedicated Linux relay**, after its read-only inventory. Select a certificate DNS SAN matching the actual relay identity. The destination directory must not already exist:

```sh
./scripts/provision.sh --dedicated-relay relay.your-domain.tld configs/secrets
```

This makes a 30-day development certificate with a DNS SAN and a cryptographically random 32-byte token. Provision only `relay.crt` and `client.token` to the client over the existing trusted administration channel. The relay private key stays on the relay. `--fixture` is available only for disposable local development/test credentials; none are deployment credentials. Partial generation never overwrites an existing directory: inspect and remove only that newly created fixture directory before retrying.

This script is a developer provisioning tool, not a production credential process. An expired relay certificate must fail TLS verification before token transmission. Before expiry, provision replacement credentials in a new private relay directory, transfer the replacement trust certificate and token through the trusted channel, and coordinate the client configuration update and relay restart. Replacing a token invalidates the old token for new sessions; restart the relay to close existing sessions when revoking access. Keep private configurations out of logs, reports and source control. Automatic import, renewal and packaged credential replacement remain required desktop and relay work.

Copy/edit `configs/relay.example.json` to `configs/relay.json`, then on the relay:

```sh
./mosaic-relay -c configs/relay.json --check-config
```

This validates the certificate/key pairing, one-owner tunnel settings and bounded fetch configuration, without opening a listener. Inventory public IPv4, existing SSH, UDP 443 occupancy/firewall policy, ordinary DNS/HTTPS and `/dev/net/tun` on the actual dedicated relay before deployment. Port availability is not proof of UDP reachability; that requires QUIC. The relay never configures inbound policy. Forwarding and NAT come from `--forwarding` or the installed service; see [Relay installation](#relay-installation).

## Local proxy

`mosaic-client proxy` runs a SOCKS5 server on this computer. Each TCP connection an application opens through it travels as its own QUIC stream to the relay, which looks up the name and connects from its own address. The proxy needs no administrator rights, no Network Extension and no driver, so it runs on macOS without Apple signing.

```sh
./mosaic-client proxy -c client.json
./mosaic-client proxy -c client.json --listen 127.0.0.1:1080 --interface en0
```

- **Listen address:** the proxy only listens on a loopback address. The default is `127.0.0.1:1080`.
- **`--interface`:** binds the relay connection to one network interface. On macOS this keeps it out of another VPN's tunnel.
- **Reconnects:** the proxy keeps one authenticated QUIC connection and reconnects when the relay restarts. Connections that were open at that moment fail; new ones use the new session.
- **What it carries:** TCP CONNECT only, with names resolved on the relay. It does not carry UDP, so applications that need UDP (including QUIC/HTTP3) fall back to TCP or bypass the proxy. IPv6 destinations are refused.
- **What it does not change:** system routes, DNS and firewall rules. Only applications configured to use the proxy are affected.
- **Relay side:** the relay must run with `--proxy`; the installed service does.
- **Relay limits:** the relay accepts up to 256 simultaneous proxied connections per session. It refuses port 25, IPv6, private, link-local and loopback ranges, and its own networks. Proxy traffic is not rate limited.
- **Relays behind NAT:** when the relay's public IPv4 address is not assigned to one of its interfaces (common on cloud hosts), list it in the relay configuration as `"public_addresses": ["203.0.113.10"]`. The proxy and the tunnel forwarding then refuse it too.
- **Failures:** a destination refused by policy gets SOCKS reply 2. A relay that does not answer within 20 seconds gets reply 1. Aborted transfers reset the stream instead of closing it cleanly, so applications see the failure.
- **Datagrams:** a datagram sent on a proxy session ends that session.

To use it as a Shadowrocket node, add a server of type SOCKS5 with address `127.0.0.1` and port `1080`, then select it or route chosen rules to it. Start the proxy with `--interface en0` (or the Mac's active interface) so its connection to the relay does not loop back through Shadowrocket.

## Relay installation

Build the relay for the server's architecture, copy it with a validated `relay.json` and its credentials, then install it as root:

```sh
sudo ./mosaic-relay -c configs/relay.json --setup
```

Setup validates the configuration and credentials, then installs:

- the binary in `/usr/local/lib/mosaic-relay/`;
- the configuration and credentials in `/etc/mosaic-relay/` (owner-only);
- `mosaic-relay.service`, which it enables and starts.

The service runs `--tunnel --forwarding --proxy`. At start it installs owned nftables tables `inet mosaic_forward` and `ip mosaic_nat`, which:

- allow and masquerade only the configured tunnel client through the single IPv4 default-route interface;
- drop tunnel traffic to private, shared, link-local (including cloud metadata), loopback, multicast and reserved IPv4 ranges, and to the relay's own WAN subnets;
- drop tunnel traffic addressed to the relay host itself, except ICMP echo and replies;
- drop all other forwarding while the relay runs, if IPv4 forwarding was off before it started;
- add a `mosaic_egress` jump to any existing forward filter chain so that chain's drop policy still admits tunnel traffic;
- enable `net.ipv4.ip_forward`.

The previous forwarding value is recorded under `/var/lib/mosaic-relay`. It is restored when the service stops, unless new forward chains appeared meanwhile; in that case forwarding is left on and a message is logged. If cleanup was interrupted, the next start or uninstall completes it. The service refuses to start while firewalld is active or ufw is enabled, while conflicting legacy iptables rules exist, or while Mosaic-named firewall objects exist without an ownership record. It never touches other services' listeners or rules. The unit runs with a restricted capability set, access only to `/dev/net/tun`, and unlimited restarts five seconds apart, so a missing default route at boot does not leave it permanently failed. Setup reports failure unless the service is still active with no restarts four seconds after starting.

Running setup again upgrades an owned installation after verifying the installed file hashes. Remove the installation with:

```sh
sudo /usr/local/lib/mosaic-relay/mosaic-relay --uninstall
```

Uninstall stops the service, which removes the forwarding rules. It then deletes only the files recorded at setup, and reports a failure instead of removing anything that changed. `tools/network/forwarding.py` remains a developer tool for the shared-node tests.

## Shared Linux node baseline

These scripts must not be run on an unidentified VPN setup. Inspect the host read-only first. Copy `configs/node-baseline.example.json` to a private local `configs/node-baseline.json` and identify the VPN role (`outbound`, `server`, `both`), actual service/container/interface and config-file paths (hashed without exporting contents), firewall manager, intended non-root transport UID, relay IP and an unused private /30. An outbound VPN needs a VPN-only probe; a VPN server needs a probe from a representative existing client. Both require ordinary HTTPS and a stable public-egress probe. A process or handshake is not sufficient.

Probes are trusted operator-supplied argument arrays, never shell strings. Each must exit zero only on genuine success, finish within 4.5 seconds, and avoid mutations. They run as the configured UID. The `representative_client` command must test service through an existing client, for example using already configured administration access. Do not put secrets in probe arguments. `stable_output` compares a hash of trimmed stdout; the public egress probe must enable it.

```sh
sudo python3 tools/network/baseline.py record --policy configs/node-baseline.json
sudo python3 tools/network/baseline.py monitor --policy configs/node-baseline.json \
  --seconds 60 --report results/node-monitor.json
sudo python3 tools/network/baseline.py verify --policy configs/node-baseline.json
```

`record` refuses existing baseline directories, namespace/interface collisions and overlapping routes/subnets. It reads link/address/route/policy-rule inventories, resolver state, namespace/process/socket inventories, qdiscs, forwarding settings, the configured firewall, VPN service/container identities and cgroup limits. Raw evidence stays in `.mosaic-baseline/` with owner-only permissions. It then requires a full 300-second sample at five-second intervals. `monitor` compares to that baseline every five seconds; `verify` checks current configuration and health. A baseline older than one hour or a changed policy requires a new explicit `--directory`, without overwriting the old evidence.

The monitor rejects VPN restart/configuration drift, changed stable egress, any unexpected probe failure, or a rolling 60-second median probe duration exceeding its baseline by both 20% and 10 ms. Two consecutive failures abort immediately. Probe duration includes command/request completion overhead, so use consistent, lightweight probes. Missing privileges/tools, unsupported VPN namespaces or missed sampling deadlines block the run. The scripts make no route/firewall/resolver/VPN changes and do not restore host snapshots.

The generic baseline tool observes control health. The developer preservation driver now supports a bounded workload after the five-minute baseline, exact ownership checks for temporary Mosaic UDP sockets, remote watchdog cancellation and verified cleanup. TCP pending-accept counts and UDP queue occupancy are runtime counters; ports, owners, TCP backlog settings, routes and firewall rules remain strict. The retired unauthenticated service was tested with a one-off harness; its failures and cleanup evidence are retained in [the earlier test record](docs/testing/README.md).

## Outstanding live gates

Representative configured-account Xray probes now pass on both supplied hosts, including a 300-second baseline and five-second checks around two fresh local test runs. All 84 samples per stream passed; see [the health evidence](results/xray-preservation-1788972931883638000/report.json) and [reproduction guide](tools/xray/README.md). Current Linux builds have passed both byte-echo repetitions and the isolated TUN checks described in [the server test record](docs/testing/README.md). The native path and privileged local firewall checks remain incomplete. Each new deployment test still requires fresh before/during/after preservation samples. These are deployment tasks, not inferred successes from unit tests. Do not begin shared-node traffic tests until V can be measured, and do not bypass its VPN to improve reachability.

Secrets, private configs, raw baselines, generated binaries and run evidence are ignored by Git. Example configs are safe to track. Never commit a relay private key or a private ready-to-use config.
