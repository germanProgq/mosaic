# Internet forwarding and native HTTPS

This is a development validation guide. Native fetch affects only its own HTTPS request, and the Linux TUN path affects only namespace applications. Neither connects a desktop VPN. The Python forwarding helper remains a developer administration tool until supported compiled relay setup and cleanup are implemented and verified as required by [fixes.md](../../fixes.md).

Native fetch carries verified HTTPS through an authenticated relay TCP connection. The Linux namespace check carries real IPv4 packets through TUN and relay NAT. Reports keep these paths separate. Local checks pass only implementation assertions; live Internet egress, NAT captures, fixture integrity and VPN preservation still require the dedicated relay and isolated client node. Earlier native Mac QUIC failures remain unresolved.

## Native fetch

Start an explicitly enabled service on the inventoried relay:

```sh
./mosaic-relay -c configs/relay.json --fetch
```

Add `--tunnel` on Linux to serve the isolated TUN owner alongside fetch and diagnostics. `--diagnostic-only` continues to reject fetch and tunnel sessions. Relay forwarding is configured separately.

Run on the native device without sudo or a local listener:

```sh
./dist/aarch64-apple-darwin/mosaic-client fetch -c configs/client.json https://api.ipify.org
./dist/aarch64-apple-darwin/mosaic-client fetch -c configs/client.json https://example.com
```

The destination must appear in the relay config's `fetch.allow`, with port 443. URLs require HTTPS and a DNS hostname; credentials, fragments, literal IPs and alternate ports are rejected. Redirects are not followed. The relay resolves once per request, validates the IPv4 answers, and connects to one of those exact addresses. A private or special IPv4 answer rejects the whole answer set. IPv6 is not dialed. Loopback, private networks, link-local, shared address space, documentation networks, multicast and known metadata addresses are rejected. Operators must also keep the allowlist restricted to their public test services.

The client uses public Web PKI roots for the destination, independently of the relay certificate. The relay forwards opaque TLS bytes. HTTP errors, incomplete bodies, TLS failures and exceeded limits fail the request. Reports contain status, byte counts and SHA-256, plus the parsed public-IP response for api.ipify.org. URLs, tokens, arbitrary response bodies and low-level errors are omitted.

`fetch.max_requests` caps requests per authenticated connection, including rejections. `fetch.max_bytes` caps the sum of both TCP directions across that connection, including TLS and HTTP overhead. `fetch.timeout_s` caps the entire relay fetch session, at most 300 seconds. Resolving/connecting and request headers have five-second deadlines. Forwarding uses fixed 4096-byte buffers, existing bounded QUIC windows, one active request per connection, and a shared 80000-byte/second schedule across all fetch connections and both directions, with overhead reserved. The native client also paces encrypted uploads in at most 4096-byte writes. This is a bounded connectivity tool, not a capacity benchmark.

To test a deterministic upload, use an allowlisted HTTPS endpoint that accepts POST and returns the exact uploaded body:

```sh
./mosaic-client fetch -c configs/client.json https://fixture.your-domain.tld/download --expect-sha256 EXPECTED_HASH
./mosaic-client fetch -c configs/client.json https://fixture.your-domain.tld/echo --upload fixture.bin --expect-sha256 EXPECTED_HASH
```

Uploads are at most 16 MiB. The upload count/hash describes the submitted body; independent server receipt or an exact echoed response verifies remote integrity. A 16 MiB response or upload needs room for encrypted protocol overhead in the relay's byte limit. Use separate fresh fetch commands for download and upload with the example 32 MiB limit. `--report NEW_FILE.json` saves an owner-only report without overwriting files.

## Dedicated relay forwarding

After read-only relay inventory, identify its WAN interface and confirm that this is the dedicated relay. Keep its administration session available. Run only on that relay:

```sh
sudo python3 tools/network/forwarding.py setup --dedicated-relay --wan eth0
sudo python3 tools/network/forwarding.py status --dedicated-relay
```

Set `--tun` and `--client` if the relay config uses different names or addresses. The helper records the original IPv4 forwarding value and validates an nftables transaction before applying it. It creates `inet mosaic_forward` and `ip mosaic_nat`; only the configured client source arriving on the TUN can be masqueraded out the selected WAN. Return forwarding accepts established/related traffic. Other forwarding involving this TUN is dropped. Input, SSH and unrelated forwarding rules are preserved.

For existing native nftables IPv4/inet forward chains, it installs a narrow `mosaic_egress` chain and a jump at the start of each existing forward chain. This integrates accepts with existing drop policies: an accept in an independent base chain cannot override another base chain's drop. Active firewalld/UFW and conflicting legacy iptables configurations return BLOCKED and require a reviewed integration using that manager. See the [nftables manual](https://netfilter.org/projects/nftables/manpage.html).

Setup is idempotent only while the recorded settings, object handles and rules match. Counters may change. Private ownership records and a lock remain under `/run/mosaic-forwarding`. Cleanup checks ownership and unrelated firewall configuration before deleting only the created tables, chains and jump rules and restoring the saved forwarding value:

```sh
sudo python3 tools/network/forwarding.py cleanup --dedicated-relay
```

Keep forwarding configured across normal relay reconnect/restart checks. If setup is interrupted after the nft transaction but before ownership capture, the helper retains its saved rules and refuses to infer ownership. Inspect that record and the actual firewall before recovery. Never flush the host ruleset or restore a whole-host snapshot.

## Isolated namespace egress

Start the existing guarded `isolated-up` launcher after a fresh five-minute baseline. The namespace must contain only loopback and its TUN. The current launcher installs a namespace default route through TUN. Measure the relay's ordinary egress independently and resolve current A records for example.com and api.ipify.org. With the guard running, use:

```sh
sudo python3 tools/network/egress.py --namespace mosaic-test \
  --example-ip VERIFIED_EXAMPLE_IP --ipify-ip VERIFIED_IPIFY_IP \
  --relay-egress MEASURED_RELAY_IP --report results/tun-egress.json
```

The helper verifies the namespace/process ownership and recent preservation samples. It checks both pins against current host-side A records using a bounded lookup, then uses the existing TUN default route. When testing an older launcher without a default, it adds only two temporary /32 routes inside the namespace. Curl runs there as the configured non-root account, with verified TLS, fixed DNS pins, no proxy, no redirect, a 20-second deadline and a capped rate. It requires ten successful requests to each host and an exact egress match on every public-IP response. Cleanup deletes only the routes added by this run; final namespace teardown also removes them after abrupt process death. No host route or resolver changes are made.

For live acceptance, run ten native fetches to each host too, and compare both public-IP results with the independently measured relay. Record relay NAT counters and bounded pre/post-NAT captures around the namespace requests. Native fetch does not exercise TUN or those NAT rules. Download and upload a deterministic 16 MiB fixture on both paths and verify the expected SHA-256. Namespace curl fixture transfers need a longer bounded timeout, such as 900 seconds, because the existing conservative packet-pump cap includes both directions. Keep the preservation guard active throughout; serialize workloads.

## Verification

```sh
python3 scripts/check.py 4 --local-only
python3 scripts/check.py 4
```

The local runner repeats native builds, real QUIC/TCP/TLS tests, destination rejection, HTTP framing/integrity tests, CLI reports and forwarding/namespace helper tests. The deployment command remains BLOCKED until the live assertions in `tests/manifest.json` are fulfilled. Local TLS fixtures use disposable certificates and a loopback destination selected only by test code; production has no private-address or certificate-verification bypass.
