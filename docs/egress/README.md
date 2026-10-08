# Internet forwarding and native HTTPS

[Mosaic](../../README.md) › Docs › Internet forwarding and native HTTPS

This is a development validation guide for two separate egress paths: native fetch, which carries verified HTTPS through an authenticated relay TCP connection, and the Linux namespace check, which carries real IPv4 packets through TUN and relay NAT. Reports keep these paths separate.

> [!IMPORTANT]
> Native fetch affects only its own HTTPS request, and the Linux TUN path affects only namespace applications. Neither connects a desktop VPN.

> [!WARNING]
> The Python forwarding helper remains a developer administration tool until supported compiled relay setup and cleanup are implemented and verified as required by [fixes.md](../../fixes.md). Local checks pass only implementation assertions; live Internet egress, NAT captures, fixture integrity and VPN preservation still require the dedicated relay and isolated client node. Earlier native Mac QUIC failures remain unresolved.

Contents: [Native fetch](#native-fetch) · [Dedicated relay forwarding](#dedicated-relay-forwarding) · [Isolated namespace egress](#isolated-namespace-egress) · [Verification](#verification) · [See also](#see-also)

## Native fetch

Start an explicitly enabled service on the inventoried relay.

```sh
./mosaic-relay -c configs/relay.json --fetch
```

- **Tunnel alongside fetch:** add `--tunnel` on Linux to serve the isolated TUN owner alongside fetch and diagnostics.
- **Diagnostic-only service:** `--diagnostic-only` continues to reject fetch and tunnel sessions.
- **Forwarding:** relay forwarding is configured separately.

Run on the native device, without sudo or a local listener.

```sh
./dist/aarch64-apple-darwin/mosaic-client fetch -c configs/client.json https://api.ipify.org
./dist/aarch64-apple-darwin/mosaic-client fetch -c configs/client.json https://example.com
```

### Destination rules

- **Allowlist:** the destination must appear in the relay config's `fetch.allow`, with port 443. Operators must also keep the allowlist restricted to their public test services.
- **URL format:** URLs require HTTPS and a DNS hostname. Credentials, fragments, literal IPs and alternate ports are rejected. Redirects are not followed.
- **Resolution:** the relay resolves once per request, validates the IPv4 answers, and connects to one of those exact addresses. A private or special IPv4 answer rejects the whole answer set. IPv6 is not dialed.
- **Rejected addresses:** loopback, private networks, link-local, shared address space, documentation networks, multicast and known metadata addresses.

### TLS and reports

- **Certificate trust:** the client uses public Web PKI roots for the destination, independently of the relay certificate. The relay forwards opaque TLS bytes.
- **Failures:** HTTP errors, incomplete bodies, TLS failures and exceeded limits fail the request.
- **Report contents:** status, byte counts and SHA-256, plus the parsed public-IP response for api.ipify.org. URLs, tokens, arbitrary response bodies and low-level errors are omitted.

### Limits

This is a bounded connectivity tool, not a capacity benchmark.

| Limit | Behavior |
| --- | --- |
| `fetch.max_requests` | Caps requests per authenticated connection, including rejections. |
| `fetch.max_bytes` | Caps the sum of both TCP directions across that connection, including TLS and HTTP overhead. |
| `fetch.timeout_s` | Caps the entire relay fetch session, at most 300 seconds. |
| Resolve and connect | Five-second deadline. |
| Request headers | Five-second deadline. |
| Forwarding buffers | Fixed 4096-byte buffers, existing bounded QUIC windows, one active request per connection. |
| Shared rate | 80000 bytes/second across all fetch connections and both directions, with overhead reserved. |
| Client uploads | The native client paces encrypted uploads in at most 4096-byte writes. |
| Upload size | At most 16 MiB. |

### Deterministic transfers

To test a deterministic upload, use an allowlisted HTTPS endpoint that accepts POST and returns the exact uploaded body.

```sh
./mosaic-client fetch -c configs/client.json https://fixture.your-domain.tld/download --expect-sha256 EXPECTED_HASH
./mosaic-client fetch -c configs/client.json https://fixture.your-domain.tld/echo --upload fixture.bin --expect-sha256 EXPECTED_HASH
```

- **Integrity:** the upload count and hash describe the submitted body. Independent server receipt or an exact echoed response verifies remote integrity.
- **Byte budget:** a 16 MiB response or upload needs room for encrypted protocol overhead in the relay's byte limit. Use separate fresh fetch commands for download and upload with the example 32 MiB limit.
- **Saved reports:** `--report NEW_FILE.json` saves an owner-only report without overwriting files.

## Dedicated relay forwarding

The installed relay service now applies the same rules itself (`mosaic-relay --tunnel --forwarding`; see [Relay installation](../relay/README.md)), with no Python at runtime. Its ownership record is under `/var/lib/mosaic-relay`. The Python helper below remains for development and shared-node tests.

### Set up

1. Complete a read-only relay inventory.
2. Identify its WAN interface and confirm that this is the dedicated relay.
3. Keep its administration session available.
4. Run only on that relay:

```sh
sudo python3 tools/network/forwarding.py setup --dedicated-relay --wan eth0
sudo python3 tools/network/forwarding.py status --dedicated-relay
```

Set `--tun` and `--client` if the relay config uses different names or addresses.

### What setup changes

- **Validation:** the helper records the original IPv4 forwarding value and validates an nftables transaction before applying it.
- **Tables:** it creates `inet mosaic_forward` and `ip mosaic_nat`. Only the configured client source arriving on the TUN can be masqueraded out the selected WAN.
- **Return traffic:** return forwarding accepts established/related traffic. Other forwarding involving this TUN is dropped.
- **Preserved rules:** input, SSH and unrelated forwarding rules are preserved.
- **Existing forward chains:** for existing native nftables IPv4/inet forward chains, it installs a narrow `mosaic_egress` chain and a jump at the start of each existing forward chain. This integrates accepts with existing drop policies, because an accept in an independent base chain cannot override another base chain's drop. See the [nftables manual](https://netfilter.org/projects/nftables/manpage.html).
- **Other firewall managers:** active firewalld/UFW and conflicting legacy iptables configurations return BLOCKED and require a reviewed integration using that manager.
- **Repeat runs:** setup is idempotent only while the recorded settings, object handles and rules match. Counters may change.
- **Ownership records:** private ownership records and a lock remain under `/run/mosaic-forwarding`.

### Clean up

Cleanup checks ownership and unrelated firewall configuration, then deletes only the created tables, chains and jump rules and restores the saved forwarding value.

```sh
sudo python3 tools/network/forwarding.py cleanup --dedicated-relay
```

- **Reconnect and restart checks:** keep forwarding configured across normal relay reconnect/restart checks.
- **Interrupted setup:** if setup is interrupted after the nft transaction but before ownership capture, the helper retains its saved rules and refuses to infer ownership. Inspect that record and the actual firewall before recovery.
- **Never:** flush the host ruleset or restore a whole-host snapshot.

## Isolated namespace egress

### Prepare

1. Start the existing guarded `isolated-up` launcher after a fresh five-minute baseline.
2. Confirm the namespace contains only loopback and its TUN. The current launcher installs a namespace default route through TUN.
3. Measure the relay's ordinary egress independently.
4. Resolve current A records for example.com and api.ipify.org.

With the guard running, run the egress helper.

```sh
sudo python3 tools/network/egress.py --namespace mosaic-test \
  --example-ip VERIFIED_EXAMPLE_IP --ipify-ip VERIFIED_IPIFY_IP \
  --relay-egress MEASURED_RELAY_IP --report results/tun-egress.json
```

### What the helper checks

- **Ownership:** it verifies the namespace/process ownership and recent preservation samples.
- **DNS pins:** it checks both pins against current host-side A records using a bounded lookup.
- **Routes:** it uses the existing TUN default route. When testing an older launcher without a default, it adds only two temporary /32 routes inside the namespace.
- **Requests:** curl runs there as the configured non-root account, with verified TLS, fixed DNS pins, no proxy, no redirect, a 20-second deadline and a capped rate.
- **Pass condition:** ten successful requests to each host and an exact egress match on every public-IP response.
- **Cleanup:** it deletes only the routes added by this run. Final namespace teardown also removes them after abrupt process death. No host route or resolver changes are made.

### Live acceptance

- **Native fetch comparison:** run ten native fetches to each host too, and compare both public-IP results with the independently measured relay.
- **NAT evidence:** record relay NAT counters and bounded pre/post-NAT captures around the namespace requests. Native fetch does not exercise TUN or those NAT rules.
- **Fixture transfers:** download and upload a deterministic 16 MiB fixture on both paths and verify the expected SHA-256. Namespace curl fixture transfers need a longer bounded timeout, such as 900 seconds, because the existing conservative packet-pump cap includes both directions.
- **Preservation:** keep the preservation guard active throughout, and serialize workloads.

## Verification

Run the local checks first, then the deployment checks.

```sh
python3 scripts/check.py 4 --local-only
python3 scripts/check.py 4
```

- **Local runner:** repeats native builds, real QUIC/TCP/TLS tests, destination rejection, HTTP framing/integrity tests, CLI reports and forwarding/namespace helper tests.
- **Deployment command:** remains BLOCKED until the live assertions in `tests/manifest.json` are fulfilled.
- **Test fixtures:** local TLS fixtures use disposable certificates and a loopback destination selected only by test code. Production has no private-address or certificate-verification bypass.

## See also

- [Relay installation](../relay/README.md)
- [Namespace DNS and routing](../dns/README.md)
- [Isolated TUN checks](../isolation/README.md)
- [Session protocol](../session/README.md)
- [Live test records](../testing/README.md)
- [Xray health probes](../../tools/xray/README.md)
