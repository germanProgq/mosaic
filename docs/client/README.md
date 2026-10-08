# Client command line

[Mosaic](../../README.md) › Docs › Client command line

`mosaic-client` validates configuration, checks ordinary networking and runs authenticated diagnostics against a relay. These commands change no system routes, DNS or firewall rules.

> [!IMPORTANT]
> `dist/aarch64-apple-darwin/mosaic-client` is a diagnostic development build for macOS Apple Silicon. It has no desktop connection mode. For the native VPN clients, see [native clients](../../native/README.md).

**Contents:** [Configure](#configure) · [Check configuration](#check-configuration) · [Authenticated diagnostics](#authenticated-diagnostics) · [Limits and tuning](#limits-and-tuning) · [Reports and exit codes](#reports-and-exit-codes) · [Handshake visibility](#handshake-visibility)

## Configure

The diagnostic and fetch commands need no VM, Python or sudo. Examples contain documentation addresses and no credentials.

Print the version and check the example schema:

```sh
./dist/aarch64-apple-darwin/mosaic-client --version
./dist/aarch64-apple-darwin/mosaic-client check-config \
  -c configs/client.example.json --schema-only
```

After provisioning an actual relay (see [relay setup](../relay/README.md)):

1. Copy `configs/client.example.json` to `configs/client.json`.
2. Replace the relay address and name.
3. Install its trust certificate and token under `configs/secrets/`.

Paths resolve relative to the config file, irrespective of the current working directory.

## Check configuration

Validate the private config, then check ordinary DNS and HTTPS:

```sh
./dist/aarch64-apple-darwin/mosaic-client check-config -c configs/client.json
./dist/aarch64-apple-darwin/mosaic-client preflight -c configs/client.json
```

| Command | What it checks |
| --- | --- |
| `check-config` | The complete schema and local credentials, without network requests. |
| `check-config --schema-only` | Just the example and schema. It cannot validate provisioning. |
| `preflight` | Validates first, then ordinary DNS resolution and verified HTTPS, each with a five-second deadline. |

- **Credentials:** certificates must contain parseable trust material. Tokens must be exactly 64 hex digits; one trailing LF/CRLF is allowed. On Unix, token and key files must have owner-only permissions.
- **Server identity:** verified during the QUIC handshake, not by parsing a trust-anchor file.
- **Relay address:** dialed by literal IP, so its certificate DNS name need not have a public DNS record. Documentation relay addresses are blocked before networking.
- **Host networking:** `preflight` keeps the environment's proxy and routing policy. Its HTTPS uses ordinary host egress and does not prove Mosaic connectivity.
- **No system changes:** diagnostic, fetch and preflight commands do not change system routes, DNS or firewalls, and open no inbound service. Linux isolation commands configure only their owned namespace.

## Authenticated diagnostics

The relay must run its diagnostic service; see [relay setup](../relay/README.md#diagnostic-service). Run each case from the client:

```sh
./dist/aarch64-apple-darwin/mosaic-client test -c configs/client.json --case session
./dist/aarch64-apple-darwin/mosaic-client test -c configs/client.json --case stream-echo
./dist/aarch64-apple-darwin/mosaic-client test -c configs/client.json --case datagram-echo --count 1000 --size 1100 --rate 50
```

All cases authenticate on a fresh connection.

### Authentication

- **Deadlines:** the TLS handshake and session exchange each have a five-second deadline.
- **TLS:** certificate trust, SAN and ALPN `mosaic-poc/2` are verified. 0-RTT and TLS resumption are disabled.
- **Token:** the relay decodes exactly 32 token bytes and compares them with `subtle::ConstantTimeEq`. Tokens appear only inside encrypted application data and never in reports.
- **Control messages:** a four-byte big-endian length and typed JSON bounded by the configured limit, at most 4096 bytes. Unknown fields, invalid lengths, unsupported versions or modes, early data and mismatched readiness values close the connection.
- **Session identifier:** a TLS exporter supplies a connection-bound identifier.
- **Datagram size:** both send directions must support at least 1112 bytes before Ready.
- **Modes:** diagnostic-only relays reject tunnel mode. The Linux `--tunnel` service accepts one authenticated tunnel owner alongside diagnostic connections.

The full message exchange is in [the session protocol](../session/README.md).

### Test cases

| Case | What it does | Pass condition |
| --- | --- | --- |
| `session` | Completes SessionInit, SessionReady and ClientReady. | Authenticated Ready. |
| `stream-echo` | 100 byte-exact echoes at each size: 0, 1, 64, 1024 and 65536 bytes, including three concurrent streams. | Every echo matches. |
| `datagram-echo` | Sends payloads with a 12-byte version/kind/length/sequence header and counts unique replies through three seconds after the final send. | 1000/1000 on loopback, at least 990/1000 remotely. |

- **Streams:** each diagnostic stream carries one raw payload terminated by FIN, separate from the control stream. Stream deadlines are 15 seconds, with a four-minute connection workload limit.
- **Datagrams:** every received payload is verified. Duplicate replies never increase the success count. Malformed packets and IP packet kinds are rejected by the diagnostic relay.
- **Datagram limits:** count up to 10000, payload size up to 1100 bytes, rate up to 50 packets/s. The capped send schedule must fit 210 seconds.

These are correctness tests, not peak-throughput measurements.

## Limits and tuning

| Setting | Value |
| --- | --- |
| Tunnel packet queue | At most 2048 packets (the examples use 512) |
| QUIC datagram send buffer | 512 KiB, which keeps queueing delay low |
| QUIC datagram receive buffer | 2 MiB |
| Connection windows | 16 MiB |
| Congestion control | BBR |
| Idle timeout | 4 to 15 seconds, at least twice the keepalive (examples: 8 seconds) |
| Keepalive | 1 to 5 seconds (examples: 2 seconds) |
| Relay connection tasks | 8 active |
| Stream tasks per connection | 3 |
| Diagnostic streams per connection | 512 |
| Tracked QUIC connections | 64, including closed connections awaiting removal |
| Diagnostic echo queues | 256 packets |
| Diagnostic response budget | Paced below 1 Mbit/s |

- **Rate limit:** tunnel traffic is not rate limited unless `limits.max_mbps` is set in the client or relay configuration; without it, congestion control alone sets the speed. The limit counts both directions together, including about 96 bytes of overhead per packet.
- **Open relays:** an unlimited relay lets anyone holding the token use its full uplink, so set a limit when that matters.
- **Client pacing:** the client's datagram pacing also includes both directions and overhead. Loopback streams skip pacing; loopback datagrams keep their bounded schedule.

## Reports and exit codes

Commands print redacted JSON. Add `--report NEW_FILE.json` to save it as an owner-only file. Parent directories must exist, and existing files are never overwritten.

| Exit code | Meaning |
| --- | --- |
| `0` | Assertions passed in the stated scope |
| `1` | FAIL |
| `2` | BLOCKED (also used by clap for invalid command-line usage) |

- **Scope:** `test` reports `scope: authenticated-diagnostics`. PASS covers only the requested case. A local config PASS is not a deployment PASS.
- **Outer path:** host egress uses an outbound-only ephemeral UDP socket and ordinary OS routing. The VPN or direct outer path and the preservation gate V require independent live evidence.
- **Failures:** failed TLS, authorization, size negotiation or blocked UDP returns FAIL without changing host network policy.

## Handshake visibility

The local rejection tests capture an actual QUIC Initial datagram and use rustls Initial keys to recover the TLS ClientHello. They observe server name `relay.example.net` and ALPN `mosaic-poc/2`, with no application token. Their JSON evidence appears in the test log.

Ordinary diagnostic runs report this visibility boundary without claiming to capture a live handshake. QUIC Initial protection does not conceal these fields; renaming an encrypted application message adds no concealment.

## See also

- [Session protocol](../session/README.md)
- [Relay setup](../relay/README.md)
- [Local proxy](../proxy/README.md)
- [Internet forwarding and native HTTPS](../egress/README.md)
- [RFC 9001, section 7](https://www.rfc-editor.org/rfc/rfc9001.html#section-7)
- [Quinn's datagram limit API](https://docs.rs/quinn/0.11.11/quinn/struct.Connection.html#method.max_datagram_size)
