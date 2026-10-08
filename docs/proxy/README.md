# Local proxy

[Mosaic](../../README.md) › Docs › Local proxy

`mosaic-client proxy` runs a SOCKS5 server on this computer. Each TCP connection an application opens through it travels as its own QUIC stream to the relay, which looks up the name and connects from its own address.

> [!TIP]
> The proxy needs no administrator rights, no Network Extension and no driver, so it runs on macOS without Apple signing.

**Contents:** [Start the proxy](#start-the-proxy) · [Behavior](#behavior) · [Relay limits](#relay-limits) · [Use with Shadowrocket](#use-with-shadowrocket)

## Start the proxy

Start it with the default listen address:

```sh
./mosaic-client proxy -c client.json
```

Or choose the listen address and bind the relay connection to one interface:

```sh
./mosaic-client proxy -c client.json --listen 127.0.0.1:1080 --interface en0
```

| Option | Meaning |
| --- | --- |
| `--listen` | Loopback address to listen on. The default is `127.0.0.1:1080`; only loopback addresses are accepted. |
| `--interface` | Binds the relay connection to one network interface. On macOS this keeps it out of another VPN's tunnel. |

The relay must run with `--proxy`; the [installed service](../relay/README.md#install) does.

## Behavior

- **Reconnects:** the proxy keeps one authenticated QUIC connection and reconnects when the relay restarts. Connections that were open at that moment fail; new ones use the new session.
- **What it carries:** TCP CONNECT only, with names resolved on the relay.
- **What it does not carry:** UDP. Applications that need UDP, including QUIC and HTTP/3, fall back to TCP or bypass the proxy. IPv6 destinations are refused.
- **What it does not change:** system routes, DNS and firewall rules. Only applications configured to use the proxy are affected.
- **Failures:** a destination refused by policy gets SOCKS reply 2. A relay that does not answer within 20 seconds gets reply 1. Aborted transfers reset the stream instead of closing it cleanly, so applications see the failure.
- **Datagrams:** a datagram sent on a proxy session ends that session.

## Relay limits

| Limit | Value |
| --- | --- |
| Simultaneous proxied connections | 256 per session |
| Refused destinations | Port 25, IPv6, private, link-local and loopback ranges, and the relay's own networks |
| Rate limit | None for proxy traffic |

When the relay's public IPv4 address is not assigned to one of its interfaces, list it under `public_addresses` in the relay configuration; see [relay setup](../relay/README.md#forwarding-rules).

## Use with Shadowrocket

1. Add a server of type SOCKS5 with address `127.0.0.1` and port `1080`.
2. Select it, or route chosen rules to it.
3. Start the proxy with `--interface en0` (or the Mac's active interface), so its connection to the relay does not loop back through Shadowrocket.

## See also

- [Relay setup](../relay/README.md)
- [Client command line](../client/README.md)
- [Live test records](../testing/README.md)
