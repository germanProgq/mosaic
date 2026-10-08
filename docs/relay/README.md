# Relay setup

[Mosaic](../../README.md) › Docs › Relay setup

`mosaic-relay` runs on a dedicated Linux server. It installs itself as a hardened systemd service with owned forwarding, and removes only what it installed.

> [!WARNING]
> Run these steps only on the dedicated relay, after its read-only inventory. Never run them on a shared node with an existing VPN.

**Contents:** [Prepare credentials](#prepare-credentials) · [Check the configuration](#check-the-configuration) · [Diagnostic service](#diagnostic-service) · [Install](#install) · [Forwarding rules](#forwarding-rules) · [Upgrade and uninstall](#upgrade-and-uninstall)

## Prepare credentials

Generate credentials **on the dedicated Linux relay**. Choose a certificate DNS SAN that matches the actual relay identity. The destination directory must not already exist:

```sh
./scripts/provision.sh --dedicated-relay relay.your-domain.tld configs/secrets
```

This makes a 30-day development certificate with a DNS SAN and a cryptographically random 32-byte token.

- **What to copy:** provision only `relay.crt` and `client.token` to the client, over the existing trusted administration channel. The relay private key stays on the relay.
- **Test credentials:** `--fixture` is only for disposable local development and test credentials. None are deployment credentials.
- **Partial runs:** generation never overwrites an existing directory. Inspect and remove only that newly created fixture directory before retrying.

> [!NOTE]
> This script is a developer provisioning tool, not a production credential process. Automatic import, renewal and packaged credential replacement remain required desktop and relay work.

### Replace credentials

An expired relay certificate must fail TLS verification before the token is sent. Before expiry:

1. Provision replacement credentials in a new private relay directory.
2. Transfer the replacement trust certificate and token through the trusted channel.
3. Coordinate the client configuration update and the relay restart.

Replacing a token invalidates the old token for new sessions. Restart the relay to close existing sessions when revoking access. Keep private configurations out of logs, reports and source control.

## Check the configuration

Copy `configs/relay.example.json` to `configs/relay.json`, edit it, then validate it on the relay:

```sh
./mosaic-relay -c configs/relay.json --check-config
```

This validates the certificate and key pairing, single-owner tunnel settings and bounded fetch configuration, without opening a listener.

Before deployment, inventory these on the actual dedicated relay:

- public IPv4;
- existing SSH;
- UDP 443 occupancy and firewall policy;
- ordinary DNS and HTTPS;
- `/dev/net/tun`.

Port availability is not proof of UDP reachability; that requires QUIC. The relay never configures inbound policy.

## Diagnostic service

On the inventoried relay, with a binary built for its OS and CPU and its existing private config, start the authenticated diagnostic service:

```sh
./mosaic-relay -c relay.json --diagnostic-only
```

- **What it does:** validates its config and credentials, opens only the configured UDP listener, emits a redacted readiness report and serves until SIGINT or SIGTERM.
- **What it cannot do:** open TUN or destination TCP connections.
- **Privileges:** binding UDP 443 requires appropriate existing privileges.
- **Modes:** running without `--diagnostic-only`, `--fetch`, `--tunnel` or `--check-config` returns BLOCKED. The unauthenticated `--echo-only` service has been removed.

Run the client side with [the client diagnostics](../client/README.md#authenticated-diagnostics).

| Option | Adds |
| --- | --- |
| `--check-config` | Validation only, no listener |
| `--diagnostic-only` | Authenticated diagnostics; rejects tunnel and fetch sessions |
| `--fetch` | Native HTTPS fetch; see [Internet forwarding](../egress/README.md) |
| `--tunnel` | One isolated TUN owner (Linux) alongside diagnostics; adds only its TUN and connected subnet |
| `--forwarding` | Owned forwarding and NAT for the tunnel |
| `--proxy` | Sessions from the [local proxy](../proxy/README.md) |
| `--setup` / `--uninstall` | Installs or removes the system service |

## Install

Build the relay for the server's architecture. Copy it with a validated `relay.json` and its credentials, then install it as root:

```sh
sudo ./mosaic-relay -c configs/relay.json --setup
```

Setup validates the configuration and credentials, then installs:

| Item | Location |
| --- | --- |
| Binary | `/usr/local/lib/mosaic-relay/` |
| Configuration and credentials (owner-only) | `/etc/mosaic-relay/` |
| Service | `mosaic-relay.service`, enabled and started |
| Previous forwarding value | `/var/lib/mosaic-relay` |

The service runs `--tunnel --forwarding --proxy`.

- **Hardening:** a restricted capability set and access only to `/dev/net/tun`.
- **Restarts:** unlimited, five seconds apart, so a missing default route at boot does not leave it permanently failed.
- **Result:** setup reports failure unless the service is still active with no restarts four seconds after starting.

## Forwarding rules

At start, the service installs the owned nftables tables `inet mosaic_forward` and `ip mosaic_nat`. They:

- allow and masquerade only the configured tunnel client through the single IPv4 default-route interface;
- drop tunnel traffic to private, shared, link-local (including cloud metadata), loopback, multicast and reserved IPv4 ranges, and to the relay's own WAN subnets;
- drop tunnel traffic addressed to the relay host itself, except ICMP echo and replies;
- drop all other forwarding while the relay runs, if IPv4 forwarding was off before it started;
- add a `mosaic_egress` jump to any existing forward filter chain, so that chain's drop policy still admits tunnel traffic;
- enable `net.ipv4.ip_forward`.

**On stop:** the previous forwarding value is restored, unless new forward chains appeared meanwhile. In that case forwarding is left on and a message is logged. If cleanup was interrupted, the next start or uninstall completes it.

**Refusals:** the service refuses to start while firewalld is active or ufw is enabled, while conflicting legacy iptables rules exist, or while Mosaic-named firewall objects exist without an ownership record. It never touches other services' listeners or rules.

**Relays behind NAT:** when the relay's public IPv4 address is not assigned to one of its interfaces (common on cloud hosts), list it in the relay configuration as `"public_addresses": ["203.0.113.10"]`. The proxy and the tunnel forwarding then refuse it too.

`tools/network/forwarding.py` remains a developer tool for the shared-node tests; see [Internet forwarding](../egress/README.md#dedicated-relay-forwarding).

## Upgrade and uninstall

Running setup again upgrades an owned installation after verifying the installed file hashes.

Remove the installation:

```sh
sudo /usr/local/lib/mosaic-relay/mosaic-relay --uninstall
```

Uninstall stops the service, which removes the forwarding rules. It then deletes only the files recorded at setup, and reports a failure instead of removing anything that changed.

## See also

- [Client command line](../client/README.md)
- [Local proxy](../proxy/README.md)
- [Internet forwarding and native HTTPS](../egress/README.md)
- [Live test records](../testing/README.md#relay-installation)
