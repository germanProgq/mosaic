# Shared node baseline

[Mosaic](../../README.md) › Docs › Shared node baseline

Shared Linux nodes already run a VPN for other people. Before any Mosaic test runs on one, these tools record a five-minute health baseline of that VPN and then watch it, so a test that harms the existing service stops at once.

> [!CAUTION]
> Never run these scripts on an unidentified VPN setup. Inspect the host read-only first. Do not bypass the node's VPN to improve reachability.

**Contents:** [Write the policy](#write-the-policy) · [Probes](#probes) · [Record, monitor and verify](#record-monitor-and-verify) · [Failure rules](#failure-rules) · [Preservation driver](#preservation-driver) · [Outstanding live gates](#outstanding-live-gates)

## Write the policy

Copy `configs/node-baseline.example.json` to a private local `configs/node-baseline.json`. Identify:

- the VPN role: `outbound`, `server` or `both`;
- the actual service, container, interface and config-file paths (hashed without exporting contents);
- the firewall manager;
- the intended non-root transport UID;
- the relay IP and an unused private /30.

## Probes

| VPN role | Required probes |
| --- | --- |
| `outbound` | A VPN-only probe |
| `server` | A probe from a representative existing client |
| Every role | Ordinary HTTPS and a stable public-egress probe |

A running process or a successful handshake is not sufficient.

- **Format:** probes are trusted, operator-supplied argument arrays, never shell strings.
- **Behavior:** each must exit zero only on genuine success, finish within 4.5 seconds and avoid mutations. They run as the configured UID.
- **Representative client:** the `representative_client` command must test service through an existing client, for example using already configured administration access.
- **Stable output:** `stable_output` compares a hash of trimmed stdout. The public egress probe must enable it.
- **Secrets:** never put secrets in probe arguments.

## Record, monitor and verify

Record the baseline, monitor against it, and verify current health:

```sh
sudo python3 tools/network/baseline.py record --policy configs/node-baseline.json
sudo python3 tools/network/baseline.py monitor --policy configs/node-baseline.json \
  --seconds 60 --report results/node-monitor.json
sudo python3 tools/network/baseline.py verify --policy configs/node-baseline.json
```

| Command | What it does |
| --- | --- |
| `record` | Reads inventories, then requires a full 300-second sample at five-second intervals. |
| `monitor` | Compares against the baseline every five seconds. |
| `verify` | Checks current configuration and health. |

- **What `record` reads:** link, address, route and policy-rule inventories; resolver state; namespace, process and socket inventories; qdiscs; forwarding settings; the configured firewall; VPN service and container identities; cgroup limits.
- **What `record` refuses:** existing baseline directories, namespace or interface collisions, and overlapping routes or subnets.
- **Evidence:** raw evidence stays in `.mosaic-baseline/` with owner-only permissions.
- **Freshness:** a baseline older than one hour, or a changed policy, requires a new explicit `--directory`. Old evidence is never overwritten.
- **No changes:** the scripts make no route, firewall, resolver or VPN changes and do not restore host snapshots.

## Failure rules

The monitor rejects:

- VPN restart or configuration drift;
- changed stable egress;
- any unexpected probe failure;
- a rolling 60-second median probe duration above its baseline by both 20% and 10 ms.

Two consecutive failures abort immediately. Missing privileges or tools, unsupported VPN namespaces and missed sampling deadlines block the run. Probe duration includes command and request completion overhead, so use consistent, lightweight probes.

## Preservation driver

The generic baseline tool observes control health. The developer preservation driver adds:

- a bounded workload after the five-minute baseline;
- exact ownership checks for temporary Mosaic UDP sockets;
- remote watchdog cancellation and verified cleanup.

TCP pending-accept counts and UDP queue occupancy are runtime counters. Ports, owners, TCP backlog settings, routes and firewall rules stay strict. See the [Xray health probes](../../tools/xray/README.md).

The retired unauthenticated service was tested with a one-off harness; its failures and cleanup evidence are kept in [the earlier test record](../testing/README.md).

## Outstanding live gates

Representative configured-account Xray probes now pass on both supplied hosts, including a 300-second baseline and five-second checks around two fresh local test runs. All 84 samples per stream passed; see [the health evidence](../../results/xray-preservation-1788972931883638000/report.json) and the [reproduction guide](../../tools/xray/README.md).

Current Linux builds have passed both byte-echo repetitions and the isolated TUN checks in [the server test record](../testing/README.md).

> [!IMPORTANT]
> The native path and privileged local firewall checks remain incomplete. Each new deployment test still requires fresh before, during and after preservation samples. These are deployment tasks, not successes inferred from unit tests. Do not begin shared-node traffic tests until V can be measured.

## See also

- [Isolated TUN checks](../isolation/README.md)
- [Xray health probes](../../tools/xray/README.md)
- [Live test records](../testing/README.md)
