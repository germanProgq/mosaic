# Xray health probes

[Mosaic](../../README.md) › Tools › Xray health probes

A developer health-check tool, separate from Mosaic's Rust client, that tests an existing configured VLESS/Reality client account and watches Xray hosts stay healthy while a workload runs. It embeds the exact Xray 26.3.27 engine used by the supplied hosts (`v1.260327.0`, pinned in `go.mod`/`go.sum`).

> [!NOTE]
> No accounts, inbound listeners, routes, VPN settings or production services are created or modified. Destination HTTPS certificate verification remains enabled; success also requires the destination to observe the expected Xray server egress IP.

> [!IMPORTANT]
> A successful preservation run covers the specified workload and observation period only. It does not certify QUIC, Linux TUN, forwarding, a future workload or the entire deployment.

Contents: [Commands](#commands) · [Build](#build) · [Run](#run) · [Credentials and staging](#credentials-and-staging) · [Preservation runs](#preservation-runs) · [preserve.py options](#preservepy-options) · [Host inventory rules](#host-inventory-rules) · [Reports](#reports) · [Implementation references](#implementation-references) · [See also](#see-also)

## Commands

`prepare.py`, `stage.py`, `probe.py`, `preserve.py` and `cleanup.py` are operator commands. All entry points support `--help` without contacting servers.

| Command | Purpose |
| --- | --- |
| `prepare.py` | Reads the existing server config through verified SSH, derives the Reality public key on the server and saves client credentials. |
| `stage.py` | Uploads the verified helper binary to a unique directory on each host. |
| `probe.py` | Runs a peer probe against one target IP. |
| `preserve.py` | Runs a preservation run: baseline, workload and post-workload observations. |
| `cleanup.py` | Removes staged binaries, refusing mismatched files or a running probe. |
| `transport.py` | Manages verified SSH worker requests. |
| `remote/` | Payloads loaded by these commands. Do not invoke them directly. |

Shared inventory and firewall checks live in `../network/`.

## Build

Build the helper locally with Go 1.27.1, running these commands from the workspace root.

```sh
mkdir -p dist/tools
(cd tools/xray/client && go build -trimpath -ldflags='-s -w' -o ../../../dist/tools/xray-health .)
(cd tools/xray/client && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o ../../../dist/tools/xray-health-linux-amd64 .)
```

## Run

Use this sequence for the two Linux hosts configured in private `servers.txt`.

```sh
python3 tools/xray/prepare.py
python3 tools/xray/stage.py --binary dist/tools/xray-health-linux-amd64
python3 tools/xray/probe.py TARGET_IP
python3 tools/xray/preserve.py --allow-verified-sshd-bans --samples 180 --workload python3 scripts/check.py 2 --local-only
python3 tools/xray/cleanup.py
```

- **Probe each host:** run `probe.py` once for each target IP. The other configured host supplies the client.
- **Paths:** default configuration paths resolve from the workspace root; explicit paths resolve from the caller's working directory.
- **Workload:** the `--workload` command runs from the workspace root and must be the last option.

## Credentials and staging

- **Key handling:** `prepare.py` derives the Reality **public** key on the server using its installed cryptography library. Server private keys never leave their hosts.
- **Client credentials:** saved owner-only under Git-ignored `configs/health/` and never included in reports. Preparation refuses to overwrite existing credential files.
- **Stdin credentials:** the probe accepts `--config -` for credentials passed through SSH stdin without staging remote credential files.
- **Staging:** creates a unique `/run/mosaic-health-*` directory, verifies executable hashes and caps SSH uploads at 1 Mbit/s per host. No toolchain is installed on a production host.
- **Build identity:** the staging manifest supplies the recorded executable hash, and both hosts must use the same build. No command depends on a historical build under `results/`.
- **Probe process:** peer probes run as `nobody`, with one flow, one Go scheduler thread and a 128 MiB Go memory target.
- **Egress policies:** both Linux hosts retain their existing egress policies. Each probes the other host using its existing configured client identity.
- **Scope:** this is a representative account test from a separate client process, not evidence about a particular user's existing device.

## Preservation runs

The preservation command requires an explicit workload. Choose enough samples to cover the 300-second baseline, the complete workload and post-workload observations; the example allows 900 seconds total.

### Schedule

- **Sampling:** a run schedules 84 probes per stream at five-second intervals by default.
- **Baseline:** a 300-second healthy baseline is required. The workload starts only after this five-minute baseline, then runs while probes and read-only host inventories continue.
- **Example workload:** runs current local authentication checks twice with fresh processes.

### Failure conditions

- **Probe failure:** any failed probe fails the run.
- **Drift:** unexplained host configuration/service drift fails the run.
- **Latency:** a rolling 60-second latency median exceeding baseline by both 20% and 10 ms fails the run.
- **Deadlines:** deadline and sample-count failures cannot pass.

### Supervision and collection

- **Supervisor:** each host uses a temporary supervisor with a deadline of the sample duration plus 30 seconds and private event logs. Supervisors own separate process groups, and cancellation checks the supervisor PID/start time.
- **Collection:** short verified SSH requests collect results while probe sessions remain continuous, so a long-lived administrative channel is unnecessary.
- **Early stop:** a failed probe or excessive rolling latency stops the owned children on the host.
- **Retry:** result collection has one bounded retry, preserving the read offset and every remote sample. A second retrieval failure fails the run.
- **Administrative retries:** reported separately and never convert a failed health sample to PASS.
- **Teardown:** remote log directories are removed after collection. Binary cleanup refuses mismatched files or a running probe.

### Latency measurement

- **Host latency:** now uses curl's `time_total` for the verified HTTPS request. Inventory and total sample durations are reported separately, and the total must still meet the five-second cadence.
- **Earlier reports:** measured inventory plus the request as host latency. Their failed results remain in the history.
- **Owned transitions:** during owned process or TUN setup and cleanup, the monitor compares verified process identities and tunnel resources before and after the complete inventory. If it changed, it repeats the inventory up to twice within the same five-second sample deadline. Unrelated drift, a stable invalid state, or repeated transitions still fail.

### Host HTTPS control

The ordinary host HTTPS control defaults to `--control ipify`. Select `--control cloudflare` before a new baseline to use Cloudflare's IPv4 trace endpoint and compare its `ip` field with the inventoried egress address. Both choices verify HTTPS certificates, use a three-second request deadline and retain the same sampling and failure thresholds. The selected control is recorded in the report; failed runs remain unchanged.

## preserve.py options

| Option | Values | Description |
| --- | --- | --- |
| `--samples` | 84–360, default 84 | Probes per stream at five-second intervals. |
| `--owned-jobs-manifest` | Path | Owned jobs, such as direct children and an explicit tunnel description. See [Isolated TUN work](#isolated-tun-work). |
| `--workload` | Argument vector, required | Trusted developer command. Runs from the workspace root after the baseline and must be the last option. |
| `--allow-verified-sshd-bans` | Flag, opt-in | Accepts verified SSH-only Fail2Ban ban list updates as expected runtime state. |
| `--control` | `ipify` (default) or `cloudflare` | Host HTTPS control endpoint. |

## Host inventory rules

### Fail2Ban exception

The user explicitly authorized verified updates to the SSH-only Fail2Ban ban list as expected runtime state. The exception is opt-in through `--allow-verified-sshd-bans`.

- **Matching:** changed entries must exactly match the live `sshd` jail.
- **Rule reference:** the set must be referenced only by the unchanged TCP-22 enforcement rule.
- **Service identity:** Fail2Ban service identity and config-file hashes remain fixed.
- **Reporting:** each accepted transition is reported.
- **Everything else:** all other nftables fields, rules, services and network configuration remain strict. The initial strict run is retained as a failed run rather than rewritten.

### UDP sockets and queues

- **Owned exemptions:** owned UDP exemptions require matching executable hashes and process identities. All unrelated listeners remain visible.
- **Queue counters:** TCP pending-accept queues and UDP queue occupancy are excluded as runtime counters, while TCP backlog configuration remains compared.
- **Outbound UDP:** the Linux socket inventory also shows unconnected outbound UDP sockets as listeners. For identified Xray processes with only TCP VLESS/Trojan inbounds and supported direct outbounds, the monitor records wildcard UDP sockets in the kernel ephemeral range as runtime traffic.
- **Verification:** it verifies the service PID/start time, executable hash and loaded configuration. Configured inbound ports, other owners and unsupported configurations remain strict. Each classification is retained in the private sample log.

### Isolated TUN work

- **Owned jobs:** an owned-job manifest can include direct children running the same verified executable and an explicit tunnel description.
- **Exclusions:** the monitor excludes only the recorded client namespace or the relay TUN held by the recorded relay process.
- **Routes:** relay addresses and routes must match the selected connected subnet. Host routes and unrelated listeners remain compared.
- **Launcher guard:** `tools/network/preservation_guard.py` connects the launcher to these running observers. Its baseline argument is the private observer ownership record from `workers.json`. It requires complete host and representative VPN histories, fresh samples, unchanged supervisor identity and continued progress in both streams.

## Reports

Reports and raw privileged inventories stay under owner-only `results/xray-preservation-*/`. Earlier unauthenticated live tests and their failed gates are recorded in [the test history](../../docs/testing/README.md).

## Implementation references

- **Entry points:** the helper uses Xray's supported [`core.StartInstance` and `core.Dial` entry points](https://github.com/XTLS/Xray-core/blob/v26.3.27/core/functions.go), with no configured inbounds.
- **Peer identity:** verification is performed by Xray's [Reality transport](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/reality/reality.go).
- **HTTPS layer:** the probe's separate HTTPS layer uses Go's normal certificate verification.

## See also

- [Live test records](../../docs/testing/README.md)
- [Isolated TUN checks](../../docs/isolation/README.md)
- [Internet forwarding and native HTTPS](../../docs/egress/README.md)
- [Mosaic README](../../README.md)
