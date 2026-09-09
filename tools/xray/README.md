# Xray preservation probes

This is a developer health-check tool, separate from Mosaic's Rust client. It embeds the exact Xray 26.3.27 engine used by the supplied hosts (`v1.260327.0`, pinned in `go.mod`/`go.sum`) to test an existing configured VLESS/Reality client account. No accounts, inbound listeners, routes, VPN settings or production services are created or modified. Destination HTTPS certificate verification remains enabled; success also requires the destination to observe the expected Xray server egress IP.

`prepare.py` reads the existing server config through verified SSH and derives the Reality **public** key on the server using its installed cryptography library. Server private keys never leave their hosts. Client credentials are saved owner-only under Git-ignored `configs/health/` and never included in reports. The probe accepts `--config -` for credentials passed through SSH stdin without staging remote credential files.

Build the helper locally with Go 1.27.1. Run these commands from the workspace root:

```sh
mkdir -p dist/tools
(cd tools/xray/client && go build -trimpath -ldflags='-s -w' -o ../../../dist/tools/xray-health .)
(cd tools/xray/client && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o ../../../dist/tools/xray-health-linux-amd64 .)
```

For the two Linux hosts configured in private `servers.txt`:

```sh
python3 tools/xray/prepare.py
python3 tools/xray/stage.py --binary dist/tools/xray-health-linux-amd64
python3 tools/xray/probe.py TARGET_IP
python3 tools/xray/preserve.py --allow-verified-sshd-bans --samples 180 --workload python3 scripts/check.py 2 --local-only
python3 tools/xray/cleanup.py
```

Run `probe.py` once for each target IP. The other configured host supplies the client. All entry points support `--help` without contacting servers. Default configuration paths resolve from the workspace root; explicit paths resolve from the caller's working directory. The `--workload` command runs from the workspace root and must be the last option.

The preservation command requires an explicit workload. Choose enough samples to cover the 300-second baseline, the complete workload and post-workload observations; the example allows 900 seconds total. The staging manifest supplies the recorded executable hash, and both hosts must use the same build. No command depends on a historical build under `results/`.

Preparation refuses to overwrite existing credential files. Staging creates a unique `/run/mosaic-health-*` directory, verifies executable hashes and caps SSH uploads at 1 Mbit/s per host. No toolchain is installed on a production host. Peer probes run as `nobody`, with one flow, one Go scheduler thread and a 128 MiB Go memory target. Both Linux hosts retain their existing egress policies. Each probes the other host using its existing configured client identity. This is a representative account test from a separate client process, not evidence about a particular user's existing device.

A preservation run schedules 84 probes per stream at five-second intervals. It requires a 300-second healthy baseline, then runs the requested workload while probes and read-only host inventories continue. The example runs current local authentication checks twice with fresh processes. Any failed probe, unexplained host configuration/service drift, or rolling 60-second latency median exceeding baseline by both 20% and 10 ms fails the run. Deadline and sample-count failures cannot pass. Each host uses a temporary supervisor with a deadline of the sample duration plus 30 seconds and private event logs. Short verified SSH requests collect results while probe sessions remain continuous, so a long-lived administrative channel is unnecessary. A failed probe or excessive rolling latency stops the owned children on the host. Result collection has one bounded retry, preserving the read offset and every remote sample; a second retrieval failure fails the run. Administrative retries are reported separately and never convert a failed health sample to PASS. Supervisors own separate process groups, and cancellation checks the supervisor PID/start time. Remote log directories are removed after collection; binary cleanup refuses mismatched files or a running probe.

Reports and raw privileged inventories stay under owner-only `results/xray-preservation-*/`. A successful preservation run covers the specified workload and observation period only. It does not certify QUIC, Linux TUN, forwarding, a future workload or the entire deployment.

The user explicitly authorized verified updates to the SSH-only Fail2Ban ban list as expected runtime state. That exception is opt-in (`--allow-verified-sshd-bans`): changed entries must exactly match the live `sshd` jail, the set must be referenced only by the unchanged TCP-22 enforcement rule, and Fail2Ban service identity/config-file hashes remain fixed. Each accepted transition is reported. All other nftables fields, rules, services and network configuration remain strict. The initial strict run is retained as a failed run rather than rewritten.

Implementation references: the helper uses Xray's supported [`core.StartInstance` and `core.Dial` entry points](https://github.com/XTLS/Xray-core/blob/v26.3.27/core/functions.go), with no configured inbounds. Peer identity verification is performed by Xray's [Reality transport](https://github.com/XTLS/Xray-core/blob/v26.3.27/transport/internet/reality/reality.go); the probe's separate HTTPS layer uses Go's normal certificate verification.

The preservation driver accepts `--samples` (84–360, default 84), `--owned-jobs-manifest` and a required trusted developer `--workload` argument vector. The workload starts only after the five-minute baseline. Owned UDP exemptions require matching executable hashes and process identities; all unrelated listeners remain visible. TCP pending-accept queues and UDP queue occupancy are excluded as runtime counters, while TCP backlog configuration remains compared. Earlier unauthenticated live tests and their failed gates are recorded in [the test history](../../docs/testing/README.md).

`prepare.py`, `stage.py`, `probe.py`, `preserve.py` and `cleanup.py` are operator commands. `transport.py` manages verified SSH worker requests. Files under `remote/` are payloads loaded by these commands; do not invoke them directly. Shared inventory and firewall checks live in `../network/`.
