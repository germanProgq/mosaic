#!/usr/bin/env python3
"""Read-only Linux inventory and VPN preservation monitoring. No network mutations.

Privileged raw inventories stay owner-only. Reports expose assertion IDs only.
Probe argv is operator-supplied policy, executed without a shell as test_uid.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import statistics
import subprocess
import sys
import time


class Blocked(Exception):
    pass


class Failed(Exception):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run(argv, uid=None):
    kwargs = {}
    if uid is not None:
        user = pwd.getpwuid(uid)
        kwargs.update(user=uid, group=user.pw_gid, extra_groups=[])
    # Do not retain probe bodies, argv or stderr in public reports. Bound both
    # runtime and output: communicate() alone would allow an unbounded response.
    import tempfile
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            wrapper = [sys.executable, "-c", "import os,resource,sys; resource.setrlimit(resource.RLIMIT_FSIZE,(2097152,2097152)); os.execvp(sys.argv[1],sys.argv[1:])"]
            result = subprocess.run([*wrapper, *argv], stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                    timeout=4.5, check=False, **kwargs)
        except (OSError, subprocess.TimeoutExpired, KeyError):
            raise Blocked("inventory/probe unavailable or exceeded deadline") from None
        if result.returncode:
            raise Blocked("inventory/probe returned nonzero")
        out.seek(0)
        return out.read(2 * 1024 * 1024).decode(errors="replace")


def policy_load(path):
    p = json.loads(Path(path).read_text())
    fields = {"vpn_role", "test_uid", "relay_ip", "namespace", "tunnel_subnet", "firewall", "vpn_services", "vpn_containers", "vpn_interfaces", "vpn_config_files", "probes"}
    if set(p) != fields or p["vpn_role"] not in ("outbound", "server", "both"):
        raise Blocked("complete, explicit VPN inventory policy required")
    if "REPLACE_" in json.dumps(p):
        raise Blocked("replace inventory and health-probe placeholders")
    if not isinstance(p["test_uid"], int) or p["test_uid"] <= 0:
        raise Blocked("explicit non-root transport/test UID required")
    if not p["vpn_services"] and not p["vpn_containers"]:
        raise Blocked("identify actual VPN service or container")
    if not p["vpn_interfaces"] or p["firewall"] not in ("nftables", "iptables", "both"):
        raise Blocked("identify VPN interfaces and actual firewall manager")
    for key in ("vpn_services", "vpn_containers", "vpn_interfaces"):
        if not isinstance(p[key], list) or not all(isinstance(v, str) and v and not v.startswith('-') and all(c.isalnum() or c in '_.@:-' for c in v) for v in p[key]):
            raise Blocked("invalid inventory identifiers")
    if not isinstance(p["namespace"], str) or not p["namespace"].startswith("mosaic-") or not all(c.isalnum() or c in '_-' for c in p["namespace"]):
        raise Blocked("invalid Mosaic namespace name")
    if not isinstance(p["vpn_config_files"], list) or not p["vpn_config_files"] or not all(isinstance(path, str) and Path(path).is_absolute() for path in p["vpn_config_files"]):
        raise Blocked("explicit VPN config files are required for drift detection; only hashes are stored")
    ipaddress.IPv4Address(p["relay_ip"])
    subnet = ipaddress.IPv4Network(p["tunnel_subnet"])
    if not subnet.is_private or subnet.prefixlen != 30:
        raise Blocked("select an unused private /30")
    required = {"ordinary_https", "host_egress"}
    if p["vpn_role"] in ("outbound", "both"):
        required.add("vpn_only")
    if p["vpn_role"] in ("server", "both"):
        required.add("representative_client")
    if not isinstance(p["probes"], list) or len(p["probes"]) > 8:
        raise Blocked("one to eight bounded probes required")
    ids = set()
    for probe in p["probes"]:
        if set(probe) != {"id", "argv", "stable_output"} or not isinstance(probe["id"], str) or probe["id"] in ids or not isinstance(probe["stable_output"], bool):
            raise Blocked("invalid or duplicate probe definition")
        ids.add(probe["id"])
        argv = probe["argv"]
        if not isinstance(argv, list) or not argv or not all(isinstance(v, str) and v for v in argv):
            raise Blocked("probe argv must be a nonempty argument array")
    if not required <= ids or not any(x["id"] == "host_egress" and x["stable_output"] for x in p["probes"]):
        raise Blocked("required role-specific health or stable egress probe missing")
    return p


# Only fields known to be counters/timers are dropped. Unknown state is retained
# conservatively, so unexplained changes block testing instead of disappearing.
VOLATILE = {"stats", "stats64", "cacheinfo", "expires", "used", "age", "lastuse", "valid_life_time", "preferred_life_time"}

def normalize(value):
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return sorted((normalize(x) for x in value), key=lambda x: json.dumps(x, sort_keys=True))
    return value


def nft_normalize(value):
    # Rule/chain order is semantic: do NOT sort the nftables list.
    if isinstance(value, list):
        return [nft_normalize(v) for v in value]
    if isinstance(value, dict):
        return {k: ({ck: nft_normalize(cv) for ck, cv in v.items() if ck not in ("packets", "bytes")}
                    if k == "counter" and isinstance(v, dict) else nft_normalize(v))
                for k, v in value.items() if k not in ("handle", "metainfo")}
    return value


def listener_semantics(line):
    fields = line.split()
    if len(fields) >= 6:
        fields[2] = "RUNTIME_QUEUE"
        if fields[0] == "udp":fields[3] = "RUNTIME_QUEUE"
    return " ".join(fields)


def inventory(p):
    state = {}
    for name, args in {
        "links": ["-j", "link", "show"], "addresses": ["-j", "addr", "show"],
        "routes4": ["-j", "-4", "route", "show", "table", "all"],
        "routes6": ["-j", "-6", "route", "show", "table", "all"],
        "rules4": ["-j", "rule", "show"], "rules6": ["-j", "-6", "rule", "show"],
        "relay_route": ["-j", "route", "get", p["relay_ip"], "uid", str(p["test_uid"])],
    }.items():
        state[name] = normalize(json.loads(run(["ip", *args])))
    state["namespaces"] = sorted(run(["ip", "netns", "list"]).splitlines())
    state["resolver"] = Path("/etc/resolv.conf").read_text()
    state["resolver_link"] = os.path.realpath("/etc/resolv.conf")
    # Required where systemd-resolved is active; no resolvectl writes.
    resolved = run(["systemctl", "show", "systemd-resolved.service", "--property=ActiveState"])
    state["resolver_status"] = run(["resolvectl", "status"]) if "ActiveState=active" in resolved else "inactive"
    state["qdiscs"] = normalize(json.loads(run(["tc", "-j", "qdisc", "show"])))
    state["forwarding"] = run(["sysctl", "net.ipv4.ip_forward", "net.ipv6.conf.all.forwarding"])
    if p["firewall"] in ("nftables", "both"):
        state["nft"] = nft_normalize(json.loads(run(["nft", "-j", "list", "ruleset"])))
    if p["firewall"] in ("iptables", "both"):
        for command in ("iptables-save", "ip6tables-save"):
            import re
            # Preserve rule order; strip only comments and chain byte/packet counters.
            state[command] = re.sub(r"\[\d+:\d+\]", "[0:0]", "\n".join(x for x in run([command]).splitlines() if not x.startswith("#")))
    state["vpn_config_hashes"] = {}
    for name in p["vpn_config_files"]:
        path = Path(name)
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            raise Blocked("VPN config file unavailable or exceeds inventory bound")
        state["vpn_config_hashes"][name] = {"target": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    state["vpn_services"] = {}
    state["vpn_cgroup_limits"] = {}
    for unit in p["vpn_services"]:
        info = run(["systemctl", "show", unit, "--property=ActiveState,SubState,MainPID,ExecMainStartTimestampMonotonic,NRestarts,ControlGroup,NeedDaemonReload"])
        if "ActiveState=active" not in info:
            raise Failed("VPN service is not active")
        state["vpn_services"][unit] = info
        group = next((line.split("=", 1)[1] for line in info.splitlines() if line.startswith("ControlGroup=")), "")
        if group:
            root = Path("/sys/fs/cgroup") / group.lstrip("/")
            state["vpn_cgroup_limits"][unit] = {name: (root / name).read_text() for name in ("cpu.max", "memory.max", "pids.max") if (root / name).exists()}
    state["vpn_containers"] = {}
    for name in p["vpn_containers"]:
        info = json.loads(run(["docker", "inspect", "--format", "{{json .State}}", name]))
        if not info.get("Running"):
            raise Failed("VPN container is not running")
        state["vpn_containers"][name] = {k: info.get(k) for k in ("Running", "Pid", "StartedAt", "Restarting", "Dead")}
    if not set(p["vpn_interfaces"]) <= {x["ifname"] for x in state["links"]}:
        raise Blocked("VPN interfaces not found in host namespace; explicitly inventory its namespace before testing")
    # Connection/process snapshots are private evidence, not config equality:
    # normal outbound flows and unrelated process exits are expected to change.
    raw = {"connections": run(["ss", "-tunap"]), "processes": run(["ps", "-eo", "pid,comm"]),
           "netns_processes": run(["lsns", "-t", "net", "-o", "NS,PID,COMMAND"]),
           "cgroup": Path("/proc/self/cgroup").read_text()}
    state["listeners"] = sorted(listener_semantics(line) for line in run(["ss", "-H", "-lntup"]).splitlines())
    cgroup_root = Path("/sys/fs/cgroup")
    raw["cgroup_limits"] = {name: (cgroup_root / name).read_text() for name in ("cpu.max", "memory.max", "pids.max") if (cgroup_root / name).exists()}
    return state, raw


def collisions(p, state):
    if any(line.split()[0] == p["namespace"] for line in state["namespaces"]):
        raise Blocked("Mosaic namespace already exists; refusing adoption")
    if any(link["ifname"].startswith("mosaic") for link in state["links"]):
        raise Blocked("Mosaic interface already exists in host namespace")
    subnet = ipaddress.ip_network(p["tunnel_subnet"])
    for route in state["routes4"]:
        destination = route.get("dst", "default")
        if destination != "default" and subnet.overlaps(ipaddress.ip_network(destination, strict=False)):
            raise Blocked("selected tunnel subnet overlaps an existing route")
    for link in state["addresses"]:
        for address in link.get("addr_info", []):
            if address.get("family") == "inet" and subnet.overlaps(ipaddress.ip_network(f'{address["local"]}/{address["prefixlen"]}', strict=False)):
                raise Blocked("selected tunnel subnet overlaps an existing interface")


def probes(p):
    samples = {}
    # Independent probes run concurrently to retain the five-second cadence.
    from concurrent.futures import ThreadPoolExecutor
    def probe(item):
        start = time.monotonic()
        try:
            output = run(item["argv"], p["test_uid"])
            return item["id"], {"ok": True, "ms": (time.monotonic() - start) * 1000, "output_hash": digest(output.strip()) if item["stable_output"] else None}
        except Blocked:
            return item["id"], {"ok": False, "ms": (time.monotonic() - start) * 1000, "output_hash": None}
    with ThreadPoolExecutor(max_workers=len(p["probes"])) as pool:
        samples.update(pool.map(probe, p["probes"]))
    return samples


def degraded(baseline_ms, recent):
    current = statistics.median(recent)
    return current > baseline_ms * 1.2 and current > baseline_ms + 10


def sample(p, state, seconds, baseline=None):
    histories = {probe["id"]: [] for probe in p["probes"]}
    failures = {key: 0 for key in histories}
    hashes = {}
    any_failure = False
    start = time.monotonic()
    for index in range(seconds // 5):
        deadline = start + index * 5
        time.sleep(max(0, deadline - time.monotonic()))
        current, _ = inventory(p)
        if current != state:
            raise Failed("host/VPN configuration or service identity changed; stop Mosaic testing")
        results = probes(p)
        for key, value in results.items():
            failures[key] = 0 if value["ok"] else failures[key] + 1
            any_failure |= not value["ok"]
            if failures[key] >= 2:
                raise Failed("two consecutive health probes failed; stop Mosaic testing")
            if not value["ok"]:
                continue
            histories[key].append(value["ms"])
            if value["output_hash"]:
                expected = baseline["output_hashes"].get(key) if baseline else hashes.setdefault(key, value["output_hash"])
                if expected != value["output_hash"]:
                    raise Failed("stable VPN/egress probe output changed")
            if baseline and len(histories[key]) >= 12 and degraded(baseline["medians_ms"][key], histories[key][-12:]):
                raise Failed("rolling control latency exceeds baseline by both 20 percent and 10 ms")
        if time.monotonic() > deadline + 5:
            raise Blocked("inventory/probes exceeded five-second cadence; no passing V result")
        if index % 6 == 0:
            print(f"control sample {index + 1}/{seconds // 5}", file=sys.stderr, flush=True)
    time.sleep(max(0, start + seconds - time.monotonic()))
    if inventory(p)[0] != state:
        raise Failed("host/VPN configuration changed after control sample")
    if any_failure:
        raise Failed("at least one unexpected control failure; V cannot pass")
    return {"medians_ms": {k: statistics.median(v) for k, v in histories.items()}, "output_hashes": hashes, "samples_per_probe": seconds // 5}


def write_new(path, data):
    with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["record", "verify", "monitor"])
    parser.add_argument("--policy", default="configs/node-baseline.json")
    parser.add_argument("--directory", default=".mosaic-baseline")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--report")
    args = parser.parse_args(argv)
    report = {"schema_version": 1, "check_level": 0, "scope": "node-control-only", "status": "BLOCKED", "assertions": []}
    code = 2
    try:
        if platform.system() != "Linux" or os.geteuid() != 0:
            raise Blocked("read-only node inventory requires Linux and root; no packages installed")
        p = policy_load(args.policy)
        directory = Path(args.directory)
        if args.action == "record":
            directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        if directory.is_symlink() or not directory.is_dir() or directory.stat().st_mode & 0o077 or directory.stat().st_uid != os.geteuid():
            raise Blocked("baseline directory must be owner-only, owned by current user and not a symlink")
        state, raw = inventory(p)
        if args.action == "record":
            collisions(p, state)
            # Retain private inventory even if the mandatory sample subsequently fails.
            write_new(directory / "inventory.json", {"state": state, "raw": raw})
            controls = sample(p, state, 300)
            write_new(directory / "baseline.json", {"policy_hash": digest(p), "recorded_at": time.time(), "state": state, "controls": controls})
        else:
            baseline = json.loads((directory / "baseline.json").read_text())
            if baseline["policy_hash"] != digest(p) or time.time() - baseline["recorded_at"] > 3600:
                raise Blocked("baseline policy changed or sample older than one hour; record a fresh baseline directory")
            if state != baseline["state"]:
                raise Failed("host configuration or VPN service changed since baseline")
            if args.action == "monitor":
                if args.seconds < 60 or args.seconds > 3600 or args.seconds % 5:
                    raise Blocked("monitor duration must be 60..3600 seconds, divisible by five")
                sample(p, state, args.seconds, baseline["controls"])
            else:
                check = probes(p)
                if not all(v["ok"] for v in check.values()):
                    raise Failed("current control probe failed")
                for key, expected in baseline["controls"]["output_hashes"].items():
                    if check[key]["output_hash"] != expected:
                        raise Failed("host/VPN egress probe changed")
                if inventory(p)[0] != state:
                    raise Failed("host/VPN configuration changed during verification")
        report.update(status="PASS")
        report["assertions"].append({"id": f"node.{args.action}", "status": "PASS", "detail": "read-only node control checks passed; this alone does not complete deployment"})
        code = 0
    except Failed as error:
        report["status"] = "FAIL"
        report["assertions"].append({"id": "node.preservation", "status": "FAIL", "detail": str(error)})
        code = 1
    except (Blocked, OSError, ValueError, KeyError, TypeError):
        report["assertions"].append({"id": "node.prerequisites", "status": "BLOCKED", "detail": "node/policy/inventory/baseline prerequisites unavailable; inspect locally and do not change VPN settings"})
    if args.report:
        try:
            write_new(args.report, report)
        except OSError:
            print("FAIL cannot create new report", file=sys.stderr)
            return 1
    print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
