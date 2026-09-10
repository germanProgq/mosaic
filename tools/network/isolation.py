import argparse
import json
import ipaddress
import os
from pathlib import Path
import re
import sys
import time

import baseline


def identity(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()[19]


def owner_load(directory):
    if directory.parent != Path("/run") or not directory.name.startswith("mosaic-"):
        raise baseline.Blocked("invalid isolation ownership path")
    meta = directory.lstat()
    if directory.is_symlink() or not directory.is_dir() or meta.st_uid != 0 or meta.st_mode & 0o077:
        raise baseline.Blocked("unsafe isolation ownership directory")
    path = directory / "owner.json"
    if path.is_symlink() or path.stat().st_size > 16384 or path.stat().st_uid != 0 or path.stat().st_mode & 0o077:
        raise baseline.Blocked("unsafe isolation ownership file")
    owner = json.loads(path.read_text())
    if directory.name != owner["namespace"]:
        raise baseline.Blocked("namespace ownership mismatch")
    return owner


def filter_state(state, owner, observed):
    namespace = owner["namespace"]
    if observed["namespace_inode"] != owner["namespace_inode"] or observed["socket_inode"] != owner["socket_inode"]:
        raise baseline.Failed("namespace or socket ownership changed")
    if observed["socket_uid"] != owner["socket_uid"] or observed["socket_port"] != owner["socket_port"]:
        raise baseline.Failed("transport socket UID or port changed")
    if observed["parent_start"] != owner["parent"]["start"] or observed["worker_start"] != owner["worker"]["start"]:
        raise baseline.Failed("Mosaic process identity changed")
    names = [line.split()[0] for line in state["namespaces"]]
    if names.count(namespace) != 1:
        raise baseline.Failed("owned namespace is missing or ambiguous")
    state["namespaces"] = [line for line in state["namespaces"] if line.split()[0] != namespace]
    worker = owner["worker"]["pid"]
    listeners = []
    matched = 0
    for line in state["listeners"]:
        pids = {int(pid) for pid in re.findall(r"pid=(\d+)", line)}
        if worker in pids:
            fields = line.split()
            matched += 1
            if matched > 1 or pids != {worker} or fields[0] != "udp" or fields[4] != f"0.0.0.0:{owner['socket_port']}":
                raise baseline.Failed("unexpected Mosaic listener")
        else:
            listeners.append(line)
    state["listeners"] = listeners
    return state


def routing(links, routes, routes6, rules, subnet, ready):
    names = {link["ifname"] for link in links}
    devices = names - {"lo"}
    if "lo" not in names or len(devices) > 1 or any(not name.startswith("mosaic") for name in devices):
        raise baseline.Failed("namespace has an alternate interface")
    if any(link["mtu"] != 1100 for link in links if link["ifname"] != "lo"):
        raise baseline.Failed("TUN MTU changed")
    if ready and len(devices) != 1:
        raise baseline.Failed("namespace TUN is missing")
    tun = next(iter(devices), None)
    network = ipaddress.IPv4Network(subnet)
    defaults = 0
    for route in routes:
        dev = route.get("dev")
        kind = route.get("type", "unicast")
        table = route.get("table", "main")
        if dev not in names or any(key in route for key in ("gateway", "nexthops", "nhid", "encap", "via")):
            raise baseline.Failed("namespace route has an alternate path")
        if route.get("dst") == "default":
            if dev != tun or kind != "unicast" or table not in ("main", 254):
                raise baseline.Failed("namespace default route changed")
            defaults += 1
            continue
        destination = ipaddress.IPv4Network(route["dst"], strict=False)
        if kind in ("local", "broadcast"):
            allowed = ipaddress.IPv4Network("127.0.0.0/8") if dev == "lo" else network
            if table not in ("local", 255) or not destination.subnet_of(allowed):
                raise baseline.Failed("namespace local route changed")
        elif kind != "unicast" or dev != tun or table not in ("main", 254) or destination != network:
            raise baseline.Failed("unexpected namespace route")
    if defaults > 1 or ready and defaults != 1:
        raise baseline.Failed("namespace must have one TUN default route")
    for route in routes6:
        if route.get("dev") != "lo" or route.get("dst") != "::1" or route.get("type") != "local":
            raise baseline.Failed("namespace has external IPv6 routing")
    expected = [(0, "local"), (32766, "main"), (32767, "default")]
    observed = [(rule.get("priority"), rule.get("table")) for rule in rules]
    if observed != expected or any(set(rule) - {"priority", "src", "table", "protocol"} or rule.get("src", "all") != "all" for rule in rules):
        raise baseline.Failed("namespace policy routing changed")


def namespace_inventory(owner, subnet, directory):
    namespace = owner["namespace"]
    ready = (directory / "tunnel.ready").exists()
    if ready and (directory / "tunnel.ready").read_bytes() != b"ready\n":
        raise baseline.Failed("namespace readiness changed")
    links = json.loads(baseline.run(["ip", "-n", namespace, "-j", "link", "show"]))
    routes = json.loads(baseline.run(["ip", "-n", namespace, "-j", "-4", "route", "show", "table", "all"]))
    routes6 = json.loads(baseline.run(["ip", "-n", namespace, "-j", "-6", "route", "show", "table", "all"]))
    rules = json.loads(baseline.run(["ip", "-n", namespace, "-j", "-4", "rule", "show"]))
    routing(links, routes, routes6, rules, subnet, ready)
    if owner.get("worker_mount_inode") is not None:
        worker = owner["worker"]["pid"]
        parent = owner["parent"]["pid"]
        current = Path(f"/proc/{worker}/ns/mnt").stat().st_ino
        if current != owner["worker_mount_inode"] or current == Path(f"/proc/{parent}/ns/mnt").stat().st_ino:
            raise baseline.Failed("worker private mount namespace changed")
        if ready:
            prefix = ["nsenter", f"--mount=/proc/{worker}/ns/mnt", "--"]
            resolver = baseline.run(prefix + ["cat", "/etc/resolv.conf"])
            if resolver.strip() != "nameserver 1.1.1.1\noptions timeout:2 attempts:1 ndots:1":
                raise baseline.Failed("namespace resolver changed")
            names = baseline.run(prefix + ["cat", "/etc/nsswitch.conf"])
            hosts = [line.split(":", 1)[1].strip() for line in names.splitlines() if line.split(":", 1)[0].strip() == "hosts"]
            if hosts != ["dns"]:
                raise baseline.Failed("namespace name service changed")
    return {"links": links, "routes": routes, "routes6": routes6, "rules": rules}


def isolated_inventory(policy, directory):
    owner = owner_load(directory)
    worker = owner["worker"]["pid"]
    parent = owner["parent"]["pid"]
    if owner["namespace"] != policy["namespace"] or owner["socket_uid"] != policy["test_uid"]:
        raise baseline.Failed("isolation policy mismatch")
    socket = f"socket:[{owner['socket_inode']}]"
    found = False
    for fd in Path(f"/proc/{worker}/fd").iterdir():
        try:
            found |= os.readlink(fd) == socket
        except FileNotFoundError:
            continue
    if not found:
        raise baseline.Failed("worker no longer owns the transport socket")
    matches = []
    for line in Path("/proc/net/udp").read_text().splitlines()[1:]:
        fields = line.split()
        if int(fields[9]) == owner["socket_inode"]:
            matches.append({"socket_inode": int(fields[9]), "socket_uid": int(fields[7]), "socket_port": int(fields[1].split(":")[1], 16)})
    if len(matches) != 1:
        raise baseline.Failed("transport socket missing from original namespace")
    observed = {**matches[0], "namespace_inode": Path(f"/run/netns/{owner['namespace']}").stat().st_ino,
                "parent_start": identity(parent), "worker_start": identity(worker)}
    if Path(f"/proc/{worker}/ns/net").stat().st_ino != owner["namespace_inode"]:
        raise baseline.Failed("worker left its namespace")
    if Path(f"/proc/{parent}/ns/net").stat().st_ino == owner["namespace_inode"]:
        raise baseline.Failed("launcher left the original namespace")
    namespace_inventory(owner, policy["tunnel_subnet"], directory)
    status = Path(f"/proc/{worker}/status").read_text()
    rss = re.search(r"^VmRSS:\s+(\d+)\s+kB", status, re.MULTILINE)
    if rss and int(rss[1]) > 256 * 1024:
        raise baseline.Failed("Mosaic worker exceeds memory limit")
    state, _ = baseline.inventory(policy)
    return filter_state(state, owner, observed)


def load_baseline(policy, directory):
    meta = directory.lstat()
    if directory.is_symlink() or not directory.is_dir() or meta.st_uid != 0 or meta.st_mode & 0o077:
        raise baseline.Blocked("unsafe baseline directory")
    saved = json.loads((directory / "baseline.json").read_text())
    if saved["policy_hash"] != baseline.digest(policy) or not 0 <= time.time() - saved["recorded_at"] <= 3600:
        raise baseline.Blocked("fresh matching baseline required")
    if saved["controls"]["samples_per_probe"] != 60:
        raise baseline.Blocked("five-minute baseline required")
    return saved


def check_probes(policy, saved):
    values = baseline.probes(policy)
    for key, value in values.items():
        if not value["ok"] or value["output_hash"] != saved["controls"]["output_hashes"].get(key):
            raise baseline.Failed("VPN control probe failed or egress changed")
    return values


def main():
    parser = argparse.ArgumentParser(description="Verify VPN preservation around the owned isolated worker.")
    parser.add_argument("action", choices=["verify", "watch"])
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    try:
        if sys.platform != "linux" or os.geteuid() != 0:
            raise baseline.Blocked("Linux root inventory required")
        policy = baseline.policy_load(args.policy)
        saved = load_baseline(policy, args.baseline)
        if args.action == "verify":
            state, _ = baseline.inventory(policy)
            if state != saved["state"]:
                raise baseline.Failed("host configuration changed")
            baseline.collisions(policy, state)
            check_probes(policy, saved)
            if baseline.inventory(policy)[0] != saved["state"]:
                raise baseline.Failed("host configuration changed during verification")
            return 0
        histories = {probe["id"]: [] for probe in policy["probes"]}
        start = time.monotonic()
        index = 0
        while True:
            deadline = start + index * 5
            time.sleep(max(0, deadline - time.monotonic()))
            if isolated_inventory(policy, args.directory) != saved["state"]:
                raise baseline.Failed("host or VPN configuration changed")
            values = check_probes(policy, saved)
            for key, value in values.items():
                histories[key] = (histories[key] + [value["ms"]])[-12:]
                if len(histories[key]) == 12 and baseline.degraded(saved["controls"]["medians_ms"][key], histories[key]):
                    raise baseline.Failed("rolling VPN control latency degraded")
            if time.monotonic() > deadline + 5:
                raise baseline.Blocked("control sampling deadline missed")
            baseline.write_new(args.directory / "guard.next", {"status": "PASS", "sample": index, "unix_time": time.time()})
            os.replace(args.directory / "guard.next", args.directory / "guard.ready")
            index += 1
    except (OSError, ValueError, KeyError, TypeError, baseline.Blocked, baseline.Failed) as error:
        if args.directory.is_dir():
            try:
                baseline.write_new(args.directory / "guard.json", {"status": "FAIL", "detail": "VPN preservation or isolation ownership check failed"})
            except OSError:
                pass
        print(f"FAIL isolation.guard: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
