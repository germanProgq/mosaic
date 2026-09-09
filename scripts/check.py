#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description="Repeat implemented checks and report missing deployment evidence.")
    parser.add_argument("check_level", type=int, choices=range(10), help="0: setup, 1: QUIC connectivity, 2: authentication, 3: isolated TUN, 4: Internet forwarding and native fetch, 5–9: planned features")
    parser.add_argument("--local-only", action="store_true", help="CI scope: local assertions may pass; deployment remains BLOCKED")
    args = parser.parse_args()
    os.umask(0o077)
    directory = ROOT / "results" / f"checks-{args.check_level}-{time.time_ns()}"
    directory.mkdir(parents=True, mode=0o700)
    manifest = json.loads((ROOT / "tests/manifest.json").read_text())
    report = {"schema_version": 1, "check_level": args.check_level, "scope": "local-only" if args.local_only else "deployment", "status": "PASS", "deployment_status": "BLOCKED", "os": platform.system(), "arch": platform.machine(), "lock_sha256": hashlib.sha256((ROOT / "Cargo.lock").read_bytes()).hexdigest(), "assertions": []}
    def assertion(id, status, detail):
        report["assertions"].append({"id": id, "status": status, "detail": detail})
        print(f"{status} {id}: {detail}", flush=True)
        if status == "FAIL" or status == "BLOCKED" and report["status"] == "PASS":
            report["status"] = status
    def execute(id, argv, timeout=300):
        with (directory / f"{id}.log").open("x") as log:
            try:
                result = subprocess.run(argv, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
                ok = result.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                ok = False
        assertion(id, "PASS" if ok else "FAIL", "bounded check completed" if ok else "check failed or timed out; inspect private run log")
        return ok
    execute("format", ["cargo", "fmt", "--all", "--", "--check"])
    execute("lint", ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"])
    execute("build", ["cargo", "build", "--workspace", "--locked"])
    for repeat in (1, 2):
        execute(f"rust-{repeat}", ["cargo", "test", "--workspace", "--locked", "--", "--show-output"])
        execute(f"native-and-monitor-{repeat}", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], timeout=180)
    for check in manifest["checks"][:args.check_level + 1]:
        if check["implementation"] == "pending":
            assertion(f"checks.{check['check_level']}.implementation", "BLOCKED", "required implementation and tests are missing")
    report["required_live_gates"] = [gate for check in manifest["checks"][:args.check_level + 1] for gate in check.get("live_required", [])]
    if not args.local_only:
        assertion(f"checks.{args.check_level}.deployment", "BLOCKED", "required live relay/VPN-preservation assertions remain incomplete; local tests cannot complete deployment gates")
    with (directory / "report.json").open("x") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(f"Report: {directory / 'report.json'}")
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[report["status"]]

if __name__ == "__main__": sys.exit(main())
