"""Run against actual native binaries, using disposable local credentials only."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("MOSAIC_BIN_DIR", ROOT / "target/debug")).resolve()

class CliTests(unittest.TestCase):
    def run_cli(self, name, *args, code=0):
        result = subprocess.run([str(BIN / name), *map(str, args)], cwd="/", capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def test_versions_and_examples_from_another_working_directory(self):
        self.assertIn("0.1.0", self.run_cli("mosaic-client", "--version").stdout)
        self.assertIn("0.1.0", self.run_cli("mosaic-relay", "--version").stdout)
        for name in ("client", "client-node"):
            output = self.run_cli("mosaic-client", "check-config", "-c", ROOT / f"configs/{name}.example.json", "--schema-only")
            self.assertEqual(json.loads(output.stdout)["status"], "PASS")
        self.run_cli("mosaic-relay", "-c", ROOT / "configs/relay.example.json", "--check-config", "--schema-only")

    def test_credentials_reports_and_blocked_deployment(self):
        with tempfile.TemporaryDirectory(prefix="mosaic-fixture-") as directory:
            d = Path(directory)
            provision = [str(ROOT / "scripts/provision.sh"), "--fixture", "relay.example.net", str(d / "secrets")]
            subprocess.run(provision, capture_output=True, check=True, timeout=10)
            self.assertNotEqual(subprocess.run(provision, capture_output=True, timeout=10).returncode, 0)
            config = d / "client.json"
            config.write_text((ROOT / "configs/client.example.json").read_text())
            relay = d / "relay.json"
            relay.write_text((ROOT / "configs/relay.example.json").read_text())
            report = d / "report.json"
            result = self.run_cli("mosaic-client", "check-config", "-c", config, "--report", report)
            self.assertEqual(json.loads(report.read_text()), json.loads(result.stdout))
            self.assertEqual(report.stat().st_mode & 0o777, 0o600)
            self.run_cli("mosaic-client", "check-config", "-c", config, "--report", report, code=1)
            self.run_cli("mosaic-relay", "-c", relay, "--check-config")
            self.run_cli("mosaic-relay", "-c", relay, code=2)
            result = self.run_cli("mosaic-client", "preflight", "-c", config, code=2)
            self.assertEqual(json.loads(result.stdout)["status"], "BLOCKED")
            node = d / "client-node.json"
            node.write_text((ROOT / "configs/client-node.example.json").read_text())
            import platform
            expected = 2 if platform.system() != "Linux" else 1
            blocked = self.run_cli("mosaic-client", "isolated-up", "-c", node, "--policy", d / "missing-policy.json", "--baseline", d / "missing-baseline", code=expected)
            self.assertEqual(json.loads(blocked.stdout)["scope"], "isolated-tun")
            token = (d / "secrets/client.token").read_text().strip()
            self.assertNotIn(token, result.stdout + result.stderr)
            value = json.loads(config.read_text())
            value["auth"]["private-key-canary"] = token
            config.write_text(json.dumps(value))
            result = self.run_cli("mosaic-client", "check-config", "-c", config, code=1)
            self.assertNotIn(token, result.stdout + result.stderr)
            self.assertNotIn("private-key-canary", result.stdout + result.stderr)

    def test_incomplete_and_unimplemented_commands_do_not_pretend_to_work(self):
        self.run_cli("mosaic-client", "test", code=2)
        self.run_cli("mosaic-client", "fetch", "https://example.com", code=2)
        self.run_cli("mosaic-client", "isolated-up", code=2)

if __name__ == "__main__": unittest.main()
