"""Real native relay/client processes on loopback; never contacts supplied servers."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get("MOSAIC_BIN_DIR", ROOT / "target/debug")).resolve()

class EchoCliTests(unittest.TestCase):
    def invoke(self, name, *args, code=0):
        result = subprocess.run([str(BIN / name), *map(str, args)], cwd="/", capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, code, result.stdout + result.stderr)
        return result

    def test_echo_restart_reports_and_redacted_negative_identity(self):
        with tempfile.TemporaryDirectory(prefix="mosaic-echo-") as directory:
            d = Path(directory)
            subprocess.run([str(ROOT / "scripts/provision.sh"), "--fixture", "relay.example.net", str(d / "secrets")], capture_output=True, check=True, timeout=10)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            relay = json.loads((ROOT / "configs/relay.example.json").read_text())
            client = json.loads((ROOT / "configs/client.example.json").read_text())
            relay["listen"] = client["server"]["address"] = f"127.0.0.1:{port}"
            relay_file, client_file = d / "relay.json", d / "client.json"
            placeholder = d / "placeholder.json"
            placeholder.write_text((ROOT / "configs/client.example.json").read_text())
            blocked = self.invoke("mosaic-client", "test", "-c", placeholder, code=2)
            self.assertEqual(json.loads(blocked.stdout)["status"], "BLOCKED")
            relay_file.write_text(json.dumps(relay))
            client_file.write_text(json.dumps(client))
            for repeat in (1, 2):
                ready = d / f"ready-{repeat}.json"
                process = subprocess.Popen([str(BIN / "mosaic-relay"), "-c", str(relay_file), "--diagnostic-only", "--report", str(ready)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 5
                    while True:
                        try:
                            startup = json.loads(ready.read_text())
                            break
                        except (FileNotFoundError, json.JSONDecodeError):
                            if process.poll() is not None or time.monotonic() >= deadline:
                                self.fail("echo relay did not become ready")
                            time.sleep(0.01)
                    self.assertEqual(startup["status"], "PASS")
                    report = d / f"echo-{repeat}.json"
                    result = self.invoke("mosaic-client", "test", "-c", client_file, "--case", "stream-echo", "--report", report)
                    body = json.loads(result.stdout)
                    self.assertEqual(body, json.loads(report.read_text()))
                    self.assertEqual(body["check_level"], 2)
                    self.assertEqual(body["scope"], "authenticated-diagnostics")
                    self.assertEqual(body["status"], "PASS")
                    self.assertEqual(len([a for a in body["assertions"] if a["id"].startswith("quic.echo.")]), 5)
                    self.assertEqual(report.stat().st_mode & 0o777, 0o600)
                    session = self.invoke("mosaic-client", "test", "-c", client_file, "--case", "session")
                    self.assertEqual(json.loads(session.stdout)["status"], "PASS")
                    datagrams = self.invoke("mosaic-client", "test", "-c", client_file, "--case", "datagram-echo", "--count", "1000", "--size", "1100", "--rate", "50")
                    self.assertIn("1000/1000", datagrams.stdout)
                    self.invoke("mosaic-client", "test", "-c", client_file, "--case", "datagram-echo", "--count", "10001", code=1)
                    token_path = d / "secrets/client.token"
                    correct_token = token_path.read_text()
                    token_path.write_text("00" * 32)
                    unauthorized = self.invoke("mosaic-client", "test", "-c", client_file, "--case", "session", code=1)
                    self.assertNotIn("00" * 32, unauthorized.stdout + unauthorized.stderr)
                    token_path.write_text(correct_token)
                    self.invoke("mosaic-client", "test", "-c", client_file, "--case", "session")
                    client["server"]["name"] = "private-name-canary.internal"
                    client_file.write_text(json.dumps(client))
                    failed = self.invoke("mosaic-client", "test", "-c", client_file, code=1)
                    self.assertEqual(json.loads(failed.stdout)["status"], "FAIL")
                    self.assertNotIn("private-name-canary", failed.stdout + failed.stderr)
                    token = (d / "secrets/client.token").read_text().strip()
                    self.assertNotIn(token, result.stdout + result.stderr + failed.stdout + failed.stderr)
                    client["server"]["name"] = "relay.example.net"
                    client_file.write_text(json.dumps(client))
                finally:
                    process.terminate()  # exact child PID owned by this fixture only
                    try:
                        stdout, stderr = process.communicate(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=2)
                        self.fail("echo relay failed graceful shutdown")
                self.assertEqual(process.returncode, 0, stdout + stderr)
                # Teardown released the same listening UDP port before the next fresh start.
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    probe.bind(("127.0.0.1", port))

    def test_documentation_target_and_unsupported_case(self):
        self.invoke("mosaic-client", "test", "-c", ROOT / "configs/client.example.json", "--case", "unsupported", code=2)
        # Missing credentials fail validation before networking.
        with tempfile.TemporaryDirectory(prefix="mosaic-no-secrets-") as directory:
            config = Path(directory) / "client.json"
            config.write_text((ROOT / "configs/client.example.json").read_text())
            self.invoke("mosaic-client", "test", "-c", config, code=1)

if __name__ == "__main__":
    unittest.main()
