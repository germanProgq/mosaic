import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get('MOSAIC_BIN_DIR', ROOT / 'target/debug')).resolve()


class FetchCliTests(unittest.TestCase):
    def test_fetch_authentication_rejection_reports_and_shutdown(self):
        with tempfile.TemporaryDirectory(prefix='mosaic-fetch-') as directory:
            directory = Path(directory)
            subprocess.run([str(ROOT / 'scripts/provision.sh'), '--fixture', 'relay.example.net', str(directory / 'secrets')], capture_output=True, check=True, timeout=10)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            relay = json.loads((ROOT / 'configs/relay.example.json').read_text())
            client = json.loads((ROOT / 'configs/client.example.json').read_text())
            relay['listen'] = client['server']['address'] = f'127.0.0.1:{port}'
            for name, config in [('client', client), ('relay', relay)]:
                (directory / f'{name}.json').write_text(json.dumps(config))
            ready = directory / 'ready.json'
            process = subprocess.Popen([str(BIN / 'mosaic-relay'), '-c', str(directory / 'relay.json'), '--fetch', '--report', str(ready)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not ready.exists():
                    self.assertIsNone(process.poll())
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.02)
                self.assertEqual(json.loads(ready.read_text())['scope'], 'fetch-service')
                report = directory / 'fetch.json'
                token = (directory / 'secrets/client.token').read_text().strip()
                url = 'https://disallowed.invalid/private-query-canary'
                result = subprocess.run([str(BIN / 'mosaic-client'), 'fetch', '-c', str(directory / 'client.json'), url, '--report', str(report)], capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                body = json.loads(result.stdout)
                self.assertEqual(body['scope'], 'native-fetch')
                self.assertEqual(body['status'], 'FAIL')
                self.assertEqual(json.loads(report.read_text()), body)
                self.assertEqual(report.stat().st_mode & 0o777, 0o600)
                self.assertNotIn(token, result.stdout + result.stderr)
                self.assertNotIn('private-query-canary', result.stdout + result.stderr)
                session = subprocess.run([str(BIN / 'mosaic-client'), 'test', '-c', str(directory / 'client.json'), '--case', 'session'], capture_output=True, text=True, timeout=10)
                self.assertEqual(session.returncode, 0, session.stdout + session.stderr)
            finally:
                process.terminate()
                try:
                    process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=2)
                    self.fail('fetch relay did not stop')
            self.assertEqual(process.returncode, 0)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(('127.0.0.1', port))


if __name__ == '__main__':
    unittest.main()
