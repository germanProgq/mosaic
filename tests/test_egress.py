from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/network'))
import baseline
import egress


class EgressTests(unittest.TestCase):
    def test_nonpublic_and_metadata_destinations_are_rejected(self):
        for address in ('127.0.0.1', '10.77.0.1', '169.254.169.254', '100.64.0.1', '168.63.129.16', '224.0.0.1', '203.0.113.1'):
            with self.subTest(address=address), self.assertRaises(baseline.Blocked):
                egress.public_address(address)

    def test_pin_must_match_current_bounded_resolution(self):
        with patch.object(baseline, 'run', return_value='1.1.1.1 STREAM example.com\n') as command:
            self.assertEqual(egress.pinned('example.com', '1.1.1.1'), '1.1.1.1')
            self.assertEqual(command.call_args.args[0], ['getent', 'ahostsv4', 'example.com'])
            with self.assertRaises(baseline.Blocked):
                egress.pinned('example.com', '8.8.8.8')

    def test_fetch_is_namespace_only_nonroot_pinned_and_bounded(self):
        command = egress.curl('mosaic-test', 'example.com', '1.1.1.1', 65534, 65534)
        self.assertEqual(command[:4], ['ip', 'netns', 'exec', 'mosaic-test'])
        for value in ('setpriv', '--clear-groups', '--max-time', '--max-filesize', '--limit-rate', '--noproxy', 'example.com:443:1.1.1.1'):
            self.assertIn(value, command)
        self.assertNotIn('--insecure', command)
        self.assertNotIn('--location', command)


if __name__ == '__main__':
    unittest.main()
