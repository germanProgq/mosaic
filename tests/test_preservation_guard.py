import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('preservation_guard', Path(__file__).resolve().parents[1] / 'tools/network/preservation_guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class PreservationGuardTests(unittest.TestCase):
    def samples(self, count=61):
        return [json.dumps({'label': label, 'event': {'type': 'sample', 'status': 'PASS', 'duration_ms': 100}}) for _ in range(count) for label in ['host', 'representative_vpn']]

    def test_both_complete_baselines_are_required(self):
        self.assertEqual(guard.events('\n'.join(self.samples())), {'host': 61, 'representative_vpn': 61})
        with self.assertRaises(RuntimeError):
            guard.events('\n'.join(self.samples(60)))

    def test_failure_and_observer_exit_are_never_accepted(self):
        for event in [{'status': 'FAIL'}, {'type': 'exit', 'code': 0}, {'type': 'final', 'status': 'PASS'}]:
            with self.subTest(event=event), self.assertRaises(RuntimeError):
                guard.events('\n'.join(self.samples() + [json.dumps({'label': 'host', 'event': event})]))
