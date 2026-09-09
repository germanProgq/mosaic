import copy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/network'))
import forwarding


class ForwardingTests(unittest.TestCase):
    def test_existing_drop_chains_receive_only_scoped_accepts(self):
        before = [{'chain': {'family': 'inet', 'table': 'filter', 'name': 'forward', 'type': 'filter', 'hook': 'forward', 'policy': 'drop'}}]
        targets = forwarding.targets_for(before)
        rules = forwarding.rules('mosaic0', 'eth0', '10.77.0.2', targets)
        self.assertIn('insert rule inet filter forward jump mosaic_egress', rules)
        self.assertIn('iifname "mosaic0" oifname "eth0" ip saddr 10.77.0.2 counter accept', rules)
        self.assertIn('ip daddr 10.77.0.2 ct state established,related counter accept', rules)
        self.assertIn('iifname "mosaic0" oifname "eth0" ip saddr 10.77.0.2 counter masquerade', rules)
        self.assertNotIn('flush ruleset', rules)
        self.assertNotIn('hook input', rules)
        self.assertNotIn('delete', rules)

    def test_existing_names_are_never_adopted(self):
        for item in [{'table': {'family': 'ip', 'name': 'mosaic_nat'}}, {'chain': {'family': 'inet', 'table': 'filter', 'name': 'mosaic_egress'}}]:
            with self.assertRaises(forwarding.Blocked):
                forwarding.targets_for([item])

    def test_counters_can_change_but_rule_identity_and_policy_cannot(self):
        items = [{'rule': {'family': 'inet', 'table': 'mosaic_forward', 'chain': 'forward', 'handle': 10, 'expr': [{'counter': {'packets': 0, 'bytes': 0}}, {'accept': None}]}}]
        state = {'targets': [], 'owned': forwarding.fingerprint(items, handles=True)}
        changed = copy.deepcopy(items)
        changed[0]['rule']['expr'][0]['counter']['packets'] = 50
        forwarding.verify(state, changed)
        changed[0]['rule']['handle'] = 11
        with self.assertRaises(forwarding.Blocked):
            forwarding.verify(state, changed)
        changed = copy.deepcopy(items)
        changed[0]['rule']['expr'][-1] = {'drop': None}
        with self.assertRaises(forwarding.Blocked):
            forwarding.verify(state, changed)

    def test_cleanup_deletes_only_recorded_objects_and_restores_forwarding(self):
        targets = [{'family': 'inet', 'table': 'filter', 'chain': 'forward'}]
        base = [{'table': {'family': 'inet', 'name': 'filter', 'handle': 1}}]
        items = base + [{'table': {'family': 'inet', 'name': 'mosaic_forward', 'handle': 2}}, {'table': {'family': 'ip', 'name': 'mosaic_nat', 'handle': 3}}, {'rule': {'family': 'inet', 'table': 'filter', 'chain': 'forward', 'handle': 20, 'expr': [{'jump': {'target': 'mosaic_egress'}}]}}]
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory)
            setting = state_path / 'forwarding'
            setting.write_text('1\n')
            with patch.object(forwarding, 'STATE', state_path), patch.object(forwarding, 'FORWARDING', setting), patch.object(forwarding, 'inventory', return_value=items), patch.object(forwarding, 'run') as command:
                forwarding.save({'targets': targets, 'before': forwarding.fingerprint(base), 'owned': forwarding.fingerprint(items[1:], handles=True), 'forwarding': '0'})
                forwarding.cleanup()
                batch = command.call_args.args[1]
                self.assertIn('delete rule inet filter forward handle 20', batch)
                self.assertNotIn('delete table inet filter', batch)
                self.assertEqual(setting.read_text(), '0\n')
                self.assertFalse((state_path / 'owner.json').exists())
                forwarding.cleanup()

    def test_interrupted_unverified_setup_refuses_to_delete_resources(self):
        with self.assertRaises(forwarding.Blocked):
            forwarding.verify({'targets': [], 'owned': None}, [{'table': {'name': 'mosaic_nat'}}])


if __name__ == '__main__':
    unittest.main()
