import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('f2b', Path(__file__).resolve().parents[1] / 'tools/network/fail2ban.py')
f2b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f2b)

class Fail2BanTests(unittest.TestCase):
    def fixture(self):
        return {'nftables': [
            {'set': {'family': 'inet', 'table': 'f2b-table', 'name': 'addr-set-sshd', 'type': 'ipv4_addr', 'elem': ['192.0.2.1']}},
            {'rule': {'family': 'inet', 'table': 'f2b-table', 'chain': 'f2b-chain', 'expr': [
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': 22}},
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': '@addr-set-sshd'}},
                {'reject': {'type': 'icmp', 'expr': 'port-unreachable'}}]}}]}
    def test_verified_runtime_addition_preserves_original_evidence(self):
        a = self.fixture(); original = copy.deepcopy(a); b = copy.deepcopy(a)
        b['nftables'][0]['set']['elem'].append('192.0.2.2')
        reconciled, changes = f2b.reconcile_sshd_bans(a, b, ['192.0.2.1', '192.0.2.2'])
        self.assertEqual(reconciled, b); self.assertEqual(a, original); self.assertEqual(changes[0]['added'], 1)
    def test_rule_changes_never_allowed(self):
        a = self.fixture(); b = copy.deepcopy(a)
        b['nftables'][1]['rule']['expr'][0]['match']['right'] = 443
        with self.assertRaises(ValueError): f2b.reconcile_sshd_bans(a, b, ['192.0.2.1'])
    def test_unverified_bans_and_wrong_jail_are_rejected(self):
        a = self.fixture(); b = copy.deepcopy(a); b['nftables'][0]['set']['elem'].append('192.0.2.2')
        with self.assertRaises(ValueError): f2b.reconcile_sshd_bans(a, b, ['192.0.2.1'])
        for value in [a, b]: value['nftables'][0]['set']['name'] = 'other-jail'
        with self.assertRaises(ValueError): f2b.reconcile_sshd_bans(a, b, ['192.0.2.1', '192.0.2.2'])
    def test_non_ssh_rule_cannot_receive_exception(self):
        a = self.fixture(); a['nftables'][1]['rule']['expr'][0]['match']['right'] = 443
        b = copy.deepcopy(a); b['nftables'][0]['set']['elem'].append('192.0.2.2')
        with self.assertRaises(ValueError): f2b.reconcile_sshd_bans(a, b, ['192.0.2.1', '192.0.2.2'])

if __name__ == '__main__': unittest.main()
