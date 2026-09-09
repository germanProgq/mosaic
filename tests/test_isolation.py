import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/network"))
import baseline
import isolation


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.owner = {"namespace": "mosaic-test", "namespace_inode": 123, "socket_inode": 456,
                      "socket_uid": 1000, "socket_port": 45000, "parent": {"pid": 12, "start": "20"},
                      "worker": {"pid": 13, "start": "21"}}
        self.observed = {"namespace_inode": 123, "socket_inode": 456, "socket_uid": 1000,
                         "socket_port": 45000, "parent_start": "20", "worker_start": "21"}
        self.listener = 'udp UNCONN RUNTIME_QUEUE RUNTIME_QUEUE 0.0.0.0:45000 0.0.0.0:* users:(("mosaic-client",pid=13,fd=3))'
        self.state = {"namespaces": ["vpn", "mosaic-test"], "listeners": ["existing VPN listener", self.listener], "routes": ["original"]}

    def test_only_exact_owned_resources_are_removed(self):
        result = isolation.filter_state(copy.deepcopy(self.state), self.owner, self.observed)
        self.assertEqual(result, {"namespaces": ["vpn"], "listeners": ["existing VPN listener"], "routes": ["original"]})

    def test_changed_owner_socket_and_namespace_are_rejected(self):
        for key in self.observed:
            observed = dict(self.observed)
            observed[key] = "changed"
            with self.subTest(key=key), self.assertRaises(baseline.Failed):
                isolation.filter_state(copy.deepcopy(self.state), self.owner, observed)

    def test_other_ports_protocols_and_shared_sockets_are_rejected(self):
        for listener in [self.listener.replace("45000", "45001"), self.listener.replace("udp", "tcp"), self.listener.replace("0.0.0.0:45000", "[::]:45000"), self.listener + ',("other",pid=14,fd=4)']:
            state = copy.deepcopy(self.state)
            state["listeners"][-1] = listener
            with self.assertRaises(baseline.Failed):
                isolation.filter_state(state, self.owner, self.observed)

    def test_multiple_worker_sockets_are_rejected(self):
        self.state["listeners"].append(self.listener)
        with self.assertRaises(baseline.Failed):
            isolation.filter_state(self.state, self.owner, self.observed)

    def test_missing_namespace_is_rejected(self):
        self.state["namespaces"] = ["vpn"]
        with self.assertRaises(baseline.Failed):
            isolation.filter_state(self.state, self.owner, self.observed)


if __name__ == "__main__":
    unittest.main()
