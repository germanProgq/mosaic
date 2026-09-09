import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("baseline", Path(__file__).resolve().parents[1] / "tools/network/baseline.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)

class BaselineTests(unittest.TestCase):
    def test_counters_and_route_expiry_do_not_cause_drift(self):
        self.assertEqual(b.normalize({"mtu": 1500, "stats64": {"tx": 10}, "expires": 5}), b.normalize({"mtu": 1500, "stats64": {"tx": 20}, "expires": 4}))
        self.assertNotEqual(b.normalize({"mtu": 1500}), b.normalize({"mtu": 1100}))
        self.assertNotEqual(b.normalize({"gateway": "a"}), b.normalize({"gateway": "b"}))

    def test_firewall_order_preserved_counters_ignored(self):
        a = [{"rule": {"handle": 1, "expr": [{"counter": {"packets": 3, "bytes": 4}}, {"accept": None}]}}]
        c = [{"rule": {"handle": 9, "expr": [{"counter": {"packets": 7, "bytes": 8}}, {"accept": None}]}}]
        self.assertEqual(b.nft_normalize(a), b.nft_normalize(c))
        self.assertNotEqual(b.nft_normalize([{"accept": None}, {"drop": None}]), b.nft_normalize([{"drop": None}, {"accept": None}]))

    def test_latency_requires_both_thresholds(self):
        self.assertFalse(b.degraded(10, [15] * 12))
        self.assertFalse(b.degraded(100, [115] * 12))
        self.assertTrue(b.degraded(100, [121] * 12))
        self.assertTrue(b.degraded(10, [21] * 12))

    def test_refuses_existing_namespace_and_subnet(self):
        p = {"namespace": "mosaic-test", "tunnel_subnet": "10.77.0.0/30"}
        state = {"namespaces": [], "links": [], "addresses": [], "routes4": [{"dst": "default"}]}
        b.collisions(p, state)
        state["namespaces"] = ["mosaic-test (id: 0)"]
        with self.assertRaises(b.Blocked): b.collisions(p, state)
        state["namespaces"] = []
        state["routes4"] = [{"dst": "10.0.0.0/8"}]
        with self.assertRaises(b.Blocked): b.collisions(p, state)

    def controlled_sample(self, results, states=None, baseline=None):
        p = {"probes": [{"id": "vpn_only"}]}
        state = {"mtu": 1500}
        with patch.object(b, "inventory", side_effect=states, return_value=(state, {})), \
             patch.object(b, "probes", side_effect=results), \
             patch.object(b.time, "sleep"), patch.object(b.time, "monotonic", return_value=0):
            return b.sample(p, state, 60, baseline)

    def test_monitor_aborts_after_two_failures(self):
        bad = {"vpn_only": {"ok": False, "ms": 1, "output_hash": None}}
        with self.assertRaisesRegex(b.Failed, "two consecutive"):
            self.controlled_sample([bad, bad])

    def test_single_failure_never_passes_v(self):
        good = {"vpn_only": {"ok": True, "ms": 10, "output_hash": None}}
        bad = {"vpn_only": {"ok": False, "ms": 1, "output_hash": None}}
        with self.assertRaisesRegex(b.Failed, "at least one"):
            self.controlled_sample([bad] + [good] * 11)

    def test_monitor_aborts_on_drift_and_egress_change(self):
        good = {"vpn_only": {"ok": True, "ms": 10, "output_hash": "new"}}
        with self.assertRaisesRegex(b.Failed, "configuration"):
            self.controlled_sample([], states=[({"mtu": 1100}, {})])
        baseline = {"medians_ms": {"vpn_only": 10}, "output_hashes": {"vpn_only": "old"}}
        with self.assertRaisesRegex(b.Failed, "output changed"):
            self.controlled_sample([good], baseline=baseline)

    def test_monitor_rejects_sustained_latency_and_accepts_healthy_samples(self):
        baseline = {"medians_ms": {"vpn_only": 100}, "output_hashes": {}}
        high = {"vpn_only": {"ok": True, "ms": 121, "output_hash": None}}
        with self.assertRaisesRegex(b.Failed, "latency"):
            self.controlled_sample([high] * 12, baseline=baseline)
        good = {"vpn_only": {"ok": True, "ms": 101, "output_hash": None}}
        self.assertEqual(self.controlled_sample([good] * 12, baseline=baseline)["samples_per_probe"], 12)

    def test_placeholder_policy_is_blocked(self):
        with self.assertRaises(b.Blocked):
            b.policy_load(Path(__file__).resolve().parents[1] / "configs/node-baseline.example.json")

if __name__ == "__main__": unittest.main()
