import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('monitor', Path(__file__).resolve().parents[1] / 'tools/xray/remote/monitor.py')
monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(monitor)


class XrayUdpTests(unittest.TestCase):
    def test_only_identified_ephemeral_udp_is_runtime(self):
        line = 'udp UNCONN 0 0 *:40000 *:* users:(("xray",pid=123,fd=20))'
        kept, outbound = monitor.filter_outbound_udp([line], 123, {443, 8443}, (32768, 60999))
        self.assertEqual(kept, [])
        self.assertEqual(outbound, [{'pid': 123, 'port': 40000}])

    def test_other_sockets_remain_strict(self):
        line = 'udp UNCONN 0 0 *:40000 *:* users:(("xray",pid=123,fd=20))'
        for changed in (line.replace('pid=123', 'pid=124'), line.replace(':40000', ':443'), line.replace(':40000', ':32000'), line.replace('udp UNCONN', 'tcp LISTEN'), line.replace('*:40000', '127.0.0.1:40000'), line + ' pid=456'):
            self.assertEqual(monitor.filter_outbound_udp([changed], 123, {443, 8443}, (32768, 60999)), ([changed], []))
        self.assertEqual(monitor.filter_outbound_udp([line], 123, {40000}, (32768, 60999)), ([line], []))
        self.assertEqual(monitor.filter_outbound_udp([line], 123, None, (32768, 60999)), ([line], []))

    def test_unknown_or_udp_inbounds_disable_classification(self):
        config = {'inbounds': [{'protocol': 'vless', 'port': 443}], 'outbounds': [{'protocol': 'freedom'}]}
        self.assertEqual(monitor.tcp_inbound_ports(config), {443})
        self.assertIsNone(monitor.tcp_inbound_ports({**config, 'api': {}}))
        for inbound in ({'protocol': 'socks', 'port': 1080}, {'protocol': 'vless', 'port': '40000-41000'}, {'protocol': 'vless', 'port': 443, 'streamSettings': {'network': 'quic'}}):
            self.assertIsNone(monitor.tcp_inbound_ports({'inbounds': [inbound]}))
        self.assertIsNone(monitor.tcp_inbound_ports({'inbounds': []}))


class HostControlTests(unittest.TestCase):
    def test_verified_egress_and_request_duration_are_separate(self):
        ok, duration = monitor.control_result('ip=192.0.2.1\nloc=XX\n\n0.052123', 'cloudflare', '192.0.2.1')
        self.assertTrue(ok)
        self.assertAlmostEqual(duration, 52.123)
        self.assertEqual(monitor.control_result('192.0.2.2\n0.125', 'ipify', '192.0.2.1'), (False, 125))

    def test_missing_or_invalid_timing_cannot_pass(self):
        for value in ('192.0.2.1', '192.0.2.1\nnan', '192.0.2.1\n-1', '192.0.2.1\n4'):
            with self.assertRaises(ValueError):
                monitor.control_result(value, 'ipify', '192.0.2.1')


if __name__ == '__main__':
    unittest.main()
