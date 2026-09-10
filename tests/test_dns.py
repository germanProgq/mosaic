from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools/network'))
import baseline
import dns
import isolation
import no_escape


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.links = [{'ifname': 'lo', 'mtu': 65536}, {'ifname': 'mosaic0', 'mtu': 1100}]
        self.routes = [{'dst': '10.77.0.0/30', 'dev': 'mosaic0'}, {'dst': 'default', 'dev': 'mosaic0', 'protocol': 'static'}, {'dst': '10.77.0.2', 'dev': 'mosaic0', 'type': 'local', 'table': 'local'}, {'dst': '127.0.0.0/8', 'dev': 'lo', 'type': 'local', 'table': 'local'}]
        self.rules = [{'priority': priority, 'src': 'all', 'table': table} for priority, table in [(0, 'local'), (32766, 'main'), (32767, 'default')]]

    def check(self, ready=True, routes6=None):
        isolation.routing(self.links, self.routes, routes6 or [], self.rules, '10.77.0.0/30', ready)

    def test_only_tun_default_and_local_routes_are_accepted(self):
        self.check()
        self.check(routes6=[{'dst': '::1', 'dev': 'lo', 'type': 'local', 'table': 'local'}])

    def test_alternate_interfaces_routes_gateways_and_rules_fail(self):
        for extra in [{'dst': 'default', 'dev': 'eth0'}, {'dst': '1.1.1.1', 'dev': 'lo'}, {'dst': 'default', 'dev': 'mosaic0', 'gateway': '10.77.0.1'}, {'dst': 'default', 'dev': 'mosaic0', 'nexthops': []}, {'dst': 'default', 'dev': 'mosaic0', 'table': 100}, {'dst': '1.1.1.1', 'type': 'local', 'dev': 'mosaic0', 'table': 'local'}]:
            with self.subTest(route=extra):
                self.routes.append(extra)
                with self.assertRaises(baseline.Failed):
                    self.check()
                self.routes.pop()
        self.links.append({'ifname': 'eth0', 'mtu': 1500})
        with self.assertRaises(baseline.Failed):
            self.check()
        self.links.pop()
        self.rules.insert(1, {'priority': 1, 'table': 100})
        with self.assertRaises(baseline.Failed):
            self.check()

    def test_missing_tun_default_and_external_ipv6_fail(self):
        for route in [{'dst': 'default', 'dev': 'mosaic0'}, {'dst': 'fe80::/64', 'dev': 'mosaic0'}]:
            with self.assertRaises(baseline.Failed):
                self.check(routes6=[route])
        self.routes.pop(1)
        with self.assertRaises(baseline.Failed):
            self.check()
        self.check(ready=False)
        self.routes = []
        self.links.pop()
        self.check(ready=False)
        with self.assertRaises(baseline.Failed):
            self.check()


class DnsTests(unittest.TestCase):
    def test_commands_enter_private_resolver_and_bound_each_request(self):
        commands = dns.commands(Path('/tmp/mosaic-client'), 'mosaic-test')
        self.assertEqual(len(commands), 5)
        for kind, command, seconds in commands:
            self.assertEqual(command[:5], ['/tmp/mosaic-client', 'isolated-exec', '--namespace', 'mosaic-test', '--'])
            self.assertLessEqual(seconds, 25)
            self.assertNotIn('--resolve', command)
            self.assertNotIn('--insecure', command)
            if kind.startswith('https.'):
                for flag in ['--max-time', '--max-filesize', '--limit-rate', '--noproxy']:
                    self.assertIn(flag, command)
        self.assertIn('+ignore', commands[1][1])
        self.assertIn('+tcp', commands[2][1])

    def test_success_requires_actual_answers_and_measured_egress(self):
        dns.answer('resolver', b'93.184.215.14 STREAM example.com\n', '1.1.1.1')
        good = b';; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\nexample.com. 300 IN A 93.184.215.14\n'
        for kind in ('dns.udp', 'dns.tcp'):
            dns.answer(kind, good, '1.1.1.1')
            for bad in (b'', good.replace(b'NOERROR', b'SERVFAIL'), good.replace(b'93.184.215.14', b'127.0.0.1')):
                with self.assertRaises(baseline.Failed):
                    dns.answer(kind, bad, '1.1.1.1')
        dns.answer('https.egress', b'1.1.1.1\n', '1.1.1.1')
        with self.assertRaises(baseline.Failed):
            dns.answer('https.egress', b'8.8.8.8', '1.1.1.1')

    def test_outage_does_not_accept_tool_errors_or_unexpected_network_responses(self):
        for kind, code in [('resolver', 2), ('dns.udp', 9), ('dns.tcp', 9), ('https.egress', 6), ('https.pinned', 28)]:
            no_escape.failed_request(kind, code)
            for bad in (0, 1, 126, 127, -9):
                with self.assertRaises(baseline.Failed):
                    no_escape.failed_request(kind, bad)
        with self.assertRaises(baseline.Failed):
            no_escape.failed_request('https.pinned', 6)

    def test_outage_rejects_wrong_namespace_before_running_requests(self):
        with patch.object(no_escape.Path, 'stat') as metadata, patch.dict(no_escape.os.environ, {'MOSAIC_NAMESPACE': 'mosaic-test'}), patch.object(baseline, 'run') as run:
            metadata.return_value.st_ino = 123
            with self.assertRaises(baseline.Failed):
                no_escape.inventory('mosaic-test', 456)
            with self.assertRaises(baseline.Failed):
                no_escape.inventory('mosaic-other', 123)
            run.assert_not_called()

    def test_guard_failure_cancels_the_exact_running_probe(self):
        with patch.object(dns.subprocess, 'Popen') as start:
            child = start.return_value
            child.poll.return_value = None
            with self.assertRaises(baseline.Failed):
                dns.probe(['/tmp/mosaic-client'], 1, lambda: (_ for _ in ()).throw(baseline.Failed('guard stopped')))
            child.kill.assert_called_once()
            child.wait.assert_called_once()


if __name__ == '__main__':
    unittest.main()
