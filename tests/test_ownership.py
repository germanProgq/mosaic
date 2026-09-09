import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('owned',Path(__file__).resolve().parents[1]/'tools/network/ownership.py')
owned=importlib.util.module_from_spec(spec);spec.loader.exec_module(owned)

class OwnedSocketsTests(unittest.TestCase):
    def test_only_verified_owned_udp_is_excluded(self):
        relay='udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("mosaic-relay",pid=123,fd=8))'
        xray='tcp LISTEN 0 512 *:443 *:* users:(("xray",pid=999,fd=8))'
        kept,removed=owned.filter_listeners([relay,xray],{123:{'role':'relay','pid':123}})
        self.assertEqual(kept,[xray]);self.assertEqual(removed,[{'pid':123,'role':'relay','port':443}])
    def test_unowned_udp_stays_visible(self):
        line='udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("other",pid=999,fd=8))'
        self.assertEqual(owned.filter_listeners([line],{123:{'role':'relay'}}),([line],[]))
    def test_owned_tcp_or_wrong_port_is_rejected(self):
        for protocol,port in [('tcp',443),('udp',8443)]:
            line=f'{protocol} UNCONN 0 0 0.0.0.0:{port} 0.0.0.0:* users:(("mosaic-relay",pid=123,fd=8))'
            with self.assertRaises(AssertionError):owned.filter_listeners([line],{123:{'role':'relay'}})
    def test_shared_socket_with_unrelated_pid_is_rejected(self):
        line='udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:* users:(("mosaic-relay",pid=123,fd=8),("other",pid=999,fd=9))'
        with self.assertRaises(AssertionError):owned.filter_listeners([line],{123:{'role':'relay'}})

    def test_process_disappearance_during_child_scan_is_expected(self):
        from unittest.mock import Mock, patch
        process = Mock()
        process.name = '123'
        process.__truediv__ = Mock(return_value=Mock())
        process.__truediv__.return_value.read_text.side_effect = ProcessLookupError('process exited')
        root = Mock()
        root.iterdir.return_value = [process]
        with patch.object(owned, 'Path', return_value=root):
            self.assertEqual(owned.owned_children({}, Path('/run/test')), {})



class TunnelStateTests(unittest.TestCase):
    def state(self):
        return {'links': [{'ifname': 'eth0'}, {'ifname': 'mosaic0', 'mtu': 1100, 'link_type': 'none'}], 'addresses': [{'ifname': 'eth0'}, {'ifname': 'mosaic0', 'addr_info': [{'family': 'inet', 'local': '10.77.0.1', 'prefixlen': 30}]}], 'routes4': [{'dst': 'default', 'dev': 'eth0'}, {'dst': '10.77.0.0/30', 'dev': 'mosaic0', 'protocol': 'kernel', 'prefsrc': '10.77.0.1'}], 'routes6': [], 'qdiscs': [{'dev': 'eth0'}, {'dev': 'mosaic0'}]}

    def test_only_connected_owned_subnet_is_excluded(self):
        state = self.state()
        owned.filter_tun_state(state, 'mosaic0', '10.77.0.1', '10.77.0.2')
        self.assertEqual(state['links'], [{'ifname': 'eth0'}])
        self.assertEqual(state['routes4'], [{'dst': 'default', 'dev': 'eth0'}])

    def test_owned_setup_is_allowed_only_while_down(self):
        state = self.state()
        state['links'][1].update(mtu=1500, flags=['POINTOPOINT'])
        state['addresses'][1]['addr_info'] = []
        state['routes4'] = state['routes4'][:1]
        owned.filter_tun_state(state, 'mosaic0', '10.77.0.1', '10.77.0.2')
        state = self.state()
        state['links'][1].update(mtu=1500, flags=['UP'])
        with self.assertRaises(AssertionError):
            owned.filter_tun_state(state, 'mosaic0', '10.77.0.1', '10.77.0.2')

    def test_external_route_and_wrong_address_are_rejected(self):
        state = self.state()
        state['routes4'].append({'dst': 'default', 'dev': 'mosaic0', 'protocol': 'kernel', 'prefsrc': '10.77.0.1'})
        with self.assertRaises(AssertionError):
            owned.filter_tun_state(state, 'mosaic0', '10.77.0.1', '10.77.0.2')
        state = self.state()
        state['addresses'][1]['addr_info'][0]['local'] = '10.77.0.2'
        with self.assertRaises(AssertionError):
            owned.filter_tun_state(state, 'mosaic0', '10.77.0.1', '10.77.0.2')

class NamespaceOwnershipTests(unittest.TestCase):
    def test_dead_launcher_retains_only_its_recorded_namespace(self):
        import json
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            directory = root / 'jobs-root'
            (directory / 'jobs').mkdir(parents=True)
            (root / 'run/mosaic-test').mkdir(parents=True)
            (root / 'run/netns').mkdir()
            mount = root / 'run/netns/mosaic-test'
            mount.touch()
            job = {'pid': 2147483647, 'start_ticks': '123', 'role': 'isolated', 'binary': 'mosaic-client'}
            record = directory / 'jobs/isolated.owner.json'
            record.write_text(json.dumps(job))
            owner = {'parent': {'pid': job['pid'], 'start': '123'}, 'namespace': 'mosaic-test', 'namespace_inode': mount.stat().st_ino}
            (root / 'run/mosaic-test/owner.json').write_text(json.dumps(owner))
            spec = {'directory': str(directory), 'binaries': {'mosaic-client': 'verified'}, 'tunnel': {'role': 'client', 'namespace': 'mosaic-test'}}
            def path(value):
                return root / str(value).lstrip('/') if str(value).split('/')[1] in ('run', 'proc') else Path(value)
            with patch.object(owned, 'Path', path):
                state = {'namespaces': ['mosaic-test', 'unrelated']}
                owned.exclude_tunnel_resources(state, spec, {})
                self.assertEqual(state['namespaces'], ['unrelated'])
                (root / 'run/mosaic-test/owner.json').unlink()
                mount.unlink()
                state = {'namespaces': ['mosaic-test', 'unrelated']}
                owned.exclude_tunnel_resources(state, spec, {})
                self.assertEqual(state['namespaces'], ['unrelated'])
                with self.assertRaises(AssertionError):
                    owned.exclude_tunnel_resources({'namespaces': ['mosaic-test']}, spec, {})
                (root / 'run/mosaic-test/owner.json').write_text(json.dumps(owner))
                mount.touch()
                job['start_ticks'] = '124'
                record.write_text(json.dumps(job))
                with self.assertRaises(AssertionError):
                    owned.exclude_tunnel_resources({'namespaces': ['mosaic-test']}, spec, {})


class StableInventoryTests(unittest.TestCase):
    def test_owned_transition_repeats_the_complete_inventory(self):
        from unittest.mock import Mock, patch
        read = Mock(side_effect=[AssertionError('closed TUN'), {'routes': 'unchanged'}])
        with patch.object(owned, 'runtime_signature', side_effect=['active', 'absent', 'absent', 'absent']):
            self.assertEqual(owned.stable_inventory({}, read), {'routes': 'unchanged'})
        self.assertEqual(read.call_count, 2)

    def test_exited_owned_process_repeats_inventory_without_hiding_other_sockets(self):
        from unittest.mock import Mock, patch
        job = {'pid': 123, 'start_ticks': '456', 'binary': 'tunnel_probe', 'role': 'client'}
        read = Mock(side_effect=[{'listeners': ['stale test socket', 'unrelated']}, {'listeners': ['unrelated']}])
        with patch.object(owned, 'owned_processes', side_effect=[{123: job}, {}, {}, {}]), patch.object(owned, 'tunnel_signature', return_value=None):
            self.assertEqual(owned.stable_inventory({'owned_jobs': {'directory': '/run/test'}}, read), {'listeners': ['unrelated']})
        self.assertEqual(read.call_count, 2)

    def test_short_probe_can_start_and_exit_before_a_stable_inventory(self):
        from unittest.mock import Mock, patch
        read = Mock(side_effect=[{'listeners': ['unrelated']}, {'listeners': ['exited probe', 'unrelated']}, {'listeners': ['unrelated']}])
        with patch.object(owned, 'runtime_signature', side_effect=['absent', 'active', 'active', 'absent', 'absent', 'absent']):
            self.assertEqual(owned.stable_inventory({}, read), {'listeners': ['unrelated']})
        self.assertEqual(read.call_count, 3)

    def test_unexplained_error_and_repeated_transitions_fail(self):
        from unittest.mock import Mock, patch
        with patch.object(owned, 'runtime_signature', return_value='active'):
            with self.assertRaises(AssertionError):
                owned.stable_inventory({}, Mock(side_effect=AssertionError('wrong route')))
        with patch.object(owned, 'runtime_signature', side_effect=['active', 'absent', 'active', 'absent', 'active', 'absent']):
            with self.assertRaises(RuntimeError):
                owned.stable_inventory({}, lambda: {})


if __name__=='__main__':unittest.main()
