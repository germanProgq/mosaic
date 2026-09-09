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

if __name__=='__main__':unittest.main()
