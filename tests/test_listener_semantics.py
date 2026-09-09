import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('baseline',Path(__file__).resolve().parents[1]/'tools/network/baseline.py')
baseline=importlib.util.module_from_spec(spec);spec.loader.exec_module(baseline)

class ListenerSemanticsTests(unittest.TestCase):
    def test_udp_queue_occupancy_is_runtime_state(self):
        a='udp UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("resolved",pid=10,fd=5))'
        b=a.replace('UNCONN 0 0','UNCONN 768 1024')
        self.assertEqual(baseline.listener_semantics(a),baseline.listener_semantics(b))
    def test_tcp_pending_accepts_are_runtime_but_backlog_is_semantic(self):
        a='tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=10,fd=5))'
        self.assertEqual(baseline.listener_semantics(a),baseline.listener_semantics(a.replace('LISTEN 0','LISTEN 1')))
        for b in [a.replace('4096','128'),a.replace(':22',':443'),a.replace('pid=10','pid=11')]:
            self.assertNotEqual(baseline.listener_semantics(a),baseline.listener_semantics(b))

if __name__=='__main__':unittest.main()
