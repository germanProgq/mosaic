import argparse
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time

import baseline
import dns
import egress


def inventory(namespace, inode):
    current = Path('/proc/self/ns/net').stat().st_ino
    if current != inode or os.environ.get('MOSAIC_NAMESPACE') != namespace:
        raise baseline.Failed('test left its recorded namespace')
    if Path('/etc/resolv.conf').read_text() != 'nameserver 1.1.1.1\noptions timeout:2 attempts:1 ndots:1\n':
        raise baseline.Failed('private resolver changed')
    links = json.loads(baseline.run(['ip', '-j', 'link', 'show']))
    names = {link['ifname'] for link in links}
    if 'lo' not in names or len(names) > 2 or any(name != 'lo' and not name.startswith('mosaic') for name in names):
        raise baseline.Failed('namespace has an alternate interface')
    for family in ('-4', '-6'):
        routes = json.loads(baseline.run(['ip', '-j', family, 'route', 'show', 'table', 'all']))
        for route in routes:
            if route.get('dev') not in names or any(key in route for key in ('gateway', 'nexthops', 'nhid', 'encap', 'via')):
                raise baseline.Failed('namespace has an alternate route')
            if family == '-6' and (route.get('dev') != 'lo' or route.get('dst') not in ('::1', '::1/128')):
                raise baseline.Failed('namespace has an IPv6 path')
            if route.get('dst') == 'default' and not route.get('dev', '').startswith('mosaic'):
                raise baseline.Failed('namespace default bypasses TUN')


def failed_request(kind, code):
    allowed = {'resolver': {2}, 'dns.udp': {9}, 'dns.tcp': {9}, 'https.egress': {6, 7, 28}, 'https.pinned': {7, 28}}
    if code not in allowed[kind]:
        raise baseline.Failed('outage request succeeded or failed for an unexpected reason')


def request(command, seconds):
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=errors, timeout=seconds)
        except subprocess.TimeoutExpired:
            raise baseline.Failed('test process exceeded its own network deadline') from None
        output.seek(0)
        return result.returncode, output.read(1048577)


def main():
    parser = argparse.ArgumentParser(description='Run inside isolated-exec; verify normal requests, wait for relay stop, then require twenty seconds without DNS or HTTPS escape')
    parser.add_argument('--namespace', default='mosaic-test')
    parser.add_argument('--ipify-ip', required=True)
    parser.add_argument('--relay-egress', required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    report = {'scope': 'namespace-outage', 'status': 'FAIL', 'assertions': []}
    try:
        if sys.platform != 'linux' or os.geteuid() == 0:
            raise baseline.Blocked('run as the namespace test user through isolated-exec')
        if not args.namespace.startswith('mosaic-') or '/' in args.namespace or args.report.exists():
            raise baseline.Blocked('Mosaic namespace and new report path required')
        inode = int(os.environ['MOSAIC_NAMESPACE_INODE'])
        inventory(args.namespace, inode)
        relay = egress.public_address(args.relay_egress)
        pin = egress.public_address(args.ipify_ip)
        resource.setrlimit(resource.RLIMIT_FSIZE, (2097152, 2097152))
        commands = [(kind, command[5:], seconds) for kind, command, seconds in dns.commands(Path('/unused'), args.namespace)]
        for kind, command, seconds in commands:
            code, body = request(command, seconds)
            if code:
                raise baseline.Failed('healthy request failed before outage')
            dns.answer(kind, body, relay)
        pinned = ['curl', '-q', '--noproxy', '*', '-4fsS', '--max-time', '2', '--max-filesize', '1024', '--limit-rate', '40k', '--resolve', f'api.ipify.org:443:{pin}', 'https://api.ipify.org/']
        code, body = request(pinned, 4)
        if code:
            raise baseline.Failed('pinned HTTPS failed before outage')
        dns.answer('https.egress', body, relay)
        checks = [(kind, command) for kind, command, _ in commands if kind != 'https.example']
        for kind, command in checks:
            if kind == 'https.egress':
                command[command.index('--max-time') + 1] = '2'
                command[command.index('--connect-timeout') + 1] = '2'
        checks.append(('https.pinned', pinned))
        print('Ready. Stop only the recorded Mosaic relay within ten seconds and keep it stopped until this test finishes.', flush=True)
        time.sleep(10)
        start = time.monotonic()
        cycle = 0
        while time.monotonic() - start < 20:
            inventory(args.namespace, inode)
            for kind, command in checks:
                code, _ = request(command, 6)
                failed_request(kind, code)
                report['assertions'].append({'id': kind, 'cycle': cycle + 1, 'status': 'PASS', 'exit_code': code})
            cycle += 1
        inventory(args.namespace, inode)
        report.update(status='PASS', seconds=round(time.monotonic() - start, 3))
    except (baseline.Blocked, baseline.Failed, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['detail'] = str(error) if isinstance(error, (baseline.Blocked, baseline.Failed)) else 'namespace outage check failed'
    try:
        baseline.write_new(args.report, report)
    except OSError:
        print('FAIL report.write: cannot write new report', file=sys.stderr)
        return 1
    print(json.dumps(report))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
