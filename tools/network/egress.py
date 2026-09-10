import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import pwd
import subprocess
import sys
import tempfile
import time

import baseline
import isolation


def public_address(value):
    address = ipaddress.IPv4Address(value)
    if not address.is_global or address.is_multicast or str(address) == '168.63.129.16':
        raise baseline.Blocked('test destination must be public IPv4')
    return str(address)


def pinned(host, value):
    address = public_address(value)
    observed = {line.split()[0] for line in baseline.run(['getent', 'ahostsv4', host]).splitlines() if line.split()}
    if address not in observed:
        raise baseline.Blocked('pinned destination is not a current A record')
    return address


def guard(directory, owner):
    if isolation.owner_load(directory) != owner or Path(f"/run/netns/{owner['namespace']}").stat().st_ino != owner['namespace_inode']:
        raise baseline.Failed('namespace ownership changed')
    for name in ('parent', 'worker'):
        if isolation.identity(owner[name]['pid']) != owner[name]['start']:
            raise baseline.Failed('Mosaic process identity changed')
    ready = json.loads((directory / 'guard.ready').read_text())
    age = time.time() - ready['unix_time']
    if ready['status'] != 'PASS' or not 0 <= age <= 10:
        raise baseline.Failed('VPN preservation guard is not current')


def curl(namespace, host, address, uid, gid):
    return ['ip', 'netns', 'exec', namespace, 'setpriv', '--reuid', str(uid), '--regid', str(gid), '--clear-groups', 'curl', '-q', '--noproxy', '*', '-4', '--fail', '--silent', '--show-error', '--proto', '=https', '--connect-timeout', '5', '--max-time', '20', '--max-filesize', '1048576', '--limit-rate', '40k', '--resolve', f'{host}:443:{address}', f'https://{host}/']


def main():
    parser = argparse.ArgumentParser(description='Verify pinned HTTPS and relay egress through an owned Linux TUN namespace')
    parser.add_argument('--namespace', default='mosaic-test')
    parser.add_argument('--example-ip', required=True)
    parser.add_argument('--ipify-ip', required=True)
    parser.add_argument('--relay-egress', required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    report = {'scope': 'tun-egress', 'status': 'FAIL', 'assertions': []}
    routes = []
    owner = None
    try:
        if sys.platform != 'linux' or os.geteuid() != 0 or not re.fullmatch(r'mosaic-[A-Za-z0-9_-]{1,8}', args.namespace):
            raise baseline.Blocked('owned Linux namespace and root required')
        if args.report.exists():
            raise baseline.Blocked('report path must be new')
        directory = Path('/run') / args.namespace
        owner = isolation.owner_load(directory)
        uid = owner['socket_uid']
        if uid <= 0:
            raise baseline.Blocked('non-root test account required')
        gid = pwd.getpwuid(uid).pw_gid
        guard(directory, owner)
        links = json.loads(baseline.run(['ip', '-n', args.namespace, '-j', 'link', 'show']))
        devices = [link['ifname'] for link in links if link['ifname'] != 'lo']
        if len(devices) != 1 or not devices[0].startswith('mosaic'):
            raise baseline.Blocked('expected only loopback and Mosaic TUN')
        tun = devices[0]
        destinations = [('example.com', pinned('example.com', args.example_ip)), ('api.ipify.org', pinned('api.ipify.org', args.ipify_ip))]
        egress = public_address(args.relay_egress)
        original = json.loads(baseline.run(['ip', '-n', args.namespace, '-j', '-4', 'route', 'show', 'table', 'all']))
        defaults = [route for route in original if route['dst'] == 'default']
        if defaults and (len(defaults) != 1 or defaults[0].get('dev') != tun or 'gateway' in defaults[0]):
            raise baseline.Blocked('namespace default route must use only TUN')
        for address in (() if defaults else dict.fromkeys(address for _, address in destinations)):
            if any(route['dst'] in (address, address + '/32') for route in original):
                raise baseline.Blocked('test route already exists')
            baseline.run(['ip', '-n', args.namespace, 'route', 'add', address + '/32', 'dev', tun, 'proto', 'static'])
            routes.append(address)
        with tempfile.TemporaryDirectory(prefix='mosaic-egress-') as temporary:
            for host, address in destinations:
                for attempt in range(10):
                    guard(directory, owner)
                    output = Path(temporary) / 'response'
                    with output.open('wb') as body_file:
                        subprocess.run(curl(args.namespace, host, address, uid, gid), check=True, timeout=25, stdout=body_file, stderr=subprocess.PIPE)
                    guard(directory, owner)
                    body = output.read_bytes()
                    if host == 'api.ipify.org' and body.decode().strip() != egress:
                        raise baseline.Failed('TUN egress differs from measured relay egress')
                    report['assertions'].append({'id': f'{host}.{attempt + 1}', 'status': 'PASS', 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()})
        report['status'] = 'PASS'
    except (baseline.Blocked, baseline.Failed, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['detail'] = str(error) if isinstance(error, (baseline.Blocked, baseline.Failed)) else 'TUN egress check failed'
    finally:
        try:
            if routes:
                if Path(f'/run/netns/{args.namespace}').stat().st_ino != owner['namespace_inode']:
                    raise baseline.Failed('namespace changed before route cleanup')
                for address in routes:
                    baseline.run(['ip', '-n', args.namespace, 'route', 'del', address + '/32', 'dev', tun, 'proto', 'static'])
                guard(directory, owner)
        except (OSError, ValueError, KeyError, baseline.Blocked, baseline.Failed):
            report['status'] = 'FAIL'
            report['cleanup'] = 'route cleanup or preservation verification failed; inspect owned namespace'
    try:
        baseline.write_new(args.report, report)
    except OSError:
        print('FAIL report.write: cannot write new report', file=sys.stderr)
        return 1
    print(json.dumps(report))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
