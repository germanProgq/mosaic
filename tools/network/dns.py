import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

import baseline
import egress
import isolation


def commands(client, namespace):
    prefix = [str(client), 'isolated-exec', '--namespace', namespace, '--']
    curl = ['curl', '-q', '--noproxy', '*', '-4', '--fail', '--silent', '--show-error', '--proto', '=https', '--connect-timeout', '5', '--max-time', '20', '--max-filesize', '1048576', '--limit-rate', '40k']
    dig = ['dig', '-r', '@1.1.1.1', 'example.com', 'A', '+time=2', '+tries=1', '+noall', '+comments', '+answer']
    return [
        ('resolver', prefix + ['getent', 'ahostsv4', 'example.com'], 6),
        ('dns.udp', prefix + [*dig, '+notcp', '+ignore'], 6),
        ('dns.tcp', prefix + [*dig, '+tcp'], 6),
        ('https.example', prefix + [*curl, 'https://example.com/'], 25),
        ('https.egress', prefix + [*curl, 'https://api.ipify.org/'], 25),
    ]


def answer(kind, data, relay):
    text = data.decode()
    if kind == 'resolver':
        addresses = [line.split()[0] for line in text.splitlines() if line.split()]
        if not addresses or any(not ipaddress.IPv4Address(value).is_global for value in addresses):
            raise baseline.Failed('hostname lookup has no public IPv4 answer')
    elif kind.startswith('dns.'):
        addresses = re.findall(r'^\S+\s+\d+\s+IN\s+A\s+(\S+)\s*$', text, re.MULTILINE)
        if 'status: NOERROR,' not in text or not addresses or any(not ipaddress.IPv4Address(value).is_global for value in addresses):
            raise baseline.Failed('DNS response has no successful public IPv4 answer')
    elif kind == 'https.egress' and text.strip() != relay:
        raise baseline.Failed('namespace HTTPS differs from measured relay egress')
    elif kind == 'https.example' and not data:
        raise baseline.Failed('empty HTTPS response')


def probe(command, seconds, check):
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        wrapper = [sys.executable, '-c', 'import os,resource,sys; resource.setrlimit(resource.RLIMIT_FSIZE,(2097152,2097152)); os.execv(sys.argv[1],sys.argv[1:])']
        child = subprocess.Popen([*wrapper, *command], stdin=subprocess.DEVNULL, stdout=output, stderr=errors)
        start = time.monotonic()
        try:
            while child.poll() is None:
                check()
                if time.monotonic() - start >= seconds:
                    raise baseline.Failed('namespace request exceeded its deadline')
                time.sleep(0.1)
            if child.returncode:
                raise baseline.Failed('namespace request failed')
            check()
            output.seek(0)
            return output.read(1048577)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()


def main():
    parser = argparse.ArgumentParser(description='Check fresh namespace DNS and HTTPS through TUN with the VPN guard active')
    parser.add_argument('--client', required=True, type=Path)
    parser.add_argument('--namespace', default='mosaic-test')
    parser.add_argument('--subnet', default='10.77.0.0/30')
    parser.add_argument('--relay-egress', required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    report = {'scope': 'namespace-dns', 'status': 'FAIL', 'assertions': []}
    try:
        if sys.platform != 'linux' or os.geteuid() != 0 or not re.fullmatch(r'mosaic-[A-Za-z0-9_-]{1,8}', args.namespace):
            raise baseline.Blocked('owned Linux namespace and root required')
        if args.report.exists():
            raise baseline.Blocked('report path must be new')
        client = args.client.resolve(strict=True)
        relay = egress.public_address(args.relay_egress)
        directory = Path('/run') / args.namespace
        owner = isolation.owner_load(directory)
        if owner.get('worker_mount_inode') is None or (directory / 'tunnel.ready').read_bytes() != b'ready\n':
            raise baseline.Blocked('private namespace DNS and routing are not ready')
        def check():
            egress.guard(directory, owner)
        check()
        original = isolation.namespace_inventory(owner, args.subnet, directory)
        resolver = Path('/etc/resolv.conf').read_bytes()
        for attempt in range(10):
            for kind, command, seconds in commands(client, args.namespace):
                body = probe(command, seconds, check)
                answer(kind, body, relay)
                report['assertions'].append({'id': kind, 'attempt': attempt + 1, 'status': 'PASS', 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()})
            if isolation.namespace_inventory(owner, args.subnet, directory) != original:
                raise baseline.Failed('namespace routing changed during DNS checks')
            if Path('/etc/resolv.conf').read_bytes() != resolver:
                raise baseline.Failed('host resolver changed during DNS checks')
        report['status'] = 'PASS'
    except (baseline.Blocked, baseline.Failed, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['detail'] = str(error) if isinstance(error, (baseline.Blocked, baseline.Failed)) else 'namespace DNS check failed'
    try:
        baseline.write_new(args.report, report)
    except OSError:
        print('FAIL report.write: cannot write new report', file=sys.stderr)
        return 1
    print(json.dumps(report))
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
