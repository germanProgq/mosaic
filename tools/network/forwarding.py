import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

STATE = Path('/run/mosaic-forwarding')
FORWARDING = Path('/proc/sys/net/ipv4/ip_forward')


class Blocked(Exception):
    pass


def run(args, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=10)
    if result.returncode:
        raise Blocked('network command failed')
    return result.stdout


def inventory():
    return json.loads(run(['nft', '-j', '-a', 'list', 'ruleset']))['nftables']


def clean(value, handles=False):
    if isinstance(value, dict):
        omitted = ('index', 'position', 'packets', 'bytes', 'metainfo') + (() if handles else ('handle',))
        return {key: ({} if key == 'counter' else clean(item, handles)) for key, item in value.items() if key not in omitted}
    if isinstance(value, list):
        return [clean(item, handles) for item in value]
    return value


def fingerprint(items, handles=False):
    return hashlib.sha256(json.dumps([clean(item, handles) for item in items if 'metainfo' not in item], sort_keys=True).encode()).hexdigest()


def owned(item, targets):
    value = next(iter(item.values()))
    if not isinstance(value, dict):
        return False
    if value.get('table', value.get('name')) in ('mosaic_forward', 'mosaic_nat'):
        return True
    target = (value.get('family'), value.get('table'))
    tables = {(entry['family'], entry['table']) for entry in targets}
    if target not in tables:
        return False
    if value.get('chain', value.get('name')) == 'mosaic_egress':
        return True
    return any(expr.get('jump', {}).get('target') == 'mosaic_egress' for expr in value.get('expr', []))


def targets_for(items):
    targets = []
    for item in items:
        for value in item.values():
            if isinstance(value, dict) and (value.get('name') in ('mosaic_forward', 'mosaic_nat', 'mosaic_egress') or value.get('table') in ('mosaic_forward', 'mosaic_nat')):
                raise Blocked('Mosaic firewall name already exists without ownership')
        chain = item.get('chain', {})
        if chain.get('hook') == 'forward' and chain.get('family') in ('ip', 'inet'):
            if chain.get('type') != 'filter':
                raise Blocked('unsupported forwarding chain')
            for key in ('table', 'name'):
                if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', chain[key]):
                    raise Blocked('unsupported firewall identifier')
            targets.append({'family': chain['family'], 'table': chain['table'], 'chain': chain['name']})
    return targets


def accepts(tun, wan, client):
    return [f'iifname "{tun}" oifname "{wan}" ip saddr {client} counter accept', f'iifname "{wan}" oifname "{tun}" ip daddr {client} ct state established,related counter accept']


def rules(tun, wan, client, targets):
    allowed = accepts(tun, wan, client)
    lines = ['create table inet mosaic_forward', 'add chain inet mosaic_forward forward { type filter hook forward priority -10; policy accept; }', f'add rule inet mosaic_forward forward iifname "{tun}" ip saddr != {client} counter drop']
    lines += [f'add rule inet mosaic_forward forward {rule}' for rule in allowed]
    lines += [f'add rule inet mosaic_forward forward iifname "{tun}" counter drop', f'add rule inet mosaic_forward forward oifname "{tun}" counter drop', 'create table ip mosaic_nat', 'add chain ip mosaic_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }', f'add rule ip mosaic_nat postrouting iifname "{tun}" oifname "{wan}" ip saddr {client} counter masquerade']
    tables = sorted({(entry['family'], entry['table']) for entry in targets})
    for family, table in tables:
        lines.append(f'add chain {family} {table} mosaic_egress')
        lines += [f'add rule {family} {table} mosaic_egress {rule}' for rule in allowed]
    for entry in targets:
        lines.append(f"insert rule {entry['family']} {entry['table']} {entry['chain']} jump mosaic_egress")
    return '\n'.join(lines) + '\n'


def save(state):
    path = STATE / 'next.json'
    with path.open('x') as output:
        json.dump(state, output)
        output.flush()
        os.fsync(output.fileno())
    path.replace(STATE / 'owner.json')
    descriptor = os.open(STATE, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def verify(state, items):
    if state.get('owned') is None:
        raise Blocked('interrupted setup needs inventory review; saved plan retained')
    actual = [item for item in items if owned(item, state['targets'])]
    if fingerprint(actual, handles=True) != state['owned']:
        raise Blocked('owned firewall resources changed; refusing adoption or cleanup')
    return actual


def setup(args):
    if (STATE / 'owner.json').exists():
        state = json.loads((STATE / 'owner.json').read_text())
        if state['settings'] != [args.tun, args.wan, args.client]:
            raise Blocked('forwarding settings differ from owned setup')
        verify(state, inventory())
        if FORWARDING.read_text().strip() != '1':
            raise Blocked('IPv4 forwarding changed')
        return
    for service in ('firewalld', 'ufw'):
        result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, timeout=5)
        if result.returncode == 0:
            raise Blocked('managed firewall requires its own reviewed integration')
    for command in ('iptables-legacy-save',):
        import shutil
        if shutil.which(command):
            legacy = run([command])
            if any(line.startswith('-A ') or (line.startswith(':FORWARD ') and not line.startswith(':FORWARD ACCEPT ')) for line in legacy.splitlines()):
                raise Blocked('legacy firewall requires reviewed integration')
    links = json.loads(run(['ip', '-j', 'link', 'show', 'dev', args.wan]))
    if len(links) != 1 or links[0]['ifname'] != args.wan or args.wan == args.tun:
        raise Blocked('WAN interface does not match inventory')
    before = inventory()
    targets = targets_for(before)
    batch = rules(args.tun, args.wan, args.client, targets)
    run(['nft', '-c', '-f', '-'], batch)
    state = {'settings': [args.tun, args.wan, args.client], 'targets': targets, 'forwarding': FORWARDING.read_text().strip(), 'before': fingerprint(before), 'owned': None, 'rules': batch}
    save(state)
    run(['nft', '-f', '-'], batch)
    after = inventory()
    state['owned'] = fingerprint([item for item in after if owned(item, targets)], handles=True)
    save(state)
    if fingerprint([item for item in after if not owned(item, targets)]) != state['before']:
        raise Blocked('firewall changed during setup; forwarding remains unchanged')
    FORWARDING.write_text('1\n')


def cleanup():
    path = STATE / 'owner.json'
    if not path.exists():
        return
    state = json.loads(path.read_text())
    items = inventory()
    if not any(owned(item, state['targets']) for item in items) and fingerprint(items) == state['before']:
        if FORWARDING.read_text().strip() not in ('1', state['forwarding']):
            raise Blocked('forwarding value changed')
        FORWARDING.write_text(state['forwarding'] + '\n')
        path.unlink()
        return
    actual = verify(state, items)
    if fingerprint([item for item in items if not owned(item, state['targets'])]) != state['before']:
        raise Blocked('other firewall configuration changed; review before restoring forwarding')
    if FORWARDING.read_text().strip() not in ('1', state['forwarding']):
        raise Blocked('forwarding value changed')
    lines = []
    for item in actual:
        rule = item.get('rule', {})
        if rule.get('chain') != 'mosaic_egress' and rule.get('table') not in ('mosaic_forward', 'mosaic_nat') and rule:
            lines.append(f"delete rule {rule['family']} {rule['table']} {rule['chain']} handle {rule['handle']}")
    for family, table in sorted({(entry['family'], entry['table']) for entry in state['targets']}):
        lines += [f'flush chain {family} {table} mosaic_egress', f'delete chain {family} {table} mosaic_egress']
    lines += ['delete table inet mosaic_forward', 'delete table ip mosaic_nat']
    batch = '\n'.join(lines) + '\n'
    run(['nft', '-c', '-f', '-'], batch)
    run(['nft', '-f', '-'], batch)
    FORWARDING.write_text(state['forwarding'] + '\n')
    path.unlink()


def main():
    parser = argparse.ArgumentParser(description='Dedicated relay IPv4 forwarding and owned NAT rules')
    parser.add_argument('command', choices=('setup', 'status', 'cleanup'))
    parser.add_argument('--dedicated-relay', action='store_true', required=True)
    parser.add_argument('--wan', default='eth0')
    parser.add_argument('--tun', default='mosaic0')
    parser.add_argument('--client', default='10.77.0.2')
    args = parser.parse_args()
    try:
        if sys.platform != 'linux' or os.geteuid() != 0:
            raise Blocked('dedicated Linux relay root required')
        client = ipaddress.IPv4Address(args.client)
        private = any(client in ipaddress.IPv4Network(network) for network in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))
        if not all(re.fullmatch(r'[A-Za-z0-9_-]{1,15}', value) for value in (args.wan, args.tun)) or not args.tun.startswith('mosaic') or not private or int(client) & 3 not in (1, 2):
            raise Blocked('invalid interface or private client IPv4 address')
        os.umask(0o077)
        STATE.mkdir(mode=0o700, exist_ok=True)
        meta = STATE.lstat()
        if STATE.is_symlink() or meta.st_uid != 0 or meta.st_mode & 0o077:
            raise Blocked('unsafe ownership directory')
        with (STATE / 'lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.command == 'setup':
                setup(args)
            elif args.command == 'cleanup':
                cleanup()
            else:
                state = json.loads((STATE / 'owner.json').read_text())
                verify(state, inventory())
                if FORWARDING.read_text().strip() != '1':
                    raise Blocked('IPv4 forwarding changed')
        print(json.dumps({'status': 'PASS', 'scope': 'relay-forwarding', 'operation': args.command}))
        return 0
    except (Blocked, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'BLOCKED', 'scope': 'relay-forwarding', 'detail': str(error) if isinstance(error, Blocked) else 'forwarding setup or ownership check failed'}))
        return 2


if __name__ == '__main__':
    sys.exit(main())
