import hashlib
import json
import os
from pathlib import Path
import re

namespace_owners = {}


def exclude_owned_udp(state, policy):
    spec = policy.get('owned_jobs')
    if not spec:
        return []
    directory = Path(spec['directory'])
    assert directory.parent in (Path('/run'), Path('/opt')) and directory.name.startswith('mosaic-connectivity-')
    assert not directory.is_symlink()
    state['mosaic_binary_hashes'] = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in spec['binaries']}
    assert state['mosaic_binary_hashes'] == spec['binaries']
    owned = owned_processes(spec)
    exclude_tunnel_resources(state, spec, owned)
    state['listeners'], excluded = filter_listeners(state['listeners'], owned)
    return excluded


def owned_processes(spec):
    directory = Path(spec['directory'])
    owned = {}
    for path in (directory / 'jobs').glob('*.owner.json'):
        job = json.loads(path.read_text())
        process = Path('/proc') / str(job['pid'])
        try:
            if (process / 'stat').read_text().split(') ', 1)[1].split()[19] != job['start_ticks']:
                continue
            binary = os.path.realpath(process / 'exe')
            if binary != str(directory / job['binary']):
                continue
            assert job['binary'] in spec['binaries']
            owned[job['pid']] = job
        except (FileNotFoundError, ProcessLookupError):
            continue
    if spec.get("include_children"):
        owned.update(owned_children(owned, directory))
    return owned


def filter_listeners(listeners, owned):
    kept = []
    excluded = []
    for line in listeners:
        pids = {int(pid) for pid in re.findall(r'pid=(\d+)', line)}
        matching = pids & set(owned)
        if matching:
            assert pids <= set(owned) and line.split()[0] == 'udp'
            jobs = [owned[pid] for pid in pids]
            assert len({job['role'] for job in jobs}) == 1
            job = jobs[0]
            port = int(line.split()[4].rsplit(':', 1)[-1])
            assert port == 443 if job['role'] == 'relay' else port >= 1024
            excluded.append({'pid': job['pid'], 'role': job['role'], 'port': port})
        else:
            kept.append(line)
    return kept, excluded


def process_ticks(path):
    return (path / 'stat').read_text().rsplit(') ', 1)[1].split()[19]


def owned_children(owned, directory):
    children = {}
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():
            continue
        try:
            fields = (process / 'stat').read_text().rsplit(') ', 1)[1].split()
            parent = int(fields[1])
            job = owned.get(parent)
            if job and os.path.realpath(process / 'exe') == str(directory / job['binary']):
                children[int(process.name)] = {**job, 'pid': int(process.name), 'start_ticks': fields[19]}
        except (FileNotFoundError, ProcessLookupError):
            continue
    return children


def filter_tun_state(state, name, address, peer):
    links = [link for link in state['links'] if link['ifname'] == name]
    if not links:
        return
    assert len(links) == 1 and links[0]['link_type'] == 'none'
    setup = 'UP' not in links[0].get('flags', ['UP'])
    assert links[0]['mtu'] == 1100 or setup and links[0]['mtu'] == 1500
    interfaces = [link for link in state['addresses'] if link['ifname'] == name]
    assert len(interfaces) == 1
    inet = interfaces[0]['addr_info']
    assert setup and not inet or len(inet) == 1 and inet[0]['family'] == 'inet' and inet[0]['local'] == address and inet[0]['prefixlen'] == 30
    import ipaddress
    network = ipaddress.IPv4Network(address + '/30', strict=False)
    assert ipaddress.IPv4Address(peer) in network
    allowed = {str(network), address, str(network.broadcast_address)}
    for route in state['routes4']:
        if route.get('dev') == name:
            assert route['dst'] in allowed and route.get('protocol') == 'kernel' and route.get('prefsrc') == address
    assert not any(route.get('dev') == name for route in state['routes6'])
    state['links'] = [link for link in state['links'] if link['ifname'] != name]
    state['addresses'] = [link for link in state['addresses'] if link['ifname'] != name]
    state['routes4'] = [route for route in state['routes4'] if route.get('dev') != name]
    state['qdiscs'] = [qdisc for qdisc in state['qdiscs'] if qdisc.get('dev') != name]


def exclude_tunnel_resources(state, spec, owned):
    tunnel = spec.get('tunnel')
    if not tunnel:
        return
    if tunnel['role'] == 'client':
        path = Path('/run') / tunnel['namespace'] / 'owner.json'
        mount = Path('/run/netns') / tunnel['namespace']
        key = (spec['directory'], tunnel['namespace'])
        if not path.exists():
            if any(line.split()[0] == tunnel['namespace'] for line in state['namespaces']):
                assert key in namespace_owners and not mount.exists() and not mount.is_symlink()
                state['namespaces'] = [line for line in state['namespaces'] if line.split()[0] != tunnel['namespace']]
                print(json.dumps({'type': 'owned_runtime_state', 'id': 'namespace.cleanup_snapshot', 'namespace': tunnel['namespace']}), flush=True)
            namespace_owners.pop(key, None)
            return
        owner = json.loads(path.read_text())
        parent = owned.get(owner['parent']['pid'])
        if parent is None:
            matches = []
            for record in (Path(spec['directory']) / 'jobs').glob('*.owner.json'):
                job = json.loads(record.read_text())
                if job['pid'] == owner['parent']['pid'] and job['start_ticks'] == owner['parent']['start'] and job['role'] == 'isolated' and job['binary'] == 'mosaic-client':
                    matches.append(job)
            assert len(matches) == 1 and 'mosaic-client' in spec['binaries']
            parent = matches[0]
            process = Path('/proc') / str(parent['pid'])
            assert not process.exists() or process_ticks(process) != parent['start_ticks'] or (process / 'stat').read_text().rsplit(') ', 1)[1].split()[0] == 'Z'
        assert parent['start_ticks'] == owner['parent']['start']
        if not mount.exists() and namespace_owners.get(key) == owner:
            assert not mount.is_symlink()
            state['namespaces'] = [line for line in state['namespaces'] if line.split()[0] != tunnel['namespace']]
        if mount.exists() and owner['namespace_inode'] == mount.stat().st_ino:
            assert owner['namespace'] == tunnel['namespace']
            namespace_owners[key] = owner
            state['namespaces'] = [line for line in state['namespaces'] if line.split()[0] != tunnel['namespace']]
    elif tunnel['role'] == 'relay':
        if not any(link['ifname'] == tunnel['name'] for link in state['links']):
            return
        holders = []
        for pid, job in owned.items():
            if job['role'] != 'relay':
                continue
            for path in (Path('/proc') / str(pid) / 'fdinfo').iterdir():
                try:
                    if any(line.split() == ['iff:', tunnel['name']] for line in path.read_text().splitlines()):
                        holders.append(pid)
                except (FileNotFoundError, ProcessLookupError):
                    continue
        assert len(holders) == 1
        filter_tun_state(state, tunnel['name'], tunnel['address'], tunnel['peer'])
    else:
        raise AssertionError('unknown tunnel role')


def tunnel_signature(policy):
    spec = policy.get('owned_jobs', {}).get('tunnel')
    if not spec:
        return None
    paths = [Path('/run') / spec['namespace'] / 'owner.json'] if spec['role'] == 'client' else [Path('/sys/class/net') / spec['name'] / name for name in ('ifindex', 'mtu', 'flags')]
    result = []
    for path in paths:
        try:
            with path.open('rb') as source:
                data = source.read(16385)
            assert len(data) <= 16384
            result.append(data)
        except (FileNotFoundError, ProcessLookupError):
            result.append(None)
    return result


def runtime_signature(policy):
    spec = policy.get('owned_jobs')
    processes = owned_processes(spec) if spec else {}
    return tunnel_signature(policy), sorted((pid, job['start_ticks'], job['binary'], job['role']) for pid, job in processes.items())


def stable_inventory(policy, read):
    for attempt in range(3):
        before = runtime_signature(policy)
        try:
            result = read()
        except (AssertionError, FileNotFoundError, ProcessLookupError):
            if before == runtime_signature(policy):
                raise
        else:
            if before == runtime_signature(policy):
                return result
        print(json.dumps({'type': 'owned_runtime_state', 'id': 'owned.inventory_transition', 'attempt': attempt + 1}), flush=True)
    raise RuntimeError('owned resources changed during all inventory attempts')
