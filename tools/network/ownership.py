import hashlib
import json
import os
from pathlib import Path
import re


def exclude_owned_udp(state, policy):
    spec = policy.get('owned_jobs')
    if not spec:
        return []
    directory = Path(spec['directory'])
    assert directory.parent == Path('/run') and directory.name.startswith('mosaic-connectivity-')
    assert not directory.is_symlink()
    state['mosaic_binary_hashes'] = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in spec['binaries']}
    assert state['mosaic_binary_hashes'] == spec['binaries']
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
        except FileNotFoundError:
            continue
    state['listeners'], excluded = filter_listeners(state['listeners'], owned)
    return excluded


def filter_listeners(listeners, owned):
    kept = []
    excluded = []
    for line in listeners:
        pids = {int(pid) for pid in re.findall(r'pid=(\d+)', line)}
        matching = pids & set(owned)
        if matching:
            assert len(pids) == 1 and line.split()[0] == 'udp'
            job = owned[next(iter(matching))]
            port = int(line.split()[4].rsplit(':', 1)[-1])
            assert port == 443 if job['role'] == 'relay' else port >= 1024
            excluded.append({'pid': job['pid'], 'role': job['role'], 'port': port})
        else:
            kept.append(line)
    return kept, excluded
