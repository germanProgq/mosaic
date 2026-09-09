import argparse
import json
import os
from pathlib import Path
import sys
import time


def events(data):
    histories = {}
    for line in data.splitlines():
        row = json.loads(line)
        value = row['event']
        if value.get('status') == 'FAIL' or value.get('type') in ('exit', 'final'):
            raise RuntimeError('preservation observer stopped or failed')
        if value.get('type') == 'sample' or 'duration_ms' in value:
            if value.get('status') != 'PASS':
                raise RuntimeError('preservation sample did not pass')
            histories[row['label']] = histories.get(row['label'], 0) + 1
    if len(histories) != 2 or min(histories.values()) < 61 or max(histories.values()) - min(histories.values()) > 2:
        raise RuntimeError('complete five-minute host and representative VPN baseline required')
    return histories


def checkpoint(spec):
    path = Path(spec['directory'])
    if path.parent != Path('/run') or not path.name.startswith('mosaic-observe-') or path.is_symlink():
        raise RuntimeError('invalid observer path')
    meta = path.stat()
    if meta.st_uid != 0 or meta.st_mode & 0o077 or (path / 'done.json').exists():
        raise RuntimeError('observer unavailable')
    owner = json.loads((path / 'owner.json').read_text())
    if owner != spec['owner']:
        raise RuntimeError('observer ownership changed')
    fields = Path(f"/proc/{owner['pid']}/stat").read_text().rsplit(') ', 1)[1].split()
    if fields[19] != owner['start_ticks'] or fields[0] == 'Z':
        raise RuntimeError('observer process changed')
    log = path / 'events.jsonl'
    if log.stat().st_size > 4 * 1024 * 1024 or time.time() - log.stat().st_mtime > 10:
        raise RuntimeError('observer events stale or oversized')
    data = log.read_bytes()
    data = data[:data.rfind(b'\n') + 1]
    return events(data.decode())


def main():
    parser = argparse.ArgumentParser(description='Use the running host and representative VPN observer as the isolation guard.')
    parser.add_argument('action', choices=['verify', 'watch'])
    parser.add_argument('--policy', required=True, type=Path)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--directory', required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('root observer verification required')
    meta = args.baseline.stat()
    if args.baseline.is_symlink() or meta.st_uid != 0 or meta.st_mode & 0o077:
        raise RuntimeError('unsafe observer record')
    spec = json.loads(args.baseline.read_text())
    policy = json.loads(args.policy.read_text())
    if policy['namespace'] != 'mosaic-test' or policy['test_uid'] != 65534 or policy['vpn_role'] != 'server':
        raise RuntimeError('observer policy mismatch')
    first = checkpoint(spec)
    if args.action == 'verify':
        start = time.monotonic()
        while time.monotonic() - start < 12:
            current = checkpoint(spec)
            if all(current.get(key, 0) > value for key, value in first.items()):
                return 0
            time.sleep(.2)
        raise RuntimeError('fresh preservation checkpoint missing')
    previous = first
    last_change = {key: time.monotonic() for key in first}
    while True:
        owner = json.loads((args.directory / "owner.json").read_text())
        parent = owner["parent"]
        fields = Path(f"/proc/{parent['pid']}/stat").read_text().rsplit(") ", 1)[1].split()
        if fields[19] != parent["start"] or fields[0] == "Z":
            raise RuntimeError("isolation launcher exited")
        current = checkpoint(spec)
        for key, count in current.items():
            if count > previous[key]:
                last_change[key] = time.monotonic()
            if time.monotonic() - last_change[key] > 10:
                raise RuntimeError('preservation stream stopped sampling')
        previous = current
        next_file = args.directory / 'guard.next'
        with open(os.open(next_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:
            json.dump({'status': 'PASS', 'samples': current, 'unix_time': time.time()}, output)
        os.replace(next_file, args.directory / 'guard.ready')
        time.sleep(.5)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError):
        print('FAIL isolation.preservation_observer', file=sys.stderr)
        sys.exit(1)
