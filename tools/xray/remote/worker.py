#!/usr/bin/env python3
"""Bounded private remote supervision; no production-service or network changes."""
import json
import os
from pathlib import Path
import queue
import signal
import statistics
import subprocess
import sys
import threading
import time


def run(payload):
    directory = Path(payload['directory'])
    os.umask(0o077)
    directory.mkdir(mode=0o700)
    identity = {'pid': os.getpid(), 'start_ticks': Path('/proc/self/stat').read_text().split(') ', 1)[1].split()[19]}
    (directory / 'owner.json').write_text(json.dumps(identity))
    events = queue.Queue()
    children = []
    histories = {}
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGHUP, signal.SIG_IGN)

    def reader(label, child):
        for line in child.stdout:
            try:
                event = json.loads(line)
            except ValueError:
                event = {'status': 'FAIL', 'id': 'invalid_probe_output'}
            events.put((label, event))
        events.put((label, {'type': 'exit', 'code': child.wait()}))

    with (directory / 'events.jsonl').open('x') as log:
        try:
            for label, source in payload['streams'].items():
                error = (directory / (label + '.stderr.log')).open('x')
                child = subprocess.Popen(['python3', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error, text=True, start_new_session=True)
                error.close()
                children.append(child)
                threading.Thread(target=reader, args=(label, child), daemon=True).start()
                child.stdin.write(source)
                child.stdin.close()
            deadline = time.monotonic() + payload.get('deadline_seconds', 450)
            finished = set()
            while len(finished) < len(children) and not stopped.is_set():
                if time.monotonic() > deadline:
                    raise TimeoutError('worker deadline')
                try:
                    label, event = events.get(timeout=0.2)
                except queue.Empty:
                    continue
                log.write(json.dumps({'label': label, 'event': event}) + '\n')
                log.flush()
                if 'duration_ms' in event:
                    history = histories.setdefault(label, [])
                    history.append(event['duration_ms'])
                    if len(history) > 60:
                        baseline = statistics.median(history[:60])
                        recent = statistics.median(history[-12:])
                        if recent > baseline * 1.2 and recent > baseline + 10:
                            log.write(json.dumps({'label': label, 'event': {'status': 'FAIL', 'id': 'worker.rolling_latency'}}) + '\n')
                            log.flush()
                            break
                if event.get('type') == 'exit':
                    finished.add(label)
                    if event['code'] != 0:
                        break
                if event.get('status') == 'FAIL':
                    break
        finally:
            for child in children:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGTERM)
            for child in children:
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
            (directory / 'done.json').write_text(json.dumps({'finished': True}))


if __name__ == '__main__':
    run(json.load(sys.stdin))
