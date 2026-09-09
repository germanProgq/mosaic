"""Short verified SSH requests for a deadline-bound, independently running worker."""
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def ssh(host, password, source, timeout=15):
    read, write = os.pipe()
    os.write(write, (password + '\n').encode())
    os.close(write)
    try:
        result = subprocess.run(['sshpass', '-d', str(read), 'ssh', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=3', '-o', 'ServerAliveCountMax=2', '-o', 'PreferredAuthentications=password', 'root@' + host, 'python3 -'], input=source, text=True, capture_output=True, pass_fds=(read,), timeout=timeout)
        if result.returncode:
            raise RuntimeError('administrative SSH request failed')
        return json.loads(result.stdout)
    finally:
        os.close(read)


def start(host, password, streams, directory, deadline_seconds=450):
    worker = (ROOT / 'tools/xray/remote/worker.py').read_text()
    payload = {'directory': directory, 'streams': streams, 'deadline_seconds': deadline_seconds}
    # Only generic worker code is in argv; client credentials remain in stdin/memory.
    source = "import subprocess,json,os,time,pathlib\np=subprocess.Popen(['python3','-c'," + repr(worker) + "],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\np.stdin.write(" + repr(json.dumps(payload).encode()) + ")\np.stdin.close()\n"
    source += "d=pathlib.Path(" + repr(directory) + ")\nfor _ in range(50):\n if (d/'owner.json').exists():break\n time.sleep(.1)\nprint((d/'owner.json').read_text())\n"
    try:
        return ssh(host, password, source)
    except (OSError,RuntimeError,ValueError,subprocess.TimeoutExpired):
        recovery="import pathlib\nprint(pathlib.Path("+repr(directory+'/owner.json')+").read_text())\n"
        return ssh(host,password,recovery)


def poll(host, password, directory, offset):
    source = "import json,pathlib\nd=pathlib.Path(" + repr(directory) + ")\np=d/'events.jsonl'\ndata=p.read_bytes() if p.exists() else b''\ndata=data[" + str(offset) + ":]\ndata=data[:data.rfind(b'\\n')+1]\nprint(json.dumps({'data':data.decode(),'offset':" + str(offset) + "+len(data),'done':(d/'done.json').exists()}))\n"
    return ssh(host, password, source)


def finish(host, password, directory, owner):
    source = """import json,pathlib,os,signal,time
d=pathlib.Path(DIRECTORY)
expected=OWNER
assert d.parent==pathlib.Path('/run') and d.name.startswith('mosaic-observe-') and not d.is_symlink()
p=pathlib.Path('/proc')/str(expected['pid'])
def alive():
 try:
  fields=(p/'stat').read_text().split(') ',1)[1].split()
  return fields[19]==expected['start_ticks'] and fields[0]!='Z'
 except FileNotFoundError:return False
if not d.exists():
 for _ in range(30):
  if not alive():break
  time.sleep(.1)
 assert not alive(),'worker still active after directory disappeared'
 print(json.dumps({'status':'PASS','errors':{},'already_removed':True}));raise SystemExit(0)
assert json.loads((d/'owner.json').read_text())==expected
if alive():os.kill(expected['pid'],signal.SIGTERM)
for _ in range(80):
 if (d/'done.json').exists():break
 time.sleep(.1)
assert (d/'done.json').exists(),'worker cleanup incomplete'
errors={f.name:f.read_text() for f in d.glob('*.stderr.log')}
assert all(f.is_file() and not f.is_symlink() and (f.name in ['owner.json','events.jsonl','done.json'] or f.name.endswith('.stderr.log')) for f in d.iterdir())
for f in d.iterdir():f.unlink()
d.rmdir()
print(json.dumps({'status':'PASS','errors':errors}))
""".replace('DIRECTORY',repr(directory)).replace('OWNER',repr(owner))
    try:return ssh(host,password,source,timeout=20)
    except (OSError,RuntimeError,subprocess.TimeoutExpired):return ssh(host,password,source,timeout=20)
