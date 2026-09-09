#!/usr/bin/env python3
"""Remove only hash-verified staged probe binaries when no process uses them."""
import argparse,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
REMOTE=r'''
import hashlib,json,os
from pathlib import Path
p=Path(BINARY);directory=p.parent
assert str(directory).startswith('/run/mosaic-health-') and p.name=='xray-health'
assert not directory.is_symlink() and not p.is_symlink()
for process in Path('/proc').iterdir():
 if process.name.isdigit():
  try:
   if os.path.realpath(process/'exe').removesuffix(' (deleted)')==str(p):raise RuntimeError('probe still running')
  except FileNotFoundError:pass
if not directory.exists():
 print(json.dumps({'status':'PASS','id':'cleanup.owned_probe_already_absent'}));raise SystemExit(0)
assert {x.name for x in directory.iterdir()}=={'xray-health'}
assert hashlib.sha256(p.read_bytes()).hexdigest()==DIGEST
p.unlink();directory.rmdir()
print(json.dumps({'status':'PASS','id':'cleanup.owned_probe_binary'}))
'''
def main():
 argparse.ArgumentParser(description=__doc__).parse_args()
 os.umask(0o077)
 records=dict(line.split(':',1) for line in (ROOT/'servers.txt').read_text().splitlines() if line and line[0].isdigit())
 staged=json.loads((ROOT/'configs/health/staged.json').read_text());results={}
 for host,entry in staged.items():
  remote=REMOTE.replace('BINARY',repr(entry['path'])).replace('DIGEST',repr(entry['sha256']))
  read,write=os.pipe();os.write(write,(records[host]+'\n').encode());os.close(write)
  try:r=subprocess.run(['sshpass','-d',str(read),'ssh','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','PreferredAuthentications=password','root@'+host,'python3 -'],pass_fds=(read,),input=remote,capture_output=True,text=True,timeout=20)
  finally:os.close(read)
  results[host]={'status':'PASS' if r.returncode==0 else 'BLOCKED'}
  print(host,results[host]['status'],'owned-resource cleanup')
 (ROOT/'configs/health/cleanup.json').write_text(json.dumps(results,indent=2)+'\n')
 return 0 if all(x['status']=='PASS' for x in results.values()) else 2
if __name__=='__main__':raise SystemExit(main())
