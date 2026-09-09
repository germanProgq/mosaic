#!/usr/bin/env python3
"""Stage only the probe executable in a new Mosaic-owned /run directory.
The SSH upload is capped at 1 Mbit/s per host; no packages/services are installed.
"""
import argparse,gzip,hashlib,json,os,subprocess,time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
ROOT=Path(__file__).resolve().parents[2]
REMOTE=r'''
import gzip,hashlib,json,os,sys
from pathlib import Path
raw=gzip.decompress(sys.stdin.buffer.read(40000000))
assert len(raw)<100000000
assert hashlib.sha256(raw).hexdigest()==EXPECTED
path=Path(DIRECTORY);path.mkdir(mode=0o755,exist_ok=False)
with open(os.open(path/'xray-health',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o755),'wb') as f:f.write(raw)
print(json.dumps({'status':'PASS','path':str(path/'xray-health'),'sha256':hashlib.sha256(raw).hexdigest()}))
'''
def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--binary',type=Path,required=True,help='Linux probe executable built from tools/xray/client')
 args=parser.parse_args()
 os.umask(0o077)
 binary=args.binary.read_bytes();digest=hashlib.sha256(binary).hexdigest();payload=gzip.compress(binary)
 directory='/run/mosaic-health-'+str(time.time_ns())
 records=dict(line.split(':',1) for line in (ROOT/'servers.txt').read_text().splitlines() if line and line[0].isdigit())
 def stage(record):
  host,password=record;read,write=os.pipe();os.write(write,(password+'\n').encode());os.close(write)
  import shlex
  remote=REMOTE.replace('EXPECTED',repr(digest)).replace('DIRECTORY',repr(directory))
  try:
   proc=subprocess.Popen(['sshpass','-d',str(read),'ssh','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','PreferredAuthentications=password','root@'+host,'python3 -c '+shlex.quote(remote)],pass_fds=(read,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  finally:os.close(read)
  started=time.monotonic()
  for index in range(0,len(payload),8192):
   proc.stdin.write(payload[index:index+8192]);proc.stdin.flush()
   time.sleep(max(0,(index+8192)/125000-(time.monotonic()-started)))
  proc.stdin.close();proc.wait(timeout=30)
  stdout=proc.stdout.read();stderr=proc.stderr.read()
  if proc.returncode:raise RuntimeError('staging failed for '+host)
  result=json.loads(stdout);print(host,'probe staged; SHA-256 verified',flush=True)
  return host,result
 with ThreadPoolExecutor(max_workers=2) as pool:results=dict(pool.map(stage,records.items()))
 (ROOT/'configs/health/staged.json').write_text(json.dumps(results,indent=2)+'\n')
 print('No daemon or network configuration changed')
if __name__=='__main__':main()
