#!/usr/bin/env python3
"""Run the staged no-listener probe from the other supplied host as nobody.
Credentials travel through SSH stdin into memory; no credential file is staged.
"""
import argparse,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def command(source,password,target_config,staged_path,count,diagnostic=False):
    remote=r'''
import ctypes,json,os,pwd,resource,subprocess,signal
user=pwd.getpwnam('nobody')
def setup():
    # Linux parent-death signal ensures SSH cancellation cannot orphan the probe.
    libc=ctypes.CDLL(None);libc.prctl(1,signal.SIGTERM)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
args=[BINARY,'--config','-','--count',str(COUNT),'--interval','5s']
if DIAGNOSTIC:args.append('--diagnostic')
p=subprocess.Popen(args,stdin=subprocess.PIPE,user=user.pw_uid,group=user.pw_gid,extra_groups=[],preexec_fn=setup,env={'PATH':'/usr/bin:/bin','GOMAXPROCS':'1','GOMEMLIMIT':'128MiB'})
print(json.dumps({'type':'ownership','pid':p.pid,'start_ticks':open('/proc/'+str(p.pid)+'/stat').read().split(') ',1)[1].split()[19],'binary':BINARY}),flush=True)
try:
    p.communicate(json.dumps(CONFIG).encode(),timeout=COUNT*5+10)
except BaseException:
    p.terminate()
    try:p.wait(timeout=5)
    except subprocess.TimeoutExpired:p.kill();p.wait()
    raise
raise SystemExit(p.returncode)
'''.replace('BINARY',repr(staged_path)).replace('COUNT',repr(count)).replace('DIAGNOSTIC',repr(diagnostic)).replace('CONFIG',repr(target_config))
    read,write=os.pipe();os.write(write,(password+'\n').encode());os.close(write)
    argv=['sshpass','-d',str(read),'ssh','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=2','-o','PreferredAuthentications=password','root@'+source,'python3 -']
    return argv,remote,read

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('target');parser.add_argument('--count',type=int,default=1);parser.add_argument('--diagnostic',action='store_true');args=parser.parse_args()
    records=dict(line.split(':',1) for line in (ROOT/'servers.txt').read_text().splitlines() if line and line[0].isdigit())
    source=next(host for host in records if host!=args.target)
    cfg=json.loads((ROOT/'configs/health'/f'{args.target}.json').read_text());staged=json.loads((ROOT/'configs/health/staged.json').read_text())
    argv,remote,fd=command(source,records[source],cfg,staged[source]['path'],args.count,args.diagnostic)
    try:return subprocess.run(argv,input=remote,text=True,pass_fds=(fd,),timeout=args.count*5+20).returncode
    finally:os.close(fd)
if __name__=='__main__':raise SystemExit(main())
