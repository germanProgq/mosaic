#!/usr/bin/env python3
"""Read authorized Xray servers over verified SSH; export existing client credentials
and a derived PUBLIC Reality key only. Never export server private keys.
"""
import argparse, json, os, subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]

REMOTE = r'''
import base64, hashlib, json, subprocess
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
state=subprocess.check_output(['systemctl','show','xray.service','--property=ActiveState,MainPID,ExecMainStartTimestampMonotonic,NRestarts'],text=True,timeout=5)
assert 'ActiveState=active' in state
pid=next(line.split('=',1)[1] for line in state.splitlines() if line.startswith('MainPID='))
args=Path('/proc/'+pid+'/cmdline').read_bytes().split(b'\0')
name=next(args[i+1].decode() for i,a in enumerate(args[:-1]) if a in (b'-c',b'-config',b'--config'))
raw=Path(name).read_bytes();config=json.loads(raw)
ib=next(i for i in config['inbounds'] if i['protocol']=='vless' and i['streamSettings']['security']=='reality')
client=ib['settings']['clients'][0]
reality=ib['streamSettings']['realitySettings']
private=X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(reality['privateKey']+'='*(-len(reality['privateKey'])%4)))
public=base64.urlsafe_b64encode(private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode().rstrip('=')
result={'port':ib['port'],'id':client['id'],'flow':client.get('flow',''),'server_name':reality['serverNames'][0],'public_key':public,'short_id':reality['shortIds'][0], 'xray_config_path':name,'xray_config_sha256':hashlib.sha256(raw).hexdigest(),'service':state,'xray_version':subprocess.check_output([args[0].decode(),'version'],text=True,timeout=5).splitlines()[0]}
assert raw==Path(name).read_bytes()
print(json.dumps(result))
'''

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--servers',default=str(ROOT/'servers.txt'));p.add_argument('--output',default=str(ROOT/'configs/health'));a=p.parse_args()
    os.umask(0o077);directory=Path(a.output);directory.mkdir(mode=0o700,parents=True,exist_ok=True)
    for line in Path(a.servers).read_text().splitlines():
        if not line or not line[0].isdigit():continue
        host,password=line.split(':',1)
        read,write=os.pipe();os.write(write,(password+'\n').encode());os.close(write)
        try:
            result=subprocess.run(['sshpass','-d',str(read),'ssh','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8','-o','PreferredAuthentications=password','root@'+host,'python3 -'],pass_fds=(read,),input=REMOTE,capture_output=True,text=True,timeout=25)
        finally:os.close(read)
        if result.returncode:
            (directory/(host+'-private-error.log')).write_text(result.stderr)
            print('BLOCKED preparation for',host);return 2
        data=json.loads(result.stdout);data['server']=host;data['expected_egress']=host
        path=directory/(host+'.json')
        with open(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:json.dump(data,f,indent=2);f.write('\n')
        print('PASS prepared representative configured VLESS client for',host,';',data['xray_version'])
    return 0
if __name__=='__main__':raise SystemExit(main())
