#!/usr/bin/env python3
"""Run representative existing-account Xray probes plus read-only server controls.

No new accounts, listeners, host routing or production config changes. The caller's
existing OS egress policy remains in effect. All run files are owner-only.
"""
import argparse
import json
import os
from pathlib import Path
import queue
import statistics
import subprocess
import threading
import time

import probe as peer
import transport

ROOT=Path(__file__).resolve().parents[2]

def degraded(baseline, recent):
    current=statistics.median(recent)
    return current>baseline*1.2 and current>baseline+10

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--servers',default=str(ROOT/'servers.txt'))
    parser.add_argument('--configs',default=str(ROOT/'configs/health'))
    parser.add_argument('--allow-verified-sshd-bans',action='store_true',help='explicitly authorized exception for SSH jail runtime membership only')
    parser.add_argument('--samples',type=int,default=84)
    parser.add_argument('--control',choices=('ipify','cloudflare'),default='ipify')
    parser.add_argument('--owned-jobs-manifest')
    parser.add_argument('--workload',nargs=argparse.REMAINDER,required=True,help='trusted command to run after the healthy baseline')
    args=parser.parse_args()
    if not 84 <= args.samples <= 360:parser.error('samples must be 84..360')
    if not args.workload:parser.error('workload must contain a command')
    owned_jobs=json.loads(Path(args.owned_jobs_manifest).read_text()) if args.owned_jobs_manifest else {}
    staged=json.loads((Path(args.configs)/"staged.json").read_text())
    os.umask(0o077)
    out=ROOT/'results'/f'xray-preservation-{time.time_ns()}'
    out.mkdir(mode=0o700)
    records=dict(line.split(':',1) for line in Path(args.servers).read_text().splitlines() if line and line[0].isdigit())
    if len(records)!=2:raise SystemExit('Exactly two explicitly configured servers required')
    digests={staged[host]['sha256'] for host in records}
    if len(digests)!=1:raise SystemExit('Staged probe hashes must match on both hosts')
    report={'schema_version':1,'scope':'representative-configured-xray-clients','status':'BLOCKED','baseline_seconds':300,'https_control':args.control,'host_latency_measurement':'curl time_total; inventory duration reported separately','probe_interval_seconds':5,'configured_samples_per_stream':args.samples,'workload':args.workload,'assertions':[],'client_identity_kind':'existing configured account, outbound-only probe from the other supplied Linux host as nobody; not an existing user device','allow_verified_sshd_bans':args.allow_verified_sshd_bans,'expected_runtime_updates':[],'probe_sha256':digests.pop()}
    events=queue.Queue();histories={};initial_inventories=set();test_proc=None
    workers={};poll_stop=threading.Event();poll_threads=[]
    streams_by_source={host:{} for host in records}
    baseline_source=(ROOT/'tools/network/baseline.py').read_text()
    monitor_source=(ROOT/'tools/network/ownership.py').read_text()+'\n'+(ROOT/'tools/network/fail2ban.py').read_text()+'\n'+(ROOT/'tools/xray/remote/monitor.py').read_text()
    def collect(host, directory):
        offset=0
        try:
            while not poll_stop.is_set():
                try:
                    result=transport.poll(host,records[host],directory,offset)
                except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
                    events.put((host+'-worker',{'type':'administrative_retry','reason':type(error).__name__}))
                    # Retrieval retries preserve the offset and every remote sample.
                    result=transport.poll(host,records[host],directory,offset)
                offset=result['offset']
                for line in result['data'].splitlines():
                    row=json.loads(line);label=row['label'];event=row['event']
                    with (out/(label+'.jsonl')).open('a') as log:log.write(json.dumps(event)+'\n')
                    events.put((label,event))
                if result['done']:
                    events.put((host+'-worker',{'type':'worker_done'}))
                    return
                poll_stop.wait(5)
        except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):
            events.put((host+'-worker',{'status':'FAIL','id':'administrative_collection'}))
    started=time.monotonic();exited=set();failed=False;tests_started=False;tests_done=False;last_progress=0
    try:
        for host,password in records.items():
            cfg=json.loads((Path(args.configs)/(host+'.json')).read_text())
            policy={'vpn_role':'server','test_uid':65534,'relay_ip':next(h for h in records if h!=host),'namespace':'mosaic-test','tunnel_subnet':'10.77.0.0/30','firewall':'both','vpn_services':['xray.service'],'vpn_containers':[],'vpn_interfaces':['eth0'],'vpn_config_files':[cfg['xray_config_path']],'expected_egress':cfg['expected_egress'],'https_control':args.control}
            if host in owned_jobs:policy['owned_jobs']=owned_jobs[host]
            remote="b={'__name__':'baseline_library'}\nexec("+repr(baseline_source)+",b)\n"+monitor_source+"\nraise SystemExit(monitor(b,"+repr(policy)+","+str(args.samples)+","+repr(args.allow_verified_sshd_bans)+"))\n"
            streams_by_source[host][host+'-host']=remote
            histories[host+'-host']=[]
            source=next(h for h in records if h!=host)
            _,remote_probe,fd=peer.command(source,records[source],cfg,staged[source]['path'],args.samples)
            os.close(fd)
            streams_by_source[source][host+'-vpn']=remote_probe
            histories[host+'-vpn']=[]
        for host,streams in streams_by_source.items():
            directory='/run/mosaic-observe-'+out.name.removeprefix('xray-preservation-')
            owner=transport.start(host,records[host],streams,directory,args.samples*5+30)
            workers[host]={'directory':directory,'owner':owner}
            (out/'workers.json').write_text(json.dumps(workers,indent=2)+'\n')
            thread=threading.Thread(target=collect,args=(host,directory),daemon=True)
            poll_threads.append(thread);thread.start()
        while len(exited)<4:
            if time.monotonic()-started>args.samples*5+60:
                report['assertions'].append({'id':'run.deadline','status':'FAIL'});failed=True;break
            try:label,event=events.get(timeout=1)
            except queue.Empty:event=None
            if event:
                if event.get('type')=='worker_done':
                    host=label.removesuffix('-worker')
                    if any(stream not in exited for stream in streams_by_source[host]):
                        report['assertions'].append({'id':label+'.incomplete','status':'FAIL'});failed=True;break
                elif event.get('type')=='owned_runtime_state':pass
                elif event.get('type')=='administrative_retry':report.setdefault('administrative_retries',[]).append({'stream':label,**event})
                elif event.get('type')=='expected_runtime_state':report['expected_runtime_updates'].append({'stream':label,**event})
                elif event.get('type')=='ownership':pass
                elif event.get('type')=='inventory':initial_inventories.add(label)
                elif event.get('type')=='exit':
                    exited.add(label)
                    if event['code']!=0 or len(histories[label])!=args.samples:
                        report['assertions'].append({'id':label+'.exit','status':'FAIL'});failed=True;break
                elif event.get('type')=='final':
                    if event.get('status')!='PASS':failed=True;break
                else:
                    if event.get('status')!='PASS':
                        report['assertions'].append({'id':label+'.'+event.get('id','probe'),'status':'FAIL','changed_keys':event.get('changed_keys',[]),'sequence':event.get('sequence')});failed=True;break
                    history=histories[label];history.append(event)
                    if len(history)>60 and degraded(statistics.median(x['duration_ms'] for x in history[:60]),[x['duration_ms'] for x in history[-12:]]):
                        report['assertions'].append({'id':label+'.rolling_latency','status':'FAIL','baseline_median_ms':statistics.median(x['duration_ms'] for x in history[:60]),'recent_median_ms':statistics.median(x['duration_ms'] for x in history[-12:])});failed=True;break
            if not tests_started and len(initial_inventories)==2 and all(len(h)>=61 for h in histories.values()):
                log=(out/'local-checks.log').open('x')
                test_env=os.environ.copy();test_env['MOSAIC_MONITOR_MANIFEST']=str(out/'workers.json');test_env['MOSAIC_PRESERVATION_DIRECTORY']=str(out)
                test_proc=subprocess.Popen(args.workload,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,env=test_env);log.close()
                tests_started=True
                print('PASS five-minute baseline on both hosts; running the configured workload under continued monitoring',flush=True)
            if test_proc and not tests_done and test_proc.poll() is not None:
                tests_done=True
                if test_proc.returncode!=0:failed=True;report['assertions'].append({'id':'local.checks','status':'FAIL'});break
                report['assertions'].append({'id':'workload.completed','status':'PASS'})
            if time.monotonic()-last_progress>=30:
                last_progress=time.monotonic()
                print('Control samples: '+', '.join(label+'='+str(len(history))+'/'+str(args.samples) for label,history in histories.items()),flush=True)
        if not failed and tests_done and len(initial_inventories)==2 and all(len(h)==args.samples for h in histories.values()):
            report['status']='PASS'
        else:report['status']='FAIL'
    except (OSError,ValueError,KeyError,RuntimeError,subprocess.TimeoutExpired,KeyboardInterrupt) as error:
        report['status']='FAIL';report['assertions'].append({'id':'driver.interrupted_or_unavailable','status':'FAIL','error_type':type(error).__name__})
    finally:
        poll_stop.set()
        for thread in poll_threads:thread.join(timeout=16)
        report['worker_cleanup']={}
        for host,worker in workers.items():
            try:
                result=transport.finish(host,records[host],worker['directory'],worker['owner'])
                for name,content in result.pop('errors').items():
                    (out/name).write_text(content)
                report['worker_cleanup'][host]=result
            except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired):
                report['worker_cleanup'][host]={'status':'BLOCKED'}
                report['status']='FAIL'
        if test_proc and test_proc.poll() is None:
            import signal
            os.killpg(test_proc.pid,signal.SIGTERM)
            try:test_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(test_proc.pid,signal.SIGKILL);test_proc.wait()
        report['elapsed_seconds']=time.monotonic()-started
        report['streams']={label:{'passed_samples':len(history),'baseline_median_ms':statistics.median(x['duration_ms'] for x in history[:60]) if history else None,'post_baseline_samples':max(0,len(history)-60)} for label,history in histories.items()}
        (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(report['status']+' preservation report: '+str(out/'report.json'),flush=True)
    return 0 if report['status']=='PASS' else 1

if __name__=='__main__':raise SystemExit(main())
