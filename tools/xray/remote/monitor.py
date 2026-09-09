#!/usr/bin/env python3
"""Read-only endpoint of the live Xray preservation driver. Executed over SSH stdin.
Uses the shared baseline implementation; keeps credentials and raw state private.
"""
import hashlib
from pathlib import Path
import json
import os
import pwd
import sys
import time


def monitor(baseline, policy, count, allow_verified_sshd_bans=False):
    def add_fail2ban_identity(state):
        if allow_verified_sshd_bans:
            state['fail2ban_service']=baseline['run'](['systemctl','show','fail2ban.service','--property=ActiveState,MainPID,NRestarts,ExecMainStartTimestampMonotonic,NeedDaemonReload'])
            if 'ActiveState=active' not in state['fail2ban_service']:
                raise RuntimeError('Fail2Ban is not active')
            state['fail2ban_configs']={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('/etc/fail2ban').rglob('*') if p.is_file() and p.suffix in ('.conf','.local')}
            if not state['fail2ban_configs']:raise RuntimeError('Fail2Ban configuration inventory missing')
    def compare(before, current, sequence):
        if allow_verified_sshd_bans and current.get('nft')!=before.get('nft'):
            # Same-host live manager state must exactly match the changed nft set.
            bans=baseline['run'](['fail2ban-client','get','sshd','banip']).split()
            updated,changes=reconcile_sshd_bans(before['nft'],current['nft'],bans)
            before['nft']=updated
            if changes:print(json.dumps({'type':'expected_runtime_state','sequence':sequence,'id':'fail2ban.verified_sshd_ban_update','changes':changes}),flush=True)
        return before==current

    # policy is prepared from the identified server config, not guessed names.
    before, raw = baseline['inventory'](policy)
    add_fail2ban_identity(before)
    exclude_owned_udp(before, policy)
    baseline['collisions'](policy, before)
    print(json.dumps({'type':'inventory','state':before,'raw':raw}),flush=True)
    start=time.monotonic()
    failures=0
    for index in range(count):
        scheduled=start+index*5
        time.sleep(max(0,scheduled-time.monotonic()))
        t=time.monotonic()
        state,_=baseline['inventory'](policy)
        add_fail2ban_identity(state)
        owned = exclude_owned_udp(state, policy)
        if owned:print(json.dumps({'type':'owned_runtime_state','sequence':index+1,'sockets':owned}),flush=True)
        if not compare(before,state,index+1):
            changed=[key for key in state if state[key]!=before.get(key)]
            print(json.dumps({'type':'sample','status':'FAIL','id':'host.configuration_drift','changed_keys':changed,'sequence':index+1,'before':{k:before.get(k) for k in changed},'after':{k:state.get(k) for k in changed}}),flush=True)
            return 1
        try:
            output=baseline['run'](['curl','--fail','--silent','--show-error','--max-time','3','--limit-rate','64k','https://api.ipify.org'],policy['test_uid']).strip()
            ok=output==policy['expected_egress']
        except Exception:
            ok=False
        failures=0 if ok else failures+1
        elapsed=time.monotonic()-scheduled
        print(json.dumps({'type':'sample','status':'PASS' if ok and elapsed<5 else 'FAIL','id':'host.control','sequence':index+1,'duration_ms':(time.monotonic()-t)*1000,'configuration_unchanged':True,'egress_matched':ok,'scheduled_lag_ms':max(0,t-scheduled)*1000}),flush=True)
        if failures>=2 or elapsed>=5:return 1
    # Final compare after the last control request and before SSH teardown.
    final,_=baseline['inventory'](policy)
    add_fail2ban_identity(final)
    exclude_owned_udp(final, policy)
    if not compare(before,final,count+1):
        print(json.dumps({'type':'final','status':'FAIL','id':'host.final_configuration'}),flush=True);return 1
    print(json.dumps({'type':'final','status':'PASS','id':'host.final_configuration'}),flush=True)
    return 0
