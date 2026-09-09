#!/usr/bin/env python3
"""Read-only endpoint of the live Xray preservation driver. Executed over SSH stdin.
Uses the shared baseline implementation; keeps credentials and raw state private.
"""
import hashlib
from pathlib import Path
import json
import os
import pwd
import re
import sys
import time


def tcp_inbound_ports(config):
    if 'api' in config:
        return None
    ports = set()
    for inbound in config.get('inbounds', []):
        if inbound.get('protocol') not in ('vless', 'trojan') or inbound.get('streamSettings', {}).get('network', 'tcp') != 'tcp':
            return None
        port = inbound.get('port')
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            return None
        ports.add(port)
    if not ports or any(item.get('protocol') not in ('freedom', 'blackhole') for item in config.get('outbounds', [])):
        return None
    return ports


def filter_outbound_udp(listeners, pid, ports, ephemeral):
    kept, outbound = [], []
    for line in listeners:
        fields = line.split()
        owners = {int(value) for value in re.findall(r'pid=(\d+)', line)}
        address, _, port = fields[4].rpartition(':')
        match = ports is not None and fields[:2] == ['udp', 'UNCONN'] and owners == {pid} and address in ('*', '0.0.0.0', '[::]') and port.isdigit() and ephemeral[0] <= int(port) <= ephemeral[1] and int(port) not in ports
        if match:
            outbound.append({'pid': pid, 'port': int(port)})
        else:
            kept.append(line)
    return kept, outbound


def classify_xray_udp(state, policy):
    service = dict(line.split('=', 1) for line in state['vpn_services']['xray.service'].splitlines())
    pid = int(service['MainPID'])
    process = Path('/proc') / str(pid)
    arguments = (process / 'cmdline').read_bytes().split(b'\0')
    name = next(arguments[index + 1].decode() for index, value in enumerate(arguments[:-1]) if value in (b'-c', b'-config', b'--config'))
    assert name in policy['vpn_config_files']
    raw = Path(name).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == state['vpn_config_hashes'][name]['sha256']
    ports = tcp_inbound_ports(json.loads(raw))
    ephemeral = tuple(map(int, Path('/proc/sys/net/ipv4/ip_local_port_range').read_text().split()))
    assert len(ephemeral) == 2
    state['xray_udp_identity'] = {'pid': pid, 'start_ticks': (process / 'stat').read_text().split(') ', 1)[1].split()[19], 'binary_sha256': hashlib.sha256((process / 'exe').read_bytes()).hexdigest(), 'ephemeral_ports': ephemeral}
    state['listeners'], outbound = filter_outbound_udp(state['listeners'], pid, ports, ephemeral)
    if outbound:
        print(json.dumps({'type': 'owned_runtime_state', 'id': 'xray.outbound_udp', 'sockets': outbound}), flush=True)


def control_result(output, control, expected):
    import math
    body, seconds = output.strip().rsplit('\n', 1)
    duration = float(seconds) * 1000
    if not math.isfinite(duration) or not 0 < duration <= 3000:
        raise ValueError('invalid HTTPS duration')
    observed = dict(line.split('=', 1) for line in body.splitlines() if '=' in line).get('ip') if control == 'cloudflare' else body.strip()
    return observed == expected, duration


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

    def snapshot():
        def read():
            state, raw = baseline['inventory'](policy)
            add_fail2ban_identity(state)
            classify_xray_udp(state, policy)
            owned = exclude_owned_udp(state, policy)
            return state, raw, owned
        return stable_inventory(policy, read)

    # policy is prepared from the identified server config, not guessed names.
    before, raw, _ = snapshot()
    baseline['collisions'](policy, before)
    print(json.dumps({'type':'inventory','state':before,'raw':raw}),flush=True)
    start=time.monotonic()
    failures=0
    for index in range(count):
        scheduled=start+index*5
        time.sleep(max(0,scheduled-time.monotonic()))
        t=time.monotonic()
        state, _, owned = snapshot()
        if owned:print(json.dumps({'type':'owned_runtime_state','sequence':index+1,'sockets':owned}),flush=True)
        if not compare(before,state,index+1):
            changed=[key for key in state if state[key]!=before.get(key)]
            print(json.dumps({'type':'sample','status':'FAIL','id':'host.configuration_drift','changed_keys':changed,'sequence':index+1,'before':{k:before.get(k) for k in changed},'after':{k:state.get(k) for k in changed}}),flush=True)
            return 1
        inventory_ms=(time.monotonic()-t)*1000
        request_ms=None
        try:
            control=policy.get('https_control','ipify')
            url='https://www.cloudflare.com/cdn-cgi/trace' if control=='cloudflare' else 'https://api.ipify.org'
            output=baseline['run'](['curl','-4','--fail','--silent','--show-error','--max-time','3','--limit-rate','64k','--write-out','\n%{time_total}',url],policy['test_uid']).strip()
            ok,request_ms=control_result(output,control,policy['expected_egress'])
        except Exception:
            ok=False
        failures=0 if ok else failures+1
        elapsed=time.monotonic()-scheduled
        print(json.dumps({'type':'sample','status':'PASS' if ok and elapsed<5 else 'FAIL','id':'host.control','sequence':index+1,'duration_ms':request_ms if request_ms is not None else 3000,'inventory_duration_ms':inventory_ms,'total_duration_ms':(time.monotonic()-t)*1000,'configuration_unchanged':True,'egress_matched':ok,'scheduled_lag_ms':max(0,t-scheduled)*1000}),flush=True)
        if failures>=2 or elapsed>=5:return 1
    # Final compare after the last control request and before SSH teardown.
    final, _, _ = snapshot()
    if not compare(before,final,count+1):
        print(json.dumps({'type':'final','status':'FAIL','id':'host.final_configuration'}),flush=True);return 1
    print(json.dumps({'type':'final','status':'PASS','id':'host.final_configuration'}),flush=True)
    return 0
