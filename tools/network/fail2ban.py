"""Narrow, explicitly authorized exception for Fail2Ban's SSH-only runtime ban set.
Never changes a firewall. All non-element fields and every rule stay comparable.
"""
import copy
import ipaddress
import json


def reconcile_sshd_bans(before, after, manager_bans):
    """Return an updated expected snapshot only for a verified SSH ban-set change.

    manager_bans comes from `fail2ban-client get sshd banip` on the same host.
    Fail closed on unknown nft encodings, structural changes or non-SSH references.
    """
    expected = copy.deepcopy(before)
    previous = before.get('nftables', [])
    current = after.get('nftables', [])
    if len(previous) != len(current):
        raise ValueError('firewall objects changed')
    authorized = {str(ipaddress.ip_address(ip)) for ip in manager_bans}
    changes = []
    for i, (old, new) in enumerate(zip(previous, current)):
        if old == new:
            continue
        if set(old) != {'set'} or set(new) != {'set'}:
            raise ValueError('firewall rule or object changed')
        a, b = old['set'], new['set']
        identity = ('inet', 'f2b-table', 'addr-set-sshd', 'ipv4_addr')
        if tuple(a.get(k) for k in ('family', 'table', 'name', 'type')) != identity:
            raise ValueError('unrecognized dynamic set')
        if {k: v for k, v in a.items() if k != 'elem'} != {k: v for k, v in b.items() if k != 'elem'}:
            raise ValueError('set configuration changed')
        # This exact set must be referenced by exactly one SSH-only input rule.
        references = []
        for obj in previous:
            rule = obj.get('rule')
            if rule and any(x.get('match', {}).get('right') == '@addr-set-sshd' for x in rule.get('expr', [])):
                references.append(rule)
        if len(references) != 1 or json.dumps(previous).count('"@addr-set-sshd"') != 1:
            raise ValueError('unexpected set references')
        rule = references[0]
        if rule.get('family') != 'inet' or rule.get('table') != 'f2b-table' or rule.get('chain') != 'f2b-chain':
            raise ValueError('unexpected enforcement rule')
        ssh_match = {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}}, 'right': 22}}
        if ssh_match not in rule.get('expr', []):
            raise ValueError('dynamic ban set not restricted to SSH')
        old_ips = {str(ipaddress.IPv4Address(v)) for v in a.get('elem', [])}
        new_ips = {str(ipaddress.IPv4Address(v)) for v in b.get('elem', [])}
        if new_ips != authorized:
            raise ValueError('nft ban list does not match live Fail2Ban SSH jail')
        changes.append({'set': 'f2b-table/addr-set-sshd', 'added': len(new_ips - old_ips), 'removed': len(old_ips - new_ips)})
        expected['nftables'][i] = copy.deepcopy(new)
    if expected != after:
        raise ValueError('other firewall state changed')
    return expected, changes
