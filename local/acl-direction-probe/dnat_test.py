#!/usr/bin/env python3
"""Real netfilter regression tests; isolated containers, never host networking."""
import base64
import copy
import json
import pathlib
import subprocess
import time

HERE = pathlib.Path(__file__).resolve().parents[2]
IMAGE = 'local/netclient-acl-probe:v1.7.0'
VPN, LAN = 'nm-dnat-vpn-test', 'nm-dnat-lan-test'
ART = HERE / '.local-artifacts' / 'dnat-test'

def run(args, check=True):
    p = subprocess.run(args, text=True, capture_output=True)
    if check and p.returncode:
        raise RuntimeError(f'{args}: {p.stdout} {p.stderr}')
    return p

def exe(name, *args):
    return run(['docker', 'exec', name, *args])

def ipnet(ip):
    return {'IP': ip, 'Mask': base64.b64encode(b'\xff' * 4).decode()}

def policy(port='8090', proto='tcp', key='permit'):
    return {'id': key, 'ip_list': [ipnet('100.91.0.1')], 'dst': [ipnet('100.91.0.2')],
            'allowed_protocols': proto, 'allowed_ports': [] if port is None else [port], 'Allowed': True, 'direction': 0}

def update(rules):
    payload = {'allow_all': False, 'acl_rules': {r['id']: r for r in rules}}
    p = ART/'router.json'
    # Preserve the inode for the bind mount.
    p.write_text(json.dumps(payload))
    return p

def applied():
    return run(['docker','logs','nm-dnat-r']).stdout.count('APPLIED')

def reload(rules):
    previous = applied(); update(rules)
    run(['docker','kill','--signal','HUP','nm-dnat-r'])
    for _ in range(60):
        if applied() > previous: return
        time.sleep(.1)
    raise RuntimeError('ACL reload did not complete')

def probe(name, port, allowed, proto='tcp', ip='100.91.0.2'):
    p = run(['docker','exec',name,'acl-direction-probe','connect',proto,f'{ip}:{port}'],False)
    out = p.stdout+p.stderr
    assert (p.returncode == 0 and 'PASS' in out) if allowed else (p.returncode != 0 and 'timeout' in out), out
    print(f'{name} {proto} {ip}:{port}: '+('allowed + reply' if allowed else 'blocked'),flush=True)

ART.mkdir(parents=True,exist_ok=True)
run(['docker','network','create','--internal','--subnet','100.91.0.0/24','--gateway','100.91.0.254',VPN])
try:
    run(['docker','network','create','--internal','--subnet','172.29.91.0/24','--gateway','172.29.91.254',LAN])
    try:
        for backend in ('iptables','nftables'):
            names=[]
            try:
                print('BACKEND '+backend,flush=True)
                fixture=update([policy()])
                for name, network, ip, echo in [('nm-dnat-a',VPN,'100.91.0.1',True),('nm-dnat-c',VPN,'100.91.0.3',True),('nm-dnat-b',LAN,'172.29.91.2',True),('nm-dnat-r',VPN,'100.91.0.2',False)]:
                    names.append(name)
                    args=['docker','run','-d','--platform','linux/amd64','--cap-add','NET_ADMIN','--sysctl','net.ipv4.ip_forward=1','--network',network,'--ip',ip,'--name',name,'-e','FIREWALL_BACKEND='+backend,'-e','ACL_DIRECTION_LOCAL_ADDRESS='+ip,'-v',str(fixture)+':/fixture.json:ro']
                    if echo: args+=['-e','ACL_DIRECTION_ECHO_ONLY=1']
                    run(args+[IMAGE])
                run(['docker','network','connect','--ip','172.29.91.1',LAN,'nm-dnat-r'])
                for name in names:
                    for _ in range(60):
                        if 'READY' in run(['docker','logs',name]).stdout:break
                        time.sleep(.1)
                    else:raise RuntimeError(run(['docker','logs',name],False).stdout)
                # Separate NAT table; same before-filter translation as Docker.
                nat='table ip dnat_test { chain prerouting { type nat hook prerouting priority -100; policy accept; iifname "netmaker" ip daddr 100.91.0.2 tcp dport {8090, 8091} dnat to 172.29.91.2:18080; iifname "netmaker" ip daddr 100.91.0.2 udp dport 8090 dnat to 172.29.91.2:18081; }; chain postrouting { type nat hook postrouting priority 100; policy accept; ip daddr 172.29.91.2 masquerade; }; }'
                exe('nm-dnat-r','nft',nat)
                for name in ('nm-dnat-a','nm-dnat-c'):
                    exe(name,'ip','route','add','172.29.91.0/24','via','100.91.0.2')
                probe('nm-dnat-a',8090,True)
                probe('nm-dnat-a',8091,False)
                probe('nm-dnat-c',8090,False)
                probe('nm-dnat-a',8090,False,'udp')
                probe('nm-dnat-a',18080,False,ip='172.29.91.2')
                # A later host firewall must still be able to reject a permitted packet.
                if backend=='iptables':
                    exe('nm-dnat-r','iptables','-A','FORWARD','-p','tcp','--dport','18080','-j','DROP')
                else:
                    exe('nm-dnat-r','nft','add rule inet filter FORWARD tcp dport 18080 drop comment "after-acl-test"')
                probe('nm-dnat-a',8090,False)
                if backend=='iptables':
                    exe('nm-dnat-r','iptables','-D','FORWARD','-p','tcp','--dport','18080','-j','DROP')
                else:
                    data=json.loads(exe('nm-dnat-r','nft','-j','list','chain','inet','filter','FORWARD').stdout)
                    for item in data['nftables']:
                        r=item.get('rule',{})
                        if r.get('comment')=='after-acl-test':exe('nm-dnat-r','nft','delete','rule','inet','filter','FORWARD','handle',str(r['handle']))
                reload([policy('8091')]);probe('nm-dnat-a',8090,False);probe('nm-dnat-a',8091,True)
                reload([policy('8090-8091')]);probe('nm-dnat-a',8090,True);probe('nm-dnat-a',8091,True)
                reload([policy(),policy(key='overlap')]);probe('nm-dnat-a',8090,True)
                reload([policy(key='overlap')]);probe('nm-dnat-a',8090,True)
                reload([]);probe('nm-dnat-a',8090,False);probe('nm-dnat-a',8091,False)
                reload([policy(None,'all')]);probe('nm-dnat-a',8090,True);probe('nm-dnat-a',8091,True);probe('nm-dnat-a',8090,True,'udp');probe('nm-dnat-c',8090,False)
                print(backend+' DNAT lifecycle PASS',flush=True)
            except Exception:
                for name in names:
                    (ART/(backend+'-'+name+'.log')).write_text(run(['docker','logs',name],False).stdout)
                (ART/(backend+'-rules.txt')).write_text(exe('nm-dnat-r','nft','-a','list','ruleset').stdout)
                raise
            finally:
                for name in names:run(['docker','rm','-f',name],False)
    finally:run(['docker','network','rm',LAN],False)
finally:run(['docker','network','rm',VPN],False)
