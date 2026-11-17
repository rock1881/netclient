#!/usr/bin/env python3
"""Exercise the real Netclient firewall in disposable network namespaces."""
import json
import pathlib
import subprocess
import time

HERE=pathlib.Path(__file__).resolve().parents[2]
FIXTURES=HERE.parent/'netmaker'/'.local-artifacts'
IMAGE='local/netclient-acl-probe:v1.7.0'
NETWORK='netmaker-acl-direction-test'

def run(args,check=True):
    p=subprocess.run(args,text=True,capture_output=True)
    if check and p.returncode:
        raise RuntimeError(f'{args}: {p.stdout} {p.stderr}')
    return p

def probe(name, protocol, target, allowed):
    p=run(['docker','exec',name,'acl-direction-probe','connect',protocol,target],False)
    output=p.stdout+p.stderr
    if allowed:
        assert p.returncode==0 and 'PASS' in output,output
    else:
        assert p.returncode!=0 and 'timeout' in output,output
    print(f'{name}: {protocol} {target}: '+('request + reply allowed' if allowed else 'reverse NEW blocked'),flush=True)

if __name__=='__main__':
    for i in (0,1):assert (FIXTURES/f'device-to-device-{i}.json').is_file()
    run(['docker','network','create','--internal','--subnet','100.90.0.0/24','--gateway','100.90.0.254',NETWORK])
    try:
        for version in ('v1.7.0','v1.6.0'):
            for backend in ('iptables','nftables'):
                names=[]
                try:
                    for i,side in enumerate(('a','b')):
                        name=f'nm-dir-{side}';names.append(name)
                        args=['docker','run','-d','--platform','linux/amd64','--cap-add','NET_ADMIN',
                              '--network',NETWORK,'--ip',f'100.90.0.{i+1}','--name',name,
                              '-e','FIREWALL_BACKEND='+backend,
                              '-v',str(FIXTURES/f'device-to-device-{i}.json')+':/fixture.json:ro']
                        if version=='v1.6.0':
                            binary=HERE/'.local-artifacts'/'acl-direction-probe-v1.6.0'
                            assert binary.is_file()
                            args+=['-v',str(binary)+':/usr/local/bin/acl-direction-probe:ro']
                        run(args+[IMAGE])
                    for name in names:
                        for _ in range(30):
                            logs=run(['docker','logs',name]).stdout
                            if 'READY' in logs:break
                            time.sleep(0.3)
                        else:raise RuntimeError(run(['docker','logs',name],False))
                    print(f'Version {version}, backend {backend}',flush=True)
                    for protocol,port in (('tcp',18080),('udp',18081)):
                        probe(names[0],protocol,f'100.90.0.2:{port}',True)
                        probe(names[1],protocol,f'100.90.0.1:{port}',False)
                    for name,ip,allowed in ((names[0],'100.90.0.2',True),(names[1],'100.90.0.1',False)):
                        p=run(['docker','exec',name,'ping','-n','-c','1','-W','2',ip],False)
                        assert (p.returncode==0)==allowed,p.stdout+p.stderr
                    print('ICMP direction PASS',flush=True)
                finally:
                    for name in names:run(['docker','rm','-f',name],False)
    finally:
        run(['docker','network','rm',NETWORK],False)
