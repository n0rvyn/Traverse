"""Native local admission with an actual issuer plus corrupted completion, and pending cleanup.

Private test only. The wrapper never goes in a package and exposes no product override.
Pending Stop/EOF test native cancellation only. Actual Go owner-death guard is
covered by local_certificates_helper.py; this Python wrapper has no such guard.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import tempfile
import time

from local_certificates_native import Manager, ready
from issuer_native import Upstream

WRAPPER = '''#!/usr/bin/python3
import json,os,subprocess,sys,time
from pathlib import Path
mode={mode!r}; root=Path({root!r})
request=sys.stdin.read()
json.loads(request)
(root/'wrapper-pid').write_text(str(os.getpid()))
if mode=='pending':
 while True: time.sleep(1)
p=subprocess.Popen([{issuer!r},'--supervisor-pid',str(os.getpid())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
p.stdin.write(request);p.stdin.close()
output=json.loads(p.stdout.readline());code=p.wait(timeout=15);p.stdout.close()
assert code==0 and output['status'] in ('local-issued','local-ready')
if mode=='version':output['version']=2
elif mode=='root':output['local']['root']['fingerprint']='0'*64
elif mode=='renewal':output['local']['leaf']['renewAt']+=1
elif mode=='durability':output['publication']['durable']=False
elif mode=='exit':code=1
elif mode=='unknown':output['directory']='https://unexpected.invalid/'
elif mode=='uncertain':output={{'version':1,'status':'published_durability_uncertain','code':'local_publication_uncertain','publication':{{'committed':True,'durable':False}}}};code=2
print(json.dumps(output),flush=True)
sys.exit(code)
'''


def absent_listener(port):
    with socket.socket() as stream:
        stream.settimeout(.3)
        assert stream.connect_ex(('127.0.0.1', port)) != 0, 'Unconfirmed candidate acquired application listener'


def pid_gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', required=True, type=Path)
    parser.add_argument('--issuer', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    for mode in ('control', 'version', 'root', 'renewal', 'durability', 'exit', 'unknown', 'uncertain', 'pending-stop', 'pending-eof'):
        with tempfile.TemporaryDirectory(prefix='tlca-') as temporary:
            root = Path(temporary)
            wrapper = root/'issuer-wrapper'
            wrapper.write_text(WRAPPER.format(mode='pending' if mode.startswith('pending-') else mode, root=str(root), issuer=str(args.issuer.resolve())))
            wrapper.chmod(0o700)
            upstream = Upstream(); upstream.start()
            manager = None
            try:
                manager = Manager(args.probe, wrapper, root, 'desktop.example.test', upstream)
                if mode.startswith('pending-'):
                    manager.event(lambda state: state.get('operationActive'))
                    deadline = time.monotonic()+5
                    while not (root/'wrapper-pid').exists() and time.monotonic()<deadline:
                        time.sleep(.01)
                    child = int((root/'wrapper-pid').read_text())
                    assert not pid_gone(child)
                    absent_listener(manager.port)
                    manager.command('export-ca')
                    manager.event(lambda state: state.get('publicCARejected'))
                    if mode == 'pending-eof':
                        manager.process.stdin.close()
                    else:
                        manager.command('stop')
                    manager.process.wait(timeout=8)
                    deadline = time.monotonic()+5
                    while not pid_gone(child) and time.monotonic()<deadline:
                        time.sleep(.01)
                    assert pid_gone(child), 'Pending helper survived its owned manager'
                elif mode == 'control':
                    manager.event(ready)
                else:
                    state = manager.event(lambda value: value.get('phase')=='failed')
                    assert not state['available'] and not state['frontendFingerprint']
                    absent_listener(manager.port)
                    state_root = next((root/'data/traverse/certificates').iterdir())
                    assert (state_root/'bundle.pem').is_file(), 'Mutation did not follow actual issuer publication'
                    assert not (state_root/'application.pem').exists()
                    assert not (state_root/'schedule.json').exists()
                    digest = hashlib.sha256((state_root/'local-authority.pem').read_bytes()).hexdigest()
                    manager.close(); manager = Manager(args.probe, args.issuer, root, 'desktop.example.test', upstream)
                    manager.event(ready)
                    assert hashlib.sha256((state_root/'local-authority.pem').read_bytes()).hexdigest()==digest
                print(json.dumps({'case': mode, 'status': 'passed', 'scope':'Private native manager/helper admission boundary; not installed GUI/input acceptance'}), flush=True)
            finally:
                if manager:
                    manager.close()
                upstream.close()


if __name__ == '__main__':
    main()
