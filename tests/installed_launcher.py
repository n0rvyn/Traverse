"""Run the real installed launcher and verify validation, TLS and crash cleanup."""
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
        tcp.bind(('127.0.0.1',0));port=tcp.getsockname()[1];udp.bind(('127.0.0.1',port));return port


def children(pid):
    try:return [int(p) for p in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]
    except FileNotFoundError:return []


def alive(pid):
    try:return Path(f'/proc/{pid}/stat').read_text().split(') ',1)[1][0]!='Z'
    except FileNotFoundError:return False


with tempfile.TemporaryDirectory(prefix='traverse-launcher-') as tmp:
    directory=Path(tmp);runtime=directory/'runtime';runtime.mkdir(mode=0o700)
    certificate=directory/'cert.pem';key=directory/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(certificate)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    port=free_port();media=free_port()
    while media==port:media=free_port()
    config={'origin':f'https://localhost:{port}','certificate':str(certificate),'privateKey':str(key),'httpsPort':port,'mediaPort':media,'listenAddress':'127.0.0.1'}
    path=directory/'config.json'
    env=dict(os.environ,XDG_RUNTIME_DIR=str(runtime),XDG_CACHE_HOME=str(directory/'cache'))
    for broken in [dict(config,httpsPort='443'),dict(config,httpsPort=18446744073709552616),dict(config,origin='https://localhost/path'),dict(config,mediaPort=port),dict(config,unrecognized=True)]:
        path.write_text(json.dumps(broken))
        p=subprocess.run(['traverse','--config',str(path),'--check-config'],env=env,capture_output=True,text=True)
        assert p.returncode!=0,(broken,p.stdout,p.stderr)
        assert not (runtime/'traverse/adapter.sock').exists()
    path.write_text(json.dumps(config))
    subprocess.run(['traverse','--config',str(path),'--check-config'],env=env,check=True)
    context=ssl.create_default_context(cafile=str(certificate))
    for crash in (False,True):
        launcher_log=tempfile.TemporaryFile(mode='w+')
        launch=subprocess.Popen(['traverse','--config',str(path)],env=env,stdout=subprocess.DEVNULL,stderr=launcher_log)
        owned=[]
        last_response=None
        def failure(message):
            launcher_log.seek(0)
            return AssertionError(message+' '+json.dumps(dict(children=owned,lastResponse=last_response,
                launcherErrors=launcher_log.read())))
        try:
            end=time.monotonic()+20
            while time.monotonic()<end:
                if launch.poll() is not None:raise failure('Launcher exited before HTTPS readiness')
                owned=children(launch.pid)
                try:
                    urllib.request.urlopen(config['origin']+'/api/stats',context=context,timeout=1)
                except urllib.error.HTTPError as error:
                    last_response=dict(status=error.code)
                    if error.code==403 and len(owned)==2:break
                except (urllib.error.URLError,TimeoutError) as error:last_response=dict(error=str(error))
                time.sleep(.05)
            else:raise failure('Installed supervisor did not start the real HTTPS service')
            # A second launcher cannot replace or revoke this existing instance.
            duplicate=subprocess.run(['traverse','--config',str(path)],env=env,capture_output=True,text=True,timeout=10)
            assert duplicate.returncode!=0 and all(alive(pid) for pid in owned)
            if crash:launch.kill()
            else:launch.terminate()
            launch.wait(timeout=20)
            end=time.monotonic()+10
            while time.monotonic()<end and any(alive(pid) for pid in owned):time.sleep(.05)
            assert not any(alive(pid) for pid in owned),('Children survived launcher',crash,owned)
            print(json.dumps({'launcherCrash':crash,'ownedChildrenExited':True,'duplicateRejected':True}))
        finally:
            if launch.poll() is None:launch.terminate();launch.wait(timeout=20)
            for pid in owned:
                if not alive(pid):continue
                fd=os.pidfd_open(pid)
                try:
                    executable=os.readlink(f'/proc/{pid}/exe')
                    prefix=Path(os.path.realpath(shutil.which('traverse'))).parent.parent/'libexec/traverse'
                    assert Path(executable).parent==prefix and Path(executable).name in ('traverse-adapter','traverse-service')
                    signal.pidfd_send_signal(fd,signal.SIGTERM)
                finally:os.close(fd)
            launcher_log.close()
