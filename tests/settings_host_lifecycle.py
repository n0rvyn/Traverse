"""Actual Qt Settings over the exact private package, with live owner/input and next launch.

Disposable X11 only; no Chrome/desktop/physical latency acceptance claim.
"""
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import select
import shutil
import signal
import ssl
import subprocess
import tempfile

from installed_managed_certificates import PREFIX, prefix_processes, require_disposable_environment
from installed_standalone import alive, descendants, ipc, wait
from issuer_native import DOMAIN


def main():
    require_disposable_environment()
    driver=Path(os.environ['TRAVERSE_TEST_HOST_DRIVER'])
    with tempfile.TemporaryDirectory(prefix='settings-owner-') as temporary:
        root=Path(temporary);root.chmod(0o755)
        home=root/'home';home.mkdir(mode=0o700);os.chown(home,65534,65534)
        runtime=home/'runtime';runtime.mkdir(mode=0o700);os.chown(runtime,65534,65534)
        authority=home/'Xauthority';shutil.copyfile(os.environ['XAUTHORITY'],authority);authority.chmod(0o600);os.chown(authority,65534,65534)
        path=home/'config.json'
        config={'schemaVersion':1,'domain':DOMAIN,'port':9443,'basePath':'/','listenAddress':'127.0.0.1','certificateSettings':{'mode':'local'}}
        path.write_text(json.dumps(config));path.chmod(0o600);os.chown(path,65534,65534)
        env=dict(os.environ,HOME=str(home),XDG_DATA_HOME=str(home/'data'),XDG_RUNTIME_DIR=str(runtime),XDG_CACHE_HOME=str(home/'cache'),XAUTHORITY=str(authority),QT_QPA_PLATFORM='xcb',TRAVERSE_TEST_HOST_PREFIX=str(PREFIX),TRAVERSE_TEST_HOST_CONFIG=str(path))
        for key in ('LD_LIBRARY_PATH','TRAVERSE_RUNTIME_PREFIX','GST_PLUGIN_PATH_1_0','GST_PLUGIN_SYSTEM_PATH_1_0','GST_PLUGIN_SCANNER','GST_REGISTRY'):env.pop(key,None)
        adapter=runtime/'traverse/adapter.sock';reports=[];root_identity=None
        for ending in ('stop','close','death'):
            configured=json.loads(path.read_text());port=configured['port'];next_port=10443 if port==9443 else 9443
            baseline=prefix_processes();process=subprocess.Popen([str(driver)],user=65534,group=65534,extra_groups=[],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
            def read():
                assert select.select([process.stdout],[],[],15)[0],'Settings fixture reply timeout'
                return json.loads(process.stdout.readline())
            def call(action,**values):
                process.stdin.write(json.dumps(dict(action=action,**values))+'\n');process.stdin.flush();return read()
            def x11(*args):return json.loads(subprocess.check_output(['/tmp/x11-probe',*args],env=env,text=True))
            try:
                assert read()['fixtureReady']
                wait(lambda:call('view')['status']=='Waiting for Chrome','Configured GUI failed local startup',timeout=35)
                state=next((home/'data/traverse/certificates').iterdir());public=state/'local-ca.pem'
                digest=hashlib.sha256(public.read_bytes()).hexdigest()
                if root_identity is None:root_identity=digest
                assert digest==root_identity,'Next-launch port change replaced authority'
                context=ssl.create_default_context(cafile=str(public))
                def http(route='',body=None,token=None):
                    stream=context.wrap_socket(__import__('socket').create_connection(('127.0.0.1',port),timeout=4),server_hostname=DOMAIN)
                    connection=HTTPConnection('127.0.0.1');connection.sock=stream
                    headers={'Content-Type':'application/json','Origin':'https://'+DOMAIN+':'+str(port)}
                    if token:headers['Authorization']='Bearer '+token
                    connection.request('POST' if body is not None else 'GET','/'+route,None if body is None else json.dumps(body),headers)
                    response=connection.getresponse();status=response.status;data=response.read();connection.close();return status,data
                assert http()[0]==200
                assert not ipc(adapter,'/state')['paired']
                code=ipc(adapter,'/owner/authority')['code'];status,data=http('api/pair',{'code':code});assert status==200, ('Pair rejected',status)
                token=json.loads(data)['token'];wait(lambda:call('view')['codeUsed'],'GUI missed pairing')
                ipc(adapter,'/input',{'type':'key','code':'ShiftLeft','down':True},token);assert x11('query')['shift']==1
                assert call('click',control='settingsButton')['clicked']
                wait(lambda:call('settingsView')['saveEnabled'],'Settings failed to load')
                assert call('settingsSave',port=str(next_port))['accepted']
                def saved():
                    ipc(adapter,'/input',{'type':'heartbeat'},token)
                    return call('settingsView')['feedback']=='Saved. Changes take effect the next time you launch Traverse.'
                wait(saved,'Settings did not confirm actual durable save')
                expected=dict(configured,port=next_port);assert json.loads(path.read_text())==expected
                assert x11('query')['shift']==1 and ipc(adapter,'/state')['paired'] and http()[0]==200
                assert call('settingsClose')['closed'];assert call('click',control='copyUrl')['clicked']
                probe=subprocess.run([str(driver),'--clipboard-probe'],input=json.dumps({'expected':'https://'+DOMAIN+':'+str(port)+'/'})+'\n',user=65534,group=65534,extra_groups=[],env=env,text=True,capture_output=True,timeout=5)
                assert probe.returncode==0 and json.loads(probe.stdout)=={'matches':True}
                assert call('click',control='settingsButton')['clicked'];wait(lambda:call('settingsView')['saveEnabled'],'Saved Settings failed reopen')
                assert call('settingsView')['port']==str(next_port)
                # Leave Settings open: owner Stop/close/death must still work.
                owned=descendants(process.pid);assert owned
                if ending=='stop':assert call('click',control='stopSharing')['clicked']
                elif ending=='close':assert call('close')['closing']
                else:process.kill()
                wait(lambda:x11('query')['shift']==0,'Settings/window exit left held input',timeout=2)
                process.wait(timeout=15)
                wait(lambda:not any(alive(pid) for pid in owned),'Settings/window exit left native children',timeout=12)
                wait(lambda:prefix_processes()==baseline,'Settings/window exit left untracked children',timeout=5)
                reports.append({'ending':ending,'savedForNextLaunch':True,'activeURLAndTokenUnchanged':True,'heldInputPreservedThroughSave':True,'copyUsedRunningURL':True,'reopenUsedSavedPort':True,'settingsOpenDuringExit':True,'heldInputReleasedAndAllOwnedReaped':True,'runningPort':port,'nextPort':next_port,'sameRootAcrossLaunches':True})
            finally:
                if process.poll() is None:
                    process.stdin.close()
                    try:process.wait(timeout=15)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                if not process.stdin.closed:process.stdin.close()
                process.stdout.close()
        print(json.dumps({'status':'passed','scope':'Current Qt GUI + exact portable package on isolated X11 UID65534; real HTTPS/pair/input, not Chrome/desktop/hardware acceptance','cases':reports}),flush=True)


if __name__=='__main__':main()
