"""Actual Qt public-CA picker, export and pending-write owner cleanup.

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
        endings=json.loads(os.environ.get('TRAVERSE_TEST_EXPORT_ENDINGS','["stop","close","blocked-stop"]'))
        assert endings and all(x in ('stop','close','blocked-stop','blocked-close','blocked-owner-death') for x in endings)
        for ending in endings:
            configured=json.loads(path.read_text());port=configured['port'];next_port=10443 if port==9443 else 9443
            env['TRAVERSE_TEST_BLOCK_EXPORT']='1' if ending.startswith('blocked-') else '0'
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
                assert call('view')['stopInsideWindow'] and call('view')['stopOnScreen']
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
                wait(lambda:call('exportView')['enabled'],'Ready local CA export was not available')
                exported=home/('public-'+ending+'.crt')
                assert call('click',control='exportPublicCA')['clicked']
                wait(lambda:call('exportView')['pickerVisible'],'Native public certificate picker missing')
                assert call('exportCancel')['cancelled'];assert not exported.exists()
                assert call('exportView')['feedback']!='Certificate saved.'
                if not ending.startswith('blocked-'):
                    exported.write_bytes(b'Preserve existing selected file');os.chown(exported,65534,65534)
                    assert call('click',control='exportPublicCA')['clicked']
                    wait(lambda:call('exportView')['pickerVisible'],'Native save picker did not reopen')
                    assert call('exportSelect',path=str(exported))['selected']
                    wait(lambda:call('overwrite',accept=False)['confirmationVisible'],'Standard overwrite confirmation missing')
                    assert exported.read_bytes()==b'Preserve existing selected file'
                    assert call('exportCancel')['cancelled']
                    assert call('click',control='exportPublicCA')['clicked']
                    wait(lambda:call('exportView')['pickerVisible'],'Save picker did not reopen after declined overwrite')
                    assert call('exportSelect',path=str(exported))['selected']
                    wait(lambda:call('overwrite',accept=True)['confirmationVisible'],'Overwrite confirmation missing on accepted replacement')
                    wait(lambda:call('exportView')['feedback']=='Certificate saved.','Real selected public certificate save did not finish')
                    assert exported.read_bytes()==public.read_bytes()
                    assert b'PRIVATE KEY' not in exported.read_bytes() and exported.read_bytes().count(b'BEGIN CERTIFICATE')==1
                    assert ipc(adapter,'/state')['paired'] is False
                assert not ipc(adapter,'/state')['paired']
                code=ipc(adapter,'/owner/authority')['code'];status,data=http('api/pair',{'code':code});assert status==200, ('Pair rejected',status)
                token=json.loads(data)['token'];wait(lambda:call('view')['codeUsed'],'GUI missed pairing')
                if os.environ.get('TRAVERSE_TEST_HOST_IMAGE'):assert call('snapshot')['saved']
                ipc(adapter,'/input',{'type':'key','code':'ShiftLeft','down':True},token);assert x11('query')['shift']==1
                if ending.startswith('blocked-'):
                    failure_directory=home/('cannot-save-'+ending);failure_directory.mkdir();os.chown(failure_directory,65534,65534)
                    retained=failure_directory/'existing.crt';retained.write_bytes(b'Existing public file stays unchanged');os.chown(retained,65534,65534)
                    assert call('click',control='exportPublicCA')['clicked']
                    wait(lambda:call('exportView')['pickerVisible'],'Failure-case save picker missing')
                    assert call('exportSelect',path=str(retained))['selected']
                    wait(lambda:call('overwrite',accept=True)['confirmationVisible'],'Failure-case overwrite confirmation missing')
                    wait(lambda:call('exportView')['writeEntered'],'Failure-case write did not reach pending boundary')
                    failure_directory.chmod(0o500)
                    assert call('releaseExport')['released']
                    wait(lambda:call('exportView')['feedback']=='Cannot write the certificate. Choose another location.','Actual save failure was not visible')
                    assert retained.read_bytes()==b'Existing public file stays unchanged'
                    assert x11('query')['shift']==1 and ipc(adapter,'/state')['paired'] and http()[0]==200
                    if os.environ.get('TRAVERSE_TEST_HOST_IMAGE'):assert call('snapshotError')['saved']
                    failure_directory.chmod(0o700);assert call('resetExport')['reset']
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
                if ending.startswith('blocked-'):
                    assert call('settingsClose')['closed']
                    assert call('click',control='exportPublicCA')['clicked']
                    wait(lambda:call('exportView')['pickerVisible'],'Pending export picker missing')
                    assert call('exportSelect',path=str(exported))['selected']
                    wait(lambda:call('exportView')['writeEntered'],'Private blocked write did not reach actual export boundary')
                    assert not exported.exists() and x11('query')['shift']==1
                owned=descendants(process.pid);assert owned
                if ending in ('stop','blocked-stop'):assert call('click',control='stopSharing')['clicked']
                elif ending in ('close','blocked-close'):assert call('close')['closing']
                elif ending=='blocked-owner-death':
                    supervisors=[pid for pid in owned if Path('/proc/'+str(pid)+'/exe').resolve().name=='traverse-launcher']
                    assert len(supervisors)==1;os.kill(supervisors[0],signal.SIGKILL)
                else:raise AssertionError('Unhandled private ending')
                wait(lambda:x11('query')['shift']==0,'Settings/window exit left held input',timeout=2)
                if ending=='blocked-owner-death':
                    wait(lambda:call('exportView')['feedback']=='Certificate export cancelled.','Owner EOF did not cancel pending public-file work')
                    assert call('close')['closing']
                process.wait(timeout=15)
                wait(lambda:not any(alive(pid) for pid in owned),'Settings/window exit left native children',timeout=12)
                wait(lambda:prefix_processes()==baseline,'Settings/window exit left untracked children',timeout=5)
                if ending.startswith('blocked-'):assert not exported.exists()
                reports.append({'actualDiskFailurePreservedFileAndController':ending.startswith('blocked-'),'actualNativePicker':True,'cancelWithoutOutput':True,'overwriteConfirmation':not ending.startswith('blocked-'),'publicBytesEqualActiveRoot':not ending.startswith('blocked-'),'blockedWriteCancelledBeforeOutput':ending.startswith('blocked-'),'ending':ending,'savedForNextLaunch':True,'activeURLAndTokenUnchanged':True,'heldInputPreservedThroughSave':True,'copyUsedRunningURL':True,'reopenUsedSavedPort':True,'settingsOpenDuringExit':not ending.startswith('blocked-'),'heldInputReleasedAndAllOwnedReaped':True,'runningPort':port,'nextPort':next_port,'sameRootAcrossLaunches':True})
            finally:
                if process.poll() is None:
                    process.stdin.close()
                    try:process.wait(timeout=15)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                if not process.stdin.closed:process.stdin.close()
                process.stdout.close()
        # Supplied certificates do not gain a local-CA export control, even
        # when their leaf came from a previously generated fixture authority.
        supplied=json.loads(path.read_text());supplied.pop('certificateSettings')
        supplied['certificate']=supplied['privateKey']=str(state/'application.pem')
        path.write_text(json.dumps(supplied));env['TRAVERSE_TEST_BLOCK_EXPORT']='0'
        assert (state/'application.pem').is_file()
        env['SSL_CERT_FILE']=str(public) # private supplied fixture trust, never system/client trust
        process=subprocess.Popen([str(driver)],user=65534,group=65534,extra_groups=[],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        try:
            assert read()['fixtureReady'];wait(lambda:call('view')['status']=='Waiting for Chrome','Actual supplied-mode GUI did not start',timeout=35)
            assert not call('exportView')['visible'] and not call('exportView')['enabled']
            assert call('click',control='stopSharing')['clicked'];process.wait(timeout=15);wait(lambda:not prefix_processes(),'Supplied-mode Stop left runtime')
            reports.append({'mode':'supplied','publicCAExportAbsent':True,'actualHTTPSReady':True,'runtimeReaped':True})
        finally:
            if process.poll() is None:
                process.stdin.close()
                try:process.wait(timeout=15)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            if not process.stdin.closed:process.stdin.close()
            process.stdout.close()
        print(json.dumps({'status':'passed','scope':'Current Qt public export/Settings GUI + current launcher over exact portable basis on isolated X11 UID65534; real HTTPS/pair/input, not Chrome/desktop/hardware acceptance','cases':reports}),flush=True)


if __name__=='__main__':main()
