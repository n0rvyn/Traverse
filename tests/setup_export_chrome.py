"""Fresh actual main -> native export -> separate ordinary Chrome trust/control.

Only isolated UIDs/homes/NSS and synthetic X11; no real client trust or public deployment.
"""
import base64
import hashlib
from http.client import HTTPConnection
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from contextlib import ExitStack

from chrome_fixture import Browser, CLIENT_UID, CLIENT_GID, PAIRING_READY, ensure_client_identity
from installed_managed_certificates import PREFIX, prefix_processes, require_disposable_environment
from installed_standalone import alive, descendants, ipc, wait
from issuer_native import DOMAIN
from host_package_fixture import host_command, check_ui_process
from readiness_observer_test import DNS,hosts_file


def main():
    require_disposable_environment()
    assert not any(row.split()[1]=='00000000' for row in Path('/proc/net/route').read_text().splitlines()[1:]),'Unexpected Internet route'
    port=int(os.environ.get('TRAVERSE_TEST_CHROME_INITIAL_PORT','9443'));origin='https://'+DOMAIN+(':'+str(port) if port!=443 else '')
    executable=Path(os.environ['TRAVERSE_TEST_HOST_EXECUTABLE']);evidence=Path(os.environ['TRAVERSE_TEST_EVIDENCE']);evidence.mkdir(exist_ok=True)
    ensure_client_identity()
    from chrome_loading_guard import verify_loading_guard
    verify_loading_guard(PREFIX/'share/traverse/web', evidence)
    with tempfile.TemporaryDirectory(prefix='setup-chrome-') as temporary,ExitStack() as mappings:
        root=Path(temporary);root.chmod(0o755)
        host=root/'host';client=root/'client'
        for p,uid in ((host,65534),(client,CLIENT_UID)):
            p.mkdir(mode=0o700);os.chown(p,uid,uid);(p/'runtime').mkdir(mode=0o700);os.chown(p/'runtime',uid,uid)
        authority=host/'Xauthority';shutil.copyfile(os.environ['XAUTHORITY'],authority);authority.chmod(0o600);os.chown(authority,65534,65534)
        env=dict(os.environ,HOME=str(host),XDG_DATA_HOME=str(host/'data'),XDG_RUNTIME_DIR=str(host/'runtime'),XDG_CACHE_HOME=str(host/'cache'),XAUTHORITY=str(authority),QT_QPA_PLATFORM='xcb')
        for key in ('XDG_CONFIG_HOME','LD_LIBRARY_PATH','TRAVERSE_RUNTIME_PREFIX','GST_PLUGIN_PATH_1_0','GST_PLUGIN_SYSTEM_PATH_1_0','GST_PLUGIN_SCANNER','GST_REGISTRY'):env.pop(key,None)
        client_env=dict(env,HOME=str(client),XDG_RUNTIME_DIR=str(client/'runtime'),XDG_DATA_HOME=str(client/'.local/share'),XDG_CONFIG_HOME=str(client/'.config'),XDG_CACHE_HOME=str(client/'.cache'))
        client_env.pop('XAUTHORITY',None)
        config=host/'.config/traverse/config.json';exported=host/'exported-ca.crt';adapter=host/'runtime/traverse/adapter.sock'
        process=browser=dns=resources=None
        diagnostics=[]
        pairing_consumed=False
        def diagnostic(stage):
            row={'stage':stage,'uiExit':process.poll() if process else None}
            children=[]
            if process:
                for pid in descendants(process.pid):
                    try:
                        fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in Path('/proc',str(pid),'status').read_text().splitlines() if ':' in line}
                        children.append({key:fields[key] for key in ('Name','State','Pid','PPid','VmRSS') if key in fields})
                    except FileNotFoundError:pass
            row['children']=children
            try:
                state=ipc(adapter,'/state')
                row['adapter']={key:state[key] for key in ('pid','armed','paired','capturing','accepted','denied') if key in state}
            except OSError as failure:row['adapterError']=type(failure).__name__
            try:row['nativePeer']=service_peer()
            except (OSError,AssertionError,ValueError) as failure:row['nativePeerError']=type(failure).__name__
            row['windows']={title:window(title) is not None for title in ('Traverse','Traverse Settings','Traverse sharing')}
            if browser:
                try:
                    # Never retain page URLs, code values, HTTP bodies or headers.
                    row['browser']=browser.evaluate("({documentReady:document.readyState,handlerReady:typeof document.getElementById('pairForm')?.onsubmit==='function',moduleReady:typeof window.traverseStats==='function',hasQuery:location.search.length>0,hasPairError:!!document.getElementById('error')?.textContent,connected:document.body.classList.contains('connected'),videoReady:document.getElementById('desktop')?.readyState})")
                    row['browserResponses']=[{'path':urlsplit(value['url']).path,'status':value['status']}
                        for value in browser.cdp.responses if urlsplit(value['url']).path in ('/client.js','/api/pair','/api/offer')]
                except Exception as failure:row['browserError']=type(failure).__name__
            diagnostics.append(row)
            (evidence/'settings-process-diagnostics.json').write_text(json.dumps(diagnostics,indent=2)+'\n')
        def x11(*args):return json.loads(subprocess.check_output(['/tmp/x11-probe',*map(str,args)],env=env,text=True))
        def window(title):
            r=subprocess.run(['/tmp/x11-probe','window',title],env=env,capture_output=True,text=True)
            return json.loads(r.stdout) if r.returncode==0 else None
        def service_peer():
            paths=list((host/'runtime/traverse').glob('o-*/s'));assert len(paths)==1,'Owned service socket not unique'
            connection=HTTPConnection('localhost',timeout=3);connection.sock=socket.socket(socket.AF_UNIX)
            connection.sock.settimeout(3)
            try:
                connection.sock.connect(str(paths[0]))
                pid,uid,_=struct.unpack('3i',connection.sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
                assert uid==65534 and pid in descendants(process.pid),'Private peer is not an owned service'
                assert Path('/proc',str(pid),'exe').resolve()==PREFIX/'libexec/traverse/traverse-service'
                connection.request('GET','/state');response=connection.getresponse();value=json.loads(response.read())
                assert response.status==200 and value['schemaVersion']==1 and value['pid']==pid
                assert 0<=int(time.monotonic()*1000)-value['observedMonotonicMs']<=2000,'Private peer observation is stale'
                return {key:value[key] for key in ('schemaVersion','pid','observedMonotonicMs','generation','peerPresent','peerActive','rtcState','controlOpen')}
            finally:connection.close()
        def text(value):
            for ch in value:
                shifted=ch=='_' or ch.isupper()
                name={'.':'period','/':'slash','-':'minus','_':'minus'}.get(ch,ch.lower())
                if shifted:x11('key','Shift_L','down')
                x11('press',name)
                if shifted:x11('key','Shift_L','up')
        def replace(value):
            x11('key','Control_L','down');x11('press','a');x11('key','Control_L','up');text(value)
        def launch():
            command,application_env=host_command(executable,PREFIX,env)
            return subprocess.Popen(command,env=application_env,user=65534,group=65534,extra_groups=[],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def click(title,x,y):
            w=window(title);assert w and w['width']==520,('Unexpected observed window geometry',w)
            x11('focus',title);x11('move',w['x']+x,w['y']+y);x11('click')
        try:
            if os.environ.get('TRAVERSE_TEST_RESOURCE_TRACE')=='1':
                from resource_fixture import ResourceTrace
                resources=ResourceTrace(evidence/'resource-pressure.jsonl')
            dns=DNS()
            positive='hosts-counter-control.example.test';dns.set(positive,['127.0.0.1'])
            assert socket.getaddrinfo(positive,None,socket.AF_INET,socket.SOCK_STREAM)
            assert any(name==positive for name,kind in dns.queries),'DNS query counter positive control absent'
            dns.set(DOMAIN,'drop','drop')
            mappings.enter_context(hosts_file('127.0.0.1 '+DOMAIN))
            process=launch();wait(lambda:window('Traverse setup'),'Actual fresh setup missing')
            check_ui_process(process,PREFIX)
            assert not config.exists();x11('focus','Traverse setup');text(DOMAIN);x11('press','Tab');replace(str(port));x11('press','Tab');x11('press','Tab');x11('press','space')
            wait(lambda:config.is_file(),'Actual first Start did not publish config');saved=json.loads(config.read_text())
            assert saved['port']==port and saved['domain']==DOMAIN and saved['certificateSettings']=={'mode':'local'}
            wait(lambda:window('Traverse'),'Actual main did not open sharing')
            def ready():
                try:return bool(ipc(adapter,'/owner/authority').get('code')) and bool(list((host/'data/traverse/certificates').glob('*/local-ca.pem')))
                except OSError:return False
            wait(ready,'Actual native owner did not prepare local authority',timeout=35)
            public=next((host/'data/traverse/certificates').glob('*/local-ca.pem'));root_hash=hashlib.sha256(public.read_bytes()).hexdigest()
            bootstrap_context=ssl.create_default_context(cafile=str(public))
            def frontend_ready():
                try:
                    with bootstrap_context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=3),server_hostname=DOMAIN):return True
                except OSError:return False
            wait(frontend_ready,'Actual local HTTPS not ready for export',timeout=35)
            check_ui_process(process,PREFIX)
            # Positions come from the inspected current 520x440 native render;
            # only mapped window origin comes from X11, never guessed screen coordinates.
            click('Traverse',434,100);wait(lambda:window('Export CA certificate'),'Actual main export picker missing')
            x11('focus','Export CA certificate');replace(str(exported));x11('press','Return')
            wait(lambda:exported.is_file(),'Actual main native picker did not export certificate')
            assert exported.read_bytes()==public.read_bytes() and b'PRIVATE KEY' not in exported.read_bytes()
            context=ssl.create_default_context(cafile=str(exported));url=origin+'/'
            def https():
                connection=HTTPConnection('127.0.0.1');connection.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=3),server_hostname=DOMAIN);connection.request('GET','/');r=connection.getresponse();status=r.status;r.read();connection.close();return status
            wait(lambda:https()==200,'Exported CA did not verify actual HTTPS')
            client_ca=client/'traverse-ca.crt';shutil.copyfile(exported,client_ca);client_ca.chmod(0o600);os.chown(client_ca,CLIENT_UID,CLIENT_GID)
            browser=Browser(client,client/'untrusted',client_env);assert browser.navigate(url).get('errorText','').startswith('net::ERR_CERT_');browser.close();browser=None
            nss=client/'.local/share/pki/nssdb';nss.mkdir(parents=True,exist_ok=True)
            for p in (client/'.local',client/'.local/share',client/'.local/share/pki',nss):p.chmod(0o700);os.chown(p,CLIENT_UID,CLIENT_GID)
            def client_run(args):return subprocess.run(args,env=client_env,user=CLIENT_UID,group=CLIENT_GID,extra_groups=[],check=True,capture_output=True,text=True,timeout=20)
            if not (nss/'cert9.db').exists():client_run(['certutil','-N','--empty-password','-d','sql:'+str(nss)])
            assert 'Traverse exported fixture CA' not in client_run(['certutil','-L','-d','sql:'+str(nss)]).stdout
            client_run(['certutil','-A','-d','sql:'+str(nss),'-t','C,,','-n','Traverse exported fixture CA','-i',str(client_ca)])
            browser=Browser(client,client/'trusted',client_env);assert not browser.navigate(url).get('errorText')
            browser.wait(PAIRING_READY,'Export-trusted Chrome pairing page')
            diagnostic('before-pair-submit')
            code=ipc(adapter,'/owner/authority')['code'];browser.evaluate("document.getElementById('code').value="+json.dumps(code));browser.evaluate("document.getElementById('pairForm').requestSubmit()");del code
            browser.wait("document.body.classList.contains('connected') && document.getElementById('desktop').videoWidth>0 && document.getElementById('desktop').readyState>=2",'Fresh setup/export ordinary Chrome real video')
            video_size=browser.evaluate("({width:document.getElementById('desktop').videoWidth,height:document.getElementById('desktop').videoHeight})")
            pairing_consumed=True
            native_peer=None
            def native_connected():
                nonlocal native_peer
                try:native_peer=service_peer()
                except OSError:return False
                return native_peer['peerActive'] and native_peer['controlOpen'] and native_peer['rtcState']=='connected'
            wait(native_connected,'Native service did not report established Chrome control')
            browser.evaluate("document.getElementById('desktop').focus()");browser.key('keyDown','Shift','ShiftLeft',16)
            wait(lambda:x11('query')['shift']==1,'Fresh exported-CA Chrome input missing');browser.key('keyUp','Shift','ShiftLeft',16);wait(lambda:x11('query')['shift']==0,'Initial Chrome input release missing')
            frames=browser.evaluate("document.getElementById('desktop').getVideoPlaybackQuality().totalVideoFrames")
            click('Traverse',460,31);wait(lambda:window('Traverse Settings'),'Actual Settings missing')
            click('Traverse Settings',250,58);replace('10443')
            # The inspected native form puts Port at this local coordinate;
            # Tab traverses certificate method then Save.
            x11('press','Tab');x11('press','Tab');x11('press','space')
            wait(lambda:json.loads(config.read_text())['port']==10443,'Actual Settings did not save next-launch port')
            assert https()==200 and ipc(adapter,'/state')['paired'];x11('close','Traverse Settings')
            browser.wait("document.getElementById('desktop').getVideoPlaybackQuality().totalVideoFrames>"+str(frames),'Video did not continue through next-launch Settings save')
            browser.evaluate("document.getElementById('desktop').focus()");browser.key('keyDown','Shift','ShiftLeft',16);wait(lambda:x11('query')['shift']==1,'Controller lost after Settings save')
            media_time=browser.evaluate("document.getElementById('desktop').currentTime")
            browser.wait("document.body.classList.contains('connected') && document.getElementById('desktop').currentTime>"+str(media_time+1),'Sustained live video after Settings save')
            wait(native_connected,'Native service lost connected state after Settings save')
            # Pairing is consumed before any retained desktop screenshot.
            x11('capture',str(evidence/'fresh-export-native.ppm'))
            image=browser.send('Page.captureScreenshot',{'format':'png'})['data'];(evidence/'fresh-export-chrome.png').write_bytes(base64.b64decode(image))
            version=browser.version;owned=descendants(process.pid);assert owned
            x11('close','Traverse');wait(lambda:x11('query')['shift']==0,'Actual main Stop left Chrome-held input',timeout=2);process.wait(timeout=15)
            wait(lambda:not any(alive(pid) for pid in owned),'Actual main Stop left children',timeout=12);wait(lambda:not prefix_processes(),'Untracked runtime survived actual main Stop')
            browser.close();browser=None
            process=launch();wait(lambda:window('Traverse'),'Saved main did not reopen');assert window('Traverse setup') is None
            def restarted():
                try:
                    with context.wrap_socket(socket.create_connection(('127.0.0.1',10443),timeout=3),server_hostname=DOMAIN):return True
                except OSError:return False
            wait(restarted,'Relaunch did not use saved endpoint',timeout=35);assert hashlib.sha256(public.read_bytes()).hexdigest()==root_hash
            browser=Browser(client,client/'relaunch',client_env);assert not browser.navigate('https://'+DOMAIN+':10443/').get('errorText');browser.wait(PAIRING_READY,'Same exported trust after next launch')
            x11('close','Traverse');process.wait(timeout=15);wait(lambda:not prefix_processes(),'Relaunch Stop left children');browser.close();browser=None
            assert not any(name==DOMAIN for name,kind in dns.queries),'Hosts-only Chrome journey queried DNS for its URL'
            report={'status':'passed','scope':'Actual native main/setup/export on synthetic X11; offline separate Chrome UID/home/NSS; source size recorded, no physical or GNOME/KDE acceptance','hostsFileResolution':True,'testDomainDnsQueries':0,'sourceVideoSize':video_size,'nativePeerState':native_peer,'packagedEntry':os.environ.get('TRAVERSE_TEST_HOST_PACKAGED_ENTRY')=='1','freshSetupWithoutJSON':True,'actualNativeExportPicker':True,'trustedOnlyExportedPublicFile':True,'initialChromeDistrust':True,'realVideoAndKeyControl':True,'settingsSavedNextLaunchWithoutDisconnect':True,'stopReleasedChromeHeldInputAndReapedRuntime':True,'relaunchUsedNewPortSameCAWithoutReimport':True,'browser':version}
            (evidence/'fresh-export-summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
        except BaseException:
            diagnostic('failure-before-cleanup')
            if pairing_consumed:x11('capture',str(evidence/'failure-after-consumed-pairing.ppm'))
            elif config.is_file() and os.environ.get('TRAVERSE_TEST_STARTUP_REPLAY')=='1':
                try:
                    if process and process.poll() is None:
                        process.terminate();process.wait(timeout=15)
                    wait(lambda:not prefix_processes(),'Native startup replay requires completed original cleanup',timeout=12)
                    from startup_owner_diagnostic import replay
                    replay(config,env,PREFIX,evidence)
                except Exception as failure:
                    (evidence/'startup-owner-diagnostics.json').write_text(json.dumps({'diagnosticError':type(failure).__name__})+'\n')
            raise
        finally:
            if resources:resources.close()
            if process and process.poll() is None:
                process.terminate()
                try:process.wait(timeout=15)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            if browser:browser.close()
            if dns:dns.close()


if __name__=='__main__':main()
