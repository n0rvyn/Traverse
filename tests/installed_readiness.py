"""Exact installed one-port frontend -> native probe, without controller admission.
Root observes only its synthetic fixture; all app/native-owner clients use65534.
"""
import json
import http.client
import ssl
import shutil
import os
from pathlib import Path
import subprocess
import tempfile
from installed_managed_certificates import Desktop,PREFIX,require_disposable_environment,prefix_processes
from installed_standalone import children,ipc,wait,free_port
from managed_ca_fixture import PrivateCA
from issuer_native import DOMAIN
from readiness_observer_test import DNS


def main():
    require_disposable_environment()
    pebble=Path(os.environ.get('TRAVERSE_TEST_PEBBLE','/src/.work/issuer-tools/pebble'))
    probe=Path(os.environ.get('TRAVERSE_NATIVE_TEST_BUILD','/src/.work/build-native'))/'owner-state-probe'
    with tempfile.TemporaryDirectory(prefix='installed-readiness-') as temporary:
        root=Path(temporary);root.chmod(0o755);ca=PrivateCA(root,pebble,443)
        desktop=Desktop(root,ca,443,base='/traverse/v1.2/')
        observer=None;dns=None;fixture_baseline=prefix_processes()
        try:
            dns=DNS();dns.set(DOMAIN,['127.0.0.1']);observer_port=free_port()
            profile=subprocess.run([str(PREFIX/'bin/traverse'),'--runtime-environment'],
                env=desktop.env,text=True,capture_output=True,check=True)
            environment=dict(desktop.env,**json.loads(profile.stdout)['environment'])
            observer_cert=desktop.home/'observer.pem';observer_key=desktop.home/'observer.key'
            for source,target in ((ca.api_certificate,observer_cert),(ca.api_key,observer_key)):
                shutil.copy2(source,target);target.chmod(0o600);os.chown(target,65534,65534)
            registration='1'*32;credential='2'*64
            observer_config=desktop.home/'observer.json'
            observer_config.write_text(json.dumps(dict(schemaVersion=1,listenAddress='127.0.0.1',port=observer_port,
                certificate=str(observer_cert),privateKey=str(observer_key),registrations=[
                    dict(id=registration,token=credential,target=dict(host=DOMAIN,port=443,
                        basePath='/traverse/v1.2/',caFile=str(ca.issuing_root),allowedAddresses=['127.0.0.1']))])))
            observer_config.chmod(0o600);os.chown(observer_config,65534,65534)
            observer=subprocess.Popen([str(PREFIX/'libexec/traverse/traverse-readiness-observer'),'--config',str(observer_config)],
                env=environment,user=65534,group=65534,extra_groups=[],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            def observer_api(route,body):
                connection=http.client.HTTPSConnection('127.0.0.1',observer_port,
                    context=ssl.create_default_context(cafile=str(ca.api_certificate)),timeout=5)
                try:
                    connection.request('POST','/v1/'+route,json.dumps(body),dict(Authorization='Bearer '+credential,
                        **{'X-Traverse-Registration':registration,'Content-Type':'application/json'}))
                    response=connection.getresponse();assert response.status==200,'Installed observer API rejected request'
                    return json.loads(response.read())
                finally:connection.close()
            def observer_ready():
                if observer.poll() is not None:raise AssertionError('Exact installed observer exited')
                try:return observer_api('resolve',dict(schemaVersion=1))['status']=='resolved'
                except (OSError,ssl.SSLError,http.client.HTTPException):return False
            wait(observer_ready,'Installed authenticated observer trusted DNS/TLS startup')
            assert dns.count()>0,'Installed observer did not perform actual DNS lookup'
            assert Path(f'/proc/{observer.pid}/exe').resolve()==PREFIX/'libexec/traverse/traverse-readiness-observer'
            assert not children(observer.pid),'Observer preflight left a worker before desktop baseline'
            # Independent observer exists before the desktop's own baseline;
            # preserve the complete existing new-prefix-process cleanup guard.
            desktop.start();wait(desktop.ready,'Installed readiness trusted HTTPS startup',timeout=45)
            assert observer.pid in desktop.baseline,'Independent observer was not in pre-existing fixture state'
            def binding():
                sockets=list((desktop.runtime/'traverse').glob('o-*/s'))
                services=[]
                for pid in children(desktop.launch.pid):
                    try:
                        if Path(f'/proc/{pid}/exe').resolve()==PREFIX/'libexec/traverse/traverse-service':
                            services.append(pid)
                    except FileNotFoundError:pass
                assert len(sockets)==1 and len(services)==1,'Owned service binding ambiguous'
                return sockets[0],services[0]
            def private(route,body):
                path,pid=binding()
                prepared=subprocess.run([str(PREFIX/'bin/traverse'),'--runtime-environment'],
                    env=desktop.env,text=True,capture_output=True,check=True)
                environment=dict(desktop.env,**json.loads(prepared.stdout)['environment'])
                result=subprocess.run([str(probe),str(path),str(pid),route],input=json.dumps(body),
                    env=environment,user=65534,group=65534,extra_groups=[],text=True,capture_output=True,timeout=8)
                assert result.returncode==0,'Installed native same-UID owner rejected producer'
                return json.loads(result.stdout)
            def begin():
                row=private('/readiness/begin',{'schemaVersion':1});assert row['status']==200
                return row['response']['lease']
            def challenge(lease):
                status,body=desktop.http('api/readiness/challenge',
                    {'schemaVersion':1,'id':lease['id'],'nonce':lease['nonce']},lease['token'])
                return status,json.loads(body)
            def native_challenge(lease):
                row=observer_api('check',dict(schemaVersion=1,address='127.0.0.1',lease=lease))
                assert row['status']=='received','Installed observer did not receive exact native receipt'
                owner=private('/readiness/inspect',dict(schemaVersion=1,id=lease['id']))
                assert owner['status']==200 and row['receipt']==owner['response']['probe']['receipt'],'Independent receipt mismatch'
                assert not children(observer.pid),'Observer returned before native worker reap'
                return row
            def end(lease):
                assert private('/readiness/end',{'schemaVersion':1,'id':lease['id']})['status']==200
            original=ipc(desktop.adapter,'/owner/authority')
            idle=ipc(desktop.adapter,'/state');assert not idle['paired'] and not idle['capturing']
            lease=begin();row=native_challenge(lease)
            assert all(row['receipt'][key]==lease[key] for key in ('id','instance','nonce')),'Installed receipt mismatch'
            assert challenge(lease)[0]==403
            current=ipc(desktop.adapter,'/owner/authority')
            assert current['code']==original['code'] and current['codeStatus']=='available','Probe consumed pairing authority'
            assert ipc(desktop.adapter,'/state')==idle,'Probe started capture or changed adapter state'
            end(lease)
            status,body=desktop.http('api/pair',{'code':original['code']});assert status==200
            controller=json.loads(body)['token'];live=begin()
            ipc(desktop.adapter,'/input',{'type':'key','code':'ShiftLeft','down':True},controller)
            assert desktop.x11('query')['shift']==1
            native_challenge(live)
            assert desktop.x11('query')['shift']==1,'Readiness traffic released controller hold'
            assert desktop.http('api/stats',token=controller)[0]==200
            assert desktop.http('api/disconnect',{},live['token'])[0]==403
            end(live);pending=begin()
            desktop.finish('terminate')
            assert desktop.x11('query')['shift']==0
            assert observer.poll() is None,'Independent observer died with the desktop'
            desktop.start();wait(desktop.ready,'Installed restart trusted HTTPS startup',timeout=45)
            assert challenge(pending)[0]==403,'Old instance readiness authority survived restart'
            fresh=begin();assert fresh['instance']!=pending['instance'],'Readiness instance reused'
            native_challenge(fresh);end(fresh)
            desktop.finish('terminate')
            observer.terminate();out,err=observer.communicate(timeout=8)
            assert observer.returncode==0 and not out and not err,'Installed observer did not stop cleanly'
            assert prefix_processes()==fixture_baseline,'Owned observer/desktop fixture process survived final teardown'
            print(json.dumps({'status':'passed','scope':'installed UID65534 shared443 frontend and prefixed trustedHTTPS; synthetic X11/privateCA',
                'authenticatedObserverDnsAndNativeVerifier':True,'probePreservesPairingAndCapture':True,'realControllerHeldInputSurvivesProbe':True,
                'probeCannotDisconnectController':True,'pendingProbeRevokedOnStopAndRestart':True,
                'allOwnedChildrenStopped':True,'ownerLogsReadOrExported':False,'outsideNetworkObserver':False}),flush=True)
        finally:
            if observer is not None:
                if observer.poll() is None:observer.terminate()
                try:observer.wait(timeout=8)
                except subprocess.TimeoutExpired:observer.kill();observer.wait(timeout=5);raise
                for pipe in (observer.stdout,observer.stderr):
                    if pipe:pipe.close()
            if dns is not None:dns.close()
            desktop.close();ca.close()

if __name__=='__main__':main()
