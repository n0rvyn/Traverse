"""Real inherited-owner lifecycle; root observes, all app/owner processes use65534."""
import ctypes
import http.client
import json
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

from installed_managed_certificates import Desktop, PREFIX, prefix_processes, require_disposable_environment
from installed_standalone import alive, descendants, free_port, ipc, wait
from managed_ca_fixture import PrivateCA
from issuer_native import DOMAIN


def wire(value):
    body=json.dumps(value).encode()
    return struct.pack('!I',len(body))+body


def desktop_stats(context,port,origin,base,token):
    connection=http.client.HTTPSConnection(DOMAIN,port,context=context,timeout=5)
    connection.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname=DOMAIN)
    try:
        connection.request('GET',base+'api/stats',headers={'Origin':origin,'Authorization':'Bearer '+token})
        response=connection.getresponse()
        return response.status,response.read()
    finally:connection.close()


def broker(config_path,root_parent):
    libc=ctypes.CDLL(None)
    if libc.prctl(1,signal.SIGTERM,0,0,0) or os.getppid()!=root_parent:
        return 1
    # Complete shell runtime preparation BEFORE creating the inherited owner
    # socket. Its utilities cannot inherit a descriptor that does not yet exist.
    prepared=subprocess.run([str(PREFIX/'bin/traverse'),'--runtime-environment'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        text=True,timeout=10)
    if prepared.returncode:
        print(json.dumps({'brokerError':'runtime-environment','exit':prepared.returncode}),flush=True)
        return 1
    profile=json.loads(prepared.stdout);assert profile['schemaVersion']==1
    env=dict(os.environ,**profile['environment'])
    assert env['TRAVERSE_RUNTIME_PREFIX']==str(PREFIX)
    owner,child=socket.socketpair();owner.setblocking(False)
    backend=subprocess.Popen([str(PREFIX/'libexec/traverse/traverse-launcher'),
        '--config',config_path,'--owner-fd',str(child.fileno()),'--supervisor-pid',str(os.getpid())],
        pass_fds=(child.fileno(),),env=env,stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    inherited=child.fileno();child.close();incoming=bytearray();serial=0;token=None;last_state={};known_code=None
    config=json.loads(Path(config_path).read_text());port=config.get('port',443)
    base=config.get('basePath','/');origin='https://'+DOMAIN+('' if port==443 else ':'+str(port))
    context=ssl.create_default_context(cafile=config.get('certificateSettings',{}).get('certificateTrustFile') or env.get('SSL_CERT_FILE'))
    adapter=Path(env['XDG_RUNTIME_DIR'])/'traverse/adapter.sock'
    def request(action):
        nonlocal serial,last_state
        if backend.poll() is not None:
            return {'ok':False,'error':'backend-exited','state':dict(last_state,phase='failed')}
        serial+=1;pending=wire({'schemaVersion':1,'requestId':serial,'action':action})
        end=time.monotonic()+8
        while pending:
            assert time.monotonic()<end,'Synthetic owner write timeout'
            if select.select([],[owner],[],.1)[1]:
                pending=pending[owner.send(pending):]
        while True:
            assert time.monotonic()<end,'Synthetic owner response timeout'
            while len(incoming)>=4:
                length=struct.unpack('!I',incoming[:4])[0]
                if len(incoming)<length+4:break
                value=json.loads(incoming[4:4+length]);del incoming[:4+length]
                if value.get('event')=='state':last_state=value['state']
                if value.get('requestId')==serial:return value
            if select.select([owner],[],[],.1)[0]:
                data=owner.recv(16384)
                if not data:return {'ok':False,'error':'owner-disconnected','state':dict(last_state,phase='failed')}
                incoming.extend(data)
    def safe(value):
        state=value.get('state',{})
        authority=state.get('authority',{})
        return {'ok':value.get('ok'), 'error':value.get('error'),
            'phase':state.get('phase'),'stage':state.get('stage'),
            'supervisorPid':state.get('supervisorPid'),'instance':state.get('instance'),
            'localHttps':state.get('localHttps'),
            'authority':{key:authority[key] for key in ('codeStatus','armed','paired') if key in authority},
            'peer':state.get('peer'),'issuer':state.get('issuer')}
    print(json.dumps({'brokerReady':True,'launcherPid':backend.pid,'ownerFd':inherited}),flush=True)
    try:
        for line in sys.stdin:
            action=json.loads(line)['action']
            if action in ('status','new-code'):
                result=safe(request(action))
            elif action=='pair':
                value=request('status');code=value['state']['authority']['code']
                known_code=code
                connection=http.client.HTTPSConnection(DOMAIN,port,context=context,timeout=5)
                connection.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname=DOMAIN)
                try:
                    connection.request('POST',base+'api/pair',json.dumps({'code':code}),
                        {'Origin':origin,'Content-Type':'application/json'})
                    response=connection.getresponse();body=json.loads(response.read());assert response.status==200
                    token=body['token']
                finally:connection.close()
                result={'paired':True}
            elif action=='public-boundaries':
                # The private positive control supplies a known secret, never
                # printed by this broker. Probe the actual trusted TLS route.
                state=request('status')['state']
                code=state['authority'].get('code') or known_code
                assert code,'Private authority positive control required'
                checked=0
                for route in ('owner/authority','owner/new-code','%6fwner/authority','api/owner/new-code'):
                    for method in ('GET','POST'):
                        for supplied_origin in (origin,'https://untrusted.example.test'):
                            connection=http.client.HTTPSConnection(DOMAIN,port,context=context,timeout=5)
                            connection.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname=DOMAIN)
                            headers={'Origin':supplied_origin,'Content-Type':'application/json',
                                'X-Forwarded-For':'127.0.0.1','X-Forwarded-Host':'localhost'}
                            if token:headers['Authorization']='Bearer '+token
                            try:
                                connection.request(method,base+route,'{}' if method=='POST' else None,headers)
                                response=connection.getresponse();body=response.read()
                                assert response.status in (403,404),'Public owner route was admitted'
                                assert code.encode() not in body,'Private code leaked through public TLS'
                                checked+=1
                            finally:connection.close()
                if token:
                    status,body=desktop_stats(context,port,origin,base,token)
                    assert status==200 and code.encode() not in body
                    assert b'"code"' not in body and b'"authority"' not in body
                result={'publicTlsOwnerRoutesDenied':checked,'authorizedStatsCodeFree':bool(token)}
            elif action in ('hold-shift','heartbeat'):
                event={'type':'key','code':'ShiftLeft','down':True} if action=='hold-shift' else {'type':'heartbeat'}
                ipc(adapter,'/input',event,token);result={'accepted':True}
            elif action in ('stop','eof','request-stop','request-eof','wait-stopped'):
                if action in ('stop','request-stop'):request('stop')
                elif action in ('eof','request-eof'):owner.close()
                if action.startswith('request-'):
                    result={'stopRequested':True}
                else:
                    backend.wait(timeout=12);result={'stopped':True,'exit':backend.returncode}
            else:raise RuntimeError('Unknown synthetic fixture command')
            print(json.dumps(result),flush=True)
    finally:
        owner.close()
        if backend.poll() is None:backend.terminate();backend.wait(timeout=12)
    return 0


class OwnerFixture:
    def __init__(self,desktop):
        self.process=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'--broker',str(desktop.path),str(os.getpid())],
            user=65534,group=65534,extra_groups=[],env=desktop.env,cwd=desktop.home,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        try:
            self.ready=self.read();assert self.ready.get('brokerReady'),self.ready
        except BaseException:
            self.close();raise
    def read(self):
        assert select.select([self.process.stdout],[],[],15)[0],'Synthetic broker response timeout'
        line=self.process.stdout.readline();assert line,'Synthetic broker exited'
        return json.loads(line)
    def call(self,action):
        self.process.stdin.write(json.dumps({'action':action})+'\n');self.process.stdin.flush()
        return self.read()
    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close();self.process.wait(timeout=15)
        if not self.process.stdin.closed:self.process.stdin.close()
        self.process.stdout.close()


def main():
    require_disposable_environment()
    reports=[]
    pebble=Path(os.environ.get('TRAVERSE_TEST_PEBBLE','/src/.work/issuer-tools/pebble'))
    for ending in ('stop','eof','death'):
        with tempfile.TemporaryDirectory(prefix='traverse-host-owner-') as temporary:
            root=Path(temporary);root.chmod(0o755)
            ca=PrivateCA(root,pebble,443);desktop=Desktop(root,ca,443);owner=None
            # The previous adapter path fits, but instance-<32 hex>/s would
            # exceed Linux sun_path. Exercise the real launcher at that bound.
            component_length=70-len(str(desktop.home))-len('/traverse')-1
            assert component_length>0
            desktop.runtime=desktop.home/('r'*component_length)
            desktop.runtime.mkdir(mode=0o700);os.chown(desktop.runtime,65534,65534)
            desktop.env['XDG_RUNTIME_DIR']=str(desktop.runtime)
            desktop.adapter=desktop.runtime/'traverse/adapter.sock'
            assert len(str(desktop.adapter).encode())==83
            assert len(str(desktop.runtime/'traverse'/('instance-'+'0'*32)/'s').encode())==114
            supplied=ending=='eof'
            if supplied:
                # Independent supplied identity; trust exists only in this
                # fixture's process environment, never in a system store.
                cert,key=root/'supplied.pem',desktop.home/'supplied.key'
                subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes',
                    '-days','1','-subj','/CN='+DOMAIN,'-addext','subjectAltName=DNS:'+DOMAIN,
                    '-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
                cert.chmod(0o644);key.chmod(0o600);os.chown(key,65534,65534)
                config=json.loads(desktop.path.read_text());config.pop('certificateSettings')
                config.update(certificate=str(cert),privateKey=str(key))
                desktop.path.write_text(json.dumps(config));desktop.env['SSL_CERT_FILE']=str(cert)
            baseline=prefix_processes()
            try:
                owner=OwnerFixture(desktop)
                def ready():
                    value=owner.call('status')
                    assert value.get('phase')!='failed',('Synthetic backend failed stage',value.get('stage'))
                    return value if value.get('phase')=='ready' and value.get('localHttps',{}).get('status')=='passed' else None
                wait(ready,'Actual owner channel did not reach trusted sharing readiness',timeout=45)
                first=owner.call('status');assert first['authority']['codeStatus']=='available'
                assert len(list(desktop.data.glob('traverse/certificates/*/account-key.pem')))==(0 if supplied else 1)
                assert (ca.bridge.count()==0) if supplied else (ca.bridge.count()>0)
                assert first['peer']['rtcState']=='none' and not first['peer']['controlOpen']
                assert owner.call('new-code')['ok']
                assert owner.call('public-boundaries')=={'publicTlsOwnerRoutesDenied':16,'authorizedStatsCodeFree':False}
                assert owner.call('pair')['paired']
                assert owner.call('public-boundaries')=={'publicTlsOwnerRoutesDenied':16,'authorizedStatsCodeFree':True}
                rejected=owner.call('new-code');assert not rejected['ok'] and rejected['error']=='paired-or-stopped',{'ok':rejected.get('ok'),'error':rejected.get('error'),'phase':rejected.get('phase'),'authority':rejected.get('authority')}
                assert owner.call('heartbeat')['accepted']
                paired=owner.call('status');assert paired['authority']['codeStatus']=='used'
                assert paired['peer']['rtcState']=='none' and not paired['peer']['controlOpen']
                assert owner.call('hold-shift')['accepted'];assert desktop.x11('query')['shift']==1
                launch=owner.ready['launcherPid'];inherited=owner.ready['ownerFd']
                owned=descendants(owner.process.pid);assert launch in owned and launch in prefix_processes()
                channel=os.readlink(f'/proc/{launch}/fd/{inherited}')
                assert channel.startswith('socket:[')
                for pid in descendants(launch):
                    for descriptor in Path(f'/proc/{pid}/fd').iterdir():
                        try:assert os.readlink(descriptor)!=channel,'Inherited owner socket reached a descendant'
                        except FileNotFoundError:pass
                if ending=='death':
                    owner.process.kill();owner.process.wait(timeout=5)
                else:
                    result=owner.call(ending);assert result=={'stopped':True,'exit':0}
                wait(lambda: desktop.x11('query')['shift']==0,'Owner loss left held Shift',timeout=3)
                wait(lambda:not any(alive(pid) for pid in owned),'Owned child survived host stop/EOF/death',timeout=12)
                wait(lambda:not any(alive(pid) for pid in prefix_processes()-baseline),'Untracked owned native descendant survived',timeout=5)
                reports.append({'ending':ending,'actualOwnerUid':65534,'trustedHttps':True,
                    'longRuntimeBaseBytes':70,'priorInstanceSocketBytes':114,
                    'certificateMode':'supplied' if supplied else 'automatic',
                    'safeRefreshPreservesController':True,'pairedWithoutRtcNeverConnected':True,
                    'publicTlsOwnerRoutesDeniedBeforeAndAfterPairing':True,'authorizedStatsCodeFree':True,
                    'ownerDescriptorNotInherited':True,'inputReleasedAndAllChildrenStopped':True})
            finally:
                if owner:owner.close()
                ca.close()
    # Actual local child-readiness delay: status/Stop must stay responsive and
    # no account/order may start before every required listener is ready.
    with tempfile.TemporaryDirectory(prefix='traverse-host-child-wait-') as temporary:
        root=Path(temporary);root.chmod(0o755);ca=PrivateCA(root,pebble,443)
        desktop=Desktop(root,ca,443);owner=None;service=PREFIX/'libexec/traverse/traverse-service'
        saved=service.with_name('traverse-service.actual');gate=PREFIX/'share/traverse/web/.fixture-delay'
        service.rename(saved)
        try:
            import shutil
            shutil.copyfile(os.environ['TRAVERSE_TEST_DELAYED_SERVICE'],service);service.chmod(0o755)
            gate.write_text('owned synthetic startup gate');gate.chmod(0o644)
            owner=OwnerFixture(desktop)
            wait(lambda: bool(list((desktop.runtime/'traverse').glob('o-*/s.waiting'))),
                'Actual delayed child did not enter its readiness wait',timeout=15)
            before=owner.call('status');assert before['stage']=='service' and before['phase']=='starting'
            assert before['localHttps']['status']=='pending' and not before['issuer']['operationActive']
            assert owner.call('stop')=={'stopped':True,'exit':0}
            assert ca.bridge.count()==0 and not list(desktop.data.glob('traverse/certificates/*/account-key.pem'))
            reports.append({'pendingLocalChildReadiness':True,'statusAndStopResponsive':True,
                'noAccountOrOrderBeforeListeners':True})
        finally:
            if owner:owner.close()
            ca.close();service.unlink();saved.rename(service)
            if gate.exists():gate.unlink()
    # A real TLS frontend and real HTTP service with a deliberately blocked
    # index read prove owner EOF releases input before network teardown waits.
    with tempfile.TemporaryDirectory(prefix='traverse-host-https-wait-') as temporary:
        root=Path(temporary);root.chmod(0o755);ca=PrivateCA(root,pebble,443)
        desktop=Desktop(root,ca,443);owner=None;index=PREFIX/'share/traverse/web/index.html'
        saved=index.with_name('index.html.actual')
        try:
            owner=OwnerFixture(desktop)
            wait(lambda:owner.call('status').get('phase')=='ready','Seed material readiness',timeout=45)
            assert owner.call('stop')['exit']==0;owner.close();owner=None
            bundles=list(desktop.data.glob('traverse/certificates/*/bundle.pem'));assert len(bundles)==1
            config=json.loads(desktop.path.read_text());config.pop('certificateSettings')
            port=free_port();assert port>=1024
            config.update({'port':port,'certificate':str(bundles[0]),'privateKey':str(bundles[0])})
            desktop.path.write_text(json.dumps(config));desktop.env['SSL_CERT_FILE']=str(ca.issuing_root)
            index.rename(saved);os.mkfifo(index,0o600);os.chown(index,65534,65534)
            owner=OwnerFixture(desktop)
            wait(lambda:owner.call('status').get('stage')=='https','Actual local HTTPS wait not observed',timeout=15)
            assert owner.call('pair')['paired'];assert owner.call('hold-shift')['accepted']
            assert desktop.x11('query')['shift']==1
            assert owner.call('heartbeat')['accepted'];before=time.monotonic()
            assert owner.call('request-eof')['stopRequested']
            wait(lambda:desktop.x11('query')['shift']==0,'Owner EOF did not release input before network wait',timeout=2)
            elapsed=time.monotonic()-before
            assert owner.call('wait-stopped')=={'stopped':True,'exit':0}
            reports.append({'pendingTrustedLocalHttpsCheck':True,'statusAndEofResponsive':True,
                'heldInputReleasedBeforeNetworkTeardown':True,'releaseSeconds':elapsed})
        finally:
            if owner:owner.close()
            ca.close()
            if saved.exists():
                index.unlink();saved.rename(index)
    with tempfile.TemporaryDirectory(prefix='traverse-host-pending-ca-') as temporary:
        root=Path(temporary);root.chmod(0o755);ca=PrivateCA(root,pebble,443,slow=True)
        desktop=Desktop(root,ca,443);owner=None;baseline=prefix_processes()
        try:
            owner=OwnerFixture(desktop)
            def issuing():
                value=owner.call('status')
                assert value.get('phase')!='failed',('Pending issuer startup failed stage',value.get('stage'))
                return (value.get('issuer') or {}).get('operationActive')
            wait(issuing,'Actual issuer operation not observed through owner channel',timeout=15)
            started=time.monotonic()
            while time.monotonic()-started<16:
                assert owner.call('status')['phase']=='waiting-certificate';time.sleep(.1)
            value=owner.call('status');assert value['issuer']['operationActive'] and ca.bridge.count()>0
            assert value['localHttps']['status']=='pending' and value['authority']['codeStatus']=='available'
            try:
                unexpected=desktop.stream()
            except (OSError,ssl.SSLError):
                pass
            else:
                unexpected.close();raise AssertionError('Pending issuance admitted ordinary application TLS')
            owned=descendants(owner.process.pid);owner.process.kill();owner.process.wait(timeout=5)
            wait(lambda:not any(alive(pid) for pid in owned),'Owned issuer survived parent death',timeout=12)
            wait(lambda:not any(alive(pid) for pid in prefix_processes()-baseline),'Pending native descendant survived',timeout=5)
            reports.append({'actualIssuerPendingBeyond15s':True,'ownerStatusResponsive':True,
                'parentDeathStoppedAllOwnedWork':True,'applicationNeverAdmitted':True})
        finally:
            if owner:owner.close()
            ca.close()
    print(json.dumps({'status':'passed','scope':'actual UID65534 owner/native/privateCA/X11 lifecycle',
        'cases':reports,'ownerLogsReadOrExported':False,'publicCA':False}),flush=True)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--broker':
        raise SystemExit(broker(sys.argv[2],int(sys.argv[3])))
    main()
