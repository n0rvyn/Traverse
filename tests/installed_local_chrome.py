"""Ordinary Chrome trust/control and a seeded renewal boundary with real clocks."""
import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace

from chrome_fixture import Browser, CLIENT_UID, CLIENT_GID, PAIRING_READY, ensure_client_identity
from host_supervisor_test import OwnerFixture
from installed_managed_certificates import PREFIX, prefix_processes, require_disposable_environment
from installed_standalone import alive, descendants, free_port, ipc, wait
from issuer_native import DOMAIN, wait_for
from readiness_observer_test import DNS


def run_client(arguments, environment, **options):
    return subprocess.run(arguments, env=environment, user=CLIENT_UID, group=CLIENT_GID,
        extra_groups=[], check=True, capture_output=True, text=True, timeout=20, **options)


class CertificateServer:
    def __init__(self, root, authority, sans, days=1):
        self.directory=Path(tempfile.mkdtemp(prefix='certificate-server-',dir=root))
        key=self.directory/'key.pem';csr=self.directory/'request.pem';leaf=self.directory/'leaf.pem'
        extensions=self.directory/'extensions.txt'
        extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName='+sans+'\n')
        subprocess.run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
            '-nodes','-subj','/CN=Traverse certificate constraint fixture','-keyout',str(key),'-out',str(csr)],
            check=True,capture_output=True,timeout=10)
        subprocess.run(['openssl','x509','-req','-in',str(csr),'-CA',str(authority/'local-ca.pem'),
            '-CAkey',str(authority/'local-authority.pem'),'-set_serial','0x'+os.urandom(16).hex(),
            '-days',str(days),'-extfile',str(extensions),'-out',str(leaf)],check=True,capture_output=True,timeout=10)
        self.requests=0;owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(handler):
                owner.requests+=1
                body=b'Traverse certificate constraint witness'
                handler.send_response(200);handler.send_header('Content-Length',str(len(body)));handler.end_headers();handler.wfile.write(body)
            def log_message(*_):pass
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(leaf,key)
        self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever);self.thread.start()
        self.port=self.server.server_port

    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(5)
        assert not self.thread.is_alive()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-tool',type=Path,required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args()
    require_disposable_environment()
    routes=[line.split() for line in Path('/proc/net/route').read_text().splitlines()[1:]]
    assert any(row[0]=='traverse-test0' for row in routes),'Isolated route observation positive control missing'
    assert not any(row[1]=='00000000' for row in routes),'Unexpected IPv4 default route'
    routes6=[line.split() for line in Path('/proc/net/ipv6_route').read_text().splitlines()]
    assert not any(row[0]=='0'*32 and row[1]=='00' and int(row[8],16)&1 and not int(row[8],16)&0x200
                   for row in routes6),'Unexpected usable IPv6 default route'
    ensure_client_identity()
    args.evidence.mkdir(parents=True,exist_ok=True)
    report={'status':'failed','scope':'Exact installed package, ordinary Chrome, separate UID/home/NSS DB; no system/Mac trust change'}
    with tempfile.TemporaryDirectory(prefix='traverse-chrome-local-') as temporary:
        root=Path(temporary);root.chmod(0o755)
        host=root/'host';host.mkdir(mode=0o700);os.chown(host,65534,65534)
        runtime=host/'runtime';runtime.mkdir(mode=0o700);os.chown(runtime,65534,65534)
        authority_x=host/'Xauthority';shutil.copyfile(os.environ['XAUTHORITY'],authority_x);authority_x.chmod(0o600);os.chown(authority_x,65534,65534)
        client=root/'client';client.mkdir(mode=0o700);os.chown(client,CLIENT_UID,CLIENT_GID)
        client_runtime=client/'runtime';client_runtime.mkdir(mode=0o700);os.chown(client_runtime,CLIENT_UID,CLIENT_GID)
        client_environment=dict(os.environ,HOME=str(client),XDG_RUNTIME_DIR=str(client_runtime),
            XDG_DATA_HOME=str(client/'.local/share'),XDG_CONFIG_HOME=str(client/'.config'),XDG_CACHE_HOME=str(client/'.cache'))
        for name in ('LD_LIBRARY_PATH','TRAVERSE_RUNTIME_PREFIX','GST_PLUGIN_PATH_1_0','GST_PLUGIN_SYSTEM_PATH_1_0','GST_PLUGIN_SCANNER','GST_REGISTRY','XAUTHORITY'):
            client_environment.pop(name,None)
        environment=dict(os.environ,HOME=str(host),XDG_DATA_HOME=str(host/'data'),XDG_RUNTIME_DIR=str(runtime),
            XDG_CACHE_HOME=str(host/'cache'),XAUTHORITY=str(authority_x))
        identity=hashlib.sha256(json.dumps(['local-hostname:v1',DOMAIN],separators=(',',':')).encode()).hexdigest()
        for directory in (host/'data',host/'data/traverse',host/'data/traverse/certificates'):
            directory.mkdir(mode=0o700);os.chown(directory,65534,65534)
        authority=host/'data/traverse/certificates'/identity
        # The runtime receives no clock override. A private test-only generator
        # creates an already-valid 90-day leaf approaching its true 60-day point.
        renew_at=int(time.time())+90
        generated=subprocess.run([str(args.fixture_tool),'-test.run=^TestEmitLocalCertificateFixture$'],
            input=json.dumps({'domain':DOMAIN,'stateDirectory':str(authority),'renewAt':renew_at}),
            env=environment,user=65534,group=65534,extra_groups=[],capture_output=True,text=True,timeout=15)
        assert generated.returncode==0,'Private renewal fixture generation failed: '+generated.stdout+generated.stderr
        metadata=[json.loads(line) for line in generated.stdout.splitlines() if line.startswith('{')]
        assert len(metadata)==1 and metadata[0]['status']=='local-ready'
        initial_leaf=metadata[0]['local']['leaf']['fingerprint']
        root_hash=hashlib.sha256((authority/'local-authority.pem').read_bytes()).hexdigest()
        public=(authority/'local-ca.pem').read_bytes()
        assert public.count(b'BEGIN CERTIFICATE')==1 and b'PRIVATE KEY' not in public
        exported=client/'traverse-public-ca.pem';exported.write_bytes(public);exported.chmod(0o600);os.chown(exported,CLIENT_UID,CLIENT_GID)
        denied=subprocess.run(['python3','-c','import pathlib,sys;pathlib.Path(sys.argv[1]).read_bytes()',str(authority/'local-authority.pem')],
            env=client_environment,user=CLIENT_UID,group=CLIENT_GID,extra_groups=[],capture_output=True,text=True,timeout=10)
        assert denied.returncode!=0 and 'PermissionError' in denied.stderr
        config=host/'config.json';config.write_text(json.dumps({'schemaVersion':1,'domain':DOMAIN,'port':443,
            'basePath':'/remote/','listenAddress':'127.0.0.1','certificateSettings':{'mode':'local'}}));config.chmod(0o600);os.chown(config,65534,65534)
        desktop=SimpleNamespace(path=config,home=host,env=environment,broker_stderr=host/'broker-fixture-stderr.txt')
        owner=browser=fresh=dns=witness=None;servers=[];baseline=prefix_processes()
        try:
            dns=DNS();dns.set(DOMAIN,['127.0.0.1']);dns.set('other.example.test',['127.0.0.1']);dns.set('child.'+DOMAIN,['127.0.0.1'])
            owner=OwnerFixture(desktop)
            def ready():
                state=owner.call('status');assert state.get('phase')!='failed',state
                return state if (state.get('localHttps') or {}).get('status')=='passed' else None
            state=wait_for(ready,'Installed local Chrome host',seconds=30)
            assert state['certificate']['fingerprint']==initial_leaf,'Fixture renewed before Chrome started'
            url=state['configuredUrl'];origin=url.split('/remote/')[0]
            print(json.dumps({'stage':'host-ready','renewAt':renew_at}),flush=True)
            browser=Browser(client,client/'untrusted-profile',client_environment)
            untrusted=browser.navigate(url)
            assert untrusted.get('errorText','').startswith('net::ERR_CERT_'),'Untrusted ordinary Chrome reached the host'
            browser.close();browser=None
            nss=client/'.local/share/pki/nssdb'
            nss.mkdir(parents=True,exist_ok=True)
            for path in (client/'.local',client/'.local/share',client/'.local/share/pki',nss):
                path.chmod(0o700);os.chown(path,CLIENT_UID,CLIENT_GID)
            if not (nss/'cert9.db').exists():
                run_client(['certutil','-N','--empty-password','-d','sql:'+str(nss)],client_environment)
            run_client(['certutil','-A','-d','sql:'+str(nss),'-t','C,,','-n','Traverse isolated fixture CA','-i',str(exported)],client_environment)
            listed=run_client(['certutil','-L','-d','sql:'+str(nss)],client_environment)
            assert 'Traverse isolated fixture CA' in listed.stdout
            browser=Browser(client,client/'trusted-profile',client_environment)
            assert not browser.navigate(url).get('errorText')
            browser.wait(PAIRING_READY,'Trusted Chrome pairing page')
            code=ipc(runtime/'traverse/adapter.sock','/owner/authority')['code']
            browser.evaluate("document.getElementById('code').value="+json.dumps(code))
            browser.evaluate("document.getElementById('pairForm').requestSubmit()")
            del code
            browser.wait("document.body.classList.contains('connected') && document.getElementById('desktop').videoWidth>0 && document.getElementById('desktop').readyState>=2",'Real ordinary Chrome WebRTC video')
            assert time.time()<renew_at,'Chrome connected after the renewal boundary'
            witness=subprocess.Popen(['xmessage','-title','Traverse offline desktop witness','-geometry','1280x720+0+0',
                '-buttons','OK','Offline Linux desktop fixture'],env=environment,user=65534,group=65534,extra_groups=[],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            probe=os.environ.get('TRAVERSE_TEST_X11_PROBE','/tmp/x11-probe')
            def witness_ready():
                run=subprocess.run([probe,'focus','Traverse offline desktop witness'],env=environment,
                    user=65534,group=65534,extra_groups=[],capture_output=True,text=True)
                return run.returncode==0
            wait_for(witness_ready,'Synthetic desktop witness covers the used pairing dialog',[witness],seconds=5)
            previous=browser.evaluate("document.getElementById('desktop').getVideoPlaybackQuality().totalVideoFrames")
            browser.wait("document.getElementById('desktop').getVideoPlaybackQuality().totalVideoFrames>"+str(previous+1),'Witness rendered in Chrome')
            screenshot=browser.send('Page.captureScreenshot',{'format':'png'})['data']
            (args.evidence/'connected.png').write_bytes(base64.b64decode(screenshot))
            browser.evaluate("document.getElementById('desktop').focus()")
            browser.key('keyDown','Shift','ShiftLeft',16)
            def query():
                run=subprocess.run([probe,'query'],env=environment,user=65534,group=65534,extra_groups=[],capture_output=True,text=True,check=True)
                return json.loads(run.stdout)
            wait(lambda:query()['shift']==1,'Chrome data-channel key did not reach Linux',timeout=5)
            print(json.dumps({'stage':'chrome-connected-with-held-input','browser':browser.version['product'],'renewAt':renew_at}),flush=True)
            frames=browser.evaluate("document.getElementById('desktop').getVideoPlaybackQuality().totalVideoFrames")
            def renewed():
                state=owner.call('status');assert (state.get('authority') or {}).get('paired')
                return state if (state.get('certificate') or {}).get('fingerprint') not in (None,'',initial_leaf) else None
            latest=wait_for(renewed,'Actual natural local renewal while Chrome controls',seconds=max(30,renew_at-time.time()+30))
            assert query()['shift']==1,'Renewal released active controller input'
            browser.wait("document.getElementById('desktop').getVideoPlaybackQuality().totalVideoFrames>"+str(frames),'Video continued through local renewal')
            assert hashlib.sha256((authority/'local-authority.pem').read_bytes()).hexdigest()==root_hash
            assert (authority/'local-ca.pem').read_bytes()==public
            context=ssl.create_default_context(cafile=str(exported))
            with context.wrap_socket(socket.create_connection(('127.0.0.1',443),timeout=5),server_hostname=DOMAIN) as stream:
                assert hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest()==latest['certificate']['fingerprint']
                not_before=ssl.cert_time_to_seconds(stream.getpeercert()['notBefore'])
            # Complete held-input Stop before closing this browser. Run the
            # fresh-browser/restart witness serially to avoid two browser trees
            # competing for memory on the shared test host.
            browser_version=browser.version
            owned=descendants(owner.process.pid)
            assert owner.call('request-stop')=={'stopRequested':True}
            wait(lambda:query()['shift']==0,'Local Stop did not release Chrome-held input',timeout=3)
            assert owner.call('wait-stopped')=={'stopped':True,'exit':0}
            wait(lambda:not any(alive(pid) for pid in owned),'Installed Chrome host child survived Stop',timeout=12)
            wait(lambda:prefix_processes()==baseline,'Installed runtime survived Stop',timeout=5)
            owner.close();owner=None
            browser.close();browser=None
            owner=OwnerFixture(desktop)
            restarted=wait_for(ready,'Restart after local renewal',seconds=30)
            assert restarted['certificate']['fingerprint']==latest['certificate']['fingerprint']
            fresh=Browser(client,client/'post-renewal-profile',client_environment)
            assert not fresh.navigate(url).get('errorText')
            fresh.wait(PAIRING_READY,'Fresh ordinary Chrome trusts the renewed leaf')
            details=[r.get('securityDetails') for r in fresh.cdp.responses if r.get('url')==url and r.get('status')==200]
            assert details and details[-1]['validFrom']==not_before,'Fresh Chrome did not verify the renewed leaf'
            negatives=[]
            cases=[(DOMAIN,'DNS:'+DOMAIN,1,False),('other.example.test','DNS:other.example.test',1,True),
                ('child.'+DOMAIN,'DNS:child.'+DOMAIN,1,True),('127.0.0.1','IP:127.0.0.1',1,True),
                (DOMAIN,'DNS:'+DOMAIN+',DNS:other.example.test',1,True),(DOMAIN,'DNS:'+DOMAIN,-1,True)]
            for name,sans,days,reject in cases:
                server=CertificateServer(root,authority,sans,days);servers.append(server)
                result=fresh.navigate('https://'+name+':'+str(server.port)+'/')
                if reject:
                    assert result.get('errorText','').startswith('net::ERR_CERT_'),'Ordinary Chrome accepted forbidden certificate'
                    assert server.requests==0
                    negatives.append({'host':name,'sans':sans,'expired':days<0,'error':result['errorText']})
                else:
                    assert not result.get('errorText')
                    fresh.wait("document.body && document.body.textContent.includes('certificate constraint witness')",'Constraint-server positive control')
            assert query()['shift']==0
            owned=descendants(owner.process.pid)
            assert owner.call('request-stop')=={'stopRequested':True}
            wait(lambda:query()['shift']==0,'Local Stop did not release Chrome-held input',timeout=3)
            assert owner.call('wait-stopped')=={'stopped':True,'exit':0}
            wait(lambda:not any(alive(pid) for pid in owned),'Installed Chrome host child survived Stop',timeout=12)
            wait(lambda:prefix_processes()==baseline,'Installed runtime survived Stop',timeout=5)
            report.update(status='passed',browser=browser_version,hostUID=65534,clientUID=CLIENT_UID,
                trustDatabase='.local/share/pki/nssdb',defaultTrustRejected=True,explicitClientOnlyTrust=True,
                clientCannotReadHostCAKey=True,realChromeVideoAndInput=True,seededRenewalAt=renew_at,
                sameControllerAndHeldInputThroughRenewal=True,stableAuthority=True,freshChromeVerifiedNewLeaf=True,
                constraintPositiveControl=True,certificateNegatives=negatives,localStopReleasedHeldInput=True,
                allRuntimeChildrenReaped=True,noTLSOrSandboxBypass=True,noInternetRoute=True)
        finally:
            cleanups=[]
            if owner:cleanups.append(owner.close)
            cleanups.extend(server.close for server in reversed(servers))
            if fresh:cleanups.append(fresh.close)
            if browser:cleanups.append(browser.close)
            if witness:
                def close_witness():
                    if witness.poll() is None:witness.terminate()
                    witness.wait(timeout=5)
                cleanups.append(close_witness)
            if dns:cleanups.append(dns.close)
            cleanup_errors=[]
            for cleanup in cleanups:
                try:cleanup()
                except BaseException as error:cleanup_errors.append(type(error).__name__)
            if cleanup_errors:report.update(status='failed',cleanupErrors=cleanup_errors)
            (args.evidence/'chrome-summary.json').write_text(json.dumps(report,indent=2)+'\n')
            assert not cleanup_errors,'Owned Chrome fixture cleanup failed: '+','.join(cleanup_errors)
    print(json.dumps(report),flush=True)


if __name__=='__main__':main()
