"""Actual installed refusal and ordinary Chrome expiry enforcement for local CAs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import tempfile
import time
from types import SimpleNamespace

from chrome_fixture import Browser, CLIENT_UID, CLIENT_GID
from host_supervisor_test import OwnerFixture
from installed_local_chrome import CertificateServer, run_client
from installed_managed_certificates import prefix_processes, require_disposable_environment
from installed_standalone import free_port, wait
from issuer_native import DOMAIN, wait_for
from readiness_observer_test import DNS


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-tool',type=Path,required=True)
    parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args();require_disposable_environment()
    assert pwd.getpwuid(CLIENT_UID).pw_name=='traverse-client-fixture'
    args.evidence.mkdir(parents=True,exist_ok=True)
    report={'status':'failed','scope':'Installed host and ordinary Chrome expired-root control; disposable client trust only'}
    with tempfile.TemporaryDirectory(prefix='traverse-expired-local-') as temporary:
        root=Path(temporary);root.chmod(0o755)
        host=root/'host';host.mkdir(mode=0o700);os.chown(host,65534,65534)
        runtime=host/'runtime';runtime.mkdir(mode=0o700);os.chown(runtime,65534,65534)
        xauthority=host/'Xauthority';shutil.copyfile(os.environ['XAUTHORITY'],xauthority);xauthority.chmod(0o600);os.chown(xauthority,65534,65534)
        environment=dict(os.environ,HOME=str(host),XDG_DATA_HOME=str(host/'data'),XDG_RUNTIME_DIR=str(runtime),XAUTHORITY=str(xauthority))
        for path in (host/'data',host/'data/traverse',host/'data/traverse/certificates'):
            path.mkdir(mode=0o700);os.chown(path,65534,65534)
        identity=hashlib.sha256(json.dumps(['local-hostname:v1',DOMAIN],separators=(',',':')).encode()).hexdigest()
        expired=host/'data/traverse/certificates'/identity
        valid=host/'valid-authority'
        def generate(path,old):
            result=subprocess.run([str(args.fixture_tool),'-test.run=^TestEmitLocalCertificateFixture$'],
                input=json.dumps({'domain':DOMAIN,'stateDirectory':str(path),'renewAt':int(time.time())+3600,'expiredAuthority':old}),
                env=environment,user=65534,group=65534,extra_groups=[],capture_output=True,text=True,timeout=15)
            assert result.returncode==0,result.stdout+result.stderr
            output=[json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
            assert len(output)==1
            return output[0]
        assert generate(expired,True)['local']['authority']=='expired'
        assert generate(valid,False)['local']['authority']=='current'
        before={name:hashlib.sha256((expired/name).read_bytes()).hexdigest()
            for name in ('local-authority.pem','local-authority.json','local-ca.pem')}
        port=free_port();config=host/'config.json'
        config.write_text(json.dumps({'schemaVersion':1,'domain':DOMAIN,'port':port,
            'listenAddress':'127.0.0.1','certificateSettings':{'mode':'local'}}));config.chmod(0o600);os.chown(config,65534,65534)
        desktop=SimpleNamespace(path=config,home=host,env=environment,broker_stderr=host/'broker-fixture-stderr.txt')
        client=root/'client';client.mkdir(mode=0o700);os.chown(client,CLIENT_UID,CLIENT_GID)
        client_runtime=client/'runtime';client_runtime.mkdir(mode=0o700);os.chown(client_runtime,CLIENT_UID,CLIENT_GID)
        client_environment=dict(os.environ,HOME=str(client),XDG_RUNTIME_DIR=str(client_runtime),
            XDG_DATA_HOME=str(client/'.local/share'),XDG_CONFIG_HOME=str(client/'.config'),XDG_CACHE_HOME=str(client/'.cache'))
        for name in ('LD_LIBRARY_PATH','TRAVERSE_RUNTIME_PREFIX','GST_PLUGIN_PATH_1_0','GST_PLUGIN_SYSTEM_PATH_1_0','GST_PLUGIN_SCANNER','GST_REGISTRY','XAUTHORITY'):
            client_environment.pop(name,None)
        nss=client/'.local/share/pki/nssdb';nss.mkdir(parents=True)
        for path in (client/'.local',client/'.local/share',client/'.local/share/pki',nss):path.chmod(0o700);os.chown(path,CLIENT_UID,CLIENT_GID)
        run_client(['certutil','-N','--empty-password','-d','sql:'+str(nss)],client_environment)
        for path,nickname in ((valid,'Traverse valid expiry-control CA'),(expired,'Traverse expired expiry-control CA')):
            exported=client/(nickname.replace(' ','-')+'.pem');exported.write_bytes((path/'local-ca.pem').read_bytes())
            exported.chmod(0o600);os.chown(exported,CLIENT_UID,CLIENT_GID)
            run_client(['certutil','-A','-d','sql:'+str(nss),'-t','C,,','-n',nickname,'-i',str(exported)],client_environment)
        owner=browser=dns=None;servers=[];baseline=prefix_processes()
        try:
            owner=OwnerFixture(desktop)
            failed=wait_for(lambda:(value if (value:=owner.call('status')).get('phase')=='failed' else None),
                'Expired local authority startup rejection',seconds=15)
            with socket.socket() as denied:assert denied.connect_ex(('127.0.0.1',port))!=0
            assert not (expired/'bundle.pem').exists() and not (expired/'application.pem').exists()
            assert before=={name:hashlib.sha256((expired/name).read_bytes()).hexdigest() for name in before}
            owner.close();owner=None
            wait(lambda:prefix_processes()==baseline,'Expired local authority left runtime children',timeout=10)
            dns=DNS();dns.set(DOMAIN,['127.0.0.1'])
            browser=Browser(client,client/'expiry-profile',client_environment)
            positive=CertificateServer(root,valid,'DNS:'+DOMAIN);servers.append(positive)
            assert not browser.navigate('https://'+DOMAIN+':'+str(positive.port)+'/').get('errorText')
            browser.wait("document.body && document.body.textContent.includes('certificate constraint witness')",'Valid-root browser positive control')
            negative=CertificateServer(root,expired,'DNS:'+DOMAIN);servers.append(negative)
            result=browser.navigate('https://'+DOMAIN+':'+str(negative.port)+'/')
            assert result.get('errorText')=='net::ERR_CERT_DATE_INVALID',result
            assert negative.requests==0
            report.update(status='passed',browser=browser.version['product'],installedHostRefusedExpiredAuthority=True,
                noSilentAuthorityRotation=True,noApplicationListener=True,noRuntimeChildren=True,
                clientExplicitlyTrustedBothRoots=True,validRootPositiveControl=True,
                currentLeafUnderExpiredRootRejected=result['errorText'],noTLSOrSandboxBypass=True)
        finally:
            errors=[]
            actions=[]
            if owner:actions.append(owner.close)
            actions.extend(server.close for server in reversed(servers))
            if browser:actions.append(browser.close)
            if dns:actions.append(dns.close)
            for action in actions:
                try:action()
                except BaseException as error:errors.append(type(error).__name__)
            if errors:report.update(status='failed',cleanupErrors=errors)
            (args.evidence/'expired-ca-summary.json').write_text(json.dumps(report,indent=2)+'\n')
            assert not errors,errors
    print(json.dumps(report),flush=True)


if __name__=='__main__':main()
