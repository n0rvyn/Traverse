"""Actual configured launcher, private owner and observer; disposable network only."""
import json
import os
from pathlib import Path
import shutil
import signal
import fcntl
import socket
import struct
import subprocess
import tempfile
import time
from types import SimpleNamespace
from host_supervisor_test import OwnerFixture
from installed_managed_certificates import PREFIX,prefix_processes,require_disposable_environment
from installed_standalone import alive,children,descendants,free_port,ipc,wait
from issuer_native import DOMAIN
from readiness_observer_test import DNS,hosts_file

def certificate(cert,key,san,issuer=None,common_name=DOMAIN):
    if issuer:
        csr=cert.with_suffix('.csr');extensions=cert.with_suffix('.ext')
        extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName='+san+'\n')
        subprocess.run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
            '-nodes','-batch','-subj','/CN='+common_name,'-keyout',str(key),'-out',str(csr)],check=True,capture_output=True)
        subprocess.run(['openssl','x509','-req','-in',str(csr),'-CA',str(issuer[0]),'-CAkey',str(issuer[1]),
            '-set_serial','0x'+os.urandom(16).hex(),'-days','1','-extfile',str(extensions),'-out',str(cert)],check=True,capture_output=True)
    else:
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256',
            '-nodes','-batch','-days','1','-subj','/CN='+common_name,'-addext','subjectAltName='+san,
            '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,digitalSignature,keyCertSign,cRLSign',
            '-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
    cert.chmod(0o644);key.chmod(0o600);os.chown(key,65534,65534)

def main():
    require_disposable_environment()
    app_port=int(os.environ.get('TRAVERSE_TEST_APP_PORT','443'))
    interface_events=os.environ.get('TRAVERSE_TEST_INTERFACE_EVENTS')=='1'
    for ending in ('stop','eof','death','launcher-death'):
        with tempfile.TemporaryDirectory(prefix='host-url-') as name:
            root=Path(name);root.chmod(0o755);home=root/'home';home.mkdir(mode=0o700);os.chown(home,65534,65534)
            runtime=home/'runtime';runtime.mkdir(mode=0o700);os.chown(runtime,65534,65534)
            authority=home/'Xauthority';shutil.copyfile(os.environ['XAUTHORITY'],authority)
            authority.chmod(0o600);os.chown(authority,65534,65534)
            ca=root/'host-root.pem';ca_key=root/'host-root.key'
            certificate(ca,ca_key,'DNS:fixture-root.example.test',common_name='Traverse URL Fixture Root');os.chown(ca_key,0,0)
            cert=root/'host.pem';key=home/'host.key';certificate(cert,key,'DNS:'+DOMAIN,issuer=(ca,ca_key))
            observer_cert=root/'observer.pem';observer_key=home/'observer.key'
            certificate(observer_cert,observer_key,'IP:127.0.0.1')
            environment=dict(os.environ,HOME=str(home),XDG_RUNTIME_DIR=str(runtime),XDG_DATA_HOME=str(home/'data'),
                XDG_CACHE_HOME=str(home/'cache'),XAUTHORITY=str(authority),SSL_CERT_FILE=str(ca))
            profile=subprocess.run([str(PREFIX/'bin/traverse'),'--runtime-environment'],env=environment,
                check=True,text=True,capture_output=True)
            observer_environment=dict(environment,**json.loads(profile.stdout)['environment'])
            port=free_port();registration='1'*32;credential='2'*64
            token=home/'registration.key';token.write_text(credential+'\n');token.chmod(0o600);os.chown(token,65534,65534)
            observer_config=home/'observer.json'
            observer_config.write_text(json.dumps(dict(schemaVersion=1,listenAddress='127.0.0.1',port=port,
                certificate=str(observer_cert),privateKey=str(observer_key),registrations=[dict(id=registration,token=credential,
                    target=dict(host=DOMAIN,port=app_port,basePath='/remote/',caFile=str(ca),allowedAddresses=['127.0.0.1']))])))
            observer_config.chmod(0o600);os.chown(observer_config,65534,65534)
            config=home/'config.json'
            config.write_text(json.dumps(dict(schemaVersion=1,domain=DOMAIN,port=app_port,basePath='/remote/',listenAddress='127.0.0.1',
                certificate=str(cert),privateKey=str(key),observerSettings=dict(host='127.0.0.1',port=port,caFile=str(observer_cert),
                    registrationId=registration,tokenFile=str(token),timeoutMs=None))))
            config.chmod(0o600);os.chown(config,65534,65534)
            desktop=SimpleNamespace(path=config,home=home,env=environment,broker_stderr=home/'broker-fixture-stderr.txt')
            observer=None;owner=None;dns=None;original=prefix_processes()
            try:
                dns=DNS();dns.set(DOMAIN,['127.0.0.1'])
                observer=subprocess.Popen([str(PREFIX/'libexec/traverse/traverse-readiness-observer'),'--config',str(observer_config)],
                    env=observer_environment,user=65534,group=65534,extra_groups=[],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                # A TCP accept proves listener availability without consuming a registration.
                import socket
                def observer_ready():
                    assert observer.poll() is None,'Native observer exited'
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=1):return True
                    except OSError:return False
                wait(observer_ready,'Actual observer listener startup')
                baseline=prefix_processes();owner=OwnerFixture(desktop)
                def verified():
                    row=owner.call('status');assert row.get('phase')!='failed',row
                    check=row.get('urlCheck') or {}
                    return row if check.get('status')=='verified' and check.get('media')=='verified' else None
                wait(verified,'Automatic configured-launch URL verification',timeout=30)
                first=owner.call('status');assert first['urlCheck']['externalReachability']=='unknown'
                assert first['urlCheck']['mediaChecks']['addresses']==[
                    dict(address='127.0.0.1',mode='relay',status='verified'),
                    dict(address='127.0.0.1',mode='direct',status='verified')],first['urlCheck']
                assert first['urlCheck']['networkObservation']=='active'
                adapter=runtime/'traverse/adapter.sock'
                def authority_state():
                    value=ipc(adapter,'/owner/authority');value.pop('observedMonotonicMs');return value
                before=authority_state()
                assert owner.call('check-connection')['ok']
                rejected=owner.call('check-connection');assert not rejected['ok'] and rejected['error']=='check-running',rejected
                wait(verified,'Explicit retry completion');assert authority_state()==before
                dns.set(DOMAIN,'drop','drop')
                with hosts_file('127.0.0.1 '+DOMAIN) as hosts:
                    wait(lambda:verified() and owner.call('status')['urlCheck'].get('resolution',{}).get('basis')=='hosts',
                        'Hosts-only automatic URL verification',timeout=30)
                    count=dns.count();previous=owner.call('status')['urlCheck']['startedMonotonicMs']
                    assert owner.call('check-connection')['ok']
                    wait(lambda:verified() and owner.call('status')['urlCheck']['startedMonotonicMs']>previous,
                        'Explicit hosts-only verification')
                    assert dns.count()==count,'Hosts-only native host check contacted DNS'
                    hosts.write_text(hosts.read_text().replace('127.0.0.1 '+DOMAIN,'127.0.0.2 '+DOMAIN))
                    wait(lambda:owner.call('status').get('urlCheck',{}).get('reason')=='dnsMismatch',
                        'Changed hosts mapping did not invalidate URL proof',timeout=30)
                    assert authority_state()==before
                    dns.set(DOMAIN,['127.0.0.1'])
                wait(lambda:verified() and owner.call('status')['urlCheck']['resolution']['basis']=='system',
                    'Hosts removal did not restore current DNS evidence',timeout=30)
                start=owner.call('status')['urlCheck']['startedMonotonicMs']
                os.utime('/etc/resolv.conf',None)
                wait(lambda:(owner.call('status').get('urlCheck') or {}).get('startedMonotonicMs',0)>start,'Resolver event failed to invalidate URL result')
                wait(verified,'Resolver-triggered verification')
                if interface_events:
                    start=owner.call('status')['urlCheck']['startedMonotonicMs']
                    name=b'traverse-test0'
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as control:
                        flags=struct.unpack_from('=H',fcntl.ioctl(control,0x8913,struct.pack('16sH22x',name,0)),16)[0]
                        try:
                            fcntl.ioctl(control,0x8914,struct.pack('16sH22x',name,flags&~1))
                            wait(lambda:(owner.call('status').get('urlCheck') or {}).get('startedMonotonicMs',0)>start,
                                'Actual kernel interface change failed to invalidate the configured host')
                        finally:fcntl.ioctl(control,0x8914,struct.pack('16sH22x',name,flags))
                    wait(verified,'Interface-triggered verification')
                old=owner.call('status');start=old['urlCheck']['startedMonotonicMs']
                new_cert=root/'new.pem';new_key=home/'new.key';certificate(new_cert,new_key,'DNS:'+DOMAIN,issuer=(ca,ca_key))
                os.replace(new_key,key);os.replace(new_cert,cert)
                wait(lambda:owner.call('status').get('certificate',{}).get('fingerprint')!=old['certificate']['fingerprint'],
                    'Certificate reload not reported',timeout=10)
                wait(lambda:(owner.call('status').get('urlCheck') or {}).get('startedMonotonicMs',0)>start,'Certificate change failed to invalidate URL check')
                wait(verified,'Renewed certificate URL verification')
                # A real controller cancels a pending idle resolver before it
                # takes over. No background check runs alongside that session.
                dns.set(DOMAIN,'drop','drop');assert owner.call('check-connection')['ok']
                wait(lambda:children(observer.pid),'Pending actual observer resolver worker')
                launcher=owner.ready['launcherPid']
                def readiness_agents():
                    result=[]
                    for pid in children(launcher):
                        try:
                            if Path(f'/proc/{pid}/exe').resolve().name=='traverse-readiness-agent':result.append(pid)
                        except (FileNotFoundError,ProcessLookupError):pass
                    return result
                wait(lambda:len(readiness_agents())==1,'Pending native agent before pairing')
                assert owner.call('pair')['paired'];paired=authority_state()
                wait(lambda:owner.call('status')['urlCheck']['media']=='activeSession',
                    'Real controller did not take priority over background checks')
                wait(lambda:not children(observer.pid),'Pairing left an observer resolver running')
                assert owner.call('hold-shift')['accepted']
                def query():
                    probe=os.environ.get('TRAVERSE_TEST_X11_PROBE','/tmp/x11-probe')
                    result=subprocess.run([probe,'query'],env=environment,user=65534,group=65534,extra_groups=[],
                        text=True,capture_output=True,check=True)
                    return json.loads(result.stdout)
                assert query()['shift']==1
                rejected=owner.call('check-connection');assert not rejected['ok'],rejected
                assert authority_state()==paired
                wait(lambda:not readiness_agents(),'Background agent survived real controller priority')
                owned=descendants(owner.process.pid)
                stopped_at=time.monotonic()
                if ending=='launcher-death':
                    os.kill(launcher,signal.SIGKILL)
                elif ending=='death':owner.process.kill();owner.process.wait(timeout=5)
                else:assert owner.call('request-'+ending)==dict(stopRequested=True)
                wait(lambda:query()['shift']==0,'Active-session Stop left held input',timeout=3)
                release_ms=(time.monotonic()-stopped_at)*1000
                if ending not in ('death','launcher-death'):assert owner.call('wait-stopped')==dict(stopped=True,exit=0)
                wait(lambda:not any(alive(pid) for pid in owned),'Native child survived host loss',timeout=12)
                wait(lambda:prefix_processes()==baseline,'URL agent/worker survived host loss',timeout=5)
                print(json.dumps(dict(ending=ending,automaticStart=True,realHttpsReceipt=True,retry=True,
                    offlineHostsVerifiedWithoutDNS=True,hostsChangeAndRemovalInvalidated=True,
                    resolverInvalidation=True,interfaceInvalidation=interface_events,certificateInvalidation=True,
                    idleDirectAndRelayVerified=True,pairCancelledPendingDns=True,activeSessionSuppressesProbes=True,
                    localInputReleaseObservedMs=round(release_ms,3),allOwnedReaped=True)),flush=True)
            except BaseException:
                diagnostic=home/'broker-fixture-stderr.txt'
                if diagnostic.exists():print(diagnostic.read_text().replace(credential,'[redacted]'),flush=True)
                native=home/'native-fixture-stderr.txt'
                if native.exists():print(native.read_text().replace(credential,'[redacted]'),flush=True)
                raise
            finally:
                if owner:owner.close()
                if observer:
                    if observer.poll() is None:observer.terminate()
                    observer.wait(timeout=8);error=observer.stderr.read();observer.stderr.close()
                    assert credential.encode() not in error
                if dns:dns.close()
                wait(lambda:prefix_processes()==original,'Installed URL fixture left native processes',timeout=5)

if __name__=='__main__':main()
