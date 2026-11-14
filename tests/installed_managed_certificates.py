"""Actual installed automatic startup/renewal/Stop in an isolated X11 container.

Root is only the observer; launcher/issuer/desktop run as UID/GID65534.
Real private CA validation is bridged to the actual TCP443 validation role.
No public CA, owner-log reads, global DNS/trust or existing service changes.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import zlib

from bind_helper_test import UID, GID, BIND, verify_threads
from installed_standalone import alive, children, descendants, free_port, ipc, wait
from issuer_native import DOMAIN
from managed_ca_fixture import PrivateCA

PREFIX = Path(os.environ.get('TRAVERSE_TEST_PREFIX', '/opt/traverse'))
PEBBLE = Path('/src/.work/issuer-tools/pebble')


def prefix_processes():
    result = set()
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if (entry/'exe').resolve().is_relative_to(PREFIX):
                result.add(int(entry.name))
        except (FileNotFoundError, ProcessLookupError):
            pass
    return result


class Desktop:
    def __init__(self, root, ca, port, base='/'):
        self.root, self.ca, self.port, self.base = root, ca, port, base
        self.home = root/'home';self.home.mkdir(mode=0o700);os.chown(self.home, UID, GID)
        self.runtime = self.home/'runtime';self.runtime.mkdir(mode=0o700);os.chown(self.runtime, UID, GID)
        authority = self.home/'Xauthority';shutil.copyfile(os.environ['XAUTHORITY'], authority)
        os.chown(authority, UID, GID);authority.chmod(0o600)
        self.data = self.home/'data';self.path = self.home/'config.json'
        config = {'schemaVersion': 1, 'domain': DOMAIN, 'basePath': base,
                  'listenAddress': '127.0.0.1', 'certificateSettings': ca.options()}
        if port!=443:
            config['port'] = port
        self.path.write_text(json.dumps(config));self.path.chmod(0o600);os.chown(self.path, UID, GID)
        self.env = dict(os.environ, HOME=str(self.home), XDG_DATA_HOME=str(self.data),
                        XDG_RUNTIME_DIR=str(self.runtime), XDG_CACHE_HOME=str(self.home/'cache'),
                        XAUTHORITY=str(authority))
        self.context = ssl.create_default_context(cafile=str(ca.issuing_root))
        self.origin = 'https://'+DOMAIN+('' if port==443 else ':'+str(port))
        self.launch = None
        self.owned = set()
        self.crashed = False
        self.adapter = self.runtime/'traverse/adapter.sock'
        self.probe = os.environ.get('TRAVERSE_TEST_X11_PROBE', '/tmp/x11-probe')

    def start(self):
        self.owned = set()
        self.crashed = False
        self.baseline = prefix_processes()
        self.launch = subprocess.Popen([str(PREFIX/'bin/traverse'), '--config', str(self.path)],
            env=self.env, user=UID, group=GID, extra_groups=[], cwd=str(self.home),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def collect(self):
        if self.launch:
            self.owned.update(descendants(self.launch.pid))

    def snapshot(self):
        self.collect()
        instances = list((self.runtime/'traverse').glob('instance-*'))
        if len(instances)!=1:
            return None
        path = instances[0]/'tls-status.json'
        self.status_path = path
        if not path.exists():
            return None
        metadata = path.stat()
        assert metadata.st_uid==UID and metadata.st_mode & 0o777==0o600
        value = json.loads(path.read_text())
        assert value['schemaVersion']==1
        if value['frontendPid'] not in children(self.launch.pid):
            return None  # Owned proof-only -> application child transition.
        return value

    def stream(self):
        raw = socket.create_connection(('127.0.0.1', self.port), timeout=3)
        return self.context.wrap_socket(raw, server_hostname=DOMAIN)

    def http(self, route='', body=None, token=None, stream=None):
        connection = http.client.HTTPSConnection(DOMAIN, self.port, context=self.context, timeout=5)
        connection.sock = stream or self.stream()
        headers = {'Origin': self.origin, 'Content-Type': 'application/json', 'Connection': 'keep-alive'}
        if token:
            headers['Authorization'] = 'Bearer '+token
        connection.request('POST' if body is not None else 'GET', self.base+route,
                           None if body is None else json.dumps(body), headers)
        response = connection.getresponse();data = response.read()
        status = response.status
        # Retained TLS is owned by the caller; do not let HTTPConnection.__del__
        # close it between independent renewal witnesses.
        if stream is not None:
            connection.sock = None
        else:
            connection.close()
        return status, data

    def ready(self):
        assert self.launch.poll() is None, 'Installed automatic launcher exited before trusted readiness'
        try:
            snapshot = self.snapshot()
            return snapshot and snapshot['available'] and self.http()[0]==200
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException):
            return False

    def state(self):
        paths = list(self.data.glob('traverse/certificates/*'))
        assert len(paths)==1
        identity = json.loads((paths[0]/'directory.json').read_text())
        assert identity['directory']==self.ca.directory
        return paths[0]

    def x11(self, *arguments):
        return json.loads(subprocess.check_output([self.probe, *arguments], env=self.env, text=True))

    def local_stop(self):
        dialog = self.x11('focus', 'Traverse sharing')
        subprocess.run([self.probe, 'move', str(dialog['x']+40), str(dialog['y']+dialog['height']-15)],
                       env=self.env, check=True, stdout=subprocess.DEVNULL)
        subprocess.run([self.probe, 'click'], env=self.env, check=True, stdout=subprocess.DEVNULL)

    def stop_diagnostics(self):
        # This fixture creates every observed process and its private X display.
        # Never inspect argv, environment, account material or operator logs.
        result = {'syntheticStopDiagnostic':True,'port':self.port,'launcherExit':self.launch.poll()}
        try:
            state=ipc(self.adapter,'/state')
            result['adapter']={key:state[key] for key in ('armed','paired','capturing')}
        except (OSError,ValueError,AssertionError,http.client.HTTPException):
            result['adapter']='unavailable'
        result['shiftHeld']=self.x11('query')['shift']
        result['children']=[]
        for pid in descendants(self.launch.pid):
            try:
                root=Path(f'/proc/{pid}')
                fields=dict(line.split(':',1) for line in (root/'status').read_text().splitlines() if ':' in line)
                result['children'].append({'pid':pid,'name':fields['Name'].strip(),
                    'state':fields['State'].strip(),'waitChannel':(root/'wchan').read_text().strip()})
            except OSError:
                pass
        destination=os.environ.get('TRAVERSE_TEST_FAILURE_ARTIFACTS')
        if destination:
            try:
                directory=Path(destination);directory.mkdir(parents=True,exist_ok=True)
                image=directory/f'managed-stop-{os.getpid()}-{self.port}.ppm'
                subprocess.run(['/tmp/x11-capture',str(image)],env=self.env,check=True,timeout=5)
                magic,size,maximum,pixels=image.read_bytes().split(b'\n',3)
                width,height=map(int,size.split())
                assert magic==b'P6' and maximum==b'255' and len(pixels)==width*height*3
                def chunk(kind,data):
                    return struct.pack('!I',len(data))+kind+data+struct.pack('!I',zlib.crc32(kind+data))
                scanlines=b''.join(b'\0'+pixels[y*width*3:(y+1)*width*3] for y in range(height))
                image.with_suffix('.png').write_bytes(b'\x89PNG\r\n\x1a\n'+
                    chunk(b'IHDR',struct.pack('!IIBBBBB',width,height,8,2,0,0,0))+
                    chunk(b'IDAT',zlib.compress(scanlines))+chunk(b'IEND',b''))
                result['syntheticDisplayImage']=image.with_suffix('.png').name
            except (OSError,ValueError,AssertionError,subprocess.SubprocessError) as error:
                result['imageFailure']=type(error).__name__
        print(json.dumps(result),flush=True)

    def finish(self, how='terminate', expected=0):
        self.collect()
        if self.launch.poll() is None:
            if how=='local':
                self.local_stop()
            elif how=='kill':
                self.crashed = True
                self.launch.kill()
            else:
                self.launch.terminate()
        try:
            self.launch.wait(timeout=12)
        except subprocess.TimeoutExpired:
            try:
                self.stop_diagnostics()
            except Exception as error:
                print(json.dumps({'syntheticStopDiagnosticError':type(error).__name__}),flush=True)
            raise
        if expected is not None:
            assert self.launch.returncode==expected, ('Owned launcher exit', self.launch.returncode)
        wait(lambda: not any(alive(pid) for pid in self.owned), 'An owned automatic child survived Stop/parent death', timeout=10)
        wait(lambda: not any(alive(pid) for pid in prefix_processes()-self.baseline), 'An untracked installed descendant survived', timeout=10)
        wait(lambda: not self.x11('query')['shift'], 'Held Shift survived automatic Stop/parent death', timeout=5)
        remaining = list((self.runtime/'traverse').glob('instance-*'))
        if self.crashed:
            # SIGKILL cannot run the parent's PrivateFiles destructor. The
            # required invariant is stopped processes/listeners and private
            # remnants, rather than a fictitious successful cleanup handler.
            for path in remaining:
                info=path.lstat()
                assert path.is_dir() and not path.is_symlink() and info.st_uid==UID and info.st_mode & 0o777==0o700
        else:
            assert not remaining, 'Private runtime instance survived normal Stop'

    def close(self):
        if self.launch is not None:
            self.finish(expected=None)

    def capabilities(self):
        self.collect()
        assert self.launch.pid in prefix_processes(), 'Installed-process inventory missed its positive control'
        frontends, service = [], None
        for pid in children(self.launch.pid):
            name = Path(f'/proc/{pid}/exe').resolve().name
            fields = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
            assert set(map(int, fields['Uid'].split()))=={UID}
            assert set(map(int, fields['Gid'].split()))=={GID}
            expected = BIND if name=='traverse-service' and self.port<1024 else 0
            for field in ('CapEff','CapPrm','CapInh','CapAmb'):
                assert int(fields[field],16)==expected, (name,field)
            if name=='traverse-tls-frontend':
                verify_threads(pid,0);frontends.append(pid)
            if name=='traverse-service':
                service = pid
        assert service and len(frontends)==(1 if self.port==443 else 2)
        if self.port==443:
            verify_threads(service,BIND)
        else:
            validation = [pid for pid in frontends if b'--challenge-only\x00true\x00' in Path(f'/proc/{pid}/cmdline').read_bytes()]
            assert len(validation)==1, 'Custom-port validation443 role was not observed'
        return {'frontendCount':len(frontends),'allFrontendThreadsWithoutCaps':True,'serviceOnlyBind':self.port==443}


def changed_schedule(state):
    path = state/'schedule.json';record = json.loads(path.read_text())
    record['schedule']['renewAt'] = int(time.time())-1
    record['schedule']['checkAt'] = int(time.time())+3600
    pending = state/'.fixture-due-schedule.json'
    pending.write_text(json.dumps(record));pending.chmod(0o600);os.chown(pending,UID,GID)
    pending.replace(path)


def renewal_observation(desktop, state, old_peer, validation_count):
    """Only fixed synthetic state; never keys, accounts, orders or owner output."""
    result = {'port':desktop.port,'launcherExit':desktop.launch.poll(),
              'validationAttempts':desktop.ca.bridge.count()-validation_count}
    try:
        snapshot=desktop.snapshot()
        result['frontend']={'present':snapshot is not None}
        if snapshot:
            result['frontend'].update(available=snapshot['available'],revision=snapshot['revision'],
                changed=snapshot['fingerprint']!=old_peer,reloadErrorPresent=bool(snapshot['reloadError']))
    except (OSError,ValueError,AssertionError,KeyError,TypeError):
        result['frontend']={'readFailed':True}
    try:
        schedule=json.loads((state/'schedule.json').read_text())['schedule']
        result['schedule']={key:schedule[key] for key in
            ('renewAt','checkAt','issuing','uncertain','admissionPending','consentBlocked')}
        result['schedule'].update(renewDue=schedule['renewAt']<=time.time(),
                                  checkDue=schedule['checkAt']<=time.time())
        result['pendingPresent']=(state/'pending.json').is_file()
    except (OSError,ValueError,KeyError):
        result['schedule']={'readFailed':True}
    return result


def retain_renewal_diagnostic(desktop, state, old_peer, started, deadline, latest, observations, outcome):
    result={'syntheticRenewalDiagnostic':True,'port':desktop.port,
            'outcome':outcome,
            'launcherExit':desktop.launch.poll(),'elapsedSeconds':time.monotonic()-started,
            'deadlineExpired':time.monotonic()>=deadline,'latestChanged':latest is not None,
            'observations':observations,'children':[]}
    for pid in descendants(desktop.launch.pid):
        try:
            proc=Path('/proc',str(pid));fields=dict(line.split(':',1) for line in (proc/'status').read_text().splitlines() if ':' in line)
            result['children'].append({'name':(proc/'exe').resolve().name,'state':fields['State'].strip(),
                                       'waitChannel':(proc/'wchan').read_text().strip()})
        except OSError:
            pass
    public_bundle=state/'bundle.pem'
    if public_bundle.is_file():
        try:
            certificate=subprocess.run(['openssl','x509','-in',str(public_bundle),'-noout','-fingerprint','-sha256'],
                capture_output=True,text=True,timeout=5)
            if certificate.returncode==0:
                fingerprint=certificate.stdout.strip().split('=',1)[-1].replace(':','').lower()
                result['bundleChanged']=fingerprint!=old_peer
            else:result['bundleInspectionFailed']=True
        except (OSError,subprocess.TimeoutExpired):
            result['bundleInspectionFailed']=True
    destination=os.environ.get('TRAVERSE_TEST_FAILURE_ARTIFACTS')
    print(json.dumps(result),flush=True)
    if destination:
        try:
            directory=Path(destination);directory.mkdir(parents=True,exist_ok=True)
            (directory/f'managed-renewal-{os.getpid()}-{desktop.port}.json').write_text(json.dumps(result,indent=2)+'\n')
        except OSError as error:
            print(json.dumps({'renewalDiagnosticWriteError':type(error).__name__}),flush=True)


def require_disposable_environment():
    # The SDK diagnostic uses private mount/network/PID namespaces instead of
    # Docker. Require evidence of every namespace transition and an isolated
    # network before allowing the same low-port fixture there.
    private_namespaces = all(
        os.environ.get('TRAVERSE_TEST_ORIGINAL_'+kind.upper()+'_NS', '').startswith(kind+':[')
        and os.readlink('/proc/self/ns/'+kind)!=os.environ['TRAVERSE_TEST_ORIGINAL_'+kind.upper()+'_NS']
        for kind in ('mnt','net','pid'))
    if private_namespaces:
        interfaces = {line.split(':',1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines()[2:]}
        assert interfaces <= {'lo','traverse-test0'} and 'lo' in interfaces
    assert os.getuid()==0 and (Path('/.dockerenv').exists() or private_namespaces), \
        'Only an explicit disposable container or private mount/network/PID namespace can bind test443'
    assert Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text().strip()=='1024'


def main():
    require_disposable_environment()
    assert PEBBLE.is_file()
    reports = []
    for app_port in (443,free_port()):
        with tempfile.TemporaryDirectory(prefix='traverse-installed-managed-') as temporary:
            root = Path(temporary);root.chmod(0o755)
            ca = PrivateCA(root,PEBBLE,443)
            desktop = None
            held = None
            try:
                desktop = Desktop(root,ca,app_port,'/' if app_port==443 else '/remote/')
                desktop.start();wait(desktop.ready,'Installed automatic endpoint did not obtain/verify actual material',timeout=45)
                first = desktop.snapshot();state = desktop.state()
                key = (state/'account-key.pem').read_bytes();identity = json.loads((state/'account.json').read_text())['kid']
                validation_count = ca.bridge.count();assert validation_count>0
                capabilities = desktop.capabilities()
                desktop.finish()
                # Cached restart must admit immediately without another order or
                # challenge; this persisted due boundary then exercises renewal
                # while the real controller, TLS stream and held input exist.
                changed_schedule(state)
                desktop.start();wait(desktop.ready,'Cached automatic endpoint failed to start',timeout=15)
                held = desktop.stream();old_peer = hashlib.sha256(held.getpeercert(binary_form=True)).hexdigest()
                assert old_peer==first['fingerprint'], 'Cached startup waited for/replaced material before admission'
                assert not ipc(desktop.adapter,'/state')['paired']
                code = ipc(desktop.adapter,'/arm',{})['code']
                status,data = desktop.http('api/pair',{'code':code});assert status==200
                paired = json.loads(data);token = paired['token']
                assert ipc(desktop.adapter,'/state')['paired']
                ipc(desktop.adapter,'/input',{'type':'key','code':'ShiftLeft','down':True},token)
                assert desktop.x11('query')['shift']==1
                def renewed():
                    ipc(desktop.adapter,'/input',{'type':'heartbeat'},token)
                    snapshot = desktop.snapshot()
                    return snapshot if snapshot and snapshot['available'] and snapshot['fingerprint']!=old_peer else None
                latest = None
                started = time.monotonic();deadline = started+40;observations=[]
                while latest is None:
                    latest = renewed()
                    observation=renewal_observation(desktop,state,old_peer,validation_count)
                    if not observations or observation!=observations[-1]['state']:
                        observations.append({'elapsedSeconds':time.monotonic()-started,'state':observation})
                    if desktop.launch.poll() is not None or time.monotonic()>=deadline:
                        retain_renewal_diagnostic(desktop,state,old_peer,started,deadline,latest,observations,'failed')
                        raise AssertionError('Installed automatic renewal did not reach actual frontend')
                    if latest is None:
                        time.sleep(.03)
                if os.environ.get('TRAVERSE_TEST_RENEWAL_DIAGNOSTICS')=='1':
                    retain_renewal_diagnostic(desktop,state,old_peer,started,deadline,latest,observations,'observed')
                assert desktop.x11('query')['shift']==1 and ipc(desktop.adapter,'/state')['paired']
                assert desktop.http(stream=held)[0]==200
                assert hashlib.sha256(held.getpeercert(binary_form=True)).hexdigest()==old_peer
                with desktop.stream() as fresh:
                    assert hashlib.sha256(fresh.getpeercert(binary_form=True)).hexdigest()==latest['fingerprint']
                assert ca.bridge.count()>validation_count and (state/'account-key.pem').read_bytes()==key
                assert json.loads((state/'account.json').read_text())['kid']==identity
                assert desktop.http('api/stats',token=token)[0]==200
                # Producer metadata is a readiness witness, not authority to
                # revoke a still-valid controller. Keep it invalid across
                # supervisor polls, then observe the real producer recover.
                until = time.monotonic()+.5
                while time.monotonic()<until:
                    poison = desktop.status_path.with_name('.fixture-invalid-status.json')
                    poison.write_text('not-json');poison.chmod(0o600);os.chown(poison,UID,GID)
                    poison.replace(desktop.status_path)
                    ipc(desktop.adapter,'/input',{'type':'heartbeat'},token)
                    assert desktop.launch.poll() is None
                    time.sleep(.03)
                def metadata_recovered():
                    ipc(desktop.adapter,'/input',{'type':'heartbeat'},token)
                    try:
                        snapshot=desktop.snapshot()
                        return snapshot and snapshot['available'] and snapshot['fingerprint']==latest['fingerprint']
                    except (OSError,ValueError):
                        return False
                wait(metadata_recovered,'Certificate status did not recover without revoking controller',timeout=5)
                assert desktop.x11('query')['shift']==1 and ipc(desktop.adapter,'/state')['paired']
                assert desktop.http(stream=held)[0]==200
                desktop.finish(how='local')
                reports.append({'port':app_port,'defaultPortOmitted':app_port==443,'actualPrivateCABootstrap':True,
                    'cachedMaterialAdmittedBeforeRenewal':True,'controlledPersistedDueRenewal':True,
                    'sameControllerAndHeldShiftThroughRenewal':True,'oldTLSAndFreshTLSVerified':True,
                    'sameAccountKeyAndIdentity':True,'metadataFailureKeepsValidController':True,
                    'localStopReleasedInputAndAllChildren':True,**capabilities})
                held.close();held = None
                if app_port!=443:
                    # A valid custom-port host remains available when another
                    # owned fixture holds443; it must not reconfigure that peer.
                    before = (state/'bundle.pem').read_bytes();count = ca.bridge.count()
                    pending_before = (state/'pending.json').read_bytes()
                    account_before = (state/'account.json').read_bytes()
                    with socket.socket() as conflict:
                        conflict.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                        conflict.bind(('127.0.0.1',443));conflict.listen()
                        desktop.start();wait(desktop.ready,'Cached custom host stopped because renewal443 was occupied',timeout=15)
                        assert (state/'bundle.pem').read_bytes()==before and ca.bridge.count()==count
                        assert (state/'pending.json').read_bytes()==pending_before and (state/'account.json').read_bytes()==account_before
                        assert conflict.getsockname()[1]==443
                        desktop.finish()
                    reports.append({'cachedCustomPortWith443ConflictContinues':True,'noAccountOrderOrServiceReplacement':True})
            finally:
                if held:
                    held.close()
                if desktop:
                    desktop.close()
                ca.close()
    # Fresh-state conflicts prove no account key/order activity before ALL
    # required listeners are available. Positive tests above validate the path.
    for app_port in (443,free_port()):
        with tempfile.TemporaryDirectory(prefix='traverse-managed-conflict-') as temporary:
            root=Path(temporary);root.chmod(0o755);ca=PrivateCA(root,PEBBLE,443);desktop=None
            try:
                desktop=Desktop(root,ca,app_port)
                with socket.socket() as conflict:
                    conflict.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                    conflict.bind(('127.0.0.1',443));conflict.listen()
                    desktop.start();desktop.launch.wait(timeout=15)
                    assert desktop.launch.returncode!=0
                    state=desktop.state()
                    assert not (state/'account-key.pem').exists() and not (state/'account.json').exists() and not (state/'pending.json').exists()
                    assert ca.bridge.count()==0 and conflict.getsockname()[1]==443
                    desktop.finish(expected=None)
                reports.append({'freshPort':app_port,'443ConflictBeforeAccountOrOrder':True,'existingListenerPreserved':True})
            finally:
                if desktop:desktop.close()
                ca.close()
    # Actual pending operation beyond15s, then local Stop and owner death. The
    # private VA is held before forwarding; Retry-After20 keeps the real issuer
    # pending. Normal cases above prove successful validation is not bypassed.
    for ending in ('local','kill'):
        with tempfile.TemporaryDirectory(prefix='traverse-managed-pending-') as temporary:
            root=Path(temporary);root.chmod(0o755);ca=PrivateCA(root,PEBBLE,443,slow=True);desktop=None
            try:
                desktop=Desktop(root,ca,443);desktop.start()
                def issuer_child():
                    desktop.collect()
                    return any(Path(f'/proc/{pid}/exe').resolve().name=='traverse-issuer' for pid in children(desktop.launch.pid))
                wait(issuer_child,'Actual installed issuer child not observed',timeout=15)
                started=time.monotonic()
                while time.monotonic()-started<16:
                    desktop.collect();assert desktop.launch.poll() is None;time.sleep(.1)
                assert issuer_child() and ca.bridge.count()>0
                snapshot=desktop.snapshot();assert snapshot and not snapshot['available']
                assert not (desktop.state()/'bundle.pem').exists()
                before=time.monotonic();desktop.finish(how=ending,expected=0 if ending=='local' else None)
                reports.append({'pendingBeyond15s':True,'ending':ending,'realIssuerWasActive':True,
                                'noApplicationAdmission':True,'allOwnedChildrenStopped':True,
                                'crashRemnantsPrivate':ending=='kill','stopSeconds':time.monotonic()-before})
            finally:
                if desktop:desktop.close()
                ca.close()
    print(json.dumps({'status':'passed','scope':'actual installed native/Go/privateCA/X11 lifecycle in isolated namespace',
                      'uid':UID,'cases':reports,'publicCA':False,'ownerLogsReadOrExported':False}),flush=True)


if __name__=='__main__':
    main()
