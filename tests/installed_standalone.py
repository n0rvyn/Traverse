"""Installed one-port launcher: nonroot default/custom TLS, TURN and real X11 stop.

Runs only in the disposable package-test container under xvfb-run. The observer
is root; all application processes run as UID/GID65534 on that test display.
Ordinary Chrome video/control remains a separate exact-artifact Internet test.
"""
import hashlib
import datetime
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

from bind_helper_test import UID, GID, BIND, verify_threads
from installed_turn import attribute, exchange, peer, packet
from certificate_fixture import issue_leaf

PREFIX = Path(os.environ.get('TRAVERSE_TEST_PREFIX', '/opt/traverse'))


def children(pid):
    found=set()
    try:
        for thread in Path(f'/proc/{pid}/task').iterdir():
            try:
                found.update(int(item) for item in (thread/'children').read_text().split())
            except (FileNotFoundError,ProcessLookupError):
                pass
    except FileNotFoundError:
        pass
    return sorted(found)


def descendants(pid):
    found = set()
    pending = children(pid)
    while pending:
        item = pending.pop()
        if item not in found:
            found.add(item);pending.extend(children(item))
    return found


def alive(pid):
    try:
        return Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1][0] != 'Z'
    except FileNotFoundError:
        return False


def free_port():
    while True:
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            tcp.bind(('127.0.0.1', 0));port = tcp.getsockname()[1]
            try:
                udp.bind(('0.0.0.0', port))
                return port
            except OSError:
                continue


def ipc(path, route, body=None, token=None):
    connection = http.client.HTTPConnection('localhost', timeout=3)
    connection.sock = socket.socket(socket.AF_UNIX)
    connection.sock.settimeout(3);connection.sock.connect(str(path))
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer '+token
    try:
        connection.request('POST' if body is not None else 'GET', route,
                           None if body is None else json.dumps(body), headers)
        response = connection.getresponse()
        result = json.loads(response.read())
        assert response.status == 200, (route, response.status)
        return result
    finally:
        connection.close()


def wait(predicate, description, timeout=15):
    deadline = time.monotonic()+timeout
    while True:
        if predicate():
            return
        assert time.monotonic() < deadline, description
        time.sleep(.03)


def main():
    assert os.getuid() == 0
    with tempfile.TemporaryDirectory(prefix='traverse-standalone-') as tmp:
        root = Path(tmp);root.chmod(0o755)
        home = root/'home';home.mkdir(mode=0o700);os.chown(home, UID, GID)
        runtime = home/'runtime';runtime.mkdir(mode=0o700);os.chown(runtime, UID, GID)
        authority = home/'Xauthority'
        shutil.copyfile(os.environ['XAUTHORITY'], authority)
        os.chown(authority, UID, GID);authority.chmod(0o600)
        cert, key = root/'cert.pem', home/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign',
                        '-addext', 'subjectKeyIdentifier=hash',
                        '-addext', 'authorityKeyIdentifier=keyid:always',
                        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        os.chown(key, UID, GID);key.chmod(0o600)
        trust, issuer_key = root/'trust.pem', root/'issuer.key'
        trust.write_bytes(cert.read_bytes());trust.chmod(0o644)
        issuer_key.write_bytes(key.read_bytes());issuer_key.chmod(0o600)
        # The configured file is valid but cannot authenticate this issuer.
        # Only the second relative hashed directory supplies the right root;
        # this exercises each path before the binding helper changes cwd.
        other_trust, other_key = root/'other-trust.pem', root/'other-trust.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=Unrelated test authority',
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                        '-keyout', str(other_key), '-out', str(other_trust)], check=True, capture_output=True)
        empty_trust, trust_directory = root/'empty-trust-directory', root/'trust-directory'
        empty_trust.mkdir(mode=0o755);trust_directory.mkdir(mode=0o755)
        (trust_directory/'root.pem').write_bytes(trust.read_bytes())
        (trust_directory/'root.pem').chmod(0o644)
        subprocess.run(['openssl', 'rehash', str(trust_directory)], check=True, capture_output=True)
        env = dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(runtime),
                   XDG_CACHE_HOME=str(home/'cache'), XAUTHORITY=str(authority),
                   SSL_CERT_FILE='other-trust.pem', SSL_CERT_DIR='empty-trust-directory:trust-directory')
        options = dict(env=env, user=UID, group=GID, extra_groups=[], cwd=str(root))
        context = ssl.create_default_context(cafile=str(cert))
        path = home/'config.json'
        socket_path = runtime/'traverse/adapter.sock'
        probe = os.environ.get('TRAVERSE_TEST_X11_PROBE', '/tmp/x11-probe')
        def x11(*arguments):
            return json.loads(subprocess.check_output([probe, *arguments], env=env, text=True))
        def configure(port, base='/', domain='localhost', omit_port=False):
            config = dict(schemaVersion=1, domain=domain, port=port, basePath=base,
                          certificate=str(cert), privateKey=str(key), listenAddress='127.0.0.1')
            if omit_port:
                del config['port']
            path.write_text(json.dumps(config));os.chown(path, UID, GID);path.chmod(0o600)
        old_credentials = None
        default = free_port() if os.environ.get('TRAVERSE_TEST_CUSTOM_ONLY') == '1' else 443
        for base, ending in [('/', 'terminate'), ('/traverse/v1.2/', 'local-stop'),
                             ('/', 'crash'), ('/', 'child-failure')]:
            # Do not leave future ephemeral ports available to earlier cases'
            # outgoing connections, which can retain them in TCP TIME_WAIT.
            port = default if ending == 'terminate' else free_port()
            before_instances = set((runtime/'traverse').glob('instance-*'))
            configure(port, base, omit_port=port == 443)
            origin = 'https://localhost'+('' if port == 443 else ':'+str(port))
            owned, credentials = set(), None
            log_path = root/('launch-'+ending+'.log')
            with log_path.open('w+') as log:
                launch = subprocess.Popen(['traverse', '--config', str(path)], stdout=log, stderr=log, **options)
                relay = None
                try:
                    def ready():
                        assert launch.poll() is None, 'Standalone launcher exited before readiness'
                        owned.update(descendants(launch.pid))
                        return 'Local HTTPS verified.' in log_path.read_text()
                    wait(ready, 'Installed standalone did not verify its HTTPS endpoint')
                    direct = children(launch.pid)
                    assert len(direct) == 4, direct
                    roles = {Path(f'/proc/{pid}/exe').resolve().name: pid for pid in direct}
                    assert set(roles) == {'traverse-adapter', 'traverse-service', 'traverse-tls-frontend', 'turnserver'}
                    instances = set((runtime/'traverse').glob('instance-*'))-before_instances
                    assert len(instances) == 1
                    certificate_status = instances.pop()/'tls-status.json'
                    wait(certificate_status.exists, 'Standalone certificate status not published')
                    def snapshot():
                        metadata = certificate_status.lstat()
                        assert metadata.st_uid == UID and metadata.st_mode & 0o777 == 0o600
                        data = json.loads(certificate_status.read_text())
                        assert data['schemaVersion'] == 1
                        assert data['frontendPid'] == roles['traverse-tls-frontend']
                        return data
                    assert snapshot()['available']
                    assert ipc(socket_path, '/state')['pid'] == roles['traverse-adapter']
                    for pid in owned | {launch.pid}:
                        if not alive(pid):
                            continue
                        fields = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
                        assert set(map(int, fields['Uid'].split())) == {UID}
                        assert set(map(int, fields['Gid'].split())) == {GID}
                        expected = BIND if port == 443 and pid == roles['traverse-service'] else 0
                        for name in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb']:
                            assert int(fields[name], 16) == expected, (pid, name, fields[name])
                    if port == 443:
                        verify_threads(roles['traverse-service'], BIND)
                        verify_threads(roles['traverse-tls-frontend'], 0)
                    duplicate = subprocess.run(['traverse', '--config', str(path)], capture_output=True,
                                               text=True, timeout=10, **options)
                    assert duplicate.returncode and all(alive(pid) for pid in direct)
                    with urllib.request.urlopen(origin+base, context=context, timeout=3) as response:
                        assert response.status == 200 and b'Traverse' in response.read()
                    for suffix in ['client.js', 'style.css']:
                        with urllib.request.urlopen(origin+base+suffix, context=context, timeout=3) as response:
                            assert response.status == 200
                    try:
                        urllib.request.urlopen(origin+base+'api/stats', context=context, timeout=3)
                        raise AssertionError('Unauthenticated stats accepted')
                    except urllib.error.HTTPError as error:
                        assert error.code == 403
                    code = re.search(r'Pairing code: ([0-9a-f]+)', log_path.read_text()).group(1)
                    request = urllib.request.Request(origin+base+'api/pair', json.dumps({'code': code}).encode(),
                                                     {'Origin': origin, 'Content-Type': 'application/json'})
                    with urllib.request.urlopen(request, context=context, timeout=5) as response:
                        paired = json.loads(response.read())
                    credentials = paired['iceServers'][0]
                    assert credentials['urls'] == f'turns:localhost:{port}?transport=tcp'
                    assert paired.get('iceTransportPolicy', 'all') == 'all'
                    assert ipc(socket_path, '/state')['capturing']
                    # Real service negotiation must identify the primary source
                    # and associate RTX with it, including an early answer.
                    # A second offer exercises the same path as reconnect.
                    offer = '\r\n'.join([
                        'v=0', 'o=- 1 1 IN IP4 127.0.0.1', 's=-', 't=0 0',
                        'a=group:BUNDLE 0', 'm=video 9 UDP/TLS/RTP/SAVPF 96 97',
                        'c=IN IP4 0.0.0.0', 'a=mid:0', 'a=recvonly', 'a=rtcp-mux',
                        'a=ice-ufrag:test', 'a=ice-pwd:synthetic-negotiation-password',
                        'a=setup:actpass', 'a=fingerprint:sha-256 '+':'.join(['AA']*32),
                        'a=rtpmap:96 VP8/90000', 'a=rtcp-fb:96 nack',
                        'a=rtcp-fb:96 nack pli', 'a=rtpmap:97 rtx/90000',
                        'a=fmtp:97 apt=96', ''])
                    sources = set()
                    for _ in range(2):
                        request = urllib.request.Request(origin+base+'api/offer',
                            json.dumps({'type': 'offer', 'sdp': offer}).encode(),
                            {'Origin': origin, 'Content-Type': 'application/json',
                             'Authorization': 'Bearer '+paired['token']})
                        with urllib.request.urlopen(request, context=context, timeout=20) as response:
                            answer = json.loads(response.read())['sdp']
                        assert 'a=rtpmap:97 rtx/90000' in answer
                        association = re.search(r'^a=ssrc-group:FID (\d+) (\d+)\r?$', answer, re.M)
                        assert association and association[1] != association[2], 'Missing primary/RTX association'
                        assert re.search(r'^a=ssrc:'+association[1]+r' msid:', answer, re.M), 'Primary track absent'
                        assert re.search(r'^a=ssrc:'+association[2]+r' msid:', answer, re.M), 'RTX track absent'
                        sources.add(association[1])
                    assert len(sources) == 2, 'Reconnected peers reused a source identity'
                    # Negotiation coverage is complete. Close the synthetic peer
                    # before the independent certificate/input lifecycle proof.
                    request = urllib.request.Request(origin+base+'api/disconnect', b'{}',
                        {'Origin': origin, 'Content-Type': 'application/json',
                         'Authorization': 'Bearer '+paired['token']})
                    with urllib.request.urlopen(request, context=context, timeout=5) as response:
                        assert json.loads(response.read())['ok']
                    with socket.socket(type=socket.SOCK_DGRAM) as route:
                        route.connect(('192.0.2.1', 9));peer_ip = route.getsockname()[0]
                    relay = context.wrap_socket(socket.create_connection(('127.0.0.1', port), timeout=3), server_hostname='localhost')
                    relay.settimeout(3)
                    requested = attribute(0x19, b'\x11\0\0\0')
                    _, challenge, error = exchange(relay, 3, requested)
                    assert error == 401
                    def authorization(item):
                        auth = attribute(6, item['username'].encode())+attribute(0x14, challenge[0x14])+attribute(0x15, challenge[0x15])
                        key = hashlib.md5(item['username'].encode()+b':'+challenge[0x14]+b':'+item['credential'].encode()).digest()
                        return auth, key
                    if old_credentials:
                        auth, integrity = authorization(old_credentials)
                        assert exchange(relay, 3, requested+auth, integrity)[2] == 401
                        # A TURN TCP session retains its first username, including
                        # after a rejected allocation. A different identity needs
                        # a fresh connection (otherwise coturn correctly returns437).
                        relay.close()
                        relay = context.wrap_socket(socket.create_connection(('127.0.0.1', port), timeout=3), server_hostname='localhost')
                        relay.settimeout(3)
                        _, challenge, error = exchange(relay, 3, requested)
                        assert error == 401
                    auth, integrity = authorization(credentials)
                    assert exchange(relay, 3, requested+auth, integrity)[0] == 0x0103
                    with socket.socket(type=socket.SOCK_DGRAM) as witness:
                        witness.bind((peer_ip, 0));witness.settimeout(3)
                        destination = peer(peer_ip, witness.getsockname()[1])
                        assert exchange(relay, 8, destination+auth, integrity)[0] == 0x0108
                        relay.sendall(packet(0x0016, destination+attribute(0x13, b'standalone-real-relay'))[0])
                        assert witness.recvfrom(65536)[0] == b'standalone-real-relay'
                    ipc(socket_path, '/input', {'type': 'key', 'code': 'ShiftLeft', 'down': True}, paired['token'])
                    assert x11('query')['shift'] == 1
                    if ending == 'terminate':
                        original_cert, original_key = cert.read_bytes(), key.read_bytes()
                        heartbeat_stop, heartbeat_errors = threading.Event(), []
                        def keep_input_alive():
                            while not heartbeat_stop.wait(.1):
                                try:ipc(socket_path, '/input', {'type': 'heartbeat'}, paired['token'])
                                except Exception as error:
                                    heartbeat_errors.append(str(error));return
                        heartbeat = threading.Thread(target=keep_input_alive, daemon=True);heartbeat.start()
                        try:
                            def healthy_snapshot():
                                try:return snapshot()['available']
                                except (OSError, ValueError, AssertionError):return False
                            baseline_status = snapshot()
                            def force_certificate_refresh():
                                descriptor = os.pidfd_open(roles['traverse-tls-frontend'])
                                try:
                                    assert Path(f"/proc/{roles['traverse-tls-frontend']}/exe").resolve() == PREFIX/'libexec/traverse/traverse-tls-frontend'
                                    signal.pidfd_send_signal(descriptor, signal.SIGHUP)
                                finally:os.close(descriptor)
                            errors = {'missing': 'missing', 'malformed': 'JSON invalid',
                                      'wrong-pid': 'different frontend', 'stale': 'stale',
                                      'permissions': 'permissions', 'owner': 'ownership',
                                      'schema': 'schema invalid'}
                            for fault, reason in errors.items():
                                offset = len(log_path.read_text())
                                fault_stop = threading.Event()
                                def corrupt_status():
                                    while not fault_stop.is_set():
                                        if fault == 'missing':certificate_status.unlink(missing_ok=True)
                                        else:
                                            bad = dict(baseline_status)
                                            bad['observedMonotonicMs'] = int(time.monotonic()*1000)
                                            if fault == 'wrong-pid':bad['frontendPid'] += 1
                                            if fault == 'stale':bad['observedMonotonicMs'] = 0
                                            if fault == 'schema':bad['schemaVersion'] = 2
                                            text = 'not-json' if fault == 'malformed' else json.dumps(bad)
                                            temporary = certificate_status.with_name('.fixture-status')
                                            temporary.write_text(text)
                                            temporary.chmod(0o644 if fault == 'permissions' else 0o600)
                                            os.chown(temporary, 0 if fault == 'owner' else UID, GID)
                                            temporary.replace(certificate_status)
                                        fault_stop.wait(.02)
                                corrupter = threading.Thread(target=corrupt_status, daemon=True);corrupter.start()
                                try:
                                    wait(lambda: any('Traverse certificate: status unavailable:' in line and reason in line
                                                    for line in log_path.read_text()[offset:].splitlines()),
                                         'Supervisor did not reject '+fault+' certificate status', timeout=4)
                                    assert all(alive(pid) for pid in direct), 'Metadata failure stopped sharing'
                                finally:
                                    fault_stop.set();corrupter.join(3)
                                    assert not corrupter.is_alive()
                                repaired_offset = len(log_path.read_text())
                                if certificate_status.exists():
                                    certificate_status.chmod(0o600);os.chown(certificate_status, UID, GID)
                                force_certificate_refresh()
                                wait(healthy_snapshot, 'Frontend did not repair certificate metadata')
                                wait(lambda: 'Traverse certificate: status restored' in log_path.read_text()[repaired_offset:],
                                     'Supervisor ignored restored certificate status')
                            def replace_material(certificate_bytes, key_bytes):
                                staged_cert, staged_key = root/'tls-next.pem', home/'tls-next.key'
                                staged_cert.write_bytes(certificate_bytes);staged_cert.chmod(0o644)
                                staged_key.write_bytes(key_bytes);staged_key.chmod(0o600);os.chown(staged_key, UID, GID)
                                staged_cert.replace(cert);staged_key.replace(key)
                            def fresh_fingerprint():
                                with socket.create_connection(('127.0.0.1', port), timeout=3) as raw:
                                    with context.wrap_socket(raw, server_hostname='localhost') as stream:
                                        return hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest()
                            renewed_cert, renewed_key = issue_leaf(root, trust, issuer_key, 'installed-renewal')
                            expected_fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(renewed_cert.decode())).hexdigest()
                            offset = len(log_path.read_text())
                            replace_material(renewed_cert, renewed_key);force_certificate_refresh()
                            wait(lambda: snapshot()['fingerprint'] == expected_fingerprint, 'Renewed certificate metadata not observed')
                            wait(lambda: 'Traverse certificate: renewed' in log_path.read_text()[offset:],
                                 'Supervisor ignored accepted certificate renewal')
                            assert fresh_fingerprint() == expected_fingerprint
                            assert set(children(launch.pid)) == set(direct)
                            offset = len(log_path.read_text())
                            replace_material(renewed_cert, original_key);force_certificate_refresh()
                            wait(lambda: bool(snapshot()['reloadError']), 'Bad renewal was not recorded')
                            wait(lambda: 'Traverse certificate: renewal rejected:' in log_path.read_text()[offset:],
                                 'Supervisor ignored rejected renewal')
                            assert fresh_fingerprint() == expected_fingerprint
                            offset = len(log_path.read_text())
                            replace_material(renewed_cert, renewed_key);force_certificate_refresh()
                            wait(lambda: not snapshot()['reloadError'], 'Certificate renewal did not recover')
                            wait(lambda: 'Traverse certificate: renewal recovered' in log_path.read_text()[offset:],
                                 'Supervisor ignored recovered renewal')
                            short_cert, short_key = issue_leaf(root, trust, issuer_key, 'installed-short',
                                start=datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(minutes=1),
                                lifetime_seconds=6)
                            short_fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(short_cert.decode())).hexdigest()
                            replace_material(short_cert, short_key);force_certificate_refresh()
                            wait(lambda: snapshot()['fingerprint'] == short_fingerprint, 'Short-lived test certificate not active')
                            offset = len(log_path.read_text())
                            wait(lambda: 'Traverse certificate: expired;' in log_path.read_text()[offset:],
                                 'Supervisor ignored active certificate expiry')
                            wait(lambda: not snapshot()['available'], 'Frontend snapshot did not observe expiry')
                            assert all(alive(pid) for pid in direct)
                            offset = len(log_path.read_text())
                            replace_material(renewed_cert, renewed_key);force_certificate_refresh()
                            wait(healthy_snapshot, 'Renewal failed to restore available certificate')
                            wait(lambda: 'Traverse certificate: available' in log_path.read_text()[offset:],
                                 'Supervisor ignored restored certificate admission')
                            assert fresh_fingerprint() == expected_fingerprint
                            # The authenticated TURN connection predates every
                            # context swap and expiry; it must still carry data.
                            with socket.socket(type=socket.SOCK_DGRAM) as witness:
                                witness.bind((peer_ip, 0));witness.settimeout(3)
                                destination = peer(peer_ip, witness.getsockname()[1])
                                relay.sendall(packet(0x0016, destination+attribute(0x13, b'renewal-kept-relay'))[0])
                                assert witness.recvfrom(65536)[0] == b'renewal-kept-relay'
                            assert not heartbeat_errors, heartbeat_errors
                            assert x11('query')['shift'] == 1
                            assert set(children(launch.pid)) == set(direct)
                        finally:
                            # Restore fixture material for the following complete
                            # launcher lifecycle cases; never touch system trust.
                            staged_cert, staged_key = root/'tls-restore.pem', home/'tls-restore.key'
                            staged_cert.write_bytes(original_cert);staged_cert.chmod(0o644)
                            staged_key.write_bytes(original_key);staged_key.chmod(0o600);os.chown(staged_key, UID, GID)
                            staged_cert.replace(cert);staged_key.replace(key)
                            heartbeat_stop.set();heartbeat.join(3)
                            assert not heartbeat.is_alive()
                    if ending == 'local-stop':
                        dialog = x11('focus', 'Traverse sharing')
                        subprocess.run([probe, 'move', str(dialog['x']+40), str(dialog['y']+dialog['height']-15)], env=env, check=True, stdout=subprocess.DEVNULL)
                        subprocess.run([probe, 'click'], env=env, check=True, stdout=subprocess.DEVNULL)
                    elif ending == 'crash':
                        launch.kill()
                    elif ending == 'child-failure':
                        descriptor = os.pidfd_open(roles['turnserver'])
                        try:
                            signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                        finally:
                            os.close(descriptor)
                    else:
                        launch.terminate()
                    launch.wait(timeout=20)
                    wait(lambda: not x11('query')['shift'], 'Held Shift was not released', timeout=5)
                    wait(lambda: not any(alive(pid) for pid in owned), 'Standalone descendant survived', timeout=10)
                    try:
                        assert relay.recv(1) == b'', 'Old relay connection survived full stop'
                    except (ssl.SSLEOFError, ConnectionResetError):
                        pass
                    if ending in ['terminate', 'local-stop']:
                        assert launch.returncode == 0
                    else:
                        assert launch.returncode != 0
                    assert set((runtime/'traverse').glob('instance-*')) <= before_instances or ending == 'crash'
                    rejected_old = old_credentials is not None
                    old_credentials = credentials
                    print(json.dumps({'port': port, 'basePath': base, 'ending': ending, 'uid': UID,
                                      'httpsVerified': True, 'authenticatedRealTurn': True,
                                      'inputReleased': True, 'allOwnedProcessesExited': True,
                                      'relayConnectionClosed': True, 'oldCredentialsRejectedAfterRestart': rejected_old,
                                      'certificateMetadataOwnerPidAndModeVerified': True,
                                      'certificateRenewalExpiryAndSupervisorRecovery': ending == 'terminate'}))
                except BaseException:
                    socket_rows = {}
                    for table in ('tcp', 'tcp6', 'udp', 'udp6'):
                        try:
                            socket_rows[table] = [row.split() for row in
                                Path('/proc/net/'+table).read_text().splitlines()[1:]
                                if int(row.split()[1].rsplit(':', 1)[1], 16) == port]
                        except OSError as error:
                            socket_rows[table] = {'readErrno': error.errno}
                    print(json.dumps({'standaloneFailure': ending, 'port': port,
                                      'launcherExit': launch.poll(), 'socketRows': socket_rows}))
                    diagnostic = re.sub(r'Pairing code: \S+', 'Pairing code: [redacted]', log_path.read_text())
                    if credentials:
                        diagnostic = diagnostic.replace(credentials['credential'], '[redacted]')
                    print(diagnostic)
                    raise
                finally:
                    if relay:
                        relay.close()
                    if launch.poll() is None:
                        launch.kill();launch.wait(timeout=10)
                    wait(lambda: not any(alive(pid) for pid in owned), 'Owned process survived test cleanup', timeout=10)
        # Conflicts and certificate errors leave the occupying socket unchanged.
        for conflict in ['tcp', 'udp', 'certificate']:
            port = free_port();configure(port, domain='wrong.invalid' if conflict == 'certificate' else 'localhost')
            with socket.socket(type=socket.SOCK_DGRAM if conflict == 'udp' else socket.SOCK_STREAM) as occupied:
                if conflict != 'certificate':
                    occupied.bind(('0.0.0.0', port))
                    if conflict == 'tcp':
                        occupied.listen()
                result = subprocess.run(['traverse', '--config', str(path)], capture_output=True, text=True, timeout=25, **options)
                assert result.returncode and 'Traverse URL:' not in result.stdout
                expected = {'tcp': 'Cannot bind TLS listener', 'udp': 'Cannot bind media UDP port',
                            'certificate': 'Certificate does not match the configured domain'}[conflict]
                assert expected in result.stderr, (conflict, result.stderr)
                if conflict != 'certificate':
                    assert occupied.getsockname()[1] == port
                print(json.dumps({'startupRejected': conflict, 'existingServicePreserved': True}))


if __name__ == '__main__':
    main()
