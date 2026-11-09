"""Installed one-port launcher: nonroot default/custom TLS, TURN and real X11 stop.

Runs only in the disposable package-test container under xvfb-run. The observer
is root; all application processes run as UID/GID65534 on that test display.
Ordinary Chrome video/control remains a separate exact-artifact Internet test.
"""
import hashlib
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
import time
import urllib.error
import urllib.request

from bind_helper_test import UID, GID, BIND, verify_threads
from installed_turn import attribute, exchange, peer, packet

PREFIX = Path(os.environ.get('TRAVERSE_TEST_PREFIX', '/opt/traverse'))


def children(pid):
    try:
        return [int(item) for item in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]
    except FileNotFoundError:
        return []


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
                        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        os.chown(key, UID, GID);key.chmod(0o600)
        env = dict(os.environ, HOME=str(home), XDG_RUNTIME_DIR=str(runtime),
                   XDG_CACHE_HOME=str(home/'cache'), XAUTHORITY=str(authority), SSL_CERT_FILE=str(cert))
        options = dict(env=env, user=UID, group=GID, extra_groups=[])
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
        for port, base, ending in [(default, '/', 'terminate'), (free_port(), '/traverse/v1.2/', 'local-stop'),
                                    (free_port(), '/', 'crash'), (free_port(), '/', 'child-failure')]:
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
                                      'relayConnectionClosed': True, 'oldCredentialsRejectedAfterRestart': rejected_old}))
                except BaseException:
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
                            'certificate': 'HTTPS certificate is not trusted'}[conflict]
                assert expected in result.stderr, (conflict, result.stderr)
                if conflict != 'certificate':
                    assert occupied.getsockname()[1] == port
                print(json.dumps({'startupRejected': conflict, 'existingServicePreserved': True}))


if __name__ == '__main__':
    main()
