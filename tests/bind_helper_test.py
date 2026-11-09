"""Real installed helper, UID/capability/thread/loader witnesses in CI containers.

Root is the test observer only. Every app process runs as UID/GID 65534.
The caller must provide an isolated network namespace with low-port threshold1024.
"""
import contextlib
import http.client
import json
import os
import signal
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

PREFIX = Path('/opt/traverse')
HELPER = PREFIX/'libexec/traverse/traverse-bind-helper'
UID = GID = 65534
BIND = 1 << 10


def child_options(env=None):
    return dict(user=UID, group=GID, extra_groups=[], env=env)


def status(path):
    return dict(line.split(':', 1) for line in path.read_text().splitlines() if ':' in line)


def verify_threads(pid, capability):
    threads = list(Path(f'/proc/{pid}/task').iterdir())
    assert threads
    for thread in threads:
        fields = status(thread/'status')
        assert [int(x) for x in fields['Uid'].split()] == [UID]*4, fields['Uid']
        assert [int(x) for x in fields['Gid'].split()] == [GID]*4, fields['Gid']
        for key in ['CapEff', 'CapPrm', 'CapInh', 'CapAmb']:
            assert int(fields[key], 16) == capability, (pid, thread.name, key, fields[key])
        assert int(fields['NoNewPrivs']) == 1
    return len(threads)


def port():
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]


@contextlib.contextmanager
def running(role, arguments, directory, env):
    with (directory/(role+'.log')).open('w+') as log:
        process = subprocess.Popen([str(HELPER), role, *arguments, '--supervisor-pid', str(os.getpid())],
                                   stdout=log, stderr=log, **child_options(env))
        try:
            yield process
        except BaseException:
            log.seek(0)
            print(log.read())
            raise
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill();process.wait()
                raise AssertionError('Owned helper child did not stop')


def rejected(role, arguments, env):
    result = subprocess.run([str(HELPER), role, *arguments, '--supervisor-pid', str(os.getpid())],
                            capture_output=True, text=True, timeout=10, **child_options(env))
    assert result.returncode and 'Traverse binding helper:' in result.stderr, result


def main():
    assert os.getuid() == 0, 'This test observer belongs only in an isolated CI container'
    assert Path('/proc/sys/net/ipv4/ip_unprivileged_port_start').read_text().strip() == '1024'
    assert subprocess.check_output(['getcap', str(HELPER)], text=True).strip() == str(HELPER)+' cap_net_bind_service=ep'
    # Without the helper, both actual low-port protocols must fail for the same UID.
    for kind in ['SOCK_STREAM', 'SOCK_DGRAM']:
        result = subprocess.run(['python3', '-c', f'import socket;s=socket.socket(type=socket.{kind});s.bind(("127.0.0.1",443))'],
                                capture_output=True, text=True, **child_options())
        assert result.returncode and 'PermissionError' in result.stderr, result
    assert subprocess.check_output(['ldd', str(HELPER)], text=True).count('=>') == 1
    with tempfile.TemporaryDirectory(prefix='traverse-bind-test-') as tmp:
        directory = Path(tmp)
        directory.chmod(0o755)
        runtime = directory/'runtime';runtime.mkdir(mode=0o700);os.chown(runtime, UID, GID)
        cert, key = directory/'certificate.pem', directory/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign',
                        '-addext', 'subjectKeyIdentifier=hash',
                        '-addext', 'authorityKeyIdentifier=keyid:always',
                        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        os.chown(key, UID, GID);key.chmod(0o600)
        hostile = dict(os.environ, HOME=str(directory), XDG_RUNTIME_DIR=str(runtime),
                       LD_LIBRARY_PATH=str(directory), LD_PRELOAD=str(directory/'injected.so'),
                       GST_PLUGIN_PATH=str(directory), GST_PLUGIN_PATH_1_0=str(directory),
                       GST_PLUGIN_SYSTEM_PATH=str(directory), GST_PLUGIN_SYSTEM_PATH_1_0=str(directory),
                       GST_PLUGIN_SCANNER=str(directory/'scanner'), GST_PLUGIN_SCANNER_1_0=str(directory/'scanner'),
                       GST_REGISTRY=str(directory/'evil-registry'), GST_REGISTRY_1_0=str(directory/'evil-registry'),
                       GST_REGISTRY_UPDATE='yes', OPENSSL_CONF=str(directory/'evil-openssl.cnf'),
                       OPENSSL_MODULES=str(directory), GIO_EXTRA_MODULES=str(directory),
                       SSL_CERT_FILE=str(directory/'evil-trust.pem'),
                       SSL_CERT_DIR=str(directory/'evil-trust-directory'))
        (directory/'evil-registry').write_bytes(b'Untrusted registry must not be read')
        (directory/'evil-openssl.cnf').write_text('invalid OpenSSL configuration')
        rejected('/bin/sh', [], hostile)
        rejected('runtime-check', [], hostile)
        for unsafe in [PREFIX/'share/traverse/registry.bin', next((PREFIX/'lib').glob('libgst*.so*'))]:
            old_mode = unsafe.stat().st_mode & 0o7777
            try:
                unsafe.chmod(0o666)
                rejected('frontend', [], hostile)
            finally:
                unsafe.chmod(old_mode)
        subprocess.run(['setcap', '-r', str(HELPER)], check=True)
        try:
            rejected('frontend', [], hostile)
        finally:
            subprocess.run(['setcap', 'cap_net_bind_service=ep', str(HELPER)], check=True)
        backend = port()
        service_args = ['--internal-http', '--host', '127.0.0.1', '--port', str(backend),
                        '--origin', 'https://localhost', '--socket', str(runtime/'absent.sock'),
                        '--web', str(PREFIX/'share/traverse/web'), '--udp-port', '443', '--check-udp-port']
        with running('service', service_args, directory, hostile) as service:
            deadline = time.monotonic()+15
            while True:
                assert service.poll() is None, 'Privileged service exited'
                try:
                    with urllib.request.urlopen(f'http://127.0.0.1:{backend}/', timeout=1) as response:
                        assert response.status == 200
                        break
                except (OSError, urllib.error.URLError):
                    assert time.monotonic() < deadline, 'Service failed readiness'
                    time.sleep(.02)
            service_threads = verify_threads(service.pid, BIND)
            actual_env = dict(item.split(b'=', 1) for item in Path(f'/proc/{service.pid}/environ').read_bytes().split(b'\0') if item)
            for name in ['LD_LIBRARY_PATH', 'GST_PLUGIN_SYSTEM_PATH', 'GST_PLUGIN_SYSTEM_PATH_1_0']:
                assert actual_env[name.encode()].startswith(bytes(PREFIX)), (name, actual_env)
            assert actual_env[b'GST_REGISTRY_1_0'] == bytes(PREFIX/'share/traverse/registry.bin')
            assert actual_env[b'GST_REGISTRY_UPDATE'] == b'no'
            assert actual_env[b'HOME'] == bytes(PREFIX)
            for name in ['DISPLAY', 'XAUTHORITY', 'DBUS_SESSION_BUS_ADDRESS']:
                assert name.encode() not in actual_env
            for name in ['LD_PRELOAD', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'GIO_EXTRA_MODULES',
                         'SSL_CERT_FILE', 'SSL_CERT_DIR']:
                assert name.encode() not in actual_env
            maps = Path(f'/proc/{service.pid}/maps').read_text()
            assert str(PREFIX/'lib/libgstwebrtc') in maps and str(PREFIX/'lib/gstreamer-1.0/libgstvpx') in maps
            frontend_args = ['--host', '127.0.0.1', '--port', '443', '--http-port', str(backend),
                             '--turn-port', str(port()), '--cert', str(cert), '--key', str(key),
                             '--expected-domain', 'localhost', '--trust-file', str(cert),
                             '--trust-directory', '', '--status-file', str(runtime/'tls-status.json')]
            with running('frontend', frontend_args, directory, hostile) as frontend:
                context = ssl.create_default_context(cafile=str(cert))
                deadline = time.monotonic()+10
                while True:
                    assert frontend.poll() is None, 'Privileged frontend exited'
                    try:
                        raw = socket.create_connection(('127.0.0.1', 443), timeout=1)
                        stream = context.wrap_socket(raw, server_hostname='localhost')
                        break
                    except OSError:
                        assert time.monotonic() < deadline, 'Frontend failed readiness'
                        time.sleep(.02)
                with stream:
                    # A live TLS worker must inherit zero caps, not its pre-bind parent state.
                    stream.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n')
                    response = http.client.HTTPResponse(stream);response.begin()
                    assert response.status == 200
                    response.read();response.close()
                    frontend_threads = verify_threads(frontend.pid, 0)
                    assert frontend_threads >= 3
                    snapshot = json.loads((runtime/'tls-status.json').read_text())
                    assert snapshot['frontendPid'] == frontend.pid and snapshot['available']
                    assert (runtime/'tls-status.json').stat().st_uid == UID
                    assert (runtime/'tls-status.json').stat().st_mode & 0o777 == 0o600
                    descriptor = os.pidfd_open(frontend.pid)
                    try:signal.pidfd_send_signal(descriptor, signal.SIGHUP)
                    finally:os.close(descriptor)
                    deadline = time.monotonic()+5
                    while json.loads((runtime/'tls-status.json').read_text())['revision'] <= snapshot['revision']:
                        assert time.monotonic()<deadline, 'Low-port frontend ignored certificate refresh'
                        time.sleep(.02)
                    stream.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n')
                    response = http.client.HTTPResponse(stream);response.begin()
                    assert response.status == 200
                    response.read();response.close()
                    verify_threads(frontend.pid, 0)
                    frontend_env = dict(item.split(b'=', 1) for item in Path(f'/proc/{frontend.pid}/environ').read_bytes().split(b'\0') if item)
                    for name in ['SSL_CERT_FILE', 'SSL_CERT_DIR', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'LD_PRELOAD']:
                        assert name.encode() not in frontend_env
                    verify_threads(service.pid, BIND)
                    missing_trust = list(frontend_args)
                    missing_trust[missing_trust.index('--trust-file')+1] = str(directory/'absent-ca.pem')
                    rejected_trust = subprocess.run([str(HELPER), 'frontend', *missing_trust,
                        '--supervisor-pid', str(os.getpid())], capture_output=True, text=True,
                        timeout=10, **child_options(hostile))
                    assert rejected_trust.returncode and 'Configured certificate trust file unavailable' in rejected_trust.stderr
                    assert frontend.poll() is None
                    duplicate = subprocess.run([str(HELPER), 'frontend', *frontend_args,
                                                '--supervisor-pid', str(os.getpid())],
                                               capture_output=True, text=True, timeout=10, **child_options(hostile))
                    assert duplicate.returncode and 'Cannot bind TLS listener' in duplicate.stderr
            assert frontend.returncode == 0
        assert service.returncode == 0
        assert (directory/'evil-registry').read_bytes() == b'Untrusted registry must not be read'
        print(json.dumps({'sameUidGid': UID, 'negativeTcpUdp443': 'permission denied',
                          'frontendTcp443': 'TLS + real HTTP', 'frontendThreadsWithoutCaps': frontend_threads,
                          'serviceThreadsWithOnlyBind': service_threads, 'hostileEnvironmentIgnored': True,
                          'untrustedFilesAndMissingCapabilityRejected': True,
                          'explicitTrustSurvivesClearedEnvironment': True,
                          'certificateRefreshPreservesExistingTlsAndZeroCaps': True,
                          'boundingSet': 'inherited kernel bound; NoNewPrivs=1 prevents exec privilege gains'}))


if __name__ == '__main__':
    main()
