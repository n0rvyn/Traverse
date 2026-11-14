"""Installed local HTTPS/pairing and owner lifecycle in disposable Linux only.

This checks actual installed entry, local certificate trust and held input. It
is not ordinary Chrome acceptance and never changes a system trust database.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
from types import SimpleNamespace

from host_supervisor_test import OwnerFixture
from installed_managed_certificates import PREFIX, prefix_processes, require_disposable_environment
from installed_standalone import alive, descendants, free_port, wait
from issuer_native import DOMAIN
from installed_turn import sockets


def main():
    require_disposable_environment()
    app_port = int(os.environ.get('TRAVERSE_TEST_APP_PORT', '443'))
    listen_port = int(os.environ.get('TRAVERSE_TEST_LISTEN_PORT', str(app_port)))
    for ending in ('stop', 'eof', 'death', 'launcher-death'):
        with tempfile.TemporaryDirectory(prefix='local-installed-') as temporary:
            root = Path(temporary); root.chmod(0o755)
            home = root/'home'; home.mkdir(mode=0o700); os.chown(home, 65534, 65534)
            runtime = home/'runtime'; runtime.mkdir(mode=0o700); os.chown(runtime, 65534, 65534)
            xauthority = home/'Xauthority'; shutil.copyfile(os.environ['XAUTHORITY'], xauthority)
            xauthority.chmod(0o600); os.chown(xauthority, 65534, 65534)
            config = home/'config.json'
            configuration = {'schemaVersion': 1, 'domain': DOMAIN, 'port': app_port,
                'basePath': '/remote/', 'listenAddress': '127.0.0.1', 'certificateSettings': {'mode': 'local'}}
            if listen_port != app_port:
                turn_port = free_port()
                while turn_port in (app_port, listen_port):
                    turn_port = free_port()
                configuration.update(listenPort=listen_port, turnBackendPort=turn_port, proxyTls=True)
            config.write_text(json.dumps(configuration))
            config.chmod(0o600); os.chown(config, 65534, 65534)
            environment = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home/'data'),
                XDG_RUNTIME_DIR=str(runtime), XDG_CACHE_HOME=str(home/'cache'), XAUTHORITY=str(xauthority))
            desktop = SimpleNamespace(path=config, home=home, env=environment, broker_stderr=home/'broker-fixture-stderr.txt')
            owner = occupied = None
            baseline = prefix_processes()
            try:
                occupied_port = app_port if listen_port != app_port else 443
                if listen_port != app_port or app_port != 443:
                    occupied = socket.socket(); occupied.bind(('127.0.0.1', occupied_port)); occupied.listen(1)
                owner = OwnerFixture(desktop)
                def ready():
                    state = owner.call('status')
                    assert state.get('phase') != 'failed', state
                    return state if (state.get('localHttps') or {}).get('status') == 'passed' else None
                wait(ready, 'Installed local certificate startup', timeout=30)
                state = ready()
                assert state
                origin = 'https://'+DOMAIN+('' if app_port == 443 else ':'+str(app_port))
                assert state['configuredUrl'] == origin+'/remote/'
                assert state['publicTlsSource'] == ('proxy' if listen_port != app_port else 'host')
                if listen_port != app_port:
                    actors = {name: [] for name in ('traverse-tls-frontend', 'turnserver', 'traverse-service')}
                    for pid in prefix_processes()-baseline:
                        name = (Path('/proc')/str(pid)/'exe').resolve().name
                        if name in actors:
                            actors[name].append(pid)
                    assert all(len(pids)==1 for pids in actors.values()), actors
                    assert sockets(actors['traverse-tls-frontend'][0]) == [('tcp', f'0100007F:{listen_port:04X}')]
                    assert sockets(actors['turnserver'][0]) == [('tcp', f'0100007F:{turn_port:04X}')]
                    command = (Path('/proc')/str(actors['traverse-service'][0])/'cmdline').read_bytes().split(b'\0')
                    assert command[command.index(b'--udp-port')+1] == str(app_port).encode()
                assert not state['issuer']['operationActive'] and state['certificate']['available']
                authorities = list((home/'data/traverse/certificates').iterdir()); assert len(authorities) == 1
                authority = authorities[0]; public = authority/'local-ca.pem'
                public_bytes = public.read_bytes()
                assert public_bytes.count(b'BEGIN CERTIFICATE') == 1 and b'PRIVATE KEY' not in public_bytes
                exported = owner.call('export-ca')
                assert exported['ok'] and exported['publicCA']['pem'].encode() == public_bytes
                assert exported['publicCA']['fingerprint'] == hashlib.sha256(ssl.PEM_cert_to_DER_cert(public_bytes.decode())).hexdigest()
                before = {name: hashlib.sha256((authority/name).read_bytes()).hexdigest()
                    for name in ('local-authority.pem', 'local-authority.json', 'local-ca.pem')}
                assert not (authority/'account-key.pem').exists() and not (authority/'order.json').exists()
                # A real default client context rejects this CA before the
                # fixture explicitly selects its public certificate.
                try:
                    with ssl.create_default_context().wrap_socket(socket.create_connection(('127.0.0.1', listen_port), timeout=3), server_hostname=DOMAIN):
                        raise AssertionError('Untrusted local CA unexpectedly accepted')
                except ssl.SSLCertVerificationError:
                    pass
                context = ssl.create_default_context(cafile=str(public))
                connection = http.client.HTTPSConnection(DOMAIN, app_port, context=context, timeout=5)
                connection.sock = context.wrap_socket(socket.create_connection(('127.0.0.1', listen_port), timeout=5), server_hostname=DOMAIN)
                connection.request('GET', '/remote/'); response = connection.getresponse()
                assert response.status == 200; response.read(); connection.close()
                assert owner.call('pair')['paired']
                assert owner.call('hold-shift')['accepted']
                probe = os.environ.get('TRAVERSE_TEST_X11_PROBE', '/tmp/x11-probe')
                def query():
                    run = subprocess.run([probe, 'query'], env=environment, user=65534, group=65534,
                        extra_groups=[], capture_output=True, text=True, check=True)
                    return json.loads(run.stdout)
                assert query()['shift'] == 1
                public.chmod(0o644)
                rejected = owner.call('export-ca')
                assert not rejected['ok'] and 'publicCA' not in rejected
                assert query()['shift'] == 1 and owner.call('heartbeat')['accepted']
                public.chmod(0o600)
                owned = descendants(owner.process.pid)
                if ending == 'launcher-death':
                    os.kill(owner.ready['launcherPid'], signal.SIGKILL)
                elif ending == 'death':
                    owner.process.kill(); owner.process.wait(timeout=5)
                else:
                    assert owner.call('request-'+ending) == {'stopRequested': True}
                wait(lambda: query()['shift'] == 0, 'Local certificate owner loss retained held input', timeout=3)
                if ending not in ('death', 'launcher-death'):
                    assert owner.call('wait-stopped') == {'stopped': True, 'exit': 0}
                wait(lambda: not any(alive(pid) for pid in owned), 'Local certificate child survived owner loss', timeout=12)
                wait(lambda: prefix_processes() == baseline, 'Local certificate runtime survived stop', timeout=5)
                if listen_port != app_port:
                    for port in (listen_port, turn_port):
                        with socket.socket() as reusable:
                            reusable.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            reusable.bind(('127.0.0.1', port))
                assert before == {name: hashlib.sha256((authority/name).read_bytes()).hexdigest() for name in before}
                if occupied:
                    assert occupied.getsockname()[1] == occupied_port
                print(json.dumps({'ending': ending, 'port': app_port, 'configuredUrl': state['configuredUrl'],
                    'localHttps': True, 'defaultTrustRejected': True, 'explicitFixtureTrustPassed': True,
                    'realPairing': True, 'heldInputReleased': True, 'allOwnedReaped': True,
                    'authorityPreserved': True, 'occupiedStandardPortPreserved': occupied is not None and occupied_port==443,
                    'occupiedPublicPortPreserved': occupied is not None and occupied_port==app_port,
                    'backendPort': listen_port, 'fixedPrivateBindingsVerified': listen_port!=app_port,
                    'publicOnlyExportMatchesTrustRoot': True, 'changedExportRejectedWithoutRevokingInput': True,
                    'scope': 'Installed entry/HTTPS/private owner; no Chrome trust or video claim'}), flush=True)
            finally:
                if owner: owner.close()
                if occupied: occupied.close()


if __name__ == '__main__':
    main()
