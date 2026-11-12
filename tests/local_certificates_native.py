"""Actual native manager/helper/TLS path with private local roots and no public CA."""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import queue
import socket
import ssl
import subprocess
import tempfile
import threading
import time

from issuer_native import Upstream, free_port, retire


class Manager:
    def __init__(self, probe, issuer, root, domain, upstream):
        self.events = queue.Queue()
        self.port = free_port()
        self.error_path = root/'probe-errors.txt'
        self.error = self.error_path.open('a')
        self.process = subprocess.Popen([str(probe), '--supervisor-pid', str(os.getpid())],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.error, text=True)
        self.process.stdin.write(json.dumps({'endpoint': {'schemaVersion': 1, 'domain': domain,
            'port': self.port, 'certificateSettings': {'mode': 'local'}},
            'dataHome': str(root/'data'), 'issuer': str(issuer), 'broker': '',
            'httpPort': upstream.server_port, 'turnPort': free_port()})+'\n')
        self.process.stdin.flush()
        def read():
            for line in self.process.stdout:
                self.events.put(json.loads(line))
        self.reader = threading.Thread(target=read)
        self.reader.start()

    def event(self, predicate):
        deadline = time.monotonic()+20
        last = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError('Native certificate probe exit '+str(self.process.returncode)+': '+self.error_path.read_text())
            try:
                last = self.events.get(timeout=.1)
            except queue.Empty:
                continue
            if predicate(last):
                return last
        raise AssertionError('Native local certificate state timed out: '+json.dumps(last))

    def command(self, command):
        self.process.stdin.write(command+'\n'); self.process.stdin.flush()

    def close(self):
        if self.process.poll() is None:
            self.command('stop')
            assert self.process.wait(timeout=8) == 0
        retire(self.process)
        self.reader.join(5)
        assert not self.reader.is_alive()
        self.process.stdin.close(); self.process.stdout.close(); self.error.close()


def ready(state):
    return state.get('phase') == 'ready' and state.get('available') and not state.get('publicationUncertain') and state.get('frontendFingerprint') == state.get('fingerprint')


def connect(manager, public_ca, domain):
    try:
        domain = str(ipaddress.IPv6Address(domain).ipv4_mapped or domain)
    except ipaddress.AddressValueError:
        pass
    context = ssl.create_default_context(cafile=str(public_ca))
    stream = context.wrap_socket(socket.create_connection(('127.0.0.1', manager.port), timeout=3), server_hostname=domain)
    stream.settimeout(3)
    return stream


def request(stream):
    stream.sendall(b'GET / HTTP/1.1\r\nHost: witness\r\nConnection: keep-alive\r\n\r\n')
    response = http.client.HTTPResponse(stream); response.begin()
    assert response.status == 200 and response.read() == b'Native issuer witness'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', required=True, type=Path)
    parser.add_argument('--issuer', required=True, type=Path)
    parser.add_argument('--domain', action='append', help='Explicit focused fixture scope; default exercises all four address forms')
    args = parser.parse_args()
    os.umask(0o077)
    reports = []
    for domain in (args.domain or ('desktop.example.test', '127.0.0.1', '::1', '::ffff:192.0.2.1')):
        print(json.dumps({'checkingDomain': domain}), flush=True)
        with tempfile.TemporaryDirectory(prefix='tlc-') as temporary:
            root = Path(temporary)
            upstream = Upstream(); upstream.start()
            manager = held = None
            try:
                manager = Manager(args.probe, args.issuer, root, domain, upstream)
                first = manager.event(lambda value: ready(value) or value.get('phase') == 'failed')
                if not ready(first):
                    states = list((root/'data/traverse/certificates').iterdir())
                    if len(states) == 1 and (states[0]/'bundle.pem').exists():
                        for address in (domain, '192.0.2.1'):
                            result = subprocess.run(['openssl', 'verify', '-CAfile', str(states[0]/'local-ca.pem'),
                                '-verify_ip', address, str(states[0]/'bundle.pem')], capture_output=True, text=True, timeout=10)
                            print(json.dumps({'nativeFailureVerificationAddress': address,
                                'exit': result.returncode, 'diagnostic': result.stdout+result.stderr}), flush=True)
                assert ready(first), 'Local native bootstrap failed for '+domain+': '+json.dumps(first)
                states = list((root/'data/traverse/certificates').iterdir()); assert len(states) == 1
                state = states[0]; public = state/'local-ca.pem'
                authority = hashlib.sha256((state/'local-authority.pem').read_bytes()).hexdigest()
                public_bytes = public.read_bytes()
                assert public_bytes.count(b'BEGIN CERTIFICATE') == 1 and b'PRIVATE KEY' not in public_bytes
                assert 'BEGIN CERTIFICATE' not in json.dumps(first)
                manager.command('export-ca')
                exported = manager.event(lambda value: 'publicCA' in value)['publicCA']
                assert exported['version'] == 1 and exported['pem'].encode() == public_bytes
                assert exported['fingerprint'] == hashlib.sha256(ssl.PEM_cert_to_DER_cert(public_bytes.decode())).hexdigest()
                assert not (state/'account-key.pem').exists() and not (state/'order.json').exists()
                assert not (state/'challenge.sock').exists()
                held = connect(manager, public, domain); request(held)
                first_leaf = hashlib.sha256(held.getpeercert(binary_form=True)).hexdigest()
                assert first_leaf == first['fingerprint']
                manager.command('reload-schedule')
                restart = manager.event(lambda value: ready(value) and value.get('managerGeneration') == 1)
                assert restart['fingerprint'] == first_leaf
                assert hashlib.sha256((state/'local-authority.pem').read_bytes()).hexdigest() == authority
                assert public.read_bytes() == public_bytes
                request(held)  # Manager restart retains the established TLS connection.
                # Force missing-leaf recovery, not the 60-day clock boundary:
                # the frontend keeps its admitted generation while ensure
                # creates a replacement candidate under the original root.
                manager.command('pause-manager')
                manager.event(lambda value: value.get('managerPaused'))
                (state/'bundle.pem').unlink()
                manager.command('reload-schedule')
                replacement = manager.event(lambda value: ready(value) and value.get('managerGeneration') == 2)
                assert replacement['fingerprint'] != first_leaf
                assert public.read_bytes() == public_bytes
                assert hashlib.sha256((state/'local-authority.pem').read_bytes()).hexdigest() == authority
                request(held)
                with connect(manager, public, domain) as stream:
                    request(stream)
                    assert hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest() == replacement['fingerprint']
                first_leaf = replacement['fingerprint']
                held.close(); held = None
                manager.close(); manager = None
                # Same hostname/new listener port retains the authority and leaf.
                alias = str(ipaddress.IPv6Address(domain).ipv4_mapped) if domain.startswith('::ffff:') else domain
                manager = Manager(args.probe, args.issuer, root, alias, upstream)
                port_change = manager.event(ready)
                assert port_change['fingerprint'] == first_leaf and public.read_bytes() == public_bytes
                with connect(manager, public, domain) as stream: request(stream)
                # Export must not read a new root from disk or block current
                # input/TLS while its watcher invalidates the admitted cache.
                other = root/'other-authority'
                generated = subprocess.run([str(args.issuer), '--supervisor-pid', str(os.getpid())],
                    input=json.dumps({'version': 1, 'operation': 'local-ensure',
                        'domain': 'other.example.test', 'stateDirectory': str(other)}),
                    capture_output=True, text=True, timeout=10)
                assert generated.returncode == 0 and json.loads(generated.stdout)['status'] == 'local-issued'
                held = connect(manager, public, domain)
                replacement_public = state/'replacement-public.fixture'
                replacement_public.write_bytes((other/'local-ca.pem').read_bytes());replacement_public.chmod(0o600)
                os.replace(replacement_public, public)
                manager.command('export-ca')
                manager.event(lambda value: value.get('publicCARejected'))
                request(held);held.close();held = None
                manager.close(); manager = None
                public.write_bytes(public_bytes)
                # Missing initialized root must fail before any frontend starts;
                # the old admitted file cannot bypass helper reconciliation.
                (state/'local-authority.pem').rename(state/'retained-authority.fixture')
                admitted = (state/'application.pem').read_bytes()
                manager = Manager(args.probe, args.issuer, root, domain, upstream)
                failed = manager.event(lambda value: value.get('phase') == 'failed')
                assert not failed['available'] and not failed['frontendFingerprint']
                assert not (state/'local-authority.pem').exists()
                assert public.read_bytes() == public_bytes and (state/'application.pem').read_bytes() == admitted
                with socket.socket() as denied:
                    assert denied.connect_ex(('127.0.0.1', manager.port)) != 0
                manager.close(); manager = None
                (state/'retained-authority.fixture').rename(state/'local-authority.pem')
                # A different valid root export cannot be accepted merely
                # because a previously admitted application file still exists.
                public.write_bytes((other/'local-ca.pem').read_bytes())
                manager = Manager(args.probe, args.issuer, root, domain, upstream)
                failed = manager.event(lambda value: value.get('phase') == 'failed')
                assert not failed['available'] and not failed['frontendFingerprint']
                assert (state/'application.pem').read_bytes() == admitted
                reports.append({'domain': domain, 'bootstrap': True, 'nativeTLS': True,
                    'managerRestartKeepsConnection': True, 'portChangeStableTrust': True,
                    'missingLeafReplacementKeepsConnectionAndTrust': True,
                    'missingRootBlocksAdmissionWithoutRotation': True,
                    'swappedPublicRootBlocksAdmission': True})
                reports[-1]['publicOnlyExportAndChangedRootRejectionKeepsTLS'] = True
            finally:
                if held: held.close()
                if manager: manager.close()
                upstream.close()
    print(json.dumps({'status': 'passed', 'scope': 'Actual native manager/static helper/OpenSSL TLS in isolated Linux; no Chrome trust claim', 'cases': reports}))


if __name__ == '__main__':
    main()
