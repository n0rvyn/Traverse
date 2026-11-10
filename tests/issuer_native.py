"""Private Pebble -> real native TLS-ALPN -> managed bundle/reload witness.

All listeners are disposable loopback endpoints. No public CA, host trust,
display, system DNS or existing service is changed. Child output is discarded;
readiness comes from trusted HTTPS and the native status protocol, never logs.
"""
import argparse
import base64
import ctypes
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request

DOMAIN = 'issuer.example.test'


def emit(**data):
    print(json.dumps(data), flush=True)


def receive(connection, size):
    data = bytearray()
    while len(data) < size:
        block = connection.recv(size-len(data))
        if not block:
            raise RuntimeError('Private fixture received truncated frame')
        data.extend(block)
    return bytes(data)


def frame(connection, value):
    data = json.dumps(value, separators=(',', ':')).encode()
    connection.sendall(struct.pack('!I', len(data))+data)


def unframe(connection):
    size, = struct.unpack('!I', receive(connection, 4))
    assert 0 < size <= 1024, 'Invalid private fixture frame'
    return json.loads(receive(connection, size))


def wait_for(read, description, processes=(), seconds=20):
    end = time.monotonic()+seconds
    while time.monotonic() < end:
        assert all(p.poll() is None for p in processes), 'Owned process exited: '+description
        try:
            result = read()
            if result:
                return result
        except (OSError, ValueError, ssl.SSLError, http.client.HTTPException):
            pass
        time.sleep(.025)
    raise AssertionError('Private fixture timeout: '+description)


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


class LocalDNS(socketserver.ThreadingTCPServer):
    daemon_threads = False
    block_on_close = True
    def __init__(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(handler):
                stream = handler.request
                stream.settimeout(2)
                try:
                    length, = struct.unpack('!H', receive(stream, 2))
                    data = receive(stream, length)
                except (OSError, RuntimeError):
                    return
                if len(data) < 12:
                    return
                offset, labels = 12, []
                while offset < len(data) and data[offset]:
                    size = data[offset]
                    if size > 63 or offset+1+size > len(data):
                        return
                    labels.append(data[offset+1:offset+1+size].decode('ascii'))
                    offset += size+1
                offset += 1
                if offset+4 > len(data):
                    return
                kind, category = struct.unpack('!HH', data[offset:offset+4])
                name = '.'.join(labels).lower()
                answer = name == DOMAIN and kind == 1 and category == 1
                header = data[:2]+struct.pack('!HHHHH', 0x8180, 1, int(answer), 0, 0)
                reply = header+data[12:offset+4]
                if answer:
                    reply += b'\xc0\x0c'+struct.pack('!HHIH', 1, 1, 1, 4)+socket.inet_aton('127.0.0.1')
                stream.sendall(struct.pack('!H', len(reply))+reply)
        super().__init__(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever)

    def start(self):
        self.thread.start()

    def close(self):
        self.shutdown(); self.server_close(); self.thread.join()


class ValidationBridge(socketserver.ThreadingTCPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self):
        self.target = None
        self.accepted = 0
        self.lock = threading.Lock()
        self.connections = set()
        self.stopped = threading.Event()
        owner = self
        class Handler(socketserver.BaseRequestHandler):
            def handle(handler):
                upstream = None
                with owner.lock:
                    owner.accepted += 1
                    owner.connections.add(handler.request)
                try:
                    upstream = socket.create_connection(owner.target, timeout=2)
                    with owner.lock:
                        owner.connections.add(upstream)
                    pair = [handler.request, upstream]
                    while not owner.stopped.is_set():
                        ready, _, _ = select.select(pair, [], [], .1)
                        for source in ready:
                            data = source.recv(65536)
                            if not data:
                                return
                            pair[1 if source is pair[0] else 0].sendall(data)
                except OSError:
                    pass
                finally:
                    with owner.lock:
                        owner.connections.discard(handler.request)
                        if upstream:
                            owner.connections.discard(upstream)
                    if upstream:
                        upstream.close()
        super().__init__(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever)

    def start(self):
        self.thread.start()

    def count(self):
        with self.lock:
            return self.accepted

    def close(self):
        self.stopped.set(); self.shutdown()
        with self.lock:
            for connection in list(self.connections):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.server_close(); self.thread.join()


class Upstream(http.server.ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self):
        self.requests = 0
        owner = self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'
            def do_GET(handler):
                owner.requests += 1
                body = b'Native issuer witness'
                handler.send_response(200)
                handler.send_header('Content-Length', str(len(body)))
                handler.end_headers(); handler.wfile.write(body)
            def log_message(*_):
                pass
        super().__init__(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever)

    def start(self):
        self.thread.start()

    def close(self):
        self.shutdown(); self.server_close(); self.thread.join()


class AlteredBroker:
    def __init__(self, path, native, mode):
        self.path, self.native, self.mode = path, native, mode
        self.frames = 0
        self.revoked = False
        self.stopped = threading.Event()
        self.connection = self.upstream = None
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.bind(str(path)); path.chmod(0o600); self.socket.listen()
        self.socket.settimeout(.1)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        try:
            while not self.stopped.is_set():
                try:
                    self.connection, _ = self.socket.accept(); break
                except TimeoutError:
                    continue
            if self.connection is None:
                return
            self.connection.settimeout(5)
            request = unframe(self.connection)
            self.frames += 1
            if self.mode == 'wrong-digest':
                request['sha256'] = base64.urlsafe_b64encode(bytes(32)).rstrip(b'=').decode()
                self.upstream = socket.socket(socket.AF_UNIX)
                self.upstream.settimeout(5); self.upstream.connect(str(self.native))
                frame(self.upstream, request)
                acknowledgement = unframe(self.upstream)
                assert acknowledgement == {'ready': True}
            else:
                acknowledgement = {'ready': True}
            frame(self.connection, acknowledgement)
            while not self.stopped.is_set():
                ready, _, _ = select.select([self.connection], [], [], .1)
                if ready and not self.connection.recv(1):
                    break
        except OSError:
            pass
        finally:
            if self.connection:
                self.connection.close()
            if self.upstream:
                try:
                    self.upstream.shutdown(socket.SHUT_WR)
                    self.upstream.settimeout(2)
                    self.revoked = self.upstream.recv(1) == b''
                except OSError:
                    pass
                self.upstream.close()

    def close(self):
        self.stopped.set()
        if self.connection:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.socket.close(); self.thread.join(timeout=6)
        assert not self.thread.is_alive(), 'Owned broker worker did not stop'
        if self.mode == 'wrong-digest':
            assert self.revoked, 'Native proof revocation was not acknowledged by EOF'


def retire(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--issuer', required=True, type=Path)
    parser.add_argument('--pebble', required=True, type=Path)
    parser.add_argument('--reuse-valid-authorizations', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    processes, servers, brokers = [], [], []
    held = None
    report = {'status': 'failed', 'scope': 'Real private CA and native TLS-ALPN, no public CA or global trust/DNS changes'}
    with tempfile.TemporaryDirectory(prefix='traverse-issuer-native-') as temporary:
        root = Path(temporary)
        api_cert, api_key = root/'api.pem', root/'api.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                        '-keyout', str(api_key), '-out', str(api_cert), '-days', '1', '-subj', '/CN=Private issuer API',
                        '-addext', 'subjectAltName=IP:127.0.0.1', '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign'], check=True, capture_output=True, timeout=15)
        dns, bridge, upstream = LocalDNS(), ValidationBridge(), Upstream()
        created_servers = [dns, bridge, upstream]
        api_port, management_port, frontend_port, turn_port = [free_port() for _ in range(4)]
        bridge.target = ('127.0.0.1', frontend_port)
        config = {'pebble': {'listenAddress': '127.0.0.1:'+str(api_port), 'managementListenAddress': '127.0.0.1:'+str(management_port),
                            'certificate': str(api_cert), 'privateKey': str(api_key), 'tlsPort': bridge.server_address[1], 'httpPort': free_port(),
                            'keyAlgorithm': 'ecdsa', 'retryAfter': {'authz': 1, 'order': 1}}}
        configuration = root/'pebble.json'; configuration.write_text(json.dumps(config))
        environment = dict(os.environ, PEBBLE_VA_NOSLEEP='1', PEBBLE_AUTHZREUSE='100' if args.reuse_valid_authorizations else '0')
        environment.pop('PEBBLE_VA_ALWAYS_VALID', None)
        # Before starting any fixture thread, install the CA's owned-parent guard.
        assert threading.active_count() == 1
        libc = ctypes.CDLL(None); parent = os.getpid()
        def guard():
            if libc.prctl(1, signal.SIGTERM, 0, 0, 0) or os.getppid() != parent:
                os._exit(125)
        try:
            ca = subprocess.Popen([str(args.pebble), '-config', str(configuration), '-dnsserver', '127.0.0.1:'+str(dns.server_address[1]), '-strict=false'],
                                  env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=guard, start_new_session=True)
            processes.append(ca)
            for server in (dns, bridge, upstream):
                server.start(); servers.append(server)
            context = ssl.create_default_context(cafile=str(api_cert))
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
            def get(uri):
                with opener.open(uri, timeout=2) as response:
                    return response.read()
            # Same TCP transport as Pebble's pinned DNS client, with a real A answer.
            labels = b''.join(bytes([len(part)])+part.encode() for part in DOMAIN.split('.'))+b'\0'
            question = struct.pack('!HHHHHH', 0x4242, 0x0100, 1, 0, 0, 0)+labels+struct.pack('!HH', 1, 1)
            with socket.create_connection(dns.server_address, timeout=2) as control:
                control.sendall(struct.pack('!H', len(question))+question)
                size, = struct.unpack('!H', receive(control, 2))
                answer = receive(control, size)
                assert answer[:2] == question[:2] and struct.unpack('!H', answer[6:8])[0] == 1 and answer[-4:] == socket.inet_aton('127.0.0.1')
            directory = 'https://127.0.0.1:'+str(api_port)+'/dir'
            wait_for(lambda: json.loads(get(directory)), 'trusted private CA API', [ca])
            issuing_root = root/'issued-root.pem'
            issuing_root.write_bytes(get('https://127.0.0.1:'+str(management_port)+'/roots/0'))
            runtime = root/'runtime'; runtime.mkdir(mode=0o700)
            state_directory = root/'state'
            bundle = state_directory/'bundle.pem'
            status = runtime/'status.json'; broker = runtime/'challenge.sock'
            frontend = args.prefix/'libexec/traverse/traverse-tls-frontend'
            front = subprocess.Popen([str(frontend), '--host', '127.0.0.1', '--port', str(frontend_port), '--http-port', str(upstream.server_port),
                                      '--turn-port', str(turn_port), '--cert', str(bundle), '--key', str(bundle), '--expected-domain', DOMAIN,
                                      '--trust-file', str(issuing_root), '--status-file', str(status), '--acme-socket', str(broker), '--certificate-bootstrap', 'true',
                                      '--supervisor-pid', str(os.getpid())], env=dict(os.environ, LD_LIBRARY_PATH=str(args.prefix/'lib')),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            processes.append(front)
            def snapshot():
                data = json.loads(status.read_text())
                assert data['frontendPid'] == front.pid, 'Status belongs to another frontend'
                return data
            initial = wait_for(lambda: snapshot() if broker.exists() else None, 'owned challenge-only frontend', [front, ca])
            assert initial['revision'] == 0 and not initial['available']
            client_context = ssl.create_default_context(cafile=str(issuing_root))
            def open_application():
                connection = socket.create_connection(('127.0.0.1', frontend_port), timeout=3)
                return client_context.wrap_socket(connection, server_hostname=DOMAIN)
            try:
                connection = open_application(); connection.close()
                raise AssertionError('Bootstrap admitted ordinary HTTPS without a certificate')
            except ssl.SSLError:
                pass
            assert upstream.requests == 0
            emit(phase='private-ca-and-bootstrap-ready')
            def invoke(request, timeout=60):
                child = subprocess.Popen([str(args.issuer)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)
                processes.append(child)
                try:
                    output, _ = child.communicate(json.dumps(request).encode(), timeout=timeout)
                except BaseException:
                    retire(child); raise
                result = json.loads(output)
                assert result['version'] == 1
                return child.returncode, result
            request = {'version': 1, 'operation': 'describe', 'domain': DOMAIN, 'directory': directory, 'apiTrustFile': str(api_cert)}
            code, described = invoke(request)
            assert code == 0 and described['status'] == 'terms', ('Private metadata query failed', code, described)
            request.update(operation='issue', stateDirectory=str(state_directory), challengeSocket=str(broker), termsURL=described.get('termsURL', ''),
                           termsAgreed=True, certificateTrustFile=str(issuing_root))
            before = bridge.count()
            code, issued = invoke(request)
            assert code == 0 and issued['status'] == 'issued', ('Initial private issuance failed', issued)
            first = wait_for(lambda: (s if (s := snapshot())['revision'] >= 1 and s['available'] else None), 'trusted certificate promotion', [front, ca])
            assert bridge.count() > before and upstream.requests == 0, 'Actual validation missing or challenge forwarded application data'
            held = open_application()
            def application_request(connection):
                connection.sendall(b'GET / HTTP/1.1\r\nHost: '+DOMAIN.encode()+b'\r\nConnection: keep-alive\r\n\r\n')
                response = http.client.HTTPResponse(connection); response.begin()
                assert response.status == 200 and response.read() == b'Native issuer witness'
            application_request(held)
            first_peer = hashlib.sha256(held.getpeercert(binary_form=True)).hexdigest()
            account = json.loads((state_directory/'account.json').read_text())
            account_key = (state_directory/'account-key.pem').read_bytes()
            # Reproduce interruption after registration but before account metadata persisted.
            (state_directory/'account.json').rename(state_directory/'retained-account-before-recovery.json')
            renewal_attempts = bridge.count()
            code, renewed = invoke(request)
            assert code == 0 and renewed['status'] == 'issued', ('Private renewal/recovery failed', renewed)
            second = wait_for(lambda: (s if (s := snapshot())['revision'] > first['revision'] and s['available'] else None), 'renewed native certificate', [front, ca])
            assert first['fingerprint'] != second['fingerprint']
            assert json.loads((state_directory/'account.json').read_text())['kid'] == account['kid']
            assert (state_directory/'account-key.pem').read_bytes() == account_key
            if args.reuse_valid_authorizations:
                assert bridge.count() == renewal_attempts, 'Valid authorization reuse performed another challenge'
            application_request(held)
            assert hashlib.sha256(held.getpeercert(binary_form=True)).hexdigest() == first_peer
            with open_application() as fresh:
                assert hashlib.sha256(fresh.getpeercert(binary_form=True)).hexdigest() != first_peer
            emit(phase='private-issuance-renewal-account-recovery-and-live-session-passed')
            good_bundle = bundle.read_bytes()
            negative = {}
            # Invalid-proof checks require fresh pending authorizations. Their
            # default run keeps reuse disabled; the separate reuse run proves
            # the already-valid path without weakening those negative controls.
            for mode in (() if args.reuse_valid_authorizations else ('no-lease', 'wrong-digest')):
                altered = AlteredBroker(runtime/(mode+'.sock'), broker, mode); brokers.append(altered)
                changed = dict(request, stateDirectory=str(root/('state-'+mode)), challengeSocket=str(altered.path))
                before = bridge.count()
                code, denied = invoke(changed)
                assert code != 0 and denied['status'] == 'failed' and denied.get('code') == 'authorization_failed', ('Bad proof did not fail validation', mode, denied)
                assert altered.frames == 1 and bridge.count() > before, 'No pending authorization or actual CA validation attempt'
                assert not (Path(changed['stateDirectory'])/'bundle.pem').exists()
                assert bundle.read_bytes() == good_bundle and snapshot()['available']
                application_request(held)
                altered.close(); brokers.remove(altered)
                negative[mode] = {'failedAsExpected': True, 'pendingProofFrames': altered.frames, 'realValidationAttempts': bridge.count()-before}
                emit(phase=mode+'-rejected-by-real-ca')
            report.update(status='passed', initialRevision=first['revision'], renewedRevision=second['revision'],
                          accountRecoveredWithoutNewKeyOrAccount=True, existingTLSSessionContinued=True,
                          bootstrapDeniedApplication=True, challengeForwardedHTTPRequests=False, negative=negative,
                          validAuthorizationReuse=args.reuse_valid_authorizations,
                          caValidationBypass=False, ownerLogsReadOrExported=False)
        finally:
            if held:
                held.close()
            for altered in reversed(brokers):
                altered.close()
            for process in reversed(processes):
                retire(process)
            for server in reversed(created_servers):
                if server.thread.ident is None:
                    server.server_close()
                else:
                    server.close()
            report['allOwnedProcessesStopped'] = all(p.poll() is not None for p in processes)
            report['validationTCPAttempts'] = bridge.count()
            emit(**report)
    assert report['status'] == 'passed' and report['allOwnedProcessesStopped']


if __name__ == '__main__':
    main()
