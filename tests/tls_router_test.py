"""Independent TLS/socket witnesses for the native shared-port front end.

Run: python3 tests/tls_router_test.py /path/to/traverse-tls-frontend /path/to/traverse-service
No desktop, public listener, credentials or package changes are involved.
"""
import contextlib
import datetime
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
import sys
import tempfile
import threading
import time
import unittest
from certificate_fixture import issue_leaf

BINARY = str(Path(sys.argv.pop(1)).resolve())
SERVICE = str(Path(sys.argv.pop(1)).resolve())


class Witness(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, marker):
        self.marker = marker
        self.accepted = 0
        self.lock = threading.Lock()
        class Handler(socketserver.BaseRequestHandler):
            def handle(handler):
                with self.lock:
                    self.accepted += 1
                try:
                    self.request_ready(handler.request)
                except (OSError, TimeoutError):
                    pass
        super().__init__(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def request_ready(self, stream):
        stream.settimeout(5)
        stream.sendall(self.marker)
        while data := stream.recv(65536):
            stream.sendall(data)

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join()


def receive(stream, length):
    data = b''
    while len(data) < length:
        chunk = stream.recv(length-len(data))
        if not chunk:
            raise AssertionError(f'Early EOF after {len(data)} of {length} bytes')
        data += chunk
    return data


class RouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='traverse-router-')
        root = Path(cls.directory.name)
        cls.cert, cls.key = root/'cert.pem', root/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(cls.key), '-out', str(cls.cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign',
                        '-addext', 'subjectKeyIdentifier=hash',
                        '-addext', 'authorityKeyIdentifier=keyid:always'],
                       check=True, capture_output=True)
        cls.context = ssl.create_default_context(cafile=str(cls.cert))
        cls.context.set_alpn_protocols(['h2', 'http/1.1'])
        cls.issuer_cert, cls.issuer_key = root/'issuer.pem', root/'issuer.key'
        cls.issuer_cert.write_bytes(cls.cert.read_bytes())
        cls.issuer_key.write_bytes(cls.key.read_bytes());cls.issuer_key.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.http, self.turn = Witness(b'H:'), Witness(b'T:')
        self.start(self.http.server_address[1], self.turn.server_address[1])

    def start(self, http, turn, host='127.0.0.1', extra=()):
        self.host = host
        self.process = subprocess.Popen([BINARY, '--host', host, '--port', '0',
                                         '--http-port', str(http), '--turn-port', str(turn),
                                         '--supervisor-pid', str(os.getpid()),
                                         '--cert', str(self.cert), '--key', str(self.key), *extra],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert select.select([self.process.stdout], [], [], 5)[0], 'Router startup did not finish'
        line = self.process.stdout.readline()
        assert line, self.process.stderr.read()
        self.port = json.loads(line)['port']

    def tearDown(self):
        self.stop()
        self.http.close()
        self.turn.close()

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            stdout, stderr = self.process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()
            self.fail('Native router failed to stop while connections were active')
        self.assertEqual(self.process.returncode, 0, stderr)

    def strict_start(self):
        self.start(self.http.server_address[1], self.turn.server_address[1],
                   extra=['--expected-domain', 'localhost', '--trust-file', str(self.issuer_cert),
                          '--trust-directory', ''])

    def leaf(self, name, **options):
        return issue_leaf(self.directory.name, self.issuer_cert, self.issuer_key, name, **options)

    def replacement(self, cert, key):
        root = Path(self.directory.name)
        first, second = root/'replace.pem', root/'replace.key'
        first.write_bytes(cert);second.write_bytes(key);second.chmod(0o600)
        first.replace(self.cert);second.replace(self.key)

    def certificate_error(self, expected):
        deadline = time.monotonic()+3
        while time.monotonic()<deadline:
            if select.select([self.process.stderr], [], [], .1)[0]:
                line = self.process.stderr.readline()
                if expected in line:return
        self.fail('Certificate rejection not reported: '+expected)

    def test_invalid_renewals_preserve_verified_connections(self):
        root = Path(self.directory.name)
        original_cert, original_key = self.cert.read_bytes(), self.key.read_bytes()
        now = datetime.datetime.now(datetime.timezone.utc)
        wrong, wrong_key = self.leaf('wrong-host', hostname='wrong.invalid')
        no_san, no_san_key = self.leaf('common-name-only', san=False)
        future, future_key = self.leaf('future', start=now+datetime.timedelta(days=1),
                                       end=now+datetime.timedelta(days=2))
        expired, expired_key = self.leaf('expired', start=now-datetime.timedelta(days=2),
                                         end=now-datetime.timedelta(days=1))
        unrelated, unrelated_key = root/'untrusted.pem', root/'untrusted.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(unrelated_key), '-out', str(unrelated), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, capture_output=True)
        encrypted = root/'encrypted.key'
        subprocess.run(['openssl', 'pkey', '-in', str(self.issuer_key), '-aes256',
                        '-passout', 'pass:synthetic-test-only', '-out', str(encrypted)],
                       check=True, capture_output=True)
        cases = [('common-name only', no_san, no_san_key, 'configured domain'),
                 ('mismatched key', original_cert, wrong_key, 'Certificate/key mismatch'),
                 ('wrong hostname', wrong, wrong_key, 'configured domain'),
                 ('untrusted issuer', unrelated.read_bytes(), unrelated_key.read_bytes(), 'chain verification'),
                 ('future', future, future_key, 'not yet valid'),
                 ('expired', expired, expired_key, 'expired'),
                 ('partial PEM', original_cert[:80], original_key, 'valid PEM'),
                 ('encrypted key', original_cert, encrypted.read_bytes(), 'private key'),
                 ('missing file', None, original_key, 'file unavailable')]
        expected = ssl.PEM_cert_to_DER_cert(original_cert.decode())
        header = struct.pack('!HHI12s', 3, 0, 0x2112a442, os.urandom(12))
        try:
            for name, cert, key, error in cases:
                with self.subTest(name=name):
                    self.stop();self.replacement(original_cert, original_key);self.strict_start()
                    with self.tls() as held:
                        held.sendall(header)
                        self.assertEqual(receive(held, len(header)+2), b'T:'+header)
                        if cert is None:self.cert.unlink()
                        else:self.replacement(cert, key)
                        self.process.send_signal(signal.SIGHUP)
                        self.certificate_error(error)
                        with self.tls() as fresh:
                            self.assertEqual(fresh.getpeercert(binary_form=True), expected)
                        held.sendall(header)
                        self.assertEqual(receive(held, len(header)), header)
        finally:
            self.replacement(original_cert, original_key)

    def test_expired_active_certificate_blocks_server_admission_and_can_recover(self):
        original_cert, original_key = self.cert.read_bytes(), self.key.read_bytes()
        now = datetime.datetime.now(datetime.timezone.utc)
        renewed_cert, renewed_key = self.leaf('after-expiry')
        short_cert, short_key = self.leaf('short-lived', start=now-datetime.timedelta(minutes=1),
                                         lifetime_seconds=6)
        header = struct.pack('!HHI12s', 3, 0, 0x2112a442, os.urandom(12))
        # Negative control only: this client accepts expired certificates, so a
        # later rejected handshake proves server admission, not client policy.
        probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        probe.check_hostname = False;probe.verify_mode = ssl.CERT_NONE
        try:
            self.stop();self.replacement(short_cert, short_key);self.strict_start()
            with self.tls() as held:
                expiry = ssl.cert_time_to_seconds(held.getpeercert()['notAfter'])
                held.sendall(header)
                self.assertEqual(receive(held, len(header)+2), b'T:'+header)
                with self.tls(probe) as accepted:
                    self.assertTrue(accepted.getpeercert(binary_form=True))
                while time.time()<expiry+.05:
                    held.sendall(header);self.assertEqual(receive(held, len(header)), header)
                    time.sleep(.1)
                with self.assertRaises((ssl.SSLError, ConnectionResetError)):
                    with self.tls(probe):pass
                held.sendall(header);self.assertEqual(receive(held, len(header)), header)
                self.replacement(renewed_cert, renewed_key)
                self.process.send_signal(signal.SIGHUP)
                expected = ssl.PEM_cert_to_DER_cert(renewed_cert.decode())
                deadline = time.monotonic()+3
                while True:
                    try:
                        with self.tls() as fresh:
                            if fresh.getpeercert(binary_form=True)==expected:break
                    except (ssl.SSLError, ConnectionResetError):pass
                    self.assertLess(time.monotonic(), deadline, 'Certificate renewal did not recover admission')
                    held.sendall(header);self.assertEqual(receive(held, len(header)), header)
                    time.sleep(.03)
        finally:
            self.replacement(original_cert, original_key)

    def test_handshake_crossing_expiry_cannot_open_a_new_turn_session(self):
        original_cert, original_key = self.cert.read_bytes(), self.key.read_bytes()
        now = datetime.datetime.now(datetime.timezone.utc)
        renewed_cert, renewed_key = self.leaf('pending-handshake-renewal')
        short_cert, short_key = self.leaf('handshake-expiry',
            start=now-datetime.timedelta(minutes=1), lifetime_seconds=6)
        header = struct.pack('!HHI12s', 3, 0, 0x2112a442, os.urandom(12))
        probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        probe.check_hostname = False;probe.verify_mode = ssl.CERT_NONE
        probe.minimum_version = probe.maximum_version = ssl.TLSVersion.TLSv1_3
        try:
            self.stop();self.replacement(short_cert, short_key);self.strict_start()
            with self.tls() as held, socket.create_connection((self.host, self.port), timeout=3) as raw:
                expiry = ssl.cert_time_to_seconds(held.getpeercert()['notAfter'])
                held.sendall(header)
                self.assertEqual(receive(held, len(header)+2), b'T:'+header)
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                pending = probe.wrap_bio(incoming, outgoing, server_side=False,
                                         server_hostname='localhost')
                # Complete the client's TLS1.3 state but retain its Finished
                # flight in memory. The server is still awaiting that flight.
                while True:
                    try:
                        pending.do_handshake();break
                    except ssl.SSLWantReadError:
                        if outgoing.pending:raw.sendall(outgoing.read())
                        data = raw.recv(65536)
                        self.assertTrue(data, 'Expiry probe failed before reaching its boundary')
                        incoming.write(data)
                self.assertEqual(pending.version(), 'TLSv1.3')
                self.assertTrue(outgoing.pending, 'Client Finished was not held')
                self.assertLess(time.time(), expiry, 'Probe did not begin before expiry')
                # Activate a valid replacement while this connection retains its
                # old certificate. Checking only the new active context would
                # incorrectly permit the old handshake after its own expiry.
                self.replacement(renewed_cert, renewed_key)
                self.process.send_signal(signal.SIGHUP)
                expected = ssl.PEM_cert_to_DER_cert(renewed_cert.decode())
                deadline = time.monotonic()+3
                while True:
                    with self.tls() as fresh:
                        if fresh.getpeercert(binary_form=True)==expected:break
                    self.assertLess(time.monotonic(), deadline, 'Pending-handshake renewal not active')
                    held.sendall(header);self.assertEqual(receive(held, len(header)), header)
                    time.sleep(.03)
                before = self.turn.accepted
                while time.time()<expiry+.05:
                    held.sendall(header);self.assertEqual(receive(held, len(header)), header)
                    time.sleep(.1)
                pending.write(header)
                delivered = b''
                try:
                    raw.sendall(outgoing.read())
                    deadline = time.monotonic()+3
                    while time.monotonic()<deadline:
                        data = raw.recv(65536)
                        if not data:break
                        incoming.write(data)
                        try:
                            delivered = pending.read(65536)
                            if delivered:break
                        except ssl.SSLWantReadError:pass
                except (ssl.SSLError, ConnectionResetError):pass
                self.assertFalse(delivered, 'Handshake completed after expiry reached the TURN backend')
                self.assertEqual(self.turn.accepted, before,
                                 'Expired pending handshake opened a new backend session')
                held.sendall(header);self.assertEqual(receive(held, len(header)), header)
        finally:
            self.replacement(original_cert, original_key)

    def test_numeric_domain_uses_ip_subject_alternative_name(self):
        original_cert, original_key = self.cert.read_bytes(), self.key.read_bytes()
        certificate, key = self.leaf('numeric-domain', hostname='127.0.0.1')
        try:
            self.stop();self.replacement(certificate, key)
            self.start(self.http.server_address[1], self.turn.server_address[1],
                extra=['--expected-domain', '127.0.0.1', '--trust-file', str(self.issuer_cert),
                       '--trust-directory', ''])
            with socket.create_connection((self.host, self.port), timeout=3) as raw:
                with self.context.wrap_socket(raw, server_hostname='127.0.0.1') as stream:
                    payload = b'GET /numeric HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'
                    stream.sendall(payload)
                    self.assertEqual(receive(stream, len(payload)+2), b'H:'+payload)
        finally:
            self.replacement(original_cert, original_key)

    @contextlib.contextmanager
    def tls(self, context=None):
        raw = socket.create_connection((self.host, self.port), timeout=3)
        try:
            stream = (context or self.context).wrap_socket(raw, server_hostname='localhost')
            try:
                yield stream
            finally:
                stream.close()
        finally:
            raw.close()

    def test_fragmented_http_and_http11_alpn(self):
        payload = b'POST /api/probe HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello'
        with self.tls() as stream:
            self.assertEqual(stream.selected_alpn_protocol(), 'http/1.1')
            for byte in payload:
                stream.sendall(bytes([byte]))
            self.assertEqual(receive(stream, len(payload)+2), b'H:'+payload)
        self.assertEqual(self.http.accepted, 1)
        self.assertEqual(self.turn.accepted, 0)

    def test_certificate_replacement_preserves_established_turn_stream(self):
        root = Path(self.directory.name)
        original_cert, original_key = self.cert.read_bytes(), self.key.read_bytes()
        renewed_cert, renewed_key = root/'renewed.pem', root/'renewed.key'
        request, extensions = root/'renewal.csr', root/'renewal.ext'
        extensions.write_text('subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n'
                              'extendedKeyUsage=serverAuth\n')
        subprocess.run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(renewed_key), '-out', str(request),
                        '-subj', '/CN=localhost'], check=True, capture_output=True)
        subprocess.run(['openssl', 'x509', '-req', '-in', str(request),
                        '-CA', str(self.cert), '-CAkey', str(self.key), '-set_serial', '2',
                        '-out', str(renewed_cert), '-days', '1', '-extfile', str(extensions)],
                       check=True, capture_output=True)
        expected = ssl.PEM_cert_to_DER_cert(renewed_cert.read_text())
        header = struct.pack('!HHI12s', 3, 0, 0x2112a442, os.urandom(12))
        finished, reader_ready = threading.Event(), threading.Event()
        failures, readers = [], []
        original = ssl.PEM_cert_to_DER_cert(original_cert.decode())
        def concurrent_handshakes():
            while not finished.is_set():
                try:
                    with self.tls() as stream:
                        if stream.getpeercert(binary_form=True) not in (original, expected):
                            failures.append('Unexpected certificate during rotation')
                        reader_ready.set()
                except Exception as error:
                    failures.append(str(error))
                finished.wait(.01)
        try:
            with self.tls() as held:
                self.assertNotEqual(held.getpeercert(binary_form=True), expected)
                held.sendall(header)
                self.assertEqual(receive(held, len(header)+2), b'T:'+header)
                readers = [threading.Thread(target=concurrent_handshakes, daemon=True)
                           for _ in range(2)]
                for reader in readers:reader.start()
                self.assertTrue(reader_ready.wait(3), 'Concurrent TLS witness never connected')
                # Normal certificate-manager atomic replacement, no new CLI flags
                # or signal: the baseline must fail on the stale fingerprint.
                renewed_cert.replace(self.cert)
                renewed_key.replace(self.key)
                deadline = time.monotonic()+3
                while True:
                    with self.tls() as fresh:
                        actual = fresh.getpeercert(binary_form=True)
                    if actual == expected:
                        break
                    self.assertLess(time.monotonic(), deadline,
                                    'Renewed certificate was not activated for fresh handshakes')
                    time.sleep(.03)
                held.sendall(header)
                self.assertEqual(receive(held, len(header)), header)
                self.assertIsNone(self.process.poll())
        finally:
            finished.set()
            for reader in readers:reader.join(4)
            self.cert.write_bytes(original_cert)
            self.key.write_bytes(original_key)
        self.assertFalse(any(reader.is_alive() for reader in readers))
        self.assertFalse(failures, failures)

    def test_ipv6_listener_routes_to_fixed_ipv4_loopback_backend(self):
        self.stop()
        self.start(self.http.server_address[1], self.turn.server_address[1], '::1')
        payload = b'GET /ipv6 HTTP/1.1\r\nHost: localhost\r\n\r\n'
        with self.tls() as stream:
            stream.sendall(payload)
            self.assertEqual(receive(stream, len(payload)+2), b'H:'+payload)
        self.assertEqual(self.http.accepted, 1)
        self.assertEqual(self.turn.accepted, 0)

    def test_fragmented_stun_and_sticky_channel_data(self):
        header = struct.pack('!HHI12s', 3, 0, 0x2112a442, os.urandom(12))
        # This later channel header overlaps a complete HTTP method prefix.
        channel = b'GET '+os.urandom(21536)
        with self.tls() as stream:
            for byte in header:
                stream.sendall(bytes([byte]))
            self.assertEqual(receive(stream, len(header)+2), b'T:'+header)
            stream.sendall(channel)
            self.assertEqual(receive(stream, len(channel)), channel)
        self.assertEqual(self.http.accepted, 0)
        self.assertEqual(self.turn.accepted, 1)

    def test_invalid_prefix_reaches_neither_backend(self):
        for data in [b'not-a-protocol', struct.pack('!HHI12s', 3, 0, 0, b'0'*12), b'\x40\x01\x00\x04test']:
            with self.tls() as stream:
                stream.sendall(data)
                try:
                    self.assertEqual(stream.recv(1), b'')
                except ssl.SSLError:
                    pass
        self.assertEqual(self.http.accepted, 0)
        self.assertEqual(self.turn.accepted, 0)

    def test_certificate_validation_is_not_bypassed(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            with self.tls(ssl.create_default_context()):
                pass
        self.assertEqual(self.http.accepted+self.turn.accepted, 0)

    def test_backend_refusal_only_closes_affected_connection(self):
        self.stop()
        with socket.socket() as unavailable:
            unavailable.bind(('127.0.0.1', 0))
            self.start(unavailable.getsockname()[1], self.turn.server_address[1])
            with self.tls() as stream:
                stream.sendall(b'GET / HTTP/1.1\r\n\r\n')
                try:
                    self.assertEqual(stream.recv(1), b'')
                except ssl.SSLError:
                    pass
        header = struct.pack('!HHI12s', 3, 0, 0x2112a442, os.urandom(12))
        with self.tls() as stream:
            stream.sendall(header)
            self.assertEqual(receive(stream, len(header)+2), b'T:'+header)

    def test_stop_with_idle_handshake_fragment_and_active_stream(self):
        raw = socket.create_connection(('127.0.0.1', self.port), timeout=3)
        try:
            with self.tls() as fragment, self.tls() as active:
                fragment.sendall(b'P')
                active.sendall(b'GET / HTTP/1.1\r\n\r\n')
                self.assertEqual(receive(active, 2), b'H:')
                self.stop()
        finally:
            raw.close()

    def test_stop_while_client_is_not_reading_backend_flood(self):
        self.http.marker = b'H:'+os.urandom(8*1024*1024)
        with self.tls() as stream:
            stream.sendall(b'GET /flood HTTP/1.1\r\n\r\n')
            self.assertEqual(receive(stream, 2), b'H:')
            # The independent backend is still sending, while this client stops reading.
            self.stop()

    def test_supervisor_exit_releases_listener(self):
        command = [BINARY, '--host', '127.0.0.1', '--port', '0', '--http-port',
                   str(self.http.server_address[1]), '--turn-port', str(self.turn.server_address[1]),
                   '--cert', str(self.cert), '--key', str(self.key)]
        driver = '''import json,os,subprocess,sys
command=json.loads(sys.argv[1])+['--supervisor-pid',str(os.getpid())]
child=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,start_new_session=True)
ready=json.loads(child.stdout.readline())
print(json.dumps({'pid':child.pid,'port':ready['port']}),flush=True)
os._exit(0)
'''
        result = subprocess.run([sys.executable, '-c', driver, json.dumps(command)],
                                capture_output=True, text=True, check=True, timeout=5)
        child = json.loads(result.stdout)
        try:
            fd = os.pidfd_open(child['pid'])
        except ProcessLookupError:
            fd = None
        if fd is not None:
            try:
                poll = select.poll()
                poll.register(fd, select.POLLIN)
                self.assertTrue(poll.poll(3000), 'Router survived its supervisor')
            finally:
                os.close(fd)
        with self.assertRaises(OSError):
            with socket.create_connection(('127.0.0.1', child['port']), timeout=1):
                pass

    def test_https_successor_reuses_closed_port_without_sharing_live_listener(self):
        command = [SERVICE, '--host', '127.0.0.1', '--port', str(self.port),
                   '--origin', f'https://localhost:{self.port}', '--cert', str(self.cert),
                   '--key', str(self.key), '--socket', self.directory.name+'/absent.sock']
        duplicate = subprocess.run(command, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(duplicate.returncode, 0, 'A second listener shared a live public port')
        self.assertIn('Cannot bind', duplicate.stderr)
        with self.tls() as client:
            client.sendall(b'GET / HTTP/1.1\r\n\r\n')
            self.assertEqual(receive(client, 2), b'H:')
            # Server closes first, as happens when the local owner revokes sharing.
            self.stop()
            successor = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic()+5
                while True:
                    if successor.poll() is not None:
                        stdout, stderr = successor.communicate()
                        self.fail('HTTPS successor failed after owned router exit: '+stderr)
                    try:
                        with self.tls() as connection:
                            connection.sendall(b'GET /api/stats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                            self.assertIn(b'403', connection.recv(1024).split(b'\r\n')[0])
                        break
                    except OSError:
                        self.assertLess(time.monotonic(), deadline, 'HTTPS successor did not bind')
                        time.sleep(.02)
            finally:
                if successor.poll() is None:
                    successor.terminate()
                successor.communicate(timeout=5)

    def test_large_bidirectional_payload_is_not_truncated(self):
        payload = b'POST /bulk HTTP/1.1\r\n\r\n'+os.urandom(1024*1024)
        with self.tls() as stream:
            stream.setblocking(False)
            received = bytearray()
            offset = 0
            deadline = time.monotonic()+10
            while len(received) < len(payload)+2:
                self.assertLess(time.monotonic(), deadline, 'Bidirectional forwarding stalled')
                readable, writable, _ = select.select([stream], [stream] if offset < len(payload) else [], [], .1)
                if writable:
                    try:
                        offset += stream.send(memoryview(payload)[offset:offset+16384])
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        pass
                if readable or stream.pending():
                    try:
                        data = stream.recv(65536)
                        self.assertTrue(data, 'Early EOF during simultaneous forwarding')
                        received.extend(data)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        pass
            self.assertEqual(received, b'H:'+payload)


if __name__ == '__main__':
    unittest.main()
