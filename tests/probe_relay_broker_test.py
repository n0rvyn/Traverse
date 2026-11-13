"""Real frontend CLI, private owner socket and public TLS route lifecycle."""
import contextlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import unittest

FRONTEND = str(Path(sys.argv[1]).resolve())
# Reuse the socket witness only. This module consumes its binary argument.
from probe_relay_routes_test import Witness

A, B, C = (letter * 64 for letter in 'abc')

def exact(stream, length):
    result = b''
    while len(result) < length:
        part = stream.recv(length - len(result))
        if not part:
            raise EOFError('Private relay reply ended')
        result += part
    return result

def command(stream, value):
    text = json.dumps(value, separators=(',', ':')).encode()
    stream.sendall(struct.pack('!I', len(text)) + text)
    length = struct.unpack('!I', exact(stream, 4))[0]
    assert 0 < length < 1024
    return json.loads(exact(stream, length))

class BrokerFrontendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='traverse-broker-tls-')
        cls.root = Path(cls.directory.name)
        cls.cert, cls.key = cls.root / 'cert.pem', cls.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign',
                        '-keyout', str(cls.key), '-out', str(cls.cert)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.http, self.turn, self.probe = Witness(b'HTTP'), Witness(b'TURN'), Witness(b'PROBE')
        self.path = str(self.root / 'p')
        self.process = subprocess.Popen([FRONTEND, '--host', '127.0.0.1', '--port', '0',
            '--http-port', str(self.http.port), '--turn-port', str(self.turn.port),
            '--cert', str(self.cert), '--key', str(self.key), '--expected-domain', 'localhost',
            '--trust-file', str(self.cert), '--trust-directory', '',
            '--probe-socket', self.path, '--probe-owner-pid', str(os.getpid())],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.port = json.loads(self.process.stdout.readline())['port']

    def tearDown(self):
        self.process.terminate()
        try:
            stdout, stderr = self.process.communicate(timeout=8)
            self.assertEqual(self.process.returncode, 0, (stdout, stderr))
            self.assertEqual(stderr, b'')
            self.assertFalse(Path(self.path).exists())
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)
            for witness in (self.http, self.turn, self.probe):
                witness.close()

    def owner(self):
        stream = socket.socket(socket.AF_UNIX)
        stream.settimeout(3)
        stream.connect(self.path)
        return stream

    def begin(self, stream, lease):
        self.assertEqual(command(stream, dict(schemaVersion=1, type='begin', lease=lease,
                         port=self.probe.port)), dict(schemaVersion=1, status='installed'))

    def end(self, stream, lease):
        self.assertEqual(command(stream, dict(schemaVersion=1, type='end', lease=lease)),
                         dict(schemaVersion=1, status='ended'))

    def connect(self, lease):
        context = ssl.create_default_context(cafile=str(self.cert))
        context.set_alpn_protocols(['traverse-probe/' + lease])
        raw = socket.create_connection(('127.0.0.1', self.port), timeout=3)
        try:
            return context.wrap_socket(raw, server_hostname='localhost')
        except BaseException:
            raw.close()
            raise

    def test_actual_frontend_owner_end_eof_and_same_backend_reuse(self):
        with self.assertRaises(ssl.SSLError):
            self.connect(A)
        with self.owner() as owner, contextlib.ExitStack() as resources:
            self.begin(owner, A)
            old = resources.enter_context(self.connect(A))
            self.assertEqual(old.recv(5), b'PROBE')
            self.end(owner, A)
            self.assertEqual(old.recv(1), b'')
            with self.assertRaises(ssl.SSLError):
                self.connect(A)
        owner = self.owner()
        try:
            self.begin(owner, B)
            with self.connect(B) as stream:
                self.assertEqual(stream.recv(5), b'PROBE')
                owner.close()  # The frontend must revoke without an end request.
                self.assertEqual(stream.recv(1), b'')
        finally:
            owner.close()
        with self.owner() as ending:
            self.end(ending, C)
        with self.owner() as late:
            self.assertEqual(command(late, dict(schemaVersion=1, type='begin', lease=C,
                             port=self.probe.port)), dict(schemaVersion=1, status='invalid'))
        self.assertEqual((self.http.count, self.turn.count, self.probe.count), (0, 0, 2))

if __name__ == '__main__':
    unittest.main()
