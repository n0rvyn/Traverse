"""Real HTTP boundaries for the explicit TLS-front-end backend mode."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

BINARY = str(Path(sys.argv.pop(1)).resolve())
WEB = str(Path(sys.argv.pop(1)).resolve())


class LoopbackServiceTests(unittest.TestCase):
    def test_external_plaintext_and_non_https_origin_are_rejected(self):
        for host, origin in [('0.0.0.0', 'https://desktop.example.com'),
                             ('192.0.2.1', 'https://desktop.example.com'),
                             ('localhost', 'https://desktop.example.com'),
                             ('127.0.0.1', 'http://desktop.example.com')]:
            result = subprocess.run([BINARY, '--internal-http', '--host', host,
                                     '--origin', origin, '--port', '0'], capture_output=True,
                                    text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Internal HTTP requires', result.stderr)

    def test_https_is_still_the_default_and_needs_its_certificate(self):
        result = subprocess.run([BINARY, '--host', '127.0.0.1', '--origin',
                                 'https://desktop.example.com', '--port', '0'],
                                capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Required: --cert', result.stderr)

    def test_real_loopback_http_retains_origin_auth_and_private_ice_boundary(self):
        with tempfile.TemporaryDirectory(prefix='traverse-loopback-api-') as tmp:
            root = Path(tmp)
            credential = 'test-router-credential'
            config = root/'ice.json'
            config.write_text(json.dumps({'iceTransportPolicy': 'relay', 'iceServers': [{
                'urls': 'turns:desktop.example.com:443?transport=tcp',
                'username': 'test-router-user', 'credential': credential}]}))
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            with (root/'service.log').open('w+') as log:
                process = subprocess.Popen([BINARY, '--internal-http', '--host', '127.0.0.1',
                                            '--origin', 'https://desktop.example.com', '--port', str(port),
                                            '--socket', str(root/'absent-adapter.sock'), '--web', WEB,
                                            '--ice-config', str(config), '--supervisor-pid', str(os.getpid())],
                                           stdout=log, stderr=log)
                base = f'http://127.0.0.1:{port}'
                def request(path, body=None, origin=None):
                    headers = {'Content-Type': 'application/json'}
                    if origin:
                        headers['Origin'] = origin
                    req = urllib.request.Request(base+path, data=None if body is None else json.dumps(body).encode(),
                                                 headers=headers)
                    try:
                        with urllib.request.urlopen(req, timeout=2) as response:
                            return response.status, response.read()
                    except urllib.error.HTTPError as error:
                        return error.code, error.read()
                try:
                    deadline = time.monotonic()+5
                    while True:
                        if process.poll() is not None:
                            log.seek(0)
                            self.fail('Service failed startup: '+log.read())
                        try:
                            self.assertEqual(request('/')[0], 200)
                            break
                        except urllib.error.URLError:
                            self.assertLess(time.monotonic(), deadline, 'Loopback service never became ready')
                            time.sleep(.02)
                    for path in ['/', '/client.js', '/api/stats']:
                        _, payload = request(path)
                        self.assertNotIn(credential.encode(), payload)
                        self.assertNotIn(b'test-router-user', payload)
                    status, payload = request('/api/pair', {'code': 'invalid'}, 'https://other.example.com')
                    self.assertEqual(status, 403)
                    self.assertIn(b'Origin rejected', payload)
                    for path, body in [('/api/pair', {'code': 'invalid'}),
                                       ('/api/offer', {'type': 'offer', 'sdp': 'invalid'})]:
                        status, payload = request(path, body, 'https://desktop.example.com')
                        self.assertEqual(status, 403)
                        self.assertNotIn(credential.encode(), payload)
                        self.assertNotIn(b'test-router-user', payload)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        self.fail('Loopback service did not stop')
                self.assertEqual(process.returncode, 0)


if __name__ == '__main__':
    unittest.main()
