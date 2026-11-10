"""Installed helper's real TLS/JWS boundary, not a CA-validation substitute.

Force one badNonce, recover the same account twice, and deliberately reject
orders before challenge presentation. Full issuance uses issuer_native.py.
"""
import argparse
import base64
import http.server
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prefix', nargs='?', type=Path, default=Path('/opt/traverse'))
    parser.add_argument('--issuer', type=Path)
    args = parser.parse_args()
    binary = args.issuer or args.prefix/'libexec/traverse/traverse-issuer'
    os.umask(0o077)
    report = {'scope': 'Installed helper and real TLS/JWS protocol boundary; deliberate order failure, no public CA'}
    with tempfile.TemporaryDirectory(prefix='traverse-installed-issuer-') as temporary:
        root = Path(temporary).resolve()
        certificate, key = root/'api.pem', root/'api.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                        '-keyout', str(key), '-out', str(certificate), '-days', '1', '-subj', '/CN=Local protocol fixture',
                        '-addext', 'subjectAltName=IP:127.0.0.1', '-addext', 'basicConstraints=critical,CA:TRUE'],
                       check=True, capture_output=True, timeout=15)
        state = {'requests': 0, 'newAccountCalls': 0, 'registrations': 0, 'orders': 0, 'nonces': [], 'error': False}
        lock = threading.Lock()
        terms = 'data:text/plain,Local%20protocol%20fixture'
        origin = None
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(*_):
                pass

            def respond(handler, status, value, location=None):
                data = json.dumps(value).encode()
                handler.send_response(status)
                handler.send_header('Replay-Nonce', base64.urlsafe_b64encode(os.urandom(24)).rstrip(b'=').decode())
                handler.send_header('Content-Type', 'application/json')
                handler.send_header('Content-Length', str(len(data)))
                if location:
                    handler.send_header('Location', location)
                handler.end_headers()
                if handler.command != 'HEAD':
                    handler.wfile.write(data)

            def do_HEAD(handler):
                with lock:
                    state['requests'] += 1
                handler.respond(200, {})

            def do_GET(handler):
                with lock:
                    state['requests'] += 1
                handler.respond(200, {'newNonce': origin+'/nonce', 'newAccount': origin+'/accounts', 'newOrder': origin+'/orders',
                                      'meta': {'termsOfService': terms}})

            def do_POST(handler):
                with lock:
                    state['requests'] += 1
                try:
                    body = json.loads(handler.rfile.read(int(handler.headers['Content-Length'])))
                    decode = lambda value: base64.urlsafe_b64decode(value+'='*(-len(value) % 4))
                    protected = json.loads(decode(body['protected']))
                    assert protected['url'] == origin+handler.path and protected['nonce']
                    payload = json.loads(decode(body['payload'])) if body['payload'] else {}
                    if handler.path == '/accounts':
                        with lock:
                            state['newAccountCalls'] += 1
                            state['nonces'].append(protected['nonce'])
                            first = state['newAccountCalls'] == 1
                            exists = state['registrations'] != 0
                        if first:
                            handler.respond(400, {'type': 'urn:ietf:params:acme:error:badNonce', 'detail': 'private-nonce-error-marker'})
                        elif payload.get('onlyReturnExisting') and not exists:
                            handler.respond(400, {'type': 'urn:ietf:params:acme:error:accountDoesNotExist', 'detail': 'Not registered'})
                        else:
                            if not exists:
                                assert payload.get('termsOfServiceAgreed') is True
                                with lock:
                                    state['registrations'] += 1
                            handler.respond(200 if exists else 201, {'status': 'valid'}, origin+'/account/1')
                    elif handler.path == '/account/1':
                        handler.respond(200, {'status': 'valid'})
                    elif handler.path == '/orders':
                        with lock:
                            state['orders'] += 1
                        handler.respond(503, {'type': 'urn:ietf:params:acme:error:serverInternal', 'detail': 'private-order-error-marker'})
                    else:
                        raise AssertionError('Unexpected boundary endpoint')
                except Exception:
                    with lock:
                        state['error'] = True
                    handler.respond(500, {'type': 'urn:ietf:params:acme:error:serverInternal'})
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = False
        origin = 'https://127.0.0.1:'+str(server.server_port)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever); thread.start()
        try:
            request = {'version': 1, 'operation': 'issue', 'domain': 'installed.example.test', 'directory': origin+'/directory',
                       'stateDirectory': str(root/'state'), 'challengeSocket': str(root/'challenge.sock'),
                       'termsURL': terms, 'termsAgreed': False, 'apiTrustFile': str(certificate)}
            def invoke():
                result = subprocess.run([str(binary)], input=json.dumps(request).encode(), capture_output=True, timeout=20)
                assert result.returncode == 1 and not result.stderr, 'Failure/result channel changed'
                assert b'marker' not in result.stdout, 'Private upstream detail or retry log escaped'
                return json.loads(result.stdout)
            assert invoke()['code'] == 'invalid_request'
            assert state['requests'] == 0 and not (root/'state').exists(), 'Consent denial contacted CA or wrote state'
            request['termsAgreed'] = True
            assert invoke()['code'] == 'order_creation_failed'
            account = json.loads((root/'state/account.json').read_text())
            account_key = (root/'state/account-key.pem').read_bytes()
            # Persisted key survives a lost post-registration account metadata snapshot.
            (root/'state/account.json').rename(root/'state/retained-account.json')
            assert invoke()['code'] == 'order_creation_failed'
            assert json.loads((root/'state/account.json').read_text())['kid'] == account['kid']
            assert (root/'state/account-key.pem').read_bytes() == account_key
            assert not state['error'] and state['registrations'] == 1 and state['orders'] == 2
            assert state['newAccountCalls'] == 4 and state['nonces'][0] != state['nonces'][1]
            assert not (root/'state/bundle.pem').exists(), 'Rejected order published material'
            report.update(status='passed', consentDeniedBeforeNetworkOrState=True, badNonceRetriedWithFreshNonce=True,
                          accountRecoveredWithoutReregistering=True, upstreamErrorsAndRetryLogsRedacted=True,
                          issuerUID=os.geteuid(), noCertificatePublishedForFailedOrder=True)
        finally:
            server.shutdown(); server.server_close(); thread.join()
    print(json.dumps(report))


if __name__ == '__main__':
    main()
