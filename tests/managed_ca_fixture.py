"""Pinned private CA, actual DNS and counted native TLS validation bridge.

Synthetic tests only. No public CA, global resolver/trust changes or owner logs.
"""
import ctypes
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import threading
import urllib.request

from issuer_native import DOMAIN, LocalDNS, ValidationBridge, free_port, retire, wait_for


class PrivateCA:
    def __init__(self, root, pebble, target, slow=False):
        self.root = Path(root)
        self.process = None
        self.servers = []
        self.api_certificate, self.api_key = self.root/'api.pem', self.root/'api.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                        '-keyout', str(self.api_key), '-out', str(self.api_certificate), '-days', '1',
                        '-subj', '/CN=Private managed certificate fixture', '-addext', 'subjectAltName=IP:127.0.0.1',
                        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,digitalSignature,keyCertSign,cRLSign'],
                       check=True, capture_output=True, timeout=15)
        self.dns, self.bridge = LocalDNS(), ValidationBridge()
        self.bridge.target = ('127.0.0.1', target)
        if slow:
            # Keep the first authorization observation pending so its real
            # Retry-After20 is exercised before the VA's own15s timeout.
            self.bridge.forward_gate.clear()
        self.created = [self.dns, self.bridge]
        api_port, management_port = free_port(), free_port()
        configuration = self.root/'pebble.json'
        configuration.write_text(json.dumps({'pebble': {
            'listenAddress': '127.0.0.1:'+str(api_port), 'managementListenAddress': '127.0.0.1:'+str(management_port),
            'certificate': str(self.api_certificate), 'privateKey': str(self.api_key),
            'tlsPort': self.bridge.server_address[1], 'httpPort': free_port(), 'keyAlgorithm': 'ecdsa',
            'retryAfter': {'authz': 20 if slow else 1, 'order': 1}}}))
        environment = dict(os.environ, PEBBLE_VA_NOSLEEP='1', PEBBLE_AUTHZREUSE='0')
        environment.pop('PEBBLE_VA_ALWAYS_VALID', None)
        # Same supported owned-parent guard as the existing private CA fixture;
        # install it before creating ANY observer/server Python thread.
        assert threading.active_count() == 1
        libc, parent = ctypes.CDLL(None), os.getpid()
        def guard():
            if libc.prctl(1, signal.SIGTERM, 0, 0, 0) or os.getppid() != parent:
                os._exit(125)
        try:
            self.process = subprocess.Popen([str(pebble), '-config', str(configuration), '-dnsserver',
                '127.0.0.1:'+str(self.dns.server_address[1]), '-strict=false'], env=environment,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=guard, start_new_session=True)
            for server in self.created:
                server.start();self.servers.append(server)
            context = ssl.create_default_context(cafile=str(self.api_certificate))
            self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
            self.directory = 'https://127.0.0.1:'+str(api_port)+'/dir'
            self.metadata = wait_for(lambda: json.loads(self.get(self.directory)), 'trusted private CA directory', [self.process])
            self.issuing_root = self.root/'issued-root.pem'
            self.issuing_root.write_bytes(self.get('https://127.0.0.1:'+str(management_port)+'/roots/0'))
            self.api_certificate.chmod(0o644);self.issuing_root.chmod(0o644)
        except BaseException:
            self.close();raise

    def get(self, uri):
        with self.opener.open(uri, timeout=2) as response:
            return response.read()

    def options(self):
        return {'mode': 'automatic', 'directory': self.directory,
                'termsURL': self.metadata.get('meta', {}).get('termsOfService', ''), 'termsAgreed': True,
                'apiTrustFile': str(self.api_certificate), 'certificateTrustFile': str(self.issuing_root)}

    def close(self):
        if self.process is not None:
            retire(self.process)
        for server in reversed(self.created):
            if server in self.servers:
                server.close()
            else:
                server.server_close()
        self.servers.clear()
