"""Actual numeric-pin/verified TLS/ALPN bridge, private sockets and test CA only."""
import contextlib
import datetime
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from certificate_fixture import issue_leaf

BINARY = str(Path(sys.argv.pop(1)).resolve())
ALPN = 'traverse-probe/'+'a'*64
REPLY = struct.pack('!HHI12s',0x0103,0,0x2112a442,b'abcdefghijkl')

class Server:
    def __init__(self, certificate, key, alpn=ALPN, response=REPLY, handshake=True, family=socket.AF_INET):
        self.listener=socket.socket(family);self.listener.bind(('::1' if family==socket.AF_INET6 else '127.0.0.1',0));self.listener.listen()
        self.port=self.listener.getsockname()[1];self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificate,key);self.context.set_alpn_protocols([alpn] if alpn else [])
        self.received=b'';self.handshake=handshake;self.response=response;self.stop=threading.Event();self.accepted=threading.Event()
        self.stream=None;self.error=None
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        try:
            self.listener.settimeout(5)
            with self.listener.accept()[0] as raw:
                self.stream=raw;self.accepted.set()
                if not self.handshake:self.stop.wait(5);return
                with self.context.wrap_socket(raw,server_side=True) as stream:
                    self.stream=stream;stream.settimeout(5)
                    if self.response is not None:
                        # Deliberately split complete STUN replies across TLS records.
                        stream.sendall(self.response[:3]);stream.sendall(self.response[3:])
                    while True:
                        part=stream.recv(65536)
                        if not part:break
                        self.received+=part
                        if self.received==b'private-turn-allocate':
                            stream.unwrap();break
        except (ssl.SSLError,OSError) as error:self.error=str(error)
    def close(self):
        self.stop.set()
        if self.stream:
            try:self.stream.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        try:self.listener.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.listener.close();self.thread.join(6);assert not self.thread.is_alive()

class RelayTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory(prefix='traverse-probe-tls-');cls.root=Path(cls.directory.name)
        cls.ca=cls.root/'ca.pem';cls.ca_key=cls.root/'ca.key'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(cls.ca_key),'-out',str(cls.ca),'-days','1','-subj','/CN=probe-test','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign'],check=True,capture_output=True)
        cls.certificates={}
        now=datetime.datetime.now(datetime.timezone.utc)
        for name,hostname,dates in [('dns','localhost',{}),('ip','127.0.0.1',{}),('ip6','::1',{}),('expired','localhost',{'start':now-datetime.timedelta(days=2),'end':now-datetime.timedelta(days=1)})]:
            cert,key=issue_leaf(cls.root,cls.ca,cls.ca_key,name,hostname,**dates)
            path,secret=cls.root/(name+'-tls.pem'),cls.root/(name+'-tls.key');path.write_bytes(cert);secret.write_bytes(key);secret.chmod(0o600)
            cls.certificates[name]=(path,secret)
    @classmethod
    def tearDownClass(cls):cls.directory.cleanup()
    @contextlib.contextmanager
    def connection(self,certificate='dns',hostname='localhost',ca=True,address='127.0.0.1',**server_options):
        server=Server(*self.certificates[certificate],**server_options)
        local,peer=socket.socketpair();local.settimeout(5)
        process=subprocess.Popen([BINARY],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(peer.fileno(),))
        config=dict(address=address,hostname=hostname,ca=str(self.ca) if ca else '',alpn=ALPN,port=server.port,fd=peer.fileno())
        process.stdin.write((json.dumps(config)+'\n').encode());process.stdin.flush();peer.close()
        try:yield process,local,server
        finally:
            if process.stdin is not None:
                process.stdin.close();process.stdin=None
            try:
                stdout,stderr=process.communicate(timeout=8)
                self.assertEqual(process.returncode,0,(stdout,stderr));self.assertEqual(stderr,b'')
            finally:
                local.close();server.close()
    def result(self,process):
        result=json.loads(process.stdout.readline());self.assertIn(result['status'],('closed','cancelled','rejected'));return result
    def test_verified_dns_ip_and_ipv6_duplex(self):
        for certificate,hostname,address,family in [('dns','localhost','127.0.0.1',socket.AF_INET),('ip','127.0.0.1','127.0.0.1',socket.AF_INET),('ip6','::1','::1',socket.AF_INET6)]:
            with self.subTest(identity=hostname),self.connection(certificate,hostname,address=address,family=family) as (process,local,server):
                local.sendall(b'private-turn-allocate')
                value=b''
                while len(value)<len(REPLY):value+=local.recv(len(REPLY)-len(value))
                self.assertEqual(value,REPLY)
                # Full TLS close is expected only after the local peer observes
                # EOF; then unwrap can finish its bidirectional close_notify.
                local.shutdown(socket.SHUT_WR)
                self.assertEqual(self.result(process)['status'],'closed')
                self.assertEqual(server.received,b'private-turn-allocate')
    def test_bad_identity_trust_expiry_and_alpn_send_no_plaintext(self):
        for options in [dict(hostname='wrong.test'),dict(hostname='127.0.0.1'),dict(ca=False),dict(certificate='expired'),dict(alpn='http/1.1'),dict(alpn='')]:
            with self.subTest(options=options),self.connection(**options) as (process,local,server):
                local.sendall(b'private-turn-allocate')
                self.assertEqual(self.result(process)['status'],'rejected')
                server.close();self.assertEqual(server.received,b'')
    def test_redirect_never_reaches_native_client(self):
        response=struct.pack('!HHI12s',0x0113,8,0x2112a442,b'abcdefghijkl')+bytes([0,9,0,4,0,0,3,0])
        with self.connection(response=response) as (process,local,server):
            self.assertEqual(self.result(process)['status'],'rejected')
            self.assertEqual(local.recv(1),b'')
    def test_cancel_during_handshake_and_streaming(self):
        for handshake in (False,True):
            with self.subTest(handshake=handshake),self.connection(handshake=handshake,response=REPLY if handshake else None) as (process,local,server):
                self.assertTrue(server.accepted.wait(5))
                if handshake:
                    value=b''
                    while len(value)<len(REPLY):value+=local.recv(len(REPLY)-len(value))
                    self.assertEqual(value,REPLY)
                process.stdin.close();process.stdin=None
                self.assertEqual(self.result(process)['status'],'cancelled')
    def test_pin_cannot_trigger_dns_resolution(self):
        with self.connection(address='localhost') as (process,local,server):
            self.assertEqual(self.result(process)['status'],'rejected')
            self.assertFalse(server.accepted.is_set())

if __name__=='__main__':unittest.main()
