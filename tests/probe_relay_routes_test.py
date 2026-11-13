"""Actual shared-listener ALPN admission, live revoke and private backend reuse."""
import contextlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
BINARY=str(Path(sys.argv.pop(1)).resolve())
A,B,C=('a'*64,'b'*64,'c'*64)
def alpn(lease):return 'traverse-probe/'+lease
class Witness:
    def __init__(self,marker):
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen()
        self.port=self.listener.getsockname()[1];self.marker=marker;self.count=0;self.connections=[];self.stopped=False
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        while not self.stopped:
            try:stream=self.listener.accept()[0]
            except OSError:return
            self.count+=1;self.connections.append(stream)
            try:stream.sendall(self.marker)
            except OSError:pass
    def close(self):
        self.stopped=True
        try:self.listener.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        self.listener.close();self.thread.join(5)
        for stream in self.connections:stream.close()
        assert not self.thread.is_alive()
class RouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory(prefix='traverse-route-tls-');root=Path(cls.directory.name)
        cls.cert=root/'cert.pem';cls.key=root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign','-keyout',str(cls.key),'-out',str(cls.cert)],check=True,capture_output=True)
    @classmethod
    def tearDownClass(cls):cls.directory.cleanup()
    def setUp(self):
        self.http=Witness(b'HTTP');self.turn=Witness(b'TURN');self.probe=Witness(b'PROBE')
        self.process=subprocess.Popen([BINARY],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.write(dict(lease=A,backend=self.probe.port,http=self.http.port,turn=self.turn.port,cert=str(self.cert),key=str(self.key),ca=str(self.cert)))
        self.port=json.loads(self.process.stdout.readline())['port']
    def tearDown(self):
        if self.process.stdin:self.process.stdin.close();self.process.stdin=None
        try:
            stdout,stderr=self.process.communicate(timeout=8);self.assertEqual(self.process.returncode,0,(stdout,stderr));self.assertEqual(stderr,b'')
        finally:
            for witness in (self.http,self.turn,self.probe):witness.close()
    def write(self,value):self.process.stdin.write((json.dumps(value)+'\n').encode());self.process.stdin.flush()
    def command(self,value):self.write(value);self.assertEqual(json.loads(self.process.stdout.readline()),{'ok':True})
    def context(self,protocols):
        context=ssl.create_default_context(cafile=str(self.cert));context.set_alpn_protocols(protocols);return context
    def connect(self,context,session=None):
        raw=socket.create_connection(('127.0.0.1',self.port),timeout=3)
        try:return context.wrap_socket(raw,server_hostname='localhost',session=session)
        except BaseException:raw.close();raise
    def test_live_revoke_reuse_and_ordinary_routes(self):
        with self.connect(self.context([alpn(A)])) as old:
            self.assertEqual(old.selected_alpn_protocol(),alpn(A));self.assertEqual(old.recv(5),b'PROBE')
            self.command(dict(op='revoke',lease=A));self.assertEqual(old.recv(1),b'')
            self.command(dict(op='install',lease=B,backend=self.probe.port))
            with self.assertRaises(ssl.SSLError):self.connect(self.context([alpn(A)]))
            with self.connect(self.context([alpn(B)])) as fresh:self.assertEqual(fresh.recv(5),b'PROBE')
        with self.connect(self.context(['http/1.1'])) as http:
            http.sendall(b'GET / HTTP/1.1\r\n\r\n');self.assertEqual(http.recv(4),b'HTTP')
        with self.connect(self.context([])) as turn:
            turn.sendall(bytes.fromhex('000300002112a442')+b'abcdefghijkl');self.assertEqual(turn.recv(4),b'TURN')
        self.assertEqual((self.http.count,self.turn.count,self.probe.count),(1,1,2))
    def test_unknown_malformed_and_mixed_alpn_cannot_touch_backends(self):
        for protocols in ([alpn(C)],['traverse-probe/bad'],[alpn(A),'http/1.1'],['http/1.1',alpn(A)]):
            with self.subTest(protocols=protocols),self.assertRaises(ssl.SSLError):self.connect(self.context(protocols))
        self.assertEqual((self.http.count,self.turn.count,self.probe.count),(0,0,0))
    def test_ended_lease_rejects_tls12_session_reuse(self):
        context=self.context([alpn(A)]);context.minimum_version=context.maximum_version=ssl.TLSVersion.TLSv1_2
        with self.connect(context) as original:
            self.assertEqual(original.recv(5),b'PROBE');session=original.session
            self.command(dict(op='revoke',lease=A));self.assertEqual(original.recv(1),b'')
        self.command(dict(op='install',lease=B,backend=self.probe.port))
        with self.assertRaises((ssl.SSLError,ConnectionResetError)):self.connect(context,session)
        context.set_alpn_protocols([alpn(B)])
        with self.connect(context,session) as fresh:
            self.assertFalse(fresh.session_reused);self.assertEqual(fresh.recv(5),b'PROBE')
if __name__=='__main__':unittest.main()
