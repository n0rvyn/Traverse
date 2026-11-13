"""Actual persistent native source ownership, private FDs and port handoff."""
import json
import os
from pathlib import Path
import secrets
import selectors
import socket
import subprocess
import sys
import tempfile
import time
import types
import unittest
import hashlib
import struct
import ipaddress
import ssl
import select
from installed_turn import attribute, exchange, COOKIE
WORKER,DRIVER=map(lambda value:str(Path(value).resolve()),sys.argv[1:3])
from readiness_media_transport_test import Worker,config,available_port
sys.argv=[sys.argv[0]]

class Owner:
    def __init__(self,root,witnesses,broker=None):
        self.error=Path(root)/'owner.stderr'
        environment=dict(os.environ,DISPLAY=':unused-fixture',WAYLAND_DISPLAY='unused-fixture',
                         DBUS_SESSION_BUS_ADDRESS='unix:path=/unused-fixture',XAUTHORITY='/unused-fixture',
                         TRAVERSE_PARENT_SECRET='private-fixture-witness',XDG_RUNTIME_DIR='/unused-fixture')
        with self.error.open('wb') as error:
            arguments=[DRIVER,WORKER]+([str(broker)] if broker else [])
            self.process=subprocess.Popen(arguments,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=error,bufsize=0,env=environment,pass_fds=witnesses)
    def send(self,value):
        self.process.stdin.write((json.dumps(value)+'\n').encode())
    def read(self):
        selector=selectors.DefaultSelector();selector.register(self.process.stdout,selectors.EVENT_READ)
        try:assert selector.select(8),('Owner output watchdog',self.error.read_text())
        finally:selector.close()
        line=self.process.stdout.readline();assert line,('Owner EOF',self.process.poll(),self.error.read_text())
        return json.loads(line)
    def request(self,op,**fields):
        self.send(dict(op=op,**fields))
        while True:
            value=self.read()
            if value.get('reply')==op:return value
            assert value.get('type')!='failure',value
    def command(self,id,value):self.send(dict(op='command',id=id,command=value))
    def close(self):
        try:
            if self.process.poll() is None:
                result=self.request('stop');assert result['ok'] and result['idle'],result
                self.process.stdin.close();self.process.stdin=None
            self.process.wait(timeout=8);assert self.process.returncode==0,self.error.read_text()
            assert self.error.read_bytes()==b'',self.error.read_text()
        finally:
            if self.process.poll() is None:self.process.kill();self.process.wait(timeout=5)
            if self.process.stdin:self.process.stdin.close();self.process.stdin=None
            self.process.stdout.close()

class OwnerTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='traverse-media-owner-');self.root=Path(self.directory.name)
        self.file=tempfile.TemporaryFile(dir=self.root);self.socket=socket.socket(socket.AF_UNIX)
        self.witnesses=(self.file.fileno(),self.socket.fileno())
        self.identities={(os.fstat(fd).st_dev,os.fstat(fd).st_ino) for fd in self.witnesses}
        self.assertEqual(len(self.identities),2)
        self.owner=Owner(self.root,self.witnesses)
    def tearDown(self):
        try:self.owner.close()
        finally:self.file.close();self.socket.close();self.directory.cleanup()
    def stream(self,source_port,settings=None):
        if settings is None:
            observer_port=available_port((source_port,));nonce=secrets.token_hex(32)
            settings=config('source',source_port,observer_port,nonce)
        else:
            observer_port=settings['peers'][0]['port'];nonce=settings['nonce']
        result=self.owner.request('begin',config=settings);self.assertTrue(result['ok']);self.assertFalse(result['idle'])
        observer=Worker(config('observer',observer_port,source_port,nonce),self.root)
        selector=selectors.DefaultSelector();selector.register(self.owner.process.stdout,selectors.EVENT_READ,'source')
        selector.register(observer.process.stdout,selectors.EVENT_READ,'observer')
        receipts={};events=[]
        try:
            deadline=time.monotonic()+15
            while len(receipts)<2 and time.monotonic()<deadline:
                for key,_ in selector.select(max(0,deadline-time.monotonic())):
                    role=key.data;value=self.owner.read() if role=='source' else observer.read()
                    if 'reply' in value:self.assertTrue(value['ok']);continue
                    kind=value['type'];events.append((role,kind));self.assertNotEqual(kind,'failure',value)
                    if kind in ('description','candidate'):
                        fields=('kind','sdp') if kind=='description' else ('index','candidate')
                        command=dict(schemaVersion=1,type=kind,**{field:value[field] for field in fields})
                        if role=='source':observer.send(command)
                        else:self.owner.command(settings['peer'],command)
                    elif kind=='received':
                        self.assertEqual(value['nonce'],nonce);self.assertTrue(value['dataVerified'] and value['dtlsConnected'])
                        receipts[role]=value
            self.assertEqual(set(receipts),{'source','observer'},events);self.assertTrue(receipts['observer']['videoDecoded'])
            children=[]
            for task in (Path('/proc')/str(self.owner.process.pid)/'task').iterdir():
                for child in (task/'children').read_text().split():
                    if Path(f'/proc/{child}/exe').resolve()==Path(WORKER):children.append((int(task.name),int(child)))
            self.assertEqual(len(children),1);creator,pid=children[0]
            parent_environment=(Path('/proc')/str(self.owner.process.pid)/'environ').read_bytes().split(b'\0')
            self.assertIn(b'TRAVERSE_PARENT_SECRET=private-fixture-witness',parent_environment)
            child_environment=(Path('/proc')/str(pid)/'environ').read_bytes().split(b'\0')
            self.assertFalse(any(item.startswith(b'XDG_RUNTIME_DIR=') for item in child_environment))
            self.assertNotEqual(creator,self.owner.process.pid,'Source was created on a short-lived calling thread')
            view=types.SimpleNamespace(process=types.SimpleNamespace(pid=pid),config=settings)
            Worker.assert_private_authority(view,self.identities)
            return settings,observer,pid
        except BaseException:
            observer.close();raise
        finally:selector.close()
    def test_stream_preempt_reap_and_fresh_same_port(self):
        port=available_port();settings,observer,pid=self.stream(port)
        try:
            result=self.owner.request('preempt');self.assertTrue(result['idle']);self.assertTrue(result['ok'])
            self.assertFalse(Path(f'/proc/{pid}').exists(),'Preemption acknowledged before source reap')
            with socket.socket(type=socket.SOCK_DGRAM) as witness:witness.bind(('127.0.0.1',port))
            self.assertFalse(self.owner.request('begin',config=config('source',port,available_port((port,))))['ok'])
            self.owner.command(settings['peer'],dict(schemaVersion=1,type='candidate',index=0,candidate=''))
            while True:
                value=self.owner.read()
                if value.get('reply')=='command':self.assertFalse(value['ok']);break
        finally:observer.close()
        self.assertTrue(self.owner.request('release')['ok'])
        fresh,observer,pid=self.stream(port)
        try:
            result=self.owner.request('end',id=fresh['peer']);self.assertTrue(result['idle'])
            self.assertFalse(Path(f'/proc/{pid}').exists())
            self.assertFalse(self.owner.request('begin',config=fresh)['ok'])
        finally:observer.close()
    def test_end_before_begin_and_immediate_preemption(self):
        port=available_port();settings=config('source',port,available_port((port,)))
        self.assertTrue(self.owner.request('end',id=settings['peer'])['idle'])
        self.assertFalse(self.owner.request('begin',config=settings)['ok'])
        fresh=config('source',port,available_port((port,)))
        self.assertTrue(self.owner.request('begin',config=fresh)['ok'])
        self.assertTrue(self.owner.request('preempt')['idle'])
        with socket.socket(type=socket.SOCK_DGRAM) as witness:witness.bind(('127.0.0.1',port))
    def test_prepared_relay_then_source_yields_both_children(self):
        # Real private frontend route is owned by this persistent owner PID.
        self.owner.close();broker=self.root/'p'
        self.owner=Owner(self.root,self.witnesses,broker)
        cert,key=self.root/'cert.pem',self.root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
            '-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:TRUE',
            '-addext','keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign',
            '-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        key.chmod(0o600)
        ordinary=socket.socket();ordinary.bind(('127.0.0.1',0));ordinary.listen();self.addCleanup(ordinary.close)
        frontend=subprocess.Popen([str(Path(WORKER).parent/'traverse-tls-frontend'),'--host','127.0.0.1','--port','0',
            '--http-port',str(ordinary.getsockname()[1]),'--turn-port',str(ordinary.getsockname()[1]),
            '--cert',str(cert),'--key',str(key),'--expected-domain','localhost','--trust-file',str(cert),
            '--trust-directory','','--probe-socket',str(broker),'--probe-owner-pid',str(self.owner.process.pid)],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def close_frontend():
            if frontend.poll() is None:frontend.terminate()
            try:
                output,error=frontend.communicate(timeout=8);self.assertEqual(frontend.returncode,0,(output,error));self.assertEqual(error,b'')
            finally:
                if frontend.poll() is None:frontend.kill();frontend.wait(timeout=5)
        self.addCleanup(close_frontend)
        self.assertTrue(select.select([frontend.stdout],[],[],5)[0])
        public_port=json.loads(frontend.stdout.readline())['port'];route=secrets.token_hex(32)
        context=ssl.create_default_context(cafile=str(cert));context.set_alpn_protocols(['traverse-probe/'+route])
        def connect():
            raw=socket.create_connection(('127.0.0.1',public_port),timeout=3)
            try:return context.wrap_socket(raw,server_hostname='localhost')
            except BaseException:raw.close();raise
        port=available_port();settings=config('source',port,available_port((port,)))
        username,credential=secrets.token_hex(32),secrets.token_hex(32)
        self.assertTrue(self.owner.request('relay',id=settings['peer'],grant=dict(addresses=['127.0.0.1'],port=port,username=username,credential=credential,route=route))['ok'])
        while True:
            event=self.owner.read();self.assertNotEqual(event.get('type'),'failure',event)
            if event.get('type')=='relayReady':break
        self.assertEqual(event['peer'],settings['peer'])
        relay_children=[]
        for task in Path(f'/proc/{self.owner.process.pid}/task').iterdir():
            for child in (task/'children').read_text().split():
                relay_children.append((int(task.name),int(child)))
        self.assertEqual(len(relay_children),1);creator,relay_pid=relay_children[0]
        self.assertNotEqual(creator,self.owner.process.pid)
        with connect() as allocation:
            self.assertEqual(allocation.selected_alpn_protocol(),'traverse-probe/'+route)
            requested=attribute(0x19,b'\x11\0\0\0')
            _,challenge,error=exchange(allocation,3,requested);self.assertEqual(error,401)
            auth=attribute(6,username.encode())+attribute(0x14,challenge[0x14])+attribute(0x15,challenge[0x15])
            key=hashlib.md5(username.encode()+b':'+challenge[0x14]+b':'+credential.encode()).digest()
            _,answer,error=exchange(allocation,3,requested+auth,key);self.assertIsNone(error)
            raw=answer[0x16];relay_address=str(ipaddress.IPv4Address(struct.unpack('!I',raw[4:8])[0]^COOKIE))
            relay_port=struct.unpack('!H',raw[2:4])[0]^(COOKIE>>16)
            snapshot=self.owner.request('allocations',id=settings['peer'])
            self.assertTrue(snapshot['ok']);self.assertIn(dict(address=relay_address,port=relay_port),snapshot['peers'])
            _,observer,source_pid=self.stream(port,settings)
            try:
                self.assertTrue(self.owner.request('preempt')['idle'])
                for pid in (source_pid,relay_pid):self.assertFalse(Path(f'/proc/{pid}').exists(),'Controller admitted before owned child reap')
                for address,used in ((relay_address,relay_port),('127.0.0.1',port)):
                    with socket.socket(type=socket.SOCK_DGRAM) as reclaimed:reclaimed.bind((address,used))
                try:self.assertEqual(allocation.recv(1),b'')
                except ConnectionResetError:pass
                with self.assertRaises(ssl.SSLError):connect()
            finally:observer.close()
        self.assertTrue(self.owner.request('release')['ok'])
        fresh,observer,_=self.stream(port)
        try:self.assertTrue(self.owner.request('end',id=fresh['peer'])['idle'])
        finally:observer.close()

if __name__=='__main__':
    from native_test_identity import unprivileged_media_test
    identity=unprivileged_media_test()
    unittest.main()
