"""Actual native workers -> verified TLS/ALPN -> scoped coturn -> UDP source.

Private loopback fixtures only; no desktop, public service or system trust.
"""
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
import unittest
WORKER,BRIDGE,ROUTER,TURN=map(lambda x:str(Path(x).resolve()),sys.argv[1:5])
# Reuse only the native worker fixture; it consumes its explicit binary argument.
from readiness_media_transport_test import Worker,config,available_port
from installed_turn import sockets
sys.argv=[sys.argv[0]]

class Helper:
    def __init__(self,binary,settings,root,label):
        self.error=Path(root)/(label+'.stderr');error=self.error.open('wb')
        self.process=subprocess.Popen([binary],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=error,bufsize=0)
        error.close();self.send(settings);self.ready=self.read()
    def send(self,value):self.process.stdin.write((json.dumps(value)+'\n').encode())
    def read(self):
        selector=selectors.DefaultSelector();selector.register(self.process.stdout,selectors.EVENT_READ)
        try:assert selector.select(8),('Helper output watchdog',self.error.read_text())
        finally:selector.close()
        line=self.process.stdout.readline();assert line,('Helper EOF',self.process.poll(),self.error.read_text());return json.loads(line)
    def command(self,value):self.send(value);return self.read()
    def close(self):
        if self.process.stdin:self.process.stdin.close();self.process.stdin=None
        try:
            self.process.wait(timeout=8);assert self.process.returncode==0,(self.process.returncode,self.error.read_text());assert self.error.read_bytes()==b'',self.error.read_text()
        finally:
            if self.process.poll() is None:self.process.kill();self.process.wait(timeout=5)
            self.process.stdout.close()

class RelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory=tempfile.TemporaryDirectory(prefix='traverse-native-relay-');cls.root=Path(cls.directory.name)
        cls.cert=cls.root/'cert.pem';cls.key=cls.root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign','-keyout',str(cls.key),'-out',str(cls.cert)],check=True,capture_output=True)
        cls.key.chmod(0o600)
    @classmethod
    def tearDownClass(cls):cls.directory.cleanup()
    def test_real_relay_video_data_and_live_route_revocation(self):
        # Keep both parent witnesses alive throughout spawning and streaming.
        # Inheritable descriptors must still be excluded by the private launch.
        file_witness=tempfile.TemporaryFile(dir=self.root);self.addCleanup(file_witness.close)
        socket_witness=socket.socket(socket.AF_UNIX);self.addCleanup(socket_witness.close)
        witnesses=(file_witness.fileno(),socket_witness.fileno())
        for fd in witnesses:os.set_inheritable(fd,True)
        parent_descriptors={(os.fstat(fd).st_dev,os.fstat(fd).st_ino) for fd in witnesses}
        self.assertEqual(len(parent_descriptors),2)
        source_port=available_port();observer_port=available_port((source_port,));nonce=secrets.token_hex(32)
        username,credential,lease=(secrets.token_hex(32) for _ in range(3));alpn='traverse-probe/'+lease
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1',0));backend=reservation.getsockname()[1]
        turn_config=self.root/'turn.conf'
        turn_config.write_text(f'''listening-ip=127.0.0.1
listening-port={backend}
relay-ip=127.0.0.1
no-udp
no-tls
dtls=false
cli=false
web-admin=false
no-tcp-relay
no-stun
allow-loopback-peers
lt-cred-mech
realm=probe.test
user={username}:{credential}
denied-peer-ip=0.0.0.0-255.255.255.255
denied-peer-ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
allowed-peer-ip=127.0.0.1
probe-peer-port={source_port}
relay-threads=1
pidfile=turn.pid
userdb=turn.sqlite
log-file=turn.log
simple-log
''');turn_config.chmod(0o600)
        output=(self.root/'turn-output').open('wb');turn=subprocess.Popen([TURN,'-c',str(turn_config)],cwd=self.root,stdout=output,stderr=output);output.close()
        router=bridge=None;workers=[];selector=selectors.DefaultSelector();receipts={};events=[];cleanup=[]
        try:
            deadline=time.monotonic()+8
            while True:
                self.assertIsNone(turn.poll(),'Private relay exited')
                if any(proto=='tcp' and int(address.rsplit(':',1)[1],16)==backend for proto,address in sockets(turn.pid)):break
                self.assertLess(time.monotonic(),deadline);time.sleep(.01)
            # Ordinary backend destinations are fixed, separate unused listeners;
            # the positive media path must use this lease's coturn route.
            with socket.socket() as ordinary:
                ordinary.bind(('127.0.0.1',0));ordinary.listen();ordinary_port=ordinary.getsockname()[1]
                router=Helper(ROUTER,dict(broker=True,brokerPath=str(self.root/'p'),lease=lease,backend=backend,http=ordinary_port,turn=ordinary_port,cert=str(self.cert),key=str(self.key),ca=str(self.cert)),self.root,'router')
                bridge=Helper(BRIDGE,dict(address='127.0.0.1',hostname='localhost',ca=str(self.cert),alpn=alpn,port=router.ready['port']),self.root,'bridge')
                observer_settings=config('observer',observer_port,source_port,nonce)
                observer_settings['relay']=dict(port=bridge.ready['port'],username=username,credential=credential)
                observer=Worker(observer_settings,self.root);workers.append(observer);selector.register(observer.process.stdout,selectors.EVENT_READ,'observer')
                description=None;candidates=[];gathered=False
                deadline=time.monotonic()+15
                while not gathered and time.monotonic()<deadline:
                    for key,_ in selector.select(max(0,deadline-time.monotonic())):
                        message=observer.read();events.append(('observer',message['type']));self.assertNotEqual(message['type'],'failure',message)
                        if message['type']=='description':description=message
                        elif message['type']=='candidate':candidates.append(message)
                        elif message['type']=='gathering' and message['state']==2:gathered=True
                self.assertTrue(gathered and description,(events,observer.error.read_text()))
                peers=[];allocated=[]
                owned=sockets(turn.pid)
                for message in candidates:
                    text=message['candidate']
                    if not text:continue
                    parts=text.split();self.assertEqual(parts[1:3],['1','UDP']);self.assertEqual(parts[4],'127.0.0.1')
                    peer_port=int(parts[5]);self.assertIn(parts[7],('host','relay'))
                    if parts[7]=='relay':
                        self.assertTrue(any(proto=='udp' and int(address.rsplit(':',1)[1],16)==peer_port for proto,address in owned),'Relay candidate is not an owned coturn socket')
                        allocated.append(peer_port)
                    else:self.assertEqual(peer_port,observer_port)
                    if not any(peer['port']==peer_port for peer in peers):peers.append(dict(address='127.0.0.1',port=peer_port))
                self.assertTrue(allocated,'No actual TURN allocation')
                source_settings=config('source',source_port,observer_port,nonce);source_settings['peers']=peers
                source=Worker(source_settings,self.root);workers.append(source);selector.register(source.process.stdout,selectors.EVENT_READ,'source')
                source.send(dict(schemaVersion=1,type='description',kind=description['kind'],sdp=description['sdp']))
                for message in candidates:source.send(dict(schemaVersion=1,type='candidate',index=message['index'],candidate=message['candidate']))
                deadline=time.monotonic()+15
                while len(receipts)<2 and time.monotonic()<deadline:
                    for key,_ in selector.select(max(0,deadline-time.monotonic())):
                        role=key.data;worker=observer if role=='observer' else source;other=source if role=='observer' else observer
                        message=worker.read();kind=message['type'];events.append((role,kind));self.assertNotEqual(kind,'failure',dict(role=role,event=message,events=events))
                        if kind=='description':other.send(dict(schemaVersion=1,type=kind,kind=message['kind'],sdp=message['sdp']))
                        elif kind=='candidate':other.send(dict(schemaVersion=1,type=kind,index=message['index'],candidate=message['candidate']))
                        elif kind=='received':
                            self.assertEqual(message['nonce'],nonce);self.assertTrue(message['dtlsConnected'] and message['dataVerified']);receipts[role]=message
                self.assertEqual(set(receipts),{'source','observer'},events)
                self.assertTrue(receipts['observer']['videoDecoded']);self.assertEqual(receipts['observer']['transport']['local']['type'],3)
                relay_port=receipts['observer']['transport']['local']['port'];self.assertIn(relay_port,allocated)
                self.assertEqual(receipts['source']['transport']['remote']['port'],relay_port)
                self.assertEqual(receipts['source']['transport']['local']['port'],source_port)
                for worker in workers:worker.assert_private_authority(parent_descriptors)
                stats=bridge.command(dict(op='inspect'));self.assertGreater(stats['verified'],0);self.assertEqual(stats['failed'],0)
                self.assertEqual(router.command(dict(op='revoke',lease=lease)),{'ok':True})
                # Keep the native clients alive across route revocation. Close
                # the dedicated relay as well, revoking every old allocation.
                stopping=time.monotonic();turn.terminate();turn.wait(timeout=5)
                self.assertEqual(turn.returncode,0,'Dedicated relay did not exit gracefully')
                print(json.dumps(dict(probeRelayGracefulStopSeconds=round(time.monotonic()-stopping,6))),flush=True)
                for worker in workers:worker.close()
                workers=[]
                ended=bridge.command(dict(op='stop'));self.assertEqual(ended['started'],ended['finished']);self.assertEqual(ended['failed'],0)
                for port in allocated+[source_port,observer_port]:
                    with socket.socket(type=socket.SOCK_DGRAM) as reusable:reusable.bind(('127.0.0.1',port))
                with socket.socket() as witness:
                    witness.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);witness.bind(('127.0.0.1',bridge.ready['port']))
        finally:
            primary=sys.exc_info()[0] is not None;selector.close()
            for worker in workers:
                try:worker.close(expected=1 if any(m.get('type')=='failure' for m in worker.messages) else 0)
                except BaseException as error:cleanup.append(error)
            for helper in (bridge,router):
                if helper:
                    try:helper.close()
                    except BaseException as error:cleanup.append(error)
            if turn.poll() is None:turn.terminate()
            try:turn.wait(timeout=5)
            except subprocess.TimeoutExpired:turn.kill();turn.wait(timeout=5)
            if cleanup and not primary:raise cleanup[0]
if __name__=='__main__':
    from native_test_identity import unprivileged_media_test
    identity=unprivileged_media_test()
    unittest.main()
