"""Real isolated native synthetic workers: admitted video/data and cleanup.

No desktop, public service, system trust or controller is used.
"""
import contextlib
import ctypes
import fcntl
import termios
import array
import hashlib
import json
import os
from pathlib import Path
import secrets
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from installed_turn import sockets
BINARY=str(Path(sys.argv.pop(1)).resolve())

def available_port(exclude=()):
    while True:
        with socket.socket(type=socket.SOCK_DGRAM) as reservation:
            reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
        if port not in exclude:return port

def config(role,port,remote,nonce=None):
    return dict(schemaVersion=1,peer=secrets.token_hex(16),nonce=nonce or secrets.token_hex(32),role=role,port=port,addresses=['127.0.0.1'],peers=[dict(address='127.0.0.1',port=remote)])

class Worker:
    def __init__(self,settings,root,capacity=None,environment=None,identity=None):
        self.config=settings;self.error=Path(root)/(settings['peer']+'.stderr');error=self.error.open('wb')
        inherited=os.environ if environment is None else environment
        env={key:value for key,value in inherited.items() if key not in ('DISPLAY','WAYLAND_DISPLAY','DBUS_SESSION_BUS_ADDRESS','XAUTHORITY')}
        self.process=subprocess.Popen([BINARY,'--supervisor-pid',str(os.getpid())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=error,bufsize=0,env=env,close_fds=True,**(identity or {}))
        error.close()
        if capacity:
            actual=fcntl.fcntl(self.process.stdout,fcntl.F_SETPIPE_SZ,capacity)
            # Fill the owned output pipe before the child receives config.
            # Variable-sized atomic records can otherwise leave a small gap
            # while already backpressured, so occupancy==capacity is unreliable.
            writer=os.open(f'/proc/{self.process.pid}/fd/1',os.O_WRONLY|os.O_NONBLOCK|os.O_CLOEXEC)
            try:
                assert os.write(writer,b'x'*actual)==actual
                try:os.write(writer,b'x')
                except BlockingIOError:pass
                else:raise AssertionError('Output witness did not reach EAGAIN')
            finally:os.close(writer)
        self.send(settings);self.messages=[]
    def send(self,value):self.process.stdin.write((json.dumps(value)+'\n').encode())
    def read(self):
        raw=self.process.stdout.readline()
        assert raw,('Early worker EOF',self.process.poll(),self.error.read_text())
        value=json.loads(raw);self.messages.append(value)
        assert value.get('schemaVersion')==1,value
        if value.get('type')!='failure':assert value['peer']==self.config['peer'] and value['port']==self.config['port'],value
        return value
    def assert_private_authority(self,parent_descriptors):
        """Private fixture evidence; installed service inheritance is a separate gate."""
        proc=Path('/proc')/str(self.process.pid)
        status=dict(line.split(':',1) for line in (proc/'status').read_text().splitlines() if ':' in line)
        assert set(map(int,status['Uid'].split()))=={os.geteuid()}
        assert set(map(int,status['Gid'].split()))=={os.getegid()}
        assert os.geteuid()!=0,'Fixture must exercise an unprivileged worker'
        for key in ('CapEff','CapPrm','CapInh','CapAmb'):assert int(status[key],16)==0,(key,status[key])
        environment=(proc/'environ').read_bytes().split(b'\0')
        assert not any(entry.split(b'=',1)[0] in (b'DISPLAY',b'WAYLAND_DISPLAY',b'DBUS_SESSION_BUS_ADDRESS',b'XAUTHORITY') for entry in environment)
        assert b'TRAVERSE_PARENT_SECRET=private-fixture-witness' not in environment
        assert parent_descriptors,'Parent descriptor positive control missing'
        inherited=set()
        for fd in (proc/'fd').iterdir():
            try:
                identity=fd.stat()
                inherited.add((identity.st_dev,identity.st_ino))
            except FileNotFoundError:continue
        assert not inherited.intersection(parent_descriptors),'Private worker inherited a parent descriptor'
        assert any(proto=='udp' and int(address.rsplit(':',1)[1],16)==self.config['port'] for proto,address in sockets(self.process.pid)),'Owned UDP socket positive control missing'
    def close(self,expected=0,request=True,remote_ended=False):
        if self.process.poll() is None and self.process.stdin:
            try:
                if request:self.send(dict(schemaVersion=1,type='stop'))
                self.process.stdin.close();self.process.stdin=None
            except BrokenPipeError:self.process.stdin=None
        try:
            self.process.wait(timeout=8)
            if remote_ended and self.process.returncode==1:
                # A revoked remote transport can report its natural ICE
                # failure before this fixture's explicit Stop reaches it.
                for raw in self.process.stdout:self.messages.append(json.loads(raw))
                failures=[row.get('reason') for row in self.messages if row.get('type')=='failure']
                assert failures and all(reason=='connectionFailed' for reason in failures),failures
                expected=1
            assert self.process.returncode==expected,(self.process.returncode,self.error.read_text())
            assert self.error.read_bytes()==b'',self.error.read_text()
        finally:
            if self.process.poll() is None:self.process.kill();self.process.wait(timeout=5)
            if self.process.stdin:self.process.stdin.close();self.process.stdin=None
            self.process.stdout.close()
        with socket.socket(type=socket.SOCK_DGRAM) as proof:proof.bind(('127.0.0.1',self.config['port']))
    def ready(self):
        selector=selectors.DefaultSelector();selector.register(self.process.stdout,selectors.EVENT_READ)
        try:
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                assert selector.select(max(0,deadline-time.monotonic())),'Worker not ready'
                value=self.read();assert value['type']!='failure',value
                if value['type']=='ready':return
            raise AssertionError('Worker startup watchdog')
        finally:selector.close()

class MediaTransportTests(unittest.TestCase):
    def setUp(self):self.temporary=tempfile.TemporaryDirectory(prefix='traverse-media-worker-')
    def tearDown(self):self.temporary.cleanup()
    def pair(self,port=None,hold=False):
        source_port=port or available_port();observer_port=available_port((source_port,));nonce=secrets.token_hex(32)
        workers=[Worker(config('source',source_port,observer_port,nonce),self.temporary.name),Worker(config('observer',observer_port,source_port,nonce),self.temporary.name)]
        selected=selectors.DefaultSelector();receipts={};events=[];forwarded={}
        for index,worker in enumerate(workers):selected.register(worker.process.stdout,selectors.EVENT_READ,index)
        try:
            deadline=time.monotonic()+15
            while len(receipts)<2 and time.monotonic()<deadline:
                for key,_ in selected.select(max(0,deadline-time.monotonic())):
                    index=key.data;value=workers[index].read();kind=value['type'];events.append((index,kind));self.assertNotEqual(kind,'failure',dict(worker=index,event=value,events=events,lastIncoming=forwarded.get(index)))
                    if kind=='description':
                        self.assertEqual(value['kind'],'answer' if index==0 else 'offer')
                        forwarded[1-index]=dict(type=kind,kind=value['kind'],sdpShape=[line for line in value['sdp'].splitlines() if line.startswith(('m=','c=','a=recvonly','a=sendonly','a=sendrecv','a=rtcp'))]);workers[1-index].send(dict(schemaVersion=1,type=kind,kind=value['kind'],sdp=value['sdp']))
                    elif kind=='candidate':
                        forwarded[1-index]=dict(type=kind,index=value['index'],candidate=value['candidate']);workers[1-index].send(dict(schemaVersion=1,type=kind,index=value['index'],candidate=value['candidate']))
                    elif kind=='received':
                        self.assertEqual(value['nonce'],nonce);self.assertTrue(value['dataVerified']);self.assertTrue(value['dtlsConnected']);self.assertEqual(value['videoDecoded'],index==1)
                        self.assertEqual(value['transport']['local']['port'],workers[index].config['port'])
                        self.assertEqual(value['transport']['remote']['port'],workers[1-index].config['port'])
                        for side in ('local','remote'):self.assertEqual(value['transport'][side]['protocol'],'udp')
                        receipts[index]=value
            self.assertEqual(set(receipts),{0,1},(events,[w.error.read_text() for w in workers]))
            if hold:
                print(json.dumps(dict(stage='streaming',pids=[worker.process.pid for worker in workers],ports=[worker.config['port'] for worker in workers])),flush=True)
                while True:signal.pause()
            return source_port
        finally:
            selected.close()
            primary=sys.exc_info()[0] is not None;cleanup_errors=[]
            for worker in workers:
                expected=1 if any(message.get('type')=='failure' for message in worker.messages) else 0
                try:worker.close(expected=expected)
                except BaseException as error:cleanup_errors.append(error)
            if cleanup_errors and not primary:raise cleanup_errors[0]
    def test_real_video_data_then_exact_port_reuse(self):
        port=self.pair();self.pair(port)
    def test_stop_during_startup_and_negotiation(self):
        port=available_port();remote=available_port((port,))
        for role in ('observer','source','observer'):
            worker=Worker(config(role,port,remote),self.temporary.name)
            try:worker.ready()
            finally:worker.close()
    def test_non_numeric_foreign_and_input_commands_rejected(self):
        for candidate in ['candidate:x 1 UDP 1 foreign.local 33333 typ host','candidate:x 1 UDP 1 127.0.0.1 33333 typ host','candidate:x 1 TCP 1 127.0.0.1 33333 typ host tcptype active']:
            port=available_port();remote=available_port((port,33333));worker=Worker(config('source',port,remote),self.temporary.name)
            worker.ready();worker.send(dict(schemaVersion=1,type='candidate',index=0,candidate=candidate));worker.close(expected=1,request=False)
        port=available_port();remote=available_port((port,));worker=Worker(config('source',port,remote),self.temporary.name)
        worker.ready();worker.send(dict(schemaVersion=1,type='input',key='KeyA',down=True));worker.close(expected=1,request=False)
    def test_owner_death_reaps_streaming_workers_and_reuses_port(self):
        self.assertEqual(ctypes.CDLL(None,use_errno=True).prctl(36,1,0,0,0),0)
        port=available_port();owner=subprocess.Popen([sys.executable,__file__,BINARY,'--owner-child',str(port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        pids=[];handles=[];reaped=set()
        try:
            selector=selectors.DefaultSelector();selector.register(owner.stdout,selectors.EVENT_READ)
            try:self.assertTrue(selector.select(15),'Owner never reached streaming')
            finally:selector.close()
            message=json.loads(owner.stdout.readline());self.assertEqual(message['stage'],'streaming');pids=message['pids']
            for child in pids:handles.append(os.pidfd_open(child))
            for bound in message['ports']:
                with socket.socket(type=socket.SOCK_DGRAM) as witness:
                    with self.assertRaises(OSError):witness.bind(('127.0.0.1',bound))
            owner.kill();owner.wait(timeout=5)
            import select
            for child,handle in zip(pids,handles):
                self.assertTrue(select.select([handle],[],[],8)[0],'Worker survived owner loss')
                found,status=os.waitpid(child,0);reaped.add(found);self.assertEqual(os.waitstatus_to_exitcode(status),0)
            for bound in message['ports']:
                with socket.socket(type=socket.SOCK_DGRAM) as witness:witness.bind(('127.0.0.1',bound))
            self.pair(port)
        finally:
            if owner.poll() is None:owner.kill();owner.wait(timeout=5)
            for child in pids:
                if child in reaped:continue
                try:os.kill(child,signal.SIGKILL);os.waitpid(child,0)
                except (ProcessLookupError,ChildProcessError):pass
            for handle in handles:os.close(handle)
            owner.stdout.close();owner.stderr.close()
    def test_unread_owner_output_does_not_block_stop(self):
        port=available_port();remote=available_port((port,));settings=config('observer',port,remote)
        worker=Worker(settings,self.temporary.name,capacity=4096)
        try:
            deadline=time.monotonic()+8;bound=False
            while time.monotonic()<deadline:
                self.assertIsNone(worker.process.poll(),worker.error.read_text())
                bound=any(proto=='udp' and int(address.rsplit(':',1)[1],16)==port for proto,address in sockets(worker.process.pid))
                if bound:break
                time.sleep(.005)
            self.assertTrue(bound,'Worker could not gather while owner output was full')
            count=array.array('i',[0]);fcntl.ioctl(worker.process.stdout,termios.FIONREAD,count,True)
            self.assertEqual(count[0],4096)
        finally:worker.close()
    def test_invalid_configuration_cannot_start_transport(self):
        base=config('source',available_port(),available_port())
        for delta in [dict(role='controller'),dict(nonce='a'),dict(addresses=['localhost']),dict(port=0),dict(captureSocket='/tmp/desktop'),dict(peers=[dict(address='127.0.0.1',port=0)])]:
            process=subprocess.run([BINARY],input=(json.dumps(dict(base,**delta))+'\n').encode(),capture_output=True,timeout=8)
            self.assertEqual(process.returncode,1);self.assertEqual(process.stderr,b'');self.assertNotIn(b'"ready"',process.stdout)
if __name__=='__main__':
    from native_test_identity import unprivileged_media_test
    identity=unprivileged_media_test()
    if len(sys.argv)>1 and sys.argv[1]=='--owner-child':
        case=MediaTransportTests();case.setUp()
        try:case.pair(int(sys.argv[2]),hold=True)
        finally:case.tearDown()
    else:unittest.main()

