"""C++ owner -> production guardian -> actual private D-Bus completions.

Peer corruption uses synthetic workers; those cases make no desktop claims.
All timeouts below are test watchdogs, never product policy.
"""
import contextlib
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading
import unittest

WORKER=sys.argv.pop()
OWNER=sys.argv.pop()
import portal_session_test as portal

from native_controller_peer import Peer as NativePeer
class Peer(NativePeer):
    def __init__(self,path,environment,pass_fds=()):
        super().__init__(OWNER,path,environment,pass_fds=pass_fds)

class NativeController(portal.PortalCapabilities):
    @contextlib.contextmanager
    def owner(self,mode='valid',worker=WORKER):
        with self.mutex:type(self).mode=mode
        peer=Peer(worker,dict(os.environ,DBUS_SESSION_BUS_ADDRESS=self.address))
        try:yield peer
        finally:peer.close()
    def setUp(self):
        super().setUp()
        for items in (self.input_calls,self.input_held):
            while not items.empty():items.get_nowait()
    def ready(self,peer):
        return peer.state(lambda row:row['desktop'] and row['desktop']['state']=='capabilities-ready')
    def grant(self,peer):
        self.ready(peer)
        self.assertTrue(peer.call('request',request=dict(devices=3,sourceTypes=1,cursorMode=2,multiple=False,parentWindow=''))['ok'])
        peer.state(lambda row:row['desktop'] and row['desktop']['granted'])
        self.assertTrue(peer.call('select-stream',index=0)['ok'])
        return peer.state(lambda row:row['inputReady'])
    def test_constructor_thread_exit_and_exact_reap(self):
        with self.owner() as peer:
            initial=self.ready(peer)
            self.assertEqual(int(Path('/proc/'+str(initial['pid'])+'/stat').read_text().split()[3]),peer.process.pid)
            self.assertTrue(peer.call('snapshot')['ok'])
            self.assertTrue(peer.stop()['ok'])
            terminal=peer.state(lambda row:row['terminal'])
            self.assertEqual(terminal['exit'],0);self.assertFalse(terminal['inputReady'])
            self.assertFalse(Path('/proc/'+str(initial['pid'])).exists())
    def test_completion_waits_for_actual_bus_reply_and_stop_releases(self):
        with self.owner() as peer:
            self.grant(peer)
            with self.mutex:type(self).mode='input-hold'
            token=peer.send(dict(op='input',event=dict(type='key',code='ShiftLeft',down=True)))
            sender,method,args=self.input_calls.get(timeout=5)
            held=self.input_held.get(timeout=5)
            # A later snapshot orders admission while the native input ACK is held.
            self.assertTrue(peer.call('snapshot')['ok'])
            self.assertFalse(any(row.get('token')==token for row in peer.history))
            portal.GLib.idle_add(lambda:(held.return_value(portal.GLib.Variant('()',())),False)[1])
            self.assertTrue(peer.reply(token)['reply']['ok'])
            self.assertTrue(peer.stop()['ok'])
            self.assertTrue(self.closed_events[sender].wait(5))
            self.assertEqual(self.input_calls.get(timeout=5)[2][2:],(42,0))
    def test_stop_cancels_pending_native_input_without_ack(self):
        with self.owner() as peer:
            self.grant(peer)
            with self.mutex:type(self).mode='input-hold'
            token=peer.send(dict(op='input',event=dict(type='key',code='KeyA',down=True)))
            self.input_calls.get(timeout=5);self.input_held.get(timeout=5)
            self.assertTrue(peer.stop()['ok'])
            result=peer.reply(token)
            self.assertTrue('error' in result or result['reply']['ok'] is False,result)
    def test_stop_during_permission_and_capability_wait(self):
        for mode in ('never-reply','hold-Start'):
            with self.subTest(mode=mode),self.owner(mode) as peer:
                if mode=='hold-Start':
                    self.ready(peer)
                    self.assertTrue(peer.call('request',request=dict(devices=3,sourceTypes=1,cursorMode=2,multiple=False,parentWindow=''))['ok'])
                    while self.grant_calls.get(timeout=5)[1]!='Start':pass
                else:self.calls.get(timeout=5)
                self.assertTrue(peer.stop()['ok'])
    def test_stop_cancels_pending_capture_connection(self):
        with self.owner('connections-valid') as peer,tempfile.TemporaryDirectory() as directory:
            self.grant(peer)
            # First capture uses the original grant-issued connection. Cancel
            # its unanswered protocol before holding a fresh portal method.
            first=peer.send(dict(op='capture-start',runtimeDirectory=directory,
                outputCaps='video/x-raw,format=I420,framerate=30/1'))
            peer.state(lambda row:row['desktop'] and row['desktop'].get('capture') is not None)
            self.assertTrue(peer.call('capture-stop')['ok'])
            self.assertFalse(peer.reply(first)['reply']['ok'])
            while not self.grant_calls.empty():self.grant_calls.get_nowait()
            with self.mutex:type(self).mode='hold-OpenPipeWireRemote'
            token=peer.send(dict(op='capture-start',runtimeDirectory=directory,
                outputCaps='video/x-raw,format=I420,framerate=30/1'))
            sender,method=self.grant_calls.get(timeout=5)
            self.assertEqual(method,'OpenPipeWireRemote')
            with self.mutex:event=self.held_events.setdefault((sender,method),threading.Event())
            self.assertTrue(event.wait(5))
            self.assertTrue(peer.stop()['ok'])
            row=peer.reply(token);self.assertTrue('error' in row or not row['reply']['ok'],row)
            self.assertTrue(self.closed_events[sender].wait(5))
    def test_native_failure_and_denial_are_preserved(self):
        with self.owner('deny') as peer:
            self.ready(peer)
            invalid=peer.call('unknown-operation');self.assertFalse(invalid['ok'])
            self.assertTrue(peer.call('request',request=dict(devices=3,sourceTypes=1,cursorMode=2,multiple=False,parentWindow=''))['ok'])
            final=peer.state(lambda row:row['terminal'])
            self.assertEqual(final['exit'],1);self.assertFalse(final['inputReady'])
            self.assertTrue(final['desktop']['error']);self.assertTrue(final['error'])
    def test_unexpected_child_exit_fences_cached_authority(self):
        with self.owner() as peer:
            granted=self.grant(peer);os.kill(granted['pid'],signal.SIGKILL)
            final=peer.state(lambda row:row['terminal'])
            self.assertEqual(final['exit'],-signal.SIGKILL)
            self.assertFalse(final['accepting']);self.assertFalse(final['inputReady'])
            self.assertFalse(peer.wait(lambda row:row.get('event')=='stopped')['ok'])
    def test_spawn_failure_and_bad_protocol(self):
        with self.owner(worker='/nonexistent/traverse-worker') as peer:
            result=peer.wait(lambda row:row.get('event')=='stopped')
            self.assertFalse(result['ok']);self.assertEqual(result['failure'],1)
        for payload in ('not-json','{"schemaVersion":2,"id":null}',
                        '{"schemaVersion":1,"id":null,"event":"started","ok":true,"pid":1}'):
            with self.subTest(payload=payload),tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'worker'
                path.write_text('#!/usr/bin/python3\nimport os,socket\ns=socket.socket(fileno=0)\ns.sendall('+repr((payload+'\n').encode())+')\nwhile s.recv(4096):pass\n')
                path.chmod(0o755)
                with self.owner(worker=str(path)) as peer:
                    result=peer.wait(lambda row:row.get('event')=='stopped')
                    self.assertFalse(result['ok']);self.assertEqual(result['failure'],2)
    def test_partial_write_stop_settles_unsent_future(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);worker=root/'worker';gate=root/'read';observed=root/'observed'
            # The independent peer deliberately does not read until Stop has
            # fenced admission. Payload size is fixture backpressure, no cap.
            worker.write_text('#!/usr/bin/python3\nimport os,socket,json,time,select\n'
                's=socket.socket(fileno=0)\n'
                's.sendall((json.dumps(dict(schemaVersion=1,id=None,event="started",ok=True,pid=os.getpid()))+"\\n").encode())\n'
                'select.select([s],[],[])\n'
                'state=dict(state="probing",granted=False,inputReady=False,stopping=False,error="fixture-read-blocked",inputMethod="undetermined",streams=[])\n'
                's.sendall((json.dumps(dict(schemaVersion=1,id=None,event="state",snapshot=state))+"\\n").encode())\n'
                'while not os.path.exists('+repr(str(gate))+'):time.sleep(.001)\n'
                'data=b""\nwhile True:\n chunk=s.recv(8192)\n if not chunk:break\n data+=chunk\n'
                'open('+repr(str(observed))+',"w").write(json.dumps(dict(bytes=len(data),complete=data.endswith(b"\\n"))))\n'
                'state=dict(state="stopped",granted=False,inputReady=False,stopping=True,error="",inputMethod="undetermined",streams=[])\n'
                's.sendall((json.dumps(dict(schemaVersion=1,id=None,event="ended",snapshot=state))+"\\n").encode())\n')
            worker.chmod(0o755)
            with self.owner(worker=str(worker)) as peer:
                peer.state(lambda row:row['accepting'])
                token=peer.send(dict(op='snapshot',padding='x'*(2*1024*1024)))
                peer.state(lambda row:row['desktop'] and row['desktop']['error']=='fixture-read-blocked')
                peer.write(dict(action='stop'))
                self.assertFalse(peer.wait(lambda row:row.get('event')=='stop-fenced')['accepting'])
                gate.touch()
                self.assertEqual(peer.reply(token)['failure'],0)
                self.assertTrue(peer.wait(lambda row:row.get('event')=='stopped')['ok'])
                received=json.loads(observed.read_text())
                self.assertGreater(received['bytes'],0)
                self.assertFalse(received['complete']);self.assertLess(received['bytes'],2*1024*1024)
    def test_corrupt_authority_state_never_becomes_usable(self):
        for change in (dict(state='probing'),dict(inputMethod='unknown'),dict(selectedStream=None)):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as directory:
                state=dict(state='granted',granted=True,inputReady=True,stopping=False,
                    error='',inputMethod='portal-dbus',streams=[dict(node=41)],selectedStream=0)
                state.update(change)
                worker=Path(directory)/'worker'
                worker.write_text('#!/usr/bin/python3\nimport os,socket,json\n'
                    's=socket.socket(fileno=0)\n'
                    'rows=[dict(schemaVersion=1,id=None,event="started",ok=True,pid=os.getpid()),'
                    'dict(schemaVersion=1,id=None,event="state",snapshot='+repr(state)+')]\n'
                    's.sendall(("\\n".join(json.dumps(row) for row in rows)+"\\n").encode())\n'
                    'while s.recv(4096):pass\n')
                worker.chmod(0o755)
                with self.owner(worker=str(worker)) as peer:
                    row=peer.wait(lambda row:row.get('event')=='stopped')
                    self.assertFalse(row['ok']);self.assertEqual(row['failure'],2)
                    self.assertFalse(any(row.get('inputReady') for row in peer.history))
    def test_unrelated_inherited_descriptor_is_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);worker=root/'worker';secret=root/'unrelated';secret.write_text('fixture')
            with secret.open() as descriptor:
                target=os.fstat(descriptor.fileno())
                worker.write_text('#!/usr/bin/python3\nimport os,socket,json\n'
                    's=socket.socket(fileno=0)\n'
                    'def emit(row):\n row.update(schemaVersion=1)\n s.sendall((json.dumps(row)+"\\n").encode())\n'
                    'emit(dict(id=None,event="started",ok=True,pid=os.getpid()))\n'
                    'row=json.loads(s.makefile().readline())\nfound=False\n'
                    'for name in os.listdir("/proc/self/fd"):\n'
                    ' try:\n  stat=os.fstat(int(name))\n'
                    ' except OSError:continue\n'
                    ' if (stat.st_dev,stat.st_ino)=='+repr((target.st_dev,target.st_ino))+':found=True\n'
                    'emit(dict(id=row["id"],ok=True,leaked=found))\n'
                    'while s.recv(8192):pass\n')
                worker.chmod(0o755)
                peer=Peer(str(worker),os.environ,pass_fds=(descriptor.fileno(),))
                try:
                    # Positive control: owner really inherited the open file.
                    inherited=Path('/proc/'+str(peer.process.pid)+'/fd/'+str(descriptor.fileno()))
                    self.assertEqual(inherited.stat().st_ino,target.st_ino)
                    self.assertFalse(peer.call('snapshot')['leaked'])
                finally:peer.close()

def load_tests(loader,tests,pattern):
    # Reuse the actual bus fixture, not its independent portal-probe test cases.
    return unittest.TestSuite(NativeController(name) for name in NativeController.__dict__ if name.startswith('test_'))

if __name__=='__main__':unittest.main()
