"""Native inherited guardian IPC through actual libei/libeis traffic."""
import contextlib
import os
import json
import signal
import selectors
import subprocess
import ctypes
import time
import sys
import unittest

if len(sys.argv)>2 and sys.argv[1]=='--controller-helper':
    from guardian_controller import Controller,GuardianActions
    signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
    class Helper(GuardianActions,unittest.TestCase):pass
    actions=Helper();peer=Controller(sys.argv[2],dict(os.environ));keeper=None
    try:
        peer.started();actions.grant(peer)
        actions.event(peer,type='key',code='ShiftLeft',down=True)
        actions.event(peer,type='button',button=0,down=True)
        if len(sys.argv)>3:
            keepalive=int(sys.argv[3])
            keeper=subprocess.Popen([sys.executable,'-c','import os,sys;os.read(int(sys.argv[1]),1)',str(keepalive)],
                pass_fds=(keepalive,peer.socket.fileno()),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        print(json.dumps({'guardianPid':peer.process.pid,'keeperPid':keeper.pid if keeper else None}),flush=True)
        sys.stdin.readline()
    finally:
        peer.close()
        if keeper:keeper.wait(timeout=5)
    raise SystemExit(0)

PROVIDER=sys.argv.pop();INPUT=sys.argv.pop();GUARDIAN=sys.argv.pop()
sys.argv.extend([INPUT,PROVIDER])
import eis_input_test as wire
from eis_wire_fixture import wire_peer
from guardian_controller import Controller,GuardianActions


class GuardianEis(GuardianActions,wire.EisInput):
    @contextlib.contextmanager
    def controller(self,expected_exit=0,server_exit=0,**options):
        with wire_peer(self,PROVIDER,wire.Records,wire.configuration(),expected_exit=server_exit) as records:
            peer=Controller(GUARDIAN,dict(os.environ,DBUS_SESSION_BUS_ADDRESS=self.address),**options)
            try:
                peer.started();state=self.grant(peer);self.assertEqual(state['inputMethod'],'eis')
                yield peer,records
                if peer.process.poll() is None and not peer.stop_sent:self.assertTrue(peer.call('stop')['ok'])
                self.assertEqual(peer.process.wait(timeout=8),expected_exit)
            finally:peer.close()

    def test_guardian_eis_state_events_without_snapshot_polling(self):
        with wire_peer(self,PROVIDER,wire.Records,wire.configuration()) as records:
            peer=Controller(GUARDIAN,dict(os.environ,DBUS_SESSION_BUS_ADDRESS=self.address))
            try:
                peer.started()
                peer.wait_event('state',lambda row:row['snapshot']['state']=='capabilities-ready')
                self.assertTrue(peer.call('request',request=dict(devices=3,sourceTypes=1,cursorMode=2,multiple=False,parentWindow=''))['ok'])
                peer.wait_event('state',lambda row:row['snapshot']['granted'])
                self.assertTrue(peer.call('select-stream',index=0)['ok'])
                ready=peer.wait_event('state',lambda row:row['snapshot']['inputReady'])['snapshot']
                self.assertEqual(ready['inputMethod'],'eis')
                records.command('pause')
                paused=peer.wait_event('state',lambda row:not row['snapshot']['inputReady'])['snapshot']
                self.assertTrue(paused['granted'])
                records.command('resume')
                self.assertTrue(peer.wait_event('state',lambda row:row['snapshot']['inputReady'])['snapshot']['granted'])
                self.assertTrue(peer.call('stop')['ok']);self.assertEqual(peer.process.wait(timeout=8),0)
            finally:peer.close()

    def test_guardian_eis_physical_input_and_owned_release(self):
        with self.controller() as (peer,records):
            for down in (True,False):self.event(peer,type='key',code='KeyA',down=down)
            self.event(peer,type='key',code='KeyQ',down=True)
            self.event(peer,type='key',code='KeyQ',down=True)
            self.event(peer,type='key',code='KeyQ',down=False)
            self.event(peer,type='key',code='KeyQ',down=False)
            self.event(peer,type='move',x=.5,y=.5)
            for button in (0,1,2):
                for down in (True,False):self.event(peer,type='button',button=button,down=down)
            self.event(peer,type='wheel',axis='y',direction=1)
            self.event(peer,type='wheel',axis='x',direction=-1)
            records.wait(lambda row:row.get('event')=='scroll' and row['x']==-120)
            rows=records.snapshot()
            self.assertEqual([(r['code'],r['down']) for r in rows if r.get('event')=='key'],[(30,True),(30,False),(16,True),(16,False)])
            self.assertEqual([(r['code'],r['down']) for r in rows if r.get('event')=='button'],[(272,True),(272,False),(274,True),(274,False),(273,True),(273,False)])
            self.assertIn(dict(event='absolute',x=419.75,y=379.75,device='controlled-0'),rows)
            self.assertEqual([(r['x'],r['y']) for r in rows if r.get('event')=='scroll'],[(0,120),(-120,0)])
            self.event(peer,type='key',code='ShiftLeft',down=True);self.event(peer,type='button',button=0,down=True)
            self.assertTrue(peer.call('release')['ok'])
            records.wait(lambda row:row.get('event')=='key' and row['code']==42 and not row['down'])
            records.wait(lambda row:row.get('event')=='button' and row['code']==272 and not row['down'])

    def test_guardian_eis_stop_releases_held_input(self):
        with self.controller() as (peer,records):
            self.event(peer,type='key',code='ShiftLeft',down=True);self.event(peer,type='button',button=0,down=True)
            self.assertTrue(peer.call('stop')['ok'])
            records.wait(lambda row:row.get('event')=='key' and row['code']==42 and not row['down'])
            records.wait(lambda row:row.get('event')=='button' and row['code']==272 and not row['down'])

    def test_guardian_eis_eof_releases_held_input(self):
        with self.controller() as (peer,records):
            self.event(peer,type='key',code='ShiftLeft',down=True);self.event(peer,type='button',button=0,down=True)
            peer.socket.shutdown(1)
            self.assertEqual(peer.process.wait(timeout=8),0)
            records.wait(lambda row:row.get('event')=='key' and row['code']==42 and not row['down'])
            records.wait(lambda row:row.get('event')=='button' and row['code']==272 and not row['down'])

    def test_guardian_eis_killed_peer_preserves_terminal_error(self):
        with self.controller(expected_exit=1,server_exit=-signal.SIGKILL) as (peer,records):
            self.event(peer,type='key',code='ShiftLeft',down=True)
            records.child.kill();self.assertEqual(records.child.wait(timeout=5),-signal.SIGKILL)
            terminal=peer.terminal()['snapshot']
            self.assertFalse(terminal['granted']);self.assertTrue(terminal['error'],terminal)

    def test_guardian_eis_stop_without_protocol_ack(self):
        with self.controller() as (peer,records):
            self.event(peer,type='key',code='KeyQ',down=True);self.event(peer,type='key',code='KeyQ',down=False)
            records.command('hold')
            self.assertFalse(records.command('pending')['pending'])
            pending=peer.send('input',event=dict(type='key',code='KeyA',down=True))
            end=time.monotonic()+5
            while not records.command('pending')['pending']:
                self.assertLess(time.monotonic(),end,'Input never reached the held native wire')
            self.assertTrue(peer.call('stop')['ok'])
            self.assertFalse(peer.receive(pending)['ok'])
            self.assertEqual(peer.process.wait(timeout=8),0)
            records.command('dispatch')

    def test_guardian_eis_new_press_after_pause_resume(self):
        with self.controller() as (peer,records):
            self.event(peer,type='key',code='ShiftLeft',down=True)
            records.command('pause');self.state(peer,lambda row:not row['inputReady'])
            records.command('resume');self.state(peer,lambda row:row['inputReady'])
            records.wait(lambda row:row.get('event')=='key' and row['code']==42 and not row['down'])
            self.event(peer,type='key',code='ShiftLeft',down=False)
            self.event(peer,type='key',code='ShiftLeft',down=True)
            records.wait(lambda row:sum(r.get('event')=='key' and r['code']==42 and r['down'] for r in records.snapshot())==2)
            self.event(peer,type='key',code='ShiftLeft',down=False)

    def test_guardian_eis_sigterm_releases_held_input(self):
        with self.controller() as (peer,records):
            self.event(peer,type='key',code='ShiftLeft',down=True);self.event(peer,type='button',button=0,down=True)
            peer.process.terminate();self.assertEqual(peer.process.wait(timeout=8),0)
            records.wait(lambda row:row.get('event')=='key' and row['code']==42 and not row['down'])
            records.wait(lambda row:row.get('event')=='button' and row['code']==272 and not row['down'])

    def test_guardian_eis_controller_sigkill_releases_and_revokes(self):
        library=ctypes.CDLL(None,use_errno=True);previous=ctypes.c_int()
        self.assertEqual(library.prctl(37,ctypes.byref(previous),0,0,0),0)
        self.assertEqual(library.prctl(36,1,0,0,0),0) # This test process adopts its orphaned worker.
        helper=None;guardian=None;pidfd=None;reaped=False;keeper=None;keeper_fd=None
        keep_read,keep_write=os.pipe()
        try:
            with wire_peer(self,PROVIDER,wire.Records,wire.configuration()) as records:
                with self.mutex:before=set(self.peers)
                helper=subprocess.Popen([sys.executable,__file__,'--controller-helper',GUARDIAN,str(keep_read)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,
                    env=dict(os.environ,DBUS_SESSION_BUS_ADDRESS=self.address),pass_fds=(keep_read,))
                os.close(keep_read);keep_read=-1
                selector=selectors.DefaultSelector();selector.register(helper.stdout,selectors.EVENT_READ)
                try:self.assertTrue(selector.select(8),'Owned controller did not finish actual held input')
                finally:selector.close()
                line=helper.stdout.readline()
                self.assertTrue(line,helper.stderr.read() if helper.poll() is not None else 'Controller stdout ended')
                identity=json.loads(line);guardian=identity['guardianPid'];keeper=identity['keeperPid']
                pidfd=os.pidfd_open(guardian);keeper_fd=os.pidfd_open(keeper)
                with self.mutex:senders=set(self.peers)-before
                self.assertEqual(len(senders),1)
                sender=senders.pop()
                records.wait(lambda row:row.get('event')=='button' and row['code']==272 and row['down'])
                helper.kill();self.assertEqual(helper.wait(timeout=5),-signal.SIGKILL)
                selector=selectors.DefaultSelector();selector.register(pidfd,selectors.EVENT_READ)
                try:self.assertTrue(selector.select(8),'Guardian retained control after its owner died')
                finally:selector.close()
                pid,status=os.waitpid(guardian,0);reaped=True
                self.assertEqual(pid,guardian);self.assertEqual(os.waitstatus_to_exitcode(status),0)
                selector=selectors.DefaultSelector();selector.register(keeper_fd,selectors.EVENT_READ)
                try:self.assertFalse(selector.select(0),'The deliberate socket holder exited before the owner-death check')
                finally:selector.close()
                records.wait(lambda row:row.get('event')=='key' and row['code']==42 and not row['down'])
                records.wait(lambda row:row.get('event')=='button' and row['code']==272 and not row['down'])
                self.assertTrue(self.closed_events[sender].wait(5),'Actual portal owner remained connected')
        finally:
            if keep_read>=0:os.close(keep_read)
            os.close(keep_write)
            if helper:
                if helper.poll() is None:helper.terminate();helper.wait(timeout=8)
                for stream in (helper.stdin,helper.stdout,helper.stderr):stream.close()
            if guardian is not None and not reaped:
                try:
                    if pidfd is not None:signal.pidfd_send_signal(pidfd,signal.SIGKILL)
                    os.waitpid(guardian,0)
                except (ProcessLookupError,ChildProcessError):pass
            if pidfd is not None:os.close(pidfd)
            if keeper is not None:
                try:os.waitpid(keeper,0)
                except ChildProcessError:pass
            if keeper_fd is not None:os.close(keeper_fd)
            self.assertEqual(library.prctl(36,previous.value,0,0,0),0)


if __name__=='__main__':
    suite=unittest.TestSuite(GuardianEis(name) for name in sorted(GuardianEis.__dict__) if name.startswith('test_guardian_'))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
