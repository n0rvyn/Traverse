"""Actual C++ owner/production worker through portal-issued libei wire."""
import ctypes
import os
import selectors
import signal
import sys
import time
import unittest

PROVIDER=sys.argv.pop();INPUT=sys.argv.pop()
import wayland_controller_test as owner
sys.argv.extend([INPUT,PROVIDER])
import eis_input_test as wire
from eis_wire_fixture import wire_peer

class NativeEis(owner.NativeController,wire.EisInput):
    def test_eis_state_pause_resume_and_owned_stop(self):
        with wire_peer(self,PROVIDER,wire.Records,wire.configuration()) as records,self.owner('eis-wire') as peer:
            state=self.grant(peer);self.assertEqual(state['desktop']['inputMethod'],'eis')
            for event in (dict(type='key',code='ShiftLeft',down=True),dict(type='button',button=0,down=True)):
                self.assertTrue(peer.call('input',event=event)['ok'])
            before=len(peer.history);records.command('pause')
            peer.state(lambda row:not row['inputReady'],after=before)
            before=len(peer.history);records.command('resume')
            peer.state(lambda row:row['inputReady'],after=before)
            self.assertTrue(peer.stop()['ok'])
            records.wait(lambda row:row.get('event')=='key' and row['code']==42 and not row['down'])
            records.wait(lambda row:row.get('event')=='button' and row['code']==272 and not row['down'])
    def test_eis_stop_with_unacknowledged_wire(self):
        with wire_peer(self,PROVIDER,wire.Records,wire.configuration()) as records,self.owner('eis-wire') as peer:
            self.grant(peer)
            self.assertTrue(peer.call('input',event=dict(type='key',code='KeyQ',down=True))['ok'])
            self.assertTrue(peer.call('input',event=dict(type='key',code='KeyQ',down=False))['ok'])
            records.command('hold')
            token=peer.send(dict(op='input',event=dict(type='key',code='KeyA',down=True)))
            deadline=time.monotonic()+5 # Test watchdog only.
            while not records.command('pending')['pending']:
                self.assertLess(time.monotonic(),deadline,'Input did not reach held wire')
            self.assertTrue(peer.stop()['ok'])
            row=peer.reply(token);self.assertTrue('error' in row or not row['reply']['ok'],row)
            records.command('dispatch')
    def test_cpp_owner_sigkill_releases_and_native_child_exits(self):
        library=ctypes.CDLL(None,use_errno=True);previous=ctypes.c_int()
        self.assertEqual(library.prctl(37,ctypes.byref(previous),0,0,0),0)
        self.assertEqual(library.prctl(36,1,0,0,0),0)
        pid=None;reaped=False
        try:
            with wire_peer(self,PROVIDER,wire.Records,wire.configuration()) as records,self.owner('eis-wire') as peer:
                state=self.grant(peer);pid=state['pid']
                for event in (dict(type='key',code='ShiftLeft',down=True),dict(type='button',button=0,down=True)):
                    self.assertTrue(peer.call('input',event=event)['ok'])
                records.wait(lambda row:row.get('event')=='button' and row['down'])
                descriptor=os.pidfd_open(pid)
                try:
                    peer.process.kill();self.assertEqual(peer.process.wait(timeout=5),-signal.SIGKILL)
                    with selectors.DefaultSelector() as selected:
                        selected.register(descriptor,selectors.EVENT_READ)
                        self.assertTrue(selected.select(8),'Native worker retained authority after C++ owner death')
                    child,status=os.waitpid(pid,0);reaped=True
                    self.assertEqual(child,pid);self.assertEqual(os.waitstatus_to_exitcode(status),0)
                finally:os.close(descriptor)
                records.wait(lambda row:row.get('event')=='key' and row['code']==42 and not row['down'])
                records.wait(lambda row:row.get('event')=='button' and row['code']==272 and not row['down'])
        finally:
            if pid and not reaped:
                try:os.kill(pid,signal.SIGTERM);os.waitpid(pid,0)
                except ProcessLookupError:pass
            self.assertEqual(library.prctl(36,previous.value,0,0,0),0)

def load_tests(loader,tests,pattern):
    return unittest.TestSuite(NativeEis(name) for name in NativeEis.__dict__ if name.startswith('test_'))

if __name__=='__main__':unittest.main()
