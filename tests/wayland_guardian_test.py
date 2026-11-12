"""Actual inherited controller socket -> native guardian -> private portal.

Protocol/lifecycle checks only. Actual compositor seat release is separate.
"""
import contextlib
import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

GUARDIAN=sys.argv.pop()
import portal_session_test as portal


from guardian_controller import Controller,GuardianActions


class Guardian(GuardianActions,portal.PortalCapabilities):
    def setUp(self):
        super().setUp()
        for items in (self.input_calls,self.input_held):
            while not items.empty():items.get_nowait()

    @contextlib.contextmanager
    def controller(self,mode='valid',expected_exit=0,**options):
        with self.mutex:type(self).mode=mode
        peer=Controller(GUARDIAN,dict(os.environ,DBUS_SESSION_BUS_ADDRESS=self.address),**options)
        try:
            peer.started();yield peer
            if peer.process.poll() is None and not peer.stop_sent:self.assertTrue(peer.call('stop')['ok'])
            self.assertEqual(peer.process.wait(timeout=8),expected_exit)
        finally:peer.close()

    def test_guardian_inherited_parent_and_foreign_parent(self):
        with self.controller() as peer:
            self.state(peer,lambda row:row['state']=='capabilities-ready')
        bad=Controller(GUARDIAN,dict(os.environ,DBUS_SESSION_BUS_ADDRESS=self.address),parent=os.getpid()+1000000)
        try:
            self.assertEqual(bad.reader.readline(),'')
            self.assertEqual(bad.process.wait(timeout=5),1)
            bad.log.seek(0);self.assertIn('exclusive inherited controller',bad.log.read())
        finally:bad.close()
        bad=subprocess.run([GUARDIAN,str(os.getpid())],stdin=subprocess.DEVNULL,
            capture_output=True,text=True,timeout=5,env=dict(os.environ,DBUS_SESSION_BUS_ADDRESS=self.address))
        self.assertEqual(bad.returncode,1);self.assertIn('exclusive inherited controller',bad.stderr)

    def test_guardian_request_fields_do_not_wrap_or_add_touch(self):
        with self.controller() as peer:
            self.state(peer,lambda row:row['state']=='capabilities-ready')
            for devices in (-4294967293,4294967299,4):
                result=peer.call('request',request=dict(devices=devices,sourceTypes=1,cursorMode=2,multiple=False,parentWindow=''))
                self.assertFalse(result['ok'])
                self.assertEqual(peer.call('snapshot')['snapshot']['state'],'capabilities-ready')
            self.grant(peer)

    def test_guardian_permission_denial_reports_terminal_snapshot(self):
        with self.controller(mode='deny',expected_exit=1) as peer:
            self.state(peer,lambda row:row['state']=='capabilities-ready')
            self.assertTrue(peer.call('request',request=dict(devices=3,sourceTypes=1,cursorMode=2,multiple=False,parentWindow=''))['ok'])
            terminal=peer.terminal()['snapshot']
            self.assertFalse(terminal['granted']);self.assertTrue(terminal['error'])
            self.assertEqual(terminal['state'],'not-granted')

    def test_guardian_native_state_without_snapshot_requests(self):
        with self.controller() as peer:
            ready=peer.wait_event('state',lambda row:row['snapshot']['state']=='capabilities-ready')
            self.assertFalse(ready['snapshot']['granted'])
            self.assertTrue(peer.call('request',request=dict(devices=3,sourceTypes=1,cursorMode=2,multiple=False,parentWindow=''))['ok'])
            granted=peer.wait_event('state',lambda row:row['snapshot']['granted'])['snapshot']
            self.assertFalse(granted['inputReady']);self.assertEqual(granted['selectedStream'],None)
            self.assertTrue(peer.call('select-stream',index=0)['ok'])
            selected=peer.wait_event('state',lambda row:row['snapshot']['inputReady'])['snapshot']
            self.assertEqual(selected['inputMethod'],'portal-dbus');self.assertEqual(selected['selectedStream'],0)
            self.event(peer,type='move',x=.5,y=.5)
            sender,method,args=self.input_calls.get(timeout=2)
            self.connection.emit_signal(sender,args[0],portal.SESSION,'Closed',portal.GLib.Variant('(a{sv})',({},)))
            ended=peer.wait_event('state',lambda row:row['snapshot']['stopping'])['snapshot']
            self.assertFalse(ended['granted']);self.assertFalse(ended['inputReady'])
            self.assertEqual(peer.process.wait(timeout=8),0)

    def test_guardian_denial_state_without_further_controller_traffic(self):
        with self.controller(mode='deny',expected_exit=1) as peer:
            peer.wait_event('state',lambda row:row['snapshot']['state']=='capabilities-ready')
            self.assertTrue(peer.call('request',request=dict(devices=3,sourceTypes=1,cursorMode=2,multiple=False,parentWindow=''))['ok'])
            denied=peer.wait_event('state',lambda row:row['snapshot']['state']=='not-granted')['snapshot']
            self.assertFalse(denied['granted']);self.assertTrue(denied['error'])
            self.assertEqual(peer.terminal()['snapshot'],denied)

    def test_guardian_eof_cancels_unanswered_native_input(self):
        with self.controller() as peer:
            self.grant(peer)
            with self.mutex:type(self).mode='input-hold'
            peer.send('input',event=dict(type='key',code='KeyA',down=True))
            sender=self.input_calls.get(timeout=2)[0];self.input_held.get(timeout=2)
            peer.socket.shutdown(socket.SHUT_WR)
            self.assertEqual(peer.process.wait(timeout=8),0)
            self.assertTrue(self.closed_events[sender].wait(5))
            self.assertEqual(self.input_calls.get(timeout=2)[2][2:],(30,0))

    def test_guardian_legacy_stop_eof_and_signal_release_before_owner_close(self):
        import signal
        for ending in ('stop','eof','signal'):
            with self.subTest(ending=ending),self.controller() as peer:
                self.grant(peer)
                self.event(peer,type='key',code='ShiftLeft',down=True)
                self.event(peer,type='button',button=0,down=True)
                first=self.input_calls.get(timeout=2);sender=first[0]
                self.assertEqual(first[2][2:],(42,1))
                self.assertEqual(self.input_calls.get(timeout=2)[2][2:],(272,1))
                if ending=='stop':self.assertTrue(peer.call('stop')['ok'])
                elif ending=='eof':peer.socket.shutdown(socket.SHUT_WR)
                else:peer.process.send_signal(signal.SIGTERM)
                self.assertEqual(peer.process.wait(timeout=8),0)
                self.assertTrue(self.closed_events[sender].wait(5))
                rows=[self.input_calls.get(timeout=2) for _ in range(2)]
                self.assertEqual([row[2][2:] for row in rows],[(42,0),(272,0)])

    def test_guardian_shutdown_releases_dispatched_not_queued_presses(self):
        with self.controller() as peer:
            self.grant(peer)
            with self.mutex:type(self).mode='input-hold'
            peer.send('input',event=dict(type='key',code='KeyA',down=True))
            sender=self.input_calls.get(timeout=2)[0];self.input_held.get(timeout=2)
            peer.send('input',event=dict(type='key',code='KeyB',down=True))
            # Snapshot response orders controller admission before its EOF.
            self.assertTrue(peer.call('snapshot')['ok'])
            peer.socket.shutdown(socket.SHUT_WR)
            self.assertEqual(peer.process.wait(timeout=8),0)
            self.assertTrue(self.closed_events[sender].wait(5))
            self.assertEqual(self.input_calls.get(timeout=2)[2][2:],(30,0))
            self.assertTrue(self.input_calls.empty(),'Undispatched KeyB must not produce a press or cleanup release')

    def test_guardian_shutdown_retains_unacknowledged_keyup_hold(self):
        with self.controller() as peer:
            self.grant(peer);self.event(peer,type='key',code='ShiftLeft',down=True)
            sender=self.input_calls.get(timeout=2)[0]
            with self.mutex:type(self).mode='input-hold'
            peer.send('input',event=dict(type='key',code='ShiftLeft',down=False))
            self.assertEqual(self.input_calls.get(timeout=2)[2][2:],(42,0));self.input_held.get(timeout=2)
            peer.socket.shutdown(socket.SHUT_WR)
            self.assertEqual(peer.process.wait(timeout=8),0)
            self.assertTrue(self.closed_events[sender].wait(5))
            self.assertEqual(self.input_calls.get(timeout=2)[2][2:],(42,0),'Unacknowledged keyup must retain its owned cleanup obligation')

    def test_guardian_legacy_physical_input_and_release(self):
        with self.controller() as peer:
            state=self.grant(peer);self.assertEqual(state['inputMethod'],'portal-dbus')
            for down in (True,False):self.event(peer,type='key',code='KeyA',down=down)
            self.event(peer,type='move',x=1,y=1)
            for number in (0,1,2):
                for down in (True,False):self.event(peer,type='button',button=number,down=down)
            self.event(peer,type='wheel',axis='y',direction=1)
            self.event(peer,type='wheel',axis='x',direction=-1)
            rows=[self.input_calls.get(timeout=2) for _ in range(11)]
            self.assertEqual([r[2][2:] for r in rows],[(30,1),(30,0),(41,1279.,719.),
                (272,1),(272,0),(274,1),(274,0),(273,1),(273,0),(0,1),(1,-1)])
            self.event(peer,type='key',code='ShiftLeft',down=True)
            self.event(peer,type='button',button=0,down=True)
            self.assertTrue(peer.call('release')['ok'])
            rows=[self.input_calls.get(timeout=2) for _ in range(4)]
            self.assertEqual([r[2][2:] for r in rows],[(42,1),(272,1),(42,0),(272,0)])

    def test_guardian_invalid_input_releases_without_losing_grant(self):
        with self.controller() as peer:
            self.grant(peer);self.event(peer,type='key',code='ShiftLeft',down=True)
            rejected=peer.call('input',event=dict(type='key',code='Unidentified',down=True))
            self.assertFalse(rejected['ok'])
            rows=[self.input_calls.get(timeout=2) for _ in range(2)]
            self.assertEqual([r[2][2:] for r in rows],[(42,1),(42,0)])
            for event in (dict(type='button',button=4294967296,down=True),dict(type='wheel',axis='x',direction=4294967297),
                          dict(type='wheel',axis='x',direction=18446744073709551615),
                          dict(type='key',code='KeyA',down=1),dict(type='move',x=2,y=0)):
                self.assertFalse(peer.call('input',event=event)['ok'])
            self.assertTrue(peer.call('snapshot')['snapshot']['granted'])
            self.event(peer,type='key',code='KeyQ',down=True);self.event(peer,type='key',code='KeyQ',down=False)
            self.assertEqual([self.input_calls.get(timeout=2)[2][2:] for _ in range(2)],[(16,1),(16,0)])

    def test_guardian_stop_cancels_unanswered_native_input(self):
        with self.controller() as peer:
            self.grant(peer)
            with self.mutex:type(self).mode='input-hold'
            pending=peer.send('input',event=dict(type='key',code='KeyA',down=True))
            self.input_calls.get(timeout=2);self.input_held.get(timeout=2)
            stopped=peer.call('stop');self.assertTrue(stopped['ok'])
            self.assertFalse(stopped['snapshot']['granted'])
            self.assertFalse(peer.receive(pending)['ok'])

    def test_guardian_stop_cancels_pending_permission(self):
        with self.controller(mode='wait-response-Start') as peer:
            self.state(peer,lambda row:row['state']=='capabilities-ready')
            self.assertTrue(peer.call('request',request=dict(devices=3,sourceTypes=1,cursorMode=2,multiple=False,parentWindow=''))['ok'])
            self.state(peer,lambda row:row['state']=='waiting-permission')
            self.assertTrue(peer.call('stop')['ok'])

    def test_guardian_capture_start_cancellation_keeps_authority(self):
        with self.controller(mode='connections-valid') as peer,tempfile.TemporaryDirectory(prefix='guardian-capture-') as directory:
            self.grant(peer)
            start=peer.send('capture-start',runtimeDirectory=directory,outputCaps='video/x-raw,format=I420,framerate=30/1')
            self.state(peer,lambda row:row['capture'] is not None)
            self.assertTrue(peer.call('capture-stop')['ok'])
            self.assertFalse(peer.receive(start)['ok'])
            self.assertTrue(peer.call('snapshot')['snapshot']['granted'])
            while not self.grant_calls.empty():self.grant_calls.get_nowait()
            with self.mutex:type(self).mode='hold-OpenPipeWireRemote'
            second=peer.send('capture-start',runtimeDirectory=directory,outputCaps='video/x-raw,format=I420,framerate=30/1')
            sender,method=self.grant_calls.get(timeout=3);self.assertEqual(method,'OpenPipeWireRemote')
            with self.mutex:event=self.held_events.setdefault((sender,method),threading.Event())
            self.assertTrue(event.wait(3),'Fresh protocol connection did not reach the held method')
            self.assertTrue(peer.call('stop')['ok'])
            self.assertFalse(peer.receive(second)['ok'])

    def test_guardian_eof_cancels_pending_permission(self):
        with self.controller(mode='wait-response-Start') as peer:
            self.state(peer,lambda row:row['state']=='capabilities-ready')
            self.assertTrue(peer.call('request',request=dict(devices=3,sourceTypes=1,cursorMode=2,multiple=False,parentWindow=''))['ok'])
            self.state(peer,lambda row:row['state']=='waiting-permission')
            peer.socket.shutdown(socket.SHUT_WR);self.assertEqual(peer.process.wait(timeout=8),0)

    def test_guardian_output_backpressure_cannot_hold_stop(self):
        with self.controller(small_buffer=True) as peer:
            self.grant(peer);self.event(peer,type='key',code='ShiftLeft',down=True)
            sender=self.input_calls.get(timeout=2)[0]
            # Test workload only; no application queue/count cap.
            for _ in range(600):peer.send('snapshot')
            peer.send('stop')
            self.assertEqual(peer.process.wait(timeout=8),0)
            self.assertTrue(self.closed_events[sender].wait(5),'Private authority survived Stop')

    def test_guardian_snapshot_traffic_does_not_extend_input_deadline(self):
        with self.controller() as peer:
            self.grant(peer);self.event(peer,type='key',code='ShiftLeft',down=True)
            self.assertEqual(self.input_calls.get(timeout=2)[2][2:],(42,1))
            end=time.monotonic()+5;snapshots=0
            while True:
                try:release=self.input_calls.get(timeout=.04);break
                except queue.Empty:
                    self.assertLess(time.monotonic(),end,'Snapshot traffic postponed owned release')
                    self.assertTrue(peer.call('snapshot')['ok']);snapshots+=1
            self.assertGreater(snapshots,2)
            self.assertEqual(release[2][2:],(42,0))


if __name__=='__main__':
    suite=unittest.TestSuite(Guardian(name) for name in sorted(Guardian.__dict__) if name.startswith('test_guardian_'))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
