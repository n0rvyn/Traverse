"""Native input authority/ordering over the existing real isolated D-Bus service.

Controlled service acceptance is deliberately separate from real desktop events.
"""
import contextlib
import json
import os
import queue
import subprocess
import sys
import time
import unittest

INPUT = sys.argv.pop()
import portal_session_test as portal


class PortalInput(portal.PortalCapabilities):
    def setUp(self):
        super().setUp()
        for items in (self.input_calls, self.input_held):
            while not items.empty(): items.get_nowait()

    @contextlib.contextmanager
    def client(self, mode="valid", args=()):
        with self.mutex: type(self).mode = mode
        child = subprocess.Popen([INPUT, *args], env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            state = self.command_observation(child)
            self.assertEqual(state["granted"], "--no-grant" not in args, state)
            yield child
            self.command(child, action="stop")
            child.stdin.close()
            self.assertEqual(child.wait(timeout=5), 0, child.stderr.read())
        finally:
            if child.poll() is None:
                child.kill()
                if child.stdin.closed: child.stdin = None
                child.communicate(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None: stream.close()

    def command(self, child, **value):
        return self.command_observation(child, json.dumps(value))

    def send(self, child, **value):
        return self.command(child, action="send", **value)["id"]

    def result(self, child, index, expected="ok"):
        row = self.command(child, action="await", id=index)
        self.assertEqual(row["ok"], expected == "ok", row)
        if expected != "ok": self.assertEqual(row["inputFailure"], expected, row)
        return row

    def test_input_exact_signatures_and_owned_identity(self):
        with self.client() as child:
            events = [dict(kind=0,x=1279,y=719), dict(kind=0,x=0,y=0),
                      dict(kind=1,code=0x110,down=True), dict(kind=1,code=0x110,down=False),
                      dict(kind=1,code=0x111,down=True), dict(kind=1,code=0x112,down=False),
                      dict(kind=2,code=0,steps=-1), dict(kind=2,code=1,steps=1),
                      dict(kind=3,code=0xffe1,down=True), dict(kind=3,code=0x61,down=False),
                      dict(kind=4,code=42,down=True), dict(kind=4,code=30,down=False)]
            for event in events: self.result(child,self.send(child,**event))
            rows=[self.input_calls.get(timeout=2) for _ in events]
            self.assertEqual(len({row[0] for row in rows}),1)
            for sender,method,args in rows:
                self.assertEqual(self.sessions[args[0]]["sender"],sender)
                self.assertEqual(args[1],{})
            self.assertEqual([row[1] for row in rows], ["NotifyPointerMotionAbsolute"]*2+
                ["NotifyPointerButton"]*4+["NotifyPointerAxisDiscrete"]*2+["NotifyKeyboardKeysym"]*2+["NotifyKeyboardKeycode"]*2)
            self.assertEqual([row[2][2:] for row in rows],[(41,1279.,719.),(41,0.,0.),
                (0x110,1),(0x110,0),(0x111,1),(0x112,0),(0,-1),(1,1),(0xffe1,1),(0x61,0),(42,1),(30,0)])

    def test_input_and_remote_completion_wake_idle_native_poller(self):
        with self.client() as child:
            row=self.command(child,action="notify-batch")
            self.assertEqual(row["coalescedResults"],4)
            for down in (True,False):
                row=self.command(child,action="notify-input",kind=4,code=30,down=down)
                self.assertTrue(row["completionNotified"]);self.assertTrue(row["ok"],row)
            row=self.command(child,action="notify-input",kind=4,code=-1)
            self.assertTrue(row["completionNotified"]);self.assertFalse(row["ok"])
            row=self.command(child,action="notify-remote")
            self.assertTrue(row["completionNotified"]);self.assertTrue(row["valid"])
            row=self.command(child,action="notify-stop")
            self.assertTrue(row["terminalNotified"]);self.assertTrue(row["stopped"])

    def test_input_dom_physical_positions_use_raw_keycodes(self):
        with self.client() as child:
            positions=[("KeyA",30),("KeyQ",16),("ShiftLeft",42),("ShiftRight",54),
                       ("ControlLeft",29),("ControlRight",97),("AltLeft",56),("AltRight",100),
                       ("MetaLeft",125),("MetaRight",126)]
            for code,raw in positions:
                for down in (True,False):
                    self.result(child,self.send(child,kind=4,domCode=code,down=down))
                    sender,method,args=self.input_calls.get(timeout=2)
                    self.assertEqual(method,"NotifyKeyboardKeycode")
                    self.assertEqual(args[2:],(raw,int(down)))
                    self.assertEqual(self.sessions[args[0]]["sender"],sender)
            for code in ("a","Unidentified",""):
                result=self.result(child,self.send(child,kind=4,domCode=code,down=True),"invalid-input")
                self.assertTrue(result["granted"])
            self.assertTrue(self.input_calls.empty())

    def test_input_invalid_data_preserves_grant_and_sends_nothing(self):
        with self.client() as child:
            cases=[dict(kind=0,x=-1),dict(kind=0,x=1280),dict(kind=0,y=720),dict(kind=0,stream=42),
                dict(kind=0,nonfinite="nan"),dict(kind=0,nonfinite="infinity"),dict(kind=99),
                dict(kind=1,code=0),dict(kind=1,code=0x113),dict(kind=2,code=2,steps=1),
                dict(kind=2,code=0,steps=0),dict(kind=2,code=1,steps=2),dict(kind=3,code=-1),dict(kind=3,code=0x10000),
                dict(kind=4,code=-1),dict(kind=4,code=0),dict(kind=4,code=0x300),
                dict(kind=4,code=0x110),dict(kind=4,code=0x220),dict(kind=4,code=0x2c0)]
            for event in cases:
                row=self.result(child,self.send(child,**event),"invalid-input")
                self.assertTrue(row["granted"])
            self.assertTrue(self.input_calls.empty())
        with self.client("input-no-size") as child:
            self.result(child,self.send(child,kind=0),"invalid-input")
            self.assertTrue(self.input_calls.empty())

    def test_input_before_grant_after_stop_eis_and_explicit_unsupported(self):
        for mode,args in (("valid",("--no-grant",)),("eis-valid",())):
            with self.subTest(mode=mode),self.client(mode,args) as child:
                self.result(child,self.send(child,kind=3,code=0x61),"unavailable")
                self.assertTrue(self.input_calls.empty())
        with self.client("eis-unsupported") as child:
            self.result(child,self.send(child,kind=3,code=0x61))
            self.input_calls.get(timeout=2)
            self.command(child,action="stop")
            self.result(child,self.send(child,kind=3,code=0x61),"cancelled")

    def test_input_subset_device_grants(self):
        for devices,allowed,denied in ((1,dict(kind=3,code=0x61),dict(kind=1,code=0x110)),
                                      (2,dict(kind=1,code=0x110),dict(kind=3,code=0x61))):
            with self.subTest(devices=devices),self.client("input-subset-"+str(devices),("--devices",str(devices))) as child:
                self.result(child,self.send(child,**allowed))
                self.input_calls.get(timeout=2)
                self.result(child,self.send(child,**denied),"unavailable")
                self.assertTrue(self.input_calls.empty())

    def test_input_fifo_acknowledgment_barrier(self):
        with self.client("input-hold") as child:
            press=self.send(child,kind=3,code=0x61,down=True)
            self.input_calls.get(timeout=2); held=self.input_held.get(timeout=2)
            release=self.send(child,kind=3,code=0x61,down=False)
            # State read is a worker barrier only for futures; a held reply
            # deliberately prevents the second input from being dispatched.
            self.assertEqual(self.command(child,action="check")["resultsReady"],[False,False])
            self.assertTrue(self.input_calls.empty())
            held.return_value(portal.GLib.Variant("()",()))
            self.result(child,press)
            self.assertEqual(self.input_calls.get(timeout=2)[2][-1],0)
            self.input_held.get(timeout=2).return_value(portal.GLib.Variant("()",()))
            self.result(child,release)

    def test_input_stop_settles_held_queued_and_abandoned(self):
        with self.client("input-hold") as child:
            first=self.send(child,kind=3,code=0x61,down=True)
            self.input_calls.get(timeout=2); held=self.input_held.get(timeout=2)
            indices=[first]+[self.send(child,kind=3,code=0x61,down=False) for _ in range(32)]
            self.command(child,action="stop")
            for index in indices:self.result(child,index,"cancelled")
            held.return_value(portal.GLib.Variant("()",()))
            self.assertEqual(self.input_calls.get(timeout=2)[2][2:],(0x61,0),'Only terminal cleanup of the dispatched hold is allowed')
            self.assertTrue(self.input_calls.empty())
        with self.client("input-hold") as child:
            self.send(child,kind=1,code=0x110,down=True)
            self.input_calls.get(timeout=2);held=self.input_held.get(timeout=2)
            self.command(child,action="abandon")
            self.command(child,action="stop")
            held.return_value(portal.GLib.Variant("()",()))

    def test_input_actual_method_error_revokes_uncertain_delivery(self):
        with self.client("input-error") as child:
            self.result(child,self.send(child,kind=3,code=0x61,down=True),"method")
            end=time.monotonic()+3
            while self.command(child,action="check")["granted"]:
                self.assertLess(time.monotonic(),end)
            self.result(child,self.send(child,kind=3,code=0x61),"unavailable")
            rows=[self.input_calls.get(timeout=2) for _ in range(2)]
            self.assertEqual([row[2][2:] for row in rows],[(0x61,1),(0x61,0)])
            self.assertTrue(self.input_calls.empty())

    def test_input_parallel_submission_and_stop(self):
        for _ in range(8):
            with self.client("input-hold") as child:
                row=self.command(child,action="race-stop")
                self.assertTrue(row["stopped"],row)
                self.assertEqual(row["settled"],64)
                while not self.input_held.empty():
                    self.input_held.get_nowait().return_value(portal.GLib.Variant("()",()))
                while not self.input_calls.empty(): self.input_calls.get_nowait()

    def test_input_owner_loss_cancels_all_delivery(self):
        with self.client("input-hold") as child:
            first=self.send(child,kind=3,code=0x61,down=True)
            self.input_calls.get(timeout=2);held=self.input_held.get(timeout=2)
            second=self.send(child,kind=3,code=0x61,down=False)
            try:
                self.connection.call_sync("org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus",
                    "ReleaseName",portal.GLib.Variant("(s)",(portal.SERVICE,)),portal.GLib.VariantType.new("(u)"),
                    portal.Gio.DBusCallFlags.NONE,2000,None)
                self.result(child,first,"cancelled");self.result(child,second,"cancelled")
                held.return_value(portal.GLib.Variant("()",()))
                self.assertTrue(self.input_calls.empty())
            finally:
                self.connection.call_sync("org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus",
                    "RequestName",portal.GLib.Variant("(su)",(portal.SERVICE,0)),portal.GLib.VariantType.new("(u)"),
                    portal.Gio.DBusCallFlags.NONE,2000,None)

    def test_input_session_closed_cancels_inflight_and_queue(self):
        with self.client("input-hold") as child:
            first=self.send(child,kind=3,code=0x61,down=True)
            sender,_,args=self.input_calls.get(timeout=2)
            held=self.input_held.get(timeout=2)
            second=self.send(child,kind=3,code=0x61,down=False)
            self.connection.emit_signal(sender,args[0],portal.SESSION,"Closed",portal.GLib.Variant("(a{sv})",({},)))
            self.result(child,first,"cancelled");self.result(child,second,"cancelled")
            held.return_value(portal.GLib.Variant("()",()))
            self.assertTrue(self.input_calls.empty())

    def test_input_z_bus_loss_cancels_pending(self):
        with self.client("input-hold") as child:
            first=self.send(child,kind=3,code=0x61,down=True)
            self.input_calls.get(timeout=2);held=self.input_held.get(timeout=2)
            second=self.send(child,kind=3,code=0x61,down=False)
            self.daemon.terminate();self.daemon.wait(timeout=5)
            self.result(child,first,"cancelled");self.result(child,second,"cancelled")
            self.assertTrue(self.input_calls.empty())
            # Bus is deliberately gone; dropping invocation owns no protocol FD.
            del held


if __name__=="__main__":
    suite=unittest.TestSuite(PortalInput(name) for name in sorted(PortalInput.__dict__) if name.startswith("test_input_"))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
