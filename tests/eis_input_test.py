"""Real private D-Bus grant -> native libei sender -> native libeis process.

This verifies transport, not a compositor, Chrome keyboard policy or installed UI.
"""
import array
import contextlib
import json
import math
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
import unittest

PROVIDER = sys.argv.pop()
INPUT = sys.argv.pop()
import portal_session_test as portal
Gio, GLib = portal.Gio, portal.GLib

def interrupted(*_):
    raise KeyboardInterrupt

signal.signal(signal.SIGTERM, interrupted)


def configuration():
    return {"devices": [{"caps": ["absolute", "button", "scroll", "keyboard"], "regions": [
        {"width": 640, "height": 360, "x": 100, "y": 200, "scale": 2.0, "id": "controlled-monitor"}]}]}


class Records:
    def __init__(self, child):
        self.child = child
        self.items = []
        self.condition = threading.Condition()
        self.thread = threading.Thread(target=self.read)
        self.thread.start()

    def read(self):
        for line in self.child.stdout:
            row = json.loads(line)
            with self.condition:
                self.items.append(row)
                self.condition.notify_all()
        with self.condition: self.condition.notify_all()

    def wait(self, predicate, seconds=5):
        end = time.monotonic()+seconds
        with self.condition:
            while True:
                selected = [row for row in self.items if predicate(row)]
                if selected: return selected[-1]
                remaining = end-time.monotonic()
                if remaining <= 0: raise AssertionError("Missing native server event: "+repr(self.items))
                self.condition.wait(remaining)

    def snapshot(self):
        with self.condition: return list(self.items)

    def command(self, op, **args):
        before = sum(row.get("command") == op for row in self.snapshot())
        self.child.stdin.write(json.dumps(dict(op=op, **args))+"\n")
        self.child.stdin.flush()
        return self.wait(lambda row: row.get("command") == op and
                  sum(item.get("command") == op for item in self.items) > before)


class EisInput(portal.PortalCapabilities):
    @classmethod
    def stream_properties(cls, properties):
        result = dict(properties)
        for name, value in cls.wire_properties.items():
            if value is None: result.pop(name, None)
            else: result[name] = value
        return result

    @classmethod
    def portal_method(cls, connection, sender, path, interface, method, parameters, invocation):
        if method != "ConnectToEIS":
            return super().portal_method(connection, sender, path, interface, method, parameters, invocation)
        cls.grant_calls.put((sender, method))
        args = parameters.unpack()
        with cls.mutex:
            entry = cls.sessions.get(args[0])
            valid = entry and entry["sender"] == sender and entry.get("started") and cls.wire_fd >= 0
            fd = cls.wire_fd
            cls.wire_fd = -1
        if not valid:
            invocation.return_dbus_error("org.freedesktop.portal.Error.Failed", "Invalid test EIS grant")
            if fd >= 0: os.close(fd)
            return
        descriptors = Gio.UnixFDList.new()
        try: index = descriptors.append(fd)
        finally: os.close(fd)
        invocation.return_value_with_unix_fd_list(GLib.Variant("(h)", (index,)), descriptors)

    def setUp(self):
        super().setUp()
        type(self).wire_properties = {}
        type(self).wire_fd = -1

    @contextlib.contextmanager
    def client(self, config=None, properties=None, probe_args=()):
        from eis_wire_fixture import wire_peer
        with wire_peer(self,PROVIDER,Records,config or configuration(),properties) as records:
            child=subprocess.Popen([INPUT,*probe_args],env=dict(os.environ,DBUS_SESSION_BUS_ADDRESS=self.address),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                first=self.command_observation(child)
                if "--desktop" in probe_args:
                    self.assertTrue(first["permissionRequested"])
                    end=time.monotonic()+5
                    while True:
                        permission=self.command(child,"permission")
                        if permission["constructed"]:break
                        self.assertLess(time.monotonic(),end,permission)
                    self.assertEqual(permission["inputMethod"],"eis")
                    self.assertEqual(permission["streams"][0]["node"],41)
                else:self.assertTrue(first["constructed"])
                yield child,records
                final=self.command(child,"quit")
                self.assertTrue(final["allResultsSettled"]);self.assertTrue(final["captureRevoked"])
                child.stdin.close();self.assertEqual(child.wait(timeout=5),0,child.stderr.read())
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=5)
                for stream in (child.stdin,child.stdout,child.stderr):stream.close()

    def command(self, child, op, **values):
        return self.command_observation(child, json.dumps(dict(op=op, **values)))

    def state(self, child, expected, devices=None):
        end = time.monotonic()+5
        while True:
            row = self.command(child, "state")
            if row["state"] == expected and (devices is None or row["devices"] == devices): return row
            self.assertLess(time.monotonic(), end, row)

    def ready(self, child):
        self.assertEqual(self.command(child, "ready")["state"], "ready")

    def send(self, child, expected=True, **values):
        index = self.command(child, "input", **values)["id"]
        result = self.command(child, "result", id=index, wait=True)
        self.assertTrue(result["ready"], result)
        self.assertEqual(result["delivered"], expected, result)
        return result

    def test_eis_real_geometry_buttons_keys_and_discrete_scroll(self):
        with self.client() as (child, records):
            self.ready(child)
            self.send(child, kind="absolute", x=640, y=360)
            self.send(child, kind="button", code=272, down=True)
            self.send(child, kind="button", code=272, down=False)
            self.send(child, kind="key", code=42, down=True)
            self.send(child, kind="key", code=30, down=True)
            self.send(child, kind="key", code=30, down=False)
            self.send(child, kind="key", code=42, down=False)
            self.send(child, kind="scroll", code=0, steps=1)
            self.send(child, kind="scroll", code=1, steps=-1)
            records.command("hold")
            rows = records.snapshot()
            self.assertIn(dict(event="absolute", x=420.0, y=380.0, device="controlled-0"), rows)
            self.assertEqual([row["down"] for row in rows if row.get("event") == "key"], [True,True,False,False])
            self.assertEqual([(row["x"],row["y"]) for row in rows if row.get("event") == "scroll"], [(0,120),(-120,0)])
            self.assertFalse(any(row.get("event") == "pixel-scroll" for row in rows))
            self.assertEqual(sum(row.get("event") == "frame" for row in rows), 9)
            records.command("dispatch")

    def test_eis_dom_physical_positions_use_raw_keycodes(self):
        with self.client() as (child,records):
            self.ready(child)
            positions=[("KeyA",30),("KeyQ",16),("ShiftLeft",42),("ShiftRight",54),
                       ("ControlLeft",29),("ControlRight",97),("AltLeft",56),("AltRight",100),
                       ("MetaLeft",125),("MetaRight",126)]
            expected=[]
            for code,raw in positions:
                for down in (True,False):
                    self.send(child,kind="dom-key",code=code,down=down)
                    expected.append((raw,down))
            records.wait(lambda row:row.get("event")=="key" and row.get("code")==126 and not row.get("down"))
            self.assertEqual([(row["code"],row["down"]) for row in records.snapshot() if row.get("event")=="key"],expected)
            for code in ("a","Unidentified",""):
                self.send(child,expected=False,kind="dom-key",code=code,down=True)
            self.assertEqual(self.command(child,"state")["state"],"ready")
            self.assertTrue(self.command(child,"grant")["granted"])

    def test_eis_desktop_permission_mode_uses_the_same_native_sender(self):
        with self.client(probe_args=("--desktop",)) as (child,records):
            self.ready(child)
            self.send(child,kind="absolute",x=640,y=360)
            records.wait(lambda row: row.get("event") == "absolute" and row["x"] == 420 and row["y"] == 380)

    def test_eis_completion_wakes_idle_native_poller(self):
        with self.client() as (child,records):
            self.ready(child)
            for down in (True,False):
                row=self.command(child,"notify-key",code=30,down=down)
                self.assertTrue(row["completionNotified"]);self.assertTrue(row["delivered"])
            records.wait(lambda row:row.get("event")=="key" and row["code"]==30 and not row["down"])
            row=self.command(child,"notify-key",code=-1)
            self.assertTrue(row["completionNotified"]);self.assertFalse(row["delivered"])

    def test_eis_release_and_pause_resume_own_hold_debt(self):
        with self.client() as (child, records):
            self.ready(child)
            self.send(child, kind="key", code=42, down=True)
            self.send(child, kind="button", code=272, down=True)
            records.command("pause")
            self.state(child, "unavailable", 1)
            self.send(child, expected=False, kind="key", code=30, down=True)
            records.command("resume")
            self.ready(child)
            records.wait(lambda row: row.get("event") == "key" and not row["down"])
            records.wait(lambda row: row.get("event") == "button" and not row["down"])
            self.send(child, expected=False, kind="key", code=42, down=False)
            self.send(child, kind="key", code=30, down=True)
            result = self.command(child, "release")["id"]
            self.assertTrue(self.command(child,"result",id=result,wait=True)["delivered"])
            records.wait(lambda row: row.get("event") == "key" and row["code"] == 30 and not row["down"])

    def test_eis_edge_coordinates_survive_wire_precision(self):
        with self.client() as (child,records):
            self.ready(child)
            self.send(child,kind="absolute",x=math.nextafter(1280.0,0.0),y=math.nextafter(720.0,0.0))
            row=records.wait(lambda row: row.get("event") == "absolute")
            self.assertGreater(row["x"],739)
            self.assertLess(row["x"],740)
            self.assertGreater(row["y"],559)
            self.assertLess(row["y"],560)

    def test_eis_normal_stop_releases_owned_holds_before_disconnect(self):
        with self.client() as (child,records):
            self.ready(child)
            self.send(child,kind="key",code=42,down=True)
            self.send(child,kind="button",code=272,down=True)
            self.send(child,expected=False,kind="key",code=42,down=True)
            self.send(child,expected=False,kind="button",code=273,down=False)
            self.assertEqual(self.command(child,"stop")["state"],"stopped")
            records.wait(lambda row: row.get("event") == "disconnect")
            rows=records.snapshot()
            self.assertEqual([row["down"] for row in rows if row.get("event") == "key"],[True,False])
            self.assertEqual([row["down"] for row in rows if row.get("event") == "button"],[True,False])
            stop=next(i for i,row in enumerate(rows) if row.get("event") == "stop")
            release=max(i for i,row in enumerate(rows) if row.get("event") in ("key","button") and not row["down"])
            self.assertLess(release,stop)

    def test_eis_portal_revocation_ends_sender_with_capture_descriptor_held(self):
        with self.client() as (child,records):
            self.ready(child)
            self.send(child,kind="key",code=42,down=True)
            with self.mutex:
                entries=[(path,entry["sender"]) for path,entry in self.sessions.items() if entry.get("started")]
            self.assertEqual(len(entries),1)
            path,sender=entries[0]
            self.connection.emit_signal(sender,path,portal.SESSION,"Closed",GLib.Variant("(a{sv})",({},)))
            self.state(child,"revoked")
            grant=self.command(child,"grant")
            self.assertFalse(grant["granted"])
            self.assertFalse(grant["captureValid"])
            self.assertTrue(grant["captureDescriptorHeld"])
            self.send(child,expected=False,kind="key",code=30,down=True)
            records.wait(lambda row: row.get("event") == "disconnect")

    def test_eis_invalid_inputs_preserve_grant(self):
        with self.client() as (child, records):
            self.ready(child)
            for event in [dict(kind="absolute",x=-1,y=0),dict(kind="absolute",x=1280,y=0),
                          dict(kind="absolute",x=0,y=0,stream=99),dict(kind="button",code=275,down=True),
                          dict(kind="scroll",code=0,steps=2),dict(kind="key",code=272,down=True),
                          dict(kind="keysym",code=97,down=True),dict(kind="key",code=30,down=False)]:
                self.send(child,expected=False,**event)
            self.assertTrue(self.command(child,"grant")["granted"])
            records.command("hold")
            self.assertFalse(any(row.get("event") in ("key","button","absolute","scroll","frame") for row in records.snapshot()))
            records.command("dispatch")

    def test_eis_missing_paused_ambiguous_and_mismatched_devices(self):
        cases = []
        missing=configuration();missing["devices"][0]["caps"].remove("keyboard");cases.append((missing,1))
        paused=configuration();paused["devices"][0]["resume"]=False;cases.append((paused,1))
        duplicate=configuration();duplicate["devices"].append(json.loads(json.dumps(duplicate["devices"][0])));cases.append((duplicate,2))
        wrong=configuration();wrong["devices"][0]["regions"][0]["id"]="another-monitor";cases.append((wrong,1))
        for config,count in cases:
            with self.subTest(config=config),self.client(config) as (child,records):
                self.state(child,"unavailable",count)
                self.send(child,expected=False,kind="absolute",x=0,y=0)
                self.assertTrue(self.command(child,"grant")["granted"])

    def test_eis_metadata_fallback_and_split_devices(self):
        config={"devices":[{"caps":["absolute"],"regions":[{"width":1280,"height":720,"x":0,"y":0}]},
                           {"caps":["button","scroll"]},{"caps":["keyboard"]}]}
        with self.client(config,{"mapping_id":None,"position":GLib.Variant("(ii)",(0,0))}) as (child,records):
            self.ready(child)
            self.send(child,kind="absolute",x=100,y=200)
            self.send(child,kind="key",code=30,down=True)
            self.send(child,kind="key",code=30,down=False)
            self.send(child,kind="scroll",code=0,steps=-1)
            records.wait(lambda row: row.get("event") == "absolute" and row["x"] == 100 and row["y"] == 200)

    def test_eis_stop_cancels_nonreading_peer_without_acknowledgment(self):
        with self.client(probe_args=("--small-send-buffer",)) as (child,records):
            self.ready(child); records.command("hold")
            identifiers=[self.command(child,"input",kind="absolute",x=10,y=20)["id"] for _ in range(20)]
            self.assertFalse(self.command(child,"result",id=identifiers[0])["ready"])
            socket=self.command(child,"writable")
            self.assertTrue(socket["descriptorValid"])
            self.assertFalse(socket["writable"],"Test did not reach real socket backpressure")
            self.assertEqual(self.command(child,"stop")["state"],"stopped")
            for index in identifiers:
                result=self.command(child,"result",id=index,wait=True)
                self.assertTrue(result["ready"]);self.assertFalse(result["delivered"])
            end=time.monotonic()+5
            while self.command(child,"grant")["granted"]: self.assertLess(time.monotonic(),end)
            records.command("dispatch")

    def test_eis_disconnect_synthetic_pong_never_confirms_delivery(self):
        with self.client() as (child,records):
            self.ready(child);records.command("hold")
            index=self.command(child,"input",kind="key",code=42,down=True)["id"]
            self.assertFalse(self.command(child,"result",id=index)["ready"])
            records.command("disconnect")
            result=self.command(child,"result",id=index,wait=True)
            self.assertTrue(result["ready"]);self.assertFalse(result["delivered"])
            self.state(child,"failed")

    def test_eis_handshake_withheld_stop_and_device_removal(self):
        config=configuration();config["withhold"]=True
        with self.client(config) as (child,records):
            records.wait(lambda row: row.get("event") == "withheld")
            self.send(child,expected=False,kind="key",code=30,down=True)
            self.assertEqual(self.command(child,"stop")["state"],"stopped")
        with self.client() as (child,records):
            self.ready(child);self.send(child,kind="key",code=42,down=True)
            records.command("remove")
            self.state(child,"failed")
            self.send(child,expected=False,kind="key",code=30,down=True)

    def test_eis_seat_removal_with_and_without_owned_holds(self):
        for held in (False,True):
            with self.subTest(held=held), self.client() as (child,records):
                self.ready(child)
                if held:
                    self.send(child,kind="key",code=42,down=True)
                    self.send(child,kind="button",code=0x110,down=True)
                records.command("remove-seat")
                self.state(child,"failed" if held else "unavailable")
                self.send(child,expected=False,kind="key",code=30,down=True)
                if held:
                    end=time.monotonic()+5
                    while self.command(child,"grant")["granted"]:
                        self.assertLess(time.monotonic(),end,"Seat removal with owned holds retained authority")


if __name__ == "__main__":
    suite=unittest.TestSuite(EisInput(name) for name in sorted(EisInput.__dict__) if name.startswith("test_eis_"))
    try:
        successful=unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful()
    finally:
        # An interrupted test still owns its private bus and loop. Ordinary
        # class teardown already stopped them; this also covers SIGTERM/INT.
        loop=getattr(EisInput,"loop",None)
        if loop is not None: loop.quit()
        thread=getattr(EisInput,"thread",None)
        if thread is not None:
            thread.join(5)
            assert not thread.is_alive(), "Owned portal loop survived interrupted cleanup"
        daemon=getattr(EisInput,"daemon",None)
        if daemon is not None:
            if daemon.poll() is None: daemon.terminate()
            daemon.wait(timeout=5)
    raise SystemExit(not successful)
