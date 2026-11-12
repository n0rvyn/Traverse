"""Native private portal capability boundary over a real isolated session bus.

Run as an unprivileged user with PyGObject, dbus-daemon and the native probe.
This controlled service is not compositor/capture/input acceptance.
"""
import json
import contextlib
import os
from pathlib import Path
import queue
import selectors
import socket
import subprocess
import sys
import threading
import time
import unittest

if os.geteuid() == 0:
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)

import gi
from gi.repository import Gio, GLib

PROBE = str(Path(sys.argv.pop()).resolve())
SERVICE = "org.freedesktop.portal.Desktop"
OBJECT = "/org/freedesktop/portal/desktop"
REMOTE = "org.freedesktop.portal.RemoteDesktop"
SCREEN = "org.freedesktop.portal.ScreenCast"
XML = """<node><interface name="org.freedesktop.DBus.Properties">
<method name="GetAll"><arg type="s" direction="in"/>
<arg type="a{sv}" direction="out"/></method></interface></node>"""
PORTAL_XML = """<node><interface name="org.freedesktop.portal.RemoteDesktop">
<method name="CreateSession"><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method>
<method name="SelectDevices"><arg type="o" direction="in"/><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method>
<method name="Start"><arg type="o" direction="in"/><arg type="s" direction="in"/><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method>
<method name="ConnectToEIS"><arg type="o" direction="in"/><arg type="a{sv}" direction="in"/><arg type="h" direction="out"/></method>
</interface><interface name="org.freedesktop.portal.ScreenCast">
<method name="SelectSources"><arg type="o" direction="in"/><arg type="a{sv}" direction="in"/><arg type="o" direction="out"/></method>
<method name="OpenPipeWireRemote"><arg type="o" direction="in"/><arg type="a{sv}" direction="in"/><arg type="h" direction="out"/></method>
</interface></node>"""
# Shared actual-bus fixture for the internal input transport tests.
_input_signatures = {
    "NotifyPointerMotionAbsolute": "oa{sv}udd",
    "NotifyPointerButton": "oa{sv}iu",
    "NotifyPointerAxisDiscrete": "oa{sv}ui",
    "NotifyKeyboardKeysym": "oa{sv}iu",
    "NotifyKeyboardKeycode": "oa{sv}iu",
}
for _name, _signature in _input_signatures.items():
    _types = ["o", "a{sv}"] + list(_signature[len("oa{sv}"):])
    _xml = '<method name="' + _name + '">' + ''.join(
        '<arg type="' + item + '" direction="in"/>' for item in _types) + '</method>'
    PORTAL_XML = PORTAL_XML.replace('</interface><interface name="org.freedesktop.portal.ScreenCast">',
        _xml + '</interface><interface name="org.freedesktop.portal.ScreenCast">')

SESSION = "org.freedesktop.portal.Session"
SESSION_XML = """<node><interface name="org.freedesktop.portal.Session">
<method name="Close"/><signal name="Closed"><arg type="a{sv}"/></signal>
</interface></node>"""


class PortalCapabilities(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert os.getuid() != 0, "Real unprivileged channel required"
        cls.daemon = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--print-address=1"],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        selected = selectors.DefaultSelector()
        selected.register(cls.daemon.stdout, selectors.EVENT_READ)
        assert selected.select(10), "Owned bus did not provide an address"
        cls.address = cls.daemon.stdout.readline().decode().strip()
        selected.close()
        cls.connection = Gio.DBusConnection.new_for_address_sync(cls.address,
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION,
            None, None)
        cls.connection.set_exit_on_close(False)
        cls.stranger = Gio.DBusConnection.new_for_address_sync(cls.address,
            Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
        cls.stranger.set_exit_on_close(False)
        cls.loop = GLib.MainLoop()
        cls.mutex = threading.Lock()
        cls.mode = "valid"
        cls.calls = queue.Queue()
        cls.input_calls = queue.Queue()
        cls.input_held = queue.Queue()
        cls.held = []
        cls.held_grants = {}
        cls.held_events = {}
        cls.peers = set()
        cls.sessions = {}
        cls.closed_events = {}
        cls.grant_calls = queue.Queue()
        cls.sockets = {}
        node = Gio.DBusNodeInfo.new_for_xml(XML)
        cls.registration = cls.connection.register_object(OBJECT, node.interfaces[0], cls.method, None, None)
        node = Gio.DBusNodeInfo.new_for_xml(PORTAL_XML)
        cls.portal_registrations = [cls.connection.register_object(OBJECT, item, cls.portal_method, None, None)
                                    for item in node.interfaces]
        cls.owner_subscription = cls.connection.signal_subscribe("org.freedesktop.DBus", "org.freedesktop.DBus",
            "NameOwnerChanged", "/org/freedesktop/DBus", None, Gio.DBusSignalFlags.NONE, cls.owner_changed, None)
        cls.connection.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
            "RequestName", GLib.Variant("(su)", (SERVICE, 0)), GLib.VariantType.new("(u)"),
            Gio.DBusCallFlags.NONE, 2000, None)
        cls.thread = threading.Thread(target=cls.loop.run)
        cls.thread.start()

    @classmethod
    def method(cls, connection, sender, path, interface, method, parameters, invocation):
        requested = parameters.unpack()[0]
        with cls.mutex:
            mode = cls.mode
            cls.peers.add(sender)
        cls.calls.put((sender, requested))
        if mode == "never-reply":
            cls.held.append(invocation)
            return
        if mode == "method-error":
            invocation.return_dbus_error("org.freedesktop.portal.Error.Failed", "Controlled property failure")
            return
        if requested == REMOTE:
            values = {"version": GLib.Variant("u", 2 if mode.startswith("eis-") or mode == "hold-ConnectToEIS" else 1), "AvailableDeviceTypes": GLib.Variant("u", 3)}
        elif requested == SCREEN:
            values = {"version": GLib.Variant("u", 4), "AvailableSourceTypes": GLib.Variant("u", 3),
                      "AvailableCursorModes": GLib.Variant("u", 7)}
        else:
            invocation.return_dbus_error("org.freedesktop.DBus.Error.UnknownInterface", "Unexpected interface")
            return
        if mode == "wrong-type": values["version"] = GLib.Variant("s", "1")
        if mode == "zero-version": values["version"] = GLib.Variant("u", 0)
        if mode == "missing-property": values.pop("version")
        if mode == "duplicate-property":
            invocation.return_value(GLib.Variant.parse(GLib.VariantType.new("(a{sv})"),
                "({'version': <uint32 1>, 'version': <uint32 2>, 'AvailableDeviceTypes': <uint32 3>},)", None, None))
            return
        if mode == "screen-v1" and requested == SCREEN:
            values["version"] = GLib.Variant("u", 1)
            values.pop("AvailableCursorModes")
        invocation.return_value(GLib.Variant("(a{sv})", (values,)))

    @classmethod
    def owner_changed(cls, connection, sender, path, interface, signal_name, parameters, data):
        name, old, new = parameters.unpack()
        if not name.startswith(":") or new: return
        with cls.mutex:
            paths = [path for path, entry in cls.sessions.items() if entry["sender"] == name]
            endpoints = cls.sockets.pop(name, [])
            event = cls.closed_events.setdefault(name, threading.Event())
        for endpoint in endpoints: endpoint.close()
        for path in paths:
            with cls.mutex: entry = cls.sessions.pop(path, None)
            if entry: cls.connection.unregister_object(entry["registration"])
        event.set()

    @classmethod
    def portal_method(cls, connection, sender, path, interface, method, parameters, invocation):
        try:
            args = parameters.unpack()
            with cls.mutex: mode = cls.mode
            cls.grant_calls.put((sender, method))
            if method in _input_signatures:
                session = args[0]
                with cls.mutex:
                    entry = cls.sessions.get(session)
                    valid = entry and entry["sender"] == sender and entry.get("started")
                if not valid: raise ValueError("Input outside started owned session")
                cls.input_calls.put((sender, method, args))
                if mode == "input-hold":
                    cls.input_held.put(invocation); return
                if mode == "input-error":
                    invocation.return_dbus_error("org.freedesktop.portal.Error.Failed", "Controlled input failure"); return
                invocation.return_value(GLib.Variant("()", ())); return
            if method == "CreateSession":
                options = args[0]
                session = "/org/freedesktop/portal/desktop/session/" + sender[1:].replace(".", "_") + "/" + options["session_handle_token"]
                node = Gio.DBusNodeInfo.new_for_xml(SESSION_XML)
                registration = connection.register_object(session, node.interfaces[0], cls.close_method, None, None)
                with cls.mutex:
                    cls.sessions[session] = dict(sender=sender, registration=registration)
                    cls.closed_events.setdefault(sender, threading.Event())
                results = {"session_handle": GLib.Variant("s", session if mode != "wrong-session" else "/wrong/session")}
            elif method in ("OpenPipeWireRemote", "ConnectToEIS"):
                with cls.mutex: valid = args[0] in cls.sessions and cls.sessions[args[0]]["sender"] == sender
                if not valid: raise ValueError("Wrong descriptor session owner")
                if mode == "hold-" + method:
                    with cls.mutex:
                        cls.held_grants[(sender, method)] = invocation
                        cls.held_events.setdefault((sender, method), threading.Event()).set()
                    cls.held.append(invocation); return
                if mode == "connections-method-error":
                    invocation.return_dbus_error("org.freedesktop.portal.Error.Failed", "Controlled capture connection failure"); return
                if method == "ConnectToEIS" and mode == "eis-unsupported":
                    invocation.return_dbus_error("org.freedesktop.portal.Error.NotSupported", "Controlled unsupported EIS"); return
                if method == "ConnectToEIS" and mode == "eis-error":
                    invocation.return_dbus_error("org.freedesktop.portal.Error.Failed", "Controlled ambiguous EIS failure"); return
                if mode == "missing-fd" or (mode == "eis-missing-fd" and method == "ConnectToEIS"):
                    invocation.return_value(GLib.Variant("(h)", (0,))); return
                if mode == "wrong-fd-type":
                    read_fd, write_fd = os.pipe()
                    descriptors = Gio.UnixFDList.new(); descriptors.append(read_fd); os.close(read_fd)
                    with cls.mutex: cls.sockets.setdefault(sender, []).append(os.fdopen(write_fd, "wb", buffering=0))
                    invocation.return_value_with_unix_fd_list(GLib.Variant("(h)", (0,)), descriptors); return
                own, exported = socket.socketpair()
                if "connections" not in mode:
                    own.sendall(b"E" if method == "ConnectToEIS" else b"Z")
                descriptors = Gio.UnixFDList.new()
                descriptors.append(exported.fileno())
                exported.close()
                with cls.mutex: cls.sockets.setdefault(sender, []).append(own)
                index = 7 if mode == "invalid-fd-index" or (mode == "eis-invalid-fd-index" and method == "ConnectToEIS") else 0
                invocation.return_value_with_unix_fd_list(GLib.Variant("(h)", (index,)), descriptors)
                return
            else:
                session, options = args[0], args[-1]
                with cls.mutex: valid = session in cls.sessions and cls.sessions[session]["sender"] == sender
                if not valid: raise ValueError("Wrong session owner")
                results = {}
                if method == "SelectDevices" and options.get("types") != (int(mode.rsplit("-", 1)[1]) if mode.startswith("input-subset-") else 3): raise ValueError("Unexpected devices")
                if method == "SelectSources" and (options.get("types") != 1 or
                    options.get("multiple") != (mode in ("duplicate-node", "multiple-valid")) or options.get("cursor_mode") != 2):
                    raise ValueError("Unexpected source request")
                if method == "Start":
                    with cls.mutex: cls.sessions[session]["started"] = True
                    properties = {"size": GLib.Variant("(ii)", (1280, 720)), "position": GLib.Variant("(ii)", (-1280, 0)),
                        "source_type": GLib.Variant("u", 1), "pipewire-serial": GLib.Variant("t", 2**53 + 9),
                        "mapping_id": GLib.Variant("s", "controlled-monitor")}
                    properties = cls.stream_properties(properties)
                    if mode == "input-no-size": properties.pop("size")
                    streams = [(41, properties)]
                    if mode == "wrong-source": properties["source_type"] = GLib.Variant("u", 2)
                    if mode == "duplicate-node": streams.append((41, properties))
                    if mode == "multiple-valid":
                        second = dict(properties, position=GLib.Variant("(ii)", (0, 0)), size=GLib.Variant("(ii)", (1920, 1080)))
                        second["pipewire-serial"] = GLib.Variant("t", 2**53 + 10)
                        streams.append((42, second))
                    if mode == "missing-streams": streams = []
                    results = {"devices": GLib.Variant("u", 1 if mode == "partial-devices" else int(mode.rsplit("-", 1)[1]) if mode.startswith("input-subset-") else 3),
                               "streams": GLib.Variant("a(ua{sv})", streams)}
            request_path = "/org/freedesktop/portal/desktop/request/" + sender[1:].replace(".", "_") + "/" + options["handle_token"]
            if mode == "hold-" + method:
                with cls.mutex: cls.held_grants[(sender, method)] = invocation
                cls.held.append(invocation); return
            code = 1 if mode == "deny" and method == "Start" else 0
            response = GLib.Variant("(ua{sv})", (code, results))
            if mode == "unrelated-response":
                bad = GLib.Variant("(ua{sv})", (0, {"session_handle": GLib.Variant("s", "/wrong/session")}))
                connection.emit_signal(sender, "/unrelated/request", "org.freedesktop.portal.Request", "Response", bad)
                cls.stranger.emit_signal(sender, request_path, "org.freedesktop.portal.Request", "Response", bad)
            if mode == "early-response" or mode == "error-after-response":
                connection.emit_signal(sender, request_path, "org.freedesktop.portal.Request", "Response", response)
            if mode == "error-after-response":
                invocation.return_dbus_error("org.freedesktop.portal.Error.Failed", "Controlled error after early response"); return
            invocation.return_value(GLib.Variant("(o)", ("/wrong/request" if mode == "wrong-request" else request_path,)))
            if mode == "wait-response-Start" and method == "Start": return
            if mode != "early-response":
                connection.emit_signal(sender, request_path, "org.freedesktop.portal.Request", "Response", response)
        except Exception as error:
            invocation.return_dbus_error("org.freedesktop.portal.Error.Failed", "Fixture rejected call: " + str(error))

    @classmethod
    def close_method(cls, connection, sender, path, interface, method, parameters, invocation):
        connection.emit_signal(sender, path, SESSION, "Closed", GLib.Variant("(a{sv})", ({},)))
        invocation.return_value(GLib.Variant("()", ()))

    @classmethod
    def stream_properties(cls, properties):
        return properties

    @classmethod
    def tearDownClass(cls):
        cls.connection.unregister_object(cls.registration)
        for registration in cls.portal_registrations: cls.connection.unregister_object(registration)
        cls.connection.signal_unsubscribe(cls.owner_subscription)
        for endpoints in cls.sockets.values():
            for endpoint in endpoints: endpoint.close()
        if not cls.connection.is_closed(): cls.connection.close_sync(None)
        if not cls.stranger.is_closed(): cls.stranger.close_sync(None)
        cls.held.clear()
        cls.held_grants.clear()
        cls.held_events.clear()
        cls.loop.quit()
        cls.thread.join(5)
        assert not cls.thread.is_alive(), "Owned fixture loop survived cleanup"
        if cls.daemon.poll() is None: cls.daemon.terminate()
        cls.daemon.wait(timeout=5)
        cls.daemon.stdout.close()

    def setUp(self):
        with self.mutex: type(self).mode = "valid"
        while not self.calls.empty(): self.calls.get_nowait()
        while not self.grant_calls.empty(): self.grant_calls.get_nowait()

    def run_probe(self, expected, environment=None):
        env = dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address)
        if environment is not None: env = environment
        result = subprocess.run([PROBE], env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stderr + "\n" + result.stdout)
        report = json.loads(result.stdout)
        self.assertNotEqual(report["uid"], 0)
        self.assertFalse(report["grantOrCaptureRequested"])
        return report

    def run_grant(self, mode, expected=0):
        with self.mutex: type(self).mode = mode
        flag = "--grant-multiple-fixture" if mode in ("multiple-valid", "duplicate-node") else "--grant-fixture"
        result = subprocess.run([PROBE, flag], env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address),
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + "\n" + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["grantOrCaptureRequested"])
        self.assertTrue(report["descriptorsUnavailableBeforeGrant"])
        self.assertTrue(report["descriptorsUnavailableAfterStop"])
        if not expected:
            self.assertTrue(report["granted"])
            self.assertTrue(report["exportedDescriptorsCloexec"])
            self.assertTrue(report["connectionTransfersExactlyOnce"])
            self.assertTrue(report["actualTransferredSocketMarkersMatched"])
            self.assertTrue(report["authorityRevokedWhileConsumerDescriptorsRemain"])
        else:
            self.assertFalse(report["granted"])
        return report

    def test_grant_real_fd_transfer_and_stream_metadata(self):
        report = self.run_grant("valid")
        self.assertEqual(report["inputMethod"], "portal-dbus")
        self.assertEqual(report["grantedDevices"], 3)
        self.assertEqual(report["streams"], [dict(node=41, serial=2**53+9, sourceType=1,
            position=[-1280, 0], logicalSize=[1280, 720], mappingId="controlled-monitor")])
        methods = []
        while not self.grant_calls.empty(): methods.append(self.grant_calls.get_nowait()[1])
        self.assertEqual(methods, ["CreateSession", "SelectDevices", "SelectSources", "Start", "OpenPipeWireRemote"])

    def test_grant_response_before_method_return(self):
        self.run_grant("early-response")

    def test_grant_unrelated_sender_and_request_path_ignored(self):
        self.run_grant("unrelated-response")

    def test_grant_multiple_streams_are_preserved_without_precision_loss(self):
        report = self.run_grant("multiple-valid")
        self.assertEqual([s["node"] for s in report["streams"]], [41, 42])
        self.assertEqual([s["serial"] for s in report["streams"]], [2**53+9, 2**53+10])

    def test_grant_method_error_after_early_response_never_admits(self):
        report = self.run_grant("error-after-response", 1)
        self.assertIn("Controlled error", report["error"])
        self.assertEqual(report["failure"], "method")

    def test_grant_eis_positive_and_explicit_unsupported(self):
        self.assertEqual(self.run_grant("eis-valid")["inputMethod"], "eis")
        self.assertEqual(self.run_grant("eis-unsupported")["inputMethod"], "portal-dbus")

    def test_grant_ambiguous_eis_error_is_not_legacy_fallback(self):
        report = self.run_grant("eis-error", 1)
        self.assertEqual(report["inputMethod"], "undetermined")

    def test_grant_denial_invalid_identity_metadata_and_fds(self):
        for mode in ("deny", "wrong-session", "wrong-request", "partial-devices", "missing-streams", "duplicate-node", "wrong-source",
                     "missing-fd", "invalid-fd-index", "wrong-fd-type", "eis-missing-fd", "eis-invalid-fd-index"):
            with self.subTest(mode=mode):
                report = self.run_grant(mode, 1)
                if mode == "partial-devices":
                    self.assertTrue(report["notGranted"])
                    self.assertEqual(report["failure"], "none")
                    self.assertEqual(report["grantedDevices"], 1)
                if mode == "deny":
                    self.assertTrue(report["notGranted"])
                    self.assertEqual(report["portalResponse"], 1)

    def test_grant_pending_phases_remain_cancellable(self):
        for phase in ("CreateSession", "SelectDevices", "SelectSources", "Start", "OpenPipeWireRemote", "ConnectToEIS"):
            with self.subTest(phase=phase):
                with self.mutex: type(self).mode = "hold-" + phase
                while not self.grant_calls.empty(): self.grant_calls.get_nowait()
                child = subprocess.Popen([PROBE, "--grant-command"], env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address),
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for stream in (child.stdin, child.stdout, child.stderr): self.addCleanup(stream.close)
                try:
                    while True:
                        sender, method = self.grant_calls.get(timeout=5)
                        if method == phase: break
                    started = time.monotonic()
                    out, err = child.communicate("stop\n", timeout=5)
                    self.assertEqual(child.returncode, 0, out + err)
                    report = json.loads(out)
                    self.assertTrue(report["stopped"])
                    self.assertTrue(report["descriptorsUnavailableAfterStop"])
                    self.assertLess(time.monotonic()-started, 2)
                    with self.mutex: event = self.closed_events.setdefault(sender, threading.Event())
                    self.assertTrue(event.wait(2), "Private session owner survived Stop")
                    with self.mutex: self.assertFalse(any(x["sender"] == sender for x in self.sessions.values()))
                finally:
                    if child.poll() is None: child.kill(); child.communicate(timeout=5)

    def test_grant_session_closed_revokes_exported_authority(self):
        child = subprocess.Popen([PROBE, "--grant-observe-close"], env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for stream in (child.stdout, child.stderr): self.addCleanup(stream.close)
        try:
            selector = selectors.DefaultSelector(); selector.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(5), "No granted observation")
            first = json.loads(child.stdout.readline()); selector.close()
            self.assertTrue(first["granted"])
            sender, _ = self.grant_calls.get(timeout=2)
            with self.mutex: paths = [p for p, entry in self.sessions.items() if entry["sender"] == sender]
            self.assertEqual(len(paths), 1)
            with self.mutex: sender = self.sessions[paths[0]]["sender"]
            self.connection.emit_signal(sender, paths[0], SESSION, "Closed", GLib.Variant("(a{sv})", ({},)))
            out, err = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 0, out + err)
            final = json.loads(out)
            self.assertTrue(final["sessionClosedObserved"])
            self.assertFalse(final["granted"])
            self.assertTrue(final["descriptorsUnavailableAfterStop"])
        finally:
            if child.poll() is None: child.kill(); child.communicate(timeout=5)

    def command_observation(self, child, command=None):
        if command is not None:
            child.stdin.write(command + "\n"); child.stdin.flush()
        selector = selectors.DefaultSelector()
        try:
            selector.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(5), "Native command produced no observation")
            return json.loads(child.stdout.readline())
        finally: selector.close()

    def test_eis_owned_consumer_lifetime_and_stop(self):
        for command in ("drop", "stop", "race", "consumer-kill", "closed", "wrong-protocol"):
            with self.subTest(command=command):
                with self.mutex: type(self).mode = "eis-connections-valid"
                child = subprocess.Popen([PROBE, "--grant-eis-lease"],
                    env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for stream in (child.stdin, child.stdout, child.stderr): self.addCleanup(stream.close)
                try:
                    ready = self.command_observation(child)
                    for field in ("granted", "beforeGrantDenied", "movesPreserveSoleConsumer",
                                  "rawAndOwnedSecondTransfersDenied", "connectionsHaveCorrectProtocol"):
                        self.assertTrue(ready[field], ready)
                    calls = []
                    while not self.grant_calls.empty(): calls.append(self.grant_calls.get_nowait())
                    sender = calls[0][0]
                    self.assertEqual(sum(method == "ConnectToEIS" for _,method in calls), 1)
                    if command == "closed":
                        with self.mutex: paths = [p for p, entry in self.sessions.items() if entry["sender"] == sender]
                        self.assertEqual(len(paths), 1)
                        self.connection.emit_signal(sender, paths[0], SESSION, "Closed", GLib.Variant("(a{sv})", ({},)))
                    out, err = child.communicate(command+"\n", timeout=10)
                    self.assertEqual(child.returncode, 0, out+err)
                    final = json.loads(out)
                    for field in ("closed" if command == "closed" else "stopped", "captureRevokedWhileDescriptorHeld", "portalClosedPeer",
                                  "consumerOperationPassed", "afterStopDenied", "heldEisRevoked"):
                        self.assertTrue(final[field], final)
                    with self.mutex: closed = self.closed_events[sender]
                    self.assertTrue(closed.wait(2), "EIS consumer loss retained portal authority")
                finally:
                    if child.poll() is None: child.kill(); child.communicate(timeout=5)

    def test_eis_owned_connection_rejects_legacy_method(self):
        with self.mutex: type(self).mode = "connections-valid"
        result = subprocess.run([PROBE, "--grant-eis-lease"],
            env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address), capture_output=True,
            text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["wrongMethodDenied"])
        self.assertTrue(report["grantPreserved"])

    def test_eis_owned_transfer_cannot_follow_raw_transfer(self):
        with self.mutex: type(self).mode = "eis-connections-valid"
        result = subprocess.run([PROBE, "--grant-eis-raw-first"],
            env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address), capture_output=True,
            text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["ownedTransferDeniedAfterRaw"])
        self.assertTrue(report["grantPreserved"])

    def test_eis_owned_transfer_races_stop_without_late_lifetime_source(self):
        for attempt in range(8):
            with self.subTest(attempt=attempt):
                with self.mutex: type(self).mode = "eis-connections-valid"
                result = subprocess.run([PROBE, "--grant-eis-take-race"],
                    env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address), capture_output=True,
                    text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                report = json.loads(result.stdout)
                self.assertTrue(report["stopped"])
                self.assertTrue(report["raceSettled"])

    def test_fresh_connections_abandoned_results_and_broadcast_revocation(self):
        for mode in ("connections-valid", "eis-connections-valid"):
            with self.subTest(mode=mode):
                with self.mutex: type(self).mode = mode
                while not self.grant_calls.empty(): self.grant_calls.get_nowait()
                child = subprocess.Popen([PROBE, "--grant-connections-fixture"],
                    env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address), stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                for stream in (child.stdin, child.stdout, child.stderr): self.addCleanup(stream.close)
                try:
                    ready = self.command_observation(child)
                    self.assertTrue(ready["granted"], ready)
                    self.assertTrue(ready["beforeGrantDenied"])
                    self.assertEqual(ready["distinctConnections"], 3)
                    self.assertTrue(ready["allValidBeforeStop"])
                    self.assertTrue(ready["connectionsCloexec"])
                    calls=[]
                    while not self.grant_calls.empty(): calls.append(self.grant_calls.get_nowait())
                    methods=[method for _, method in calls]
                    self.assertEqual(methods.count("OpenPipeWireRemote"), 4)
                    self.assertEqual(methods.count("ConnectToEIS"), 1 if mode.startswith("eis-") else 0)
                    sender=calls[0][0]
                    with self.mutex: peers=list(self.sockets[sender])
                    peers[-1].settimeout(2)
                    self.assertEqual(peers[-1].recv(1), b"", "Abandoned future retained its connection endpoint")
                    for peer in peers[:-1]:
                        with self.assertRaises(BlockingIOError): peer.recv(1, socket.MSG_DONTWAIT)
                    out,err=child.communicate("stop\n",timeout=5)
                    self.assertEqual(child.returncode,0,out+err)
                    final=json.loads(out)
                    for field in ("stopped","allConnectionsRevoked","connectionDescriptorsStillOwned",
                                  "revocationBroadcastPersistsAfterRead","afterStopDenied"):
                        self.assertTrue(final[field],final)
                finally:
                    if child.poll() is None: child.kill(); child.communicate(timeout=5)

    @contextlib.contextmanager
    def connection_client(self):
        with self.mutex: type(self).mode = "connections-valid"
        child=subprocess.Popen([PROBE,"--grant-connections-command"],
            env=dict(os.environ,DBUS_SESSION_BUS_ADDRESS=self.address),stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            ready=self.command_observation(child)
            self.assertTrue(ready["granted"] and ready["heldConnectionsValid"],ready)
            while not self.grant_calls.empty(): self.grant_calls.get_nowait()
            yield child
        finally:
            if child.poll() is None: child.kill(); child.communicate(timeout=5)
            for stream in (child.stdin,child.stdout,child.stderr): stream.close()

    def hold_fresh_connection(self,child):
        with self.mutex: type(self).mode = "hold-OpenPipeWireRemote"
        self.command_observation(child,"open")
        sender,method=self.grant_calls.get(timeout=5)
        self.assertEqual(method,"OpenPipeWireRemote")
        with self.mutex: event=self.held_events.setdefault((sender,method),threading.Event())
        self.assertTrue(event.wait(2),"Provider did not retain the actual method invocation")
        with self.mutex: return sender,self.held_grants[(sender,method)]

    def test_fresh_connection_errors_preserve_the_existing_grant(self):
        for mode in ("connections-method-error","missing-fd","invalid-fd-index","wrong-fd-type"):
            with self.subTest(mode=mode),self.connection_client() as child:
                with self.mutex: type(self).mode = mode
                self.command_observation(child,"open")
                result=self.command_observation(child,"get")
                self.assertEqual(result["connectionFailure"],"method" if mode=="connections-method-error" else "invalid-response")
                self.assertTrue(result["granted"] and result["heldConnectionsValid"],result)
                self.assertTrue(self.command_observation(child,"stop")["stopped"])
                child.stdin.close();self.assertEqual(child.wait(timeout=5),0)

    def test_fresh_pending_result_is_settled_by_stop_and_late_fd_is_closed(self):
        with self.connection_client() as child:
            sender,invocation=self.hold_fresh_connection(child)
            stopped=self.command_observation(child,"stop")
            self.assertTrue(stopped["stopped"] and stopped["allFuturesSettled"],stopped)
            self.assertFalse(stopped["heldConnectionsValid"])
            result=self.command_observation(child,"get")
            self.assertEqual(result["connectionFailure"],"cancelled")
            with self.mutex: event=self.closed_events.setdefault(sender,threading.Event())
            self.assertTrue(event.wait(2),"Private session owner survived Stop")
            own,exported=socket.socketpair()
            try:
                descriptors=Gio.UnixFDList.new();descriptors.append(exported.fileno());exported.close()
                invocation.return_value_with_unix_fd_list(GLib.Variant("(h)",(0,)),descriptors);del descriptors
                own.settimeout(2);self.assertEqual(own.recv(1),b"","Late fresh FD retained an endpoint")
                state=self.command_observation(child,"check")
                self.assertTrue(state["stopped"]);self.assertFalse(state["granted"])
                child.stdin.close();self.assertEqual(child.wait(timeout=5),0)
            finally:own.close();exported.close()

    def test_fresh_pending_abandoned_future_closes_later_result(self):
        with self.connection_client() as child:
            _,invocation=self.hold_fresh_connection(child)
            self.assertTrue(self.command_observation(child,"drop")["dropped"])
            own,exported=socket.socketpair()
            try:
                descriptors=Gio.UnixFDList.new();descriptors.append(exported.fileno());exported.close()
                invocation.return_value_with_unix_fd_list(GLib.Variant("(h)",(0,)),descriptors);del descriptors
                own.settimeout(2);self.assertEqual(own.recv(1),b"","Abandoned pending future retained its eventual FD")
                state=self.command_observation(child,"check")
                self.assertTrue(state["granted"] and state["heldConnectionsValid"],state)
                self.command_observation(child,"stop")
                child.stdin.close();self.assertEqual(child.wait(timeout=5),0)
            finally:own.close();exported.close()

    def test_fresh_queued_and_pending_futures_settle_before_stop_returns(self):
        with self.mutex: type(self).mode = "connections-valid"
        result=subprocess.run([PROBE,"--grant-connections-stop-race"],
            env=dict(os.environ,DBUS_SESSION_BUS_ADDRESS=self.address),capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        observation=json.loads(result.stdout)
        self.assertTrue(observation["stopped"] and observation["allFuturesSettled"] and observation["allConnectionsRevoked"],observation)

    def test_grant_waiting_for_permission_remains_cancellable(self):
        with self.mutex: type(self).mode = "wait-response-Start"
        child = subprocess.Popen([PROBE, "--grant-command"], env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for stream in (child.stdin, child.stdout, child.stderr): self.addCleanup(stream.close)
        try:
            end = time.monotonic() + 5
            while True:
                observation = self.command_observation(child, "check")
                if observation["waitingPermission"]: break
                self.assertLess(time.monotonic(), end, "Start method handle never became accepted")
            self.assertFalse(observation["granted"])
            stopped = self.command_observation(child, "stop")
            self.assertTrue(stopped["stopped"])
            self.assertTrue(stopped["descriptorsUnavailableAfterStop"])
            child.stdin.close(); self.assertEqual(child.wait(timeout=5), 0)
        finally:
            if child.poll() is None: child.kill(); child.communicate(timeout=5)

    def test_grant_late_descriptors_after_stop_cannot_restore_authority(self):
        with self.mutex: type(self).mode = "hold-OpenPipeWireRemote"
        child = subprocess.Popen([PROBE, "--grant-command"], env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for stream in (child.stdin, child.stdout, child.stderr): self.addCleanup(stream.close)
        own = None
        try:
            while True:
                sender, method = self.grant_calls.get(timeout=5)
                if method == "OpenPipeWireRemote": break
            self.assertTrue(self.command_observation(child, "stop")["stopped"])
            with self.mutex: event = self.closed_events.setdefault(sender, threading.Event())
            self.assertTrue(event.wait(2))
            with self.mutex: invocation = self.held_grants[(sender, method)]
            own, exported = socket.socketpair()
            descriptors = Gio.UnixFDList.new(); descriptors.append(exported.fileno()); exported.close()
            invocation.return_value_with_unix_fd_list(GLib.Variant("(h)", (0,)), descriptors)
            del descriptors
            own.settimeout(2)
            self.assertEqual(own.recv(1), b"", "Late descriptor retained an authority endpoint")
            after = self.command_observation(child, "check")
            self.assertTrue(after["stopped"])
            self.assertFalse(after["granted"])
            self.assertTrue(after["descriptorsUnavailableAfterStop"])
            child.stdin.close(); self.assertEqual(child.wait(timeout=5), 0)
        finally:
            if own is not None: own.close()
            if child.poll() is None: child.kill(); child.communicate(timeout=5)

    def test_actual_native_positive_properties(self):
        report = self.run_probe(0)
        self.assertTrue(report["ready"])
        self.assertEqual([report[k] for k in ("remoteVersion", "screenVersion", "devices", "sources", "cursorModes")],
                         [1, 4, 3, 3, 7])
        self.assertEqual([self.calls.get(timeout=2)[1] for _ in range(2)], [REMOTE, SCREEN])

    def test_property_failures_are_terminal(self):
        for mode in ("wrong-type", "zero-version", "missing-property", "duplicate-property", "method-error"):
            with self.subTest(mode=mode):
                with self.mutex: type(self).mode = mode
                report = self.run_probe(1)
                self.assertFalse(report["ready"])
                self.assertTrue(report["error"])
                self.assertEqual(report["failure"], "method" if mode == "method-error" else "invalid-response")

    def test_old_interface_absence_is_unknown_not_zero(self):
        with self.mutex: type(self).mode = "screen-v1"
        report = self.run_probe(0)
        self.assertEqual(report["screenVersion"], 1)
        self.assertIsNone(report["cursorModes"])

    def test_no_bus_does_not_autolaunch_or_hang(self):
        env = dict(os.environ)
        env.pop("DBUS_SESSION_BUS_ADDRESS", None)
        report = self.run_probe(1, env)
        self.assertEqual(report["error"], "Session bus address unavailable")

    def test_invalid_bus_address_is_terminal(self):
        report = self.run_probe(1, dict(os.environ, DBUS_SESSION_BUS_ADDRESS="invalid-address"))
        self.assertFalse(report["ready"])
        self.assertTrue(report["error"])

    def test_never_reply_can_be_stopped_on_actual_pending_call(self):
        with self.mutex: type(self).mode = "never-reply"
        child = subprocess.Popen([PROBE, "--command"], env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for stream in (child.stdin, child.stdout, child.stderr): self.addCleanup(stream.close)
        try:
            sender, requested = self.calls.get(timeout=5)
            self.assertEqual(requested, REMOTE)
            started = time.monotonic()
            out, err = child.communicate("stop\n", timeout=5)
            self.assertEqual(child.returncode, 0, err)
            self.assertTrue(json.loads(out)["stopped"])
            self.assertLess(time.monotonic() - started, 2, "Cancellation blocked behind the unreturned method")
            names = self.connection.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                "ListNames", None, GLib.VariantType.new("(as)"), Gio.DBusCallFlags.NONE, 2000, None).unpack()[0]
            self.assertNotIn(sender, names, "Native private connection survived Stop")
        finally:
            if child.poll() is None: child.kill(); child.communicate(timeout=5)

    def test_portal_owner_loss_invalidates_pending_query(self):
        with self.mutex: type(self).mode = "never-reply"
        child = subprocess.Popen([PROBE], env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for stream in (child.stdout, child.stderr): self.addCleanup(stream.close)
        try:
            self.calls.get(timeout=5)
            self.connection.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                "ReleaseName", GLib.Variant("(s)", (SERVICE,)), GLib.VariantType.new("(u)"),
                Gio.DBusCallFlags.NONE, 2000, None)
            out, err = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 1, err)
            self.assertEqual(json.loads(out)["error"], "Portal owner changed")
            self.assertEqual(json.loads(out)["failure"], "transport")
        finally:
            if child.poll() is None: child.kill(); child.communicate(timeout=5)
            self.connection.call_sync("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                "RequestName", GLib.Variant("(su)", (SERVICE, 0)), GLib.VariantType.new("(u)"),
                Gio.DBusCallFlags.NONE, 2000, None)

    def test_z_bus_loss_is_terminal(self):
        with self.mutex: type(self).mode = "never-reply"
        child = subprocess.Popen([PROBE], env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for stream in (child.stdout, child.stderr): self.addCleanup(stream.close)
        try:
            self.calls.get(timeout=5)
            self.daemon.terminate()
            self.daemon.wait(timeout=5)
            out, err = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 1, err)
            self.assertFalse(json.loads(out)["ready"])
            self.assertTrue(json.loads(out)["error"])
        finally:
            if child.poll() is None: child.kill(); child.communicate(timeout=5)


if __name__ == "__main__": unittest.main()
