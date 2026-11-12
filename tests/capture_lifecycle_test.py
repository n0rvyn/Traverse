"""Real native client negotiation against owned, nonresponsive protocol peers.

This checks cancellation/authority/resource lifetimes, not compositor pixels.
"""
import contextlib
import os
import subprocess
import sys
import time
import unittest

CAPTURE = sys.argv.pop()
import portal_session_test as portal


class CaptureLifecycle(portal.PortalCapabilities):
    @contextlib.contextmanager
    def capture_client(self):
        with self.mutex:
            type(self).mode = "connections-valid"
        child = subprocess.Popen([CAPTURE], env=dict(os.environ, DBUS_SESSION_BUS_ADDRESS=self.address),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            end = time.monotonic() + 5
            while not self.command_observation(child, "check")["granted"]:
                self.assertLess(time.monotonic(), end, "Controlled grant watchdog expired")
            self.command_observation(child, "capture")
            # Actual native PipeWire protocol bytes prove negotiation started;
            # the owned peer deliberately never sends a protocol reply.
            with self.mutex:
                peers = [peer for sockets in self.sockets.values() for peer in sockets]
            self.assertTrue(peers)
            peers[-1].settimeout(2)
            self.assertTrue(peers[-1].recv(8192), "Native provider never started its protocol")
            yield child
        finally:
            if child.poll() is None:
                child.kill();
                if child.stdin.closed: child.stdin = None
                child.communicate(timeout=5)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None: stream.close()

    def test_capture_stop_during_unanswered_protocol_and_restart(self):
        with self.capture_client() as child:
            state = self.command_observation(child, "stop-capture")
            self.assertTrue(state["granted"], state)
            self.assertEqual(state["capture"]["state"], 2, state)
            self.command_observation(child, "reset-capture")
            self.command_observation(child, "capture")
            state = self.command_observation(child, "stop-capture")
            self.assertEqual(state["generation"], 2, state)
            self.assertTrue(state["granted"], state)
            self.assertEqual(state["capture"]["state"], 2, state)
            self.assertTrue(self.command_observation(child, "stop")["stopped"])
            child.stdin.close(); self.assertEqual(child.wait(timeout=5), 0, child.stderr.read())

    def test_capture_revocation_during_unanswered_protocol(self):
        with self.capture_client() as child:
            self.command_observation(child, "revoke")
            end = time.monotonic() + 5
            while True:
                state = self.command_observation(child, "check")
                if state["capture"]["state"] == 3: break
                self.assertLess(time.monotonic(), end, state)
            self.assertFalse(state["granted"], state)
            self.assertEqual(state["capture"]["frames"], 0)
            self.command_observation(child, "stop")
            child.stdin.close(); self.assertEqual(child.wait(timeout=5), 0, child.stderr.read())

    def test_capture_revocation_wakes_idle_native_poller(self):
        with self.capture_client() as child:
            state=self.command_observation(child,"revoke-notified")
            self.assertFalse(state["granted"],state)
            self.assertEqual(state["capture"]["state"],3,state)
            self.command_observation(child,"stop")
            child.stdin.close();self.assertEqual(child.wait(timeout=5),0,child.stderr.read())

    def test_capture_immediate_constructor_stop_repeats_without_lost_authority(self):
        with self.capture_client() as child:
            self.command_observation(child, "stop-capture")
            # Test stress only: no application queue/count limit.
            for _ in range(8):
                self.command_observation(child, "reset-capture")
                state=self.command_observation(child, "capture-cancel-now")
                self.assertTrue(state["granted"],state)
                self.assertEqual(state["capture"]["state"],2,state)
                self.assertEqual(state["capture"]["frames"],0,state)
            self.command_observation(child,"stop")
            child.stdin.close();self.assertEqual(child.wait(timeout=5),0,child.stderr.read())

    def test_capture_protocol_peer_disconnect_fails_and_keeps_session_authority(self):
        with self.capture_client() as child:
            with self.mutex:
                peers=[peer for sockets in self.sockets.values() for peer in sockets]
            peers[-1].shutdown(portal.socket.SHUT_RDWR);peers[-1].close()
            end=time.monotonic()+5
            while True:
                state=self.command_observation(child,"check")
                if state["capture"]["state"]==4:break
                self.assertLess(time.monotonic(),end,state)
                time.sleep(.01)
            self.assertTrue(state["granted"],state)
            self.assertTrue(state["capture"]["error"],state)
            self.command_observation(child,"stop")
            child.stdin.close();self.assertEqual(child.wait(timeout=5),0,child.stderr.read())

    def test_capture_destructor_during_unanswered_protocol(self):
        with self.capture_client() as child:
            child.stdin.close()
            self.assertEqual(child.wait(timeout=5), 1, "Pending native capture destruction did not finish")
            diagnostic=child.stderr.read()
            self.assertNotIn("Sanitizer",diagnostic,diagnostic)
            self.assertNotIn("runtime error:",diagnostic,diagnostic)


if __name__ == "__main__":
    suite = unittest.TestSuite(CaptureLifecycle(name) for name in (
        "test_capture_stop_during_unanswered_protocol_and_restart",
        "test_capture_revocation_during_unanswered_protocol",
        "test_capture_revocation_wakes_idle_native_poller",
        "test_capture_destructor_during_unanswered_protocol",
        "test_capture_immediate_constructor_stop_repeats_without_lost_authority",
        "test_capture_protocol_peer_disconnect_fails_and_keeps_session_authority"))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
