"""Real relay-only video must never send directly from the observer UDP port.

Root only captures its isolated loopback fixture. Native actors use UID65534;
their actual successful relay packets and a separate packet anchor validate
the capture before its absence claim is accepted.
"""
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time
import unittest
import readiness_media_service_test as media


class RelayEgressTests(media.MediaServiceTests):
    def test_relay_only_has_no_direct_observer_datagrams(self):
        private=all(os.environ.get('TRAVERSE_TEST_ORIGINAL_'+kind.upper()+'_NS','').startswith(kind+':[')
            and os.readlink('/proc/self/ns/'+kind)!=os.environ['TRAVERSE_TEST_ORIGINAL_'+kind.upper()+'_NS']
            for kind in ('mnt','net','pid'))
        self.assertTrue(Path('/.dockerenv').exists() or private,'Packet capture requires an isolated fixture')
        observed=[];errors=[];stopped=threading.Event()
        with socket.socket(socket.AF_PACKET,socket.SOCK_DGRAM,socket.htons(0x0800)) as capture:
            capture.bind(('lo',0));capture.settimeout(.1)
            def collect():
                try:
                    while not stopped.is_set():
                        try:packet=capture.recv(65536)
                        except socket.timeout:continue
                        if len(packet)<28 or packet[0]>>4!=4 or packet[9]!=17:continue
                        offset=(packet[0]&15)*4
                        if len(packet)<offset+8:continue
                        source,destination=struct.unpack('!HH',packet[offset:offset+4])
                        if destination==self.media_port:observed.append(source)
                except BaseException as error:errors.append(error)
            reader=threading.Thread(target=collect);reader.start()
            try:
                self.relay_lifecycle('pair')
                relay=self.last_media_receipts['observer']['transport']['local']['port']
                observer=self.last_observer_port
                with socket.socket(type=socket.SOCK_DGRAM) as witness:
                    witness.bind(('127.0.0.1',media.available_port((self.media_port,relay,observer))))
                    anchor=witness.getsockname()[1]
                    witness.sendto(b'private-capture-anchor',('127.0.0.1',self.media_port))
                    deadline=time.monotonic()+3
                    while anchor not in observed:
                        self.assertLess(time.monotonic(),deadline,'Capture positive anchor missing');time.sleep(.01)
            finally:
                stopped.set();reader.join(timeout=3);self.assertFalse(reader.is_alive())
        self.assertEqual(errors,[])
        self.assertIn(anchor,observed)
        self.assertIn(relay,observed,'No successful relayed UDP packet was captured')
        self.assertNotIn(observer,observed,'Relay-only observer sent UDP directly to its peer')
        print('Verified decoded relay video and two packet-capture anchors; no direct observer UDP',flush=True)


if __name__=='__main__':
    if os.geteuid()!=0:
        print('Packet observer requires root in an isolated namespace; native actors remain unprivileged')
        raise SystemExit(77)
    unittest.main(defaultTest=['RelayEgressTests.test_relay_only_has_no_direct_observer_datagrams'])
