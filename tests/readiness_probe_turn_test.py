"""Actual dedicated relay ownership, admission and immediate revoke/reap.

Run unprivileged inside the existing private network/PID/mount namespace.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from installed_turn import attribute, exchange, packet, peer, COOKIE, sockets
DRIVER, TURN = map(lambda p: str(Path(p).resolve()), sys.argv[1:3])
sys.argv = sys.argv[:1]


class Owner:
    def __init__(self, port, descriptors=()):
        self.username, self.credential = secrets.token_hex(32), secrets.token_hex(32)
        self.process = subprocess.Popen([DRIVER, TURN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, pass_fds=descriptors,
            env=dict(os.environ, TRAVERSE_PARENT_SECRET='relay-parent-secret', XDG_RUNTIME_DIR='/desktop-private'))
        self.send(dict(addresses=['127.0.0.1'], port=port, username=self.username, credential=self.credential))
        self.port = self.read()['port']
        deadline = time.monotonic()+5
        while not self.inspect()['ready']:
            assert time.monotonic()<deadline, 'Relay readiness watchdog'
            time.sleep(.01)
        children = Path(f'/proc/{self.process.pid}/task/{self.process.pid}/children').read_text().split()
        assert len(children)==1, children
        self.child = int(children[0])

    def send(self, message):
        self.process.stdin.write((json.dumps(message)+'\n').encode()); self.process.stdin.flush()

    def read(self):
        assert select.select([self.process.stdout], [], [], 5)[0], 'Owner output watchdog'
        text = self.process.stdout.readline()
        assert text, ('Owner EOF', self.process.poll(), self.process.stderr.read())
        return json.loads(text)

    def inspect(self):
        self.send(dict(op='inspect')); return self.read()

    def stop(self):
        self.send(dict(op='stop')); assert self.read()==dict(stopped=True)
        assert self.process.wait(timeout=5)==0
        assert not Path(f'/proc/{self.child}').exists(), 'Stop acknowledged before reap'

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=5)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if not stream.closed: stream.close()

    def allocate(self):
        stream = socket.create_connection(('127.0.0.1', self.port), timeout=3)
        requested = attribute(0x19, b'\x11\0\0\0')
        _, challenge, error = exchange(stream, 3, requested); assert error==401
        auth = attribute(6, self.username.encode())+attribute(0x14, challenge[0x14])+attribute(0x15, challenge[0x15])
        key = hashlib.md5(self.username.encode()+b':'+challenge[0x14]+b':'+self.credential.encode()).digest()
        _, result, error = exchange(stream, 3, requested+auth, key); assert error is None
        address = result[0x16]; assert address[1]==1
        relay = (str(ipaddress.IPv4Address(struct.unpack('!I', address[4:8])[0]^COOKIE)), struct.unpack('!H', address[2:4])[0]^(COOKIE>>16))
        return stream, relay, auth, key


class DedicatedRelayTests(unittest.TestCase):
    def test_authority_owned_allocation_and_reap(self):
        with tempfile.TemporaryFile() as inherited, socket.socket(type=socket.SOCK_DGRAM) as allowed, socket.socket(type=socket.SOCK_DGRAM) as forbidden:
            allowed.bind(('127.0.0.1', 0)); allowed.settimeout(3)
            forbidden.bind(('127.0.0.1', 0)); forbidden.setblocking(False)
            owner = Owner(allowed.getsockname()[1], (inherited.fileno(), forbidden.fileno()))
            self.addCleanup(owner.close)
            child = Path(f'/proc/{owner.child}')
            status = child.joinpath('status').read_text()
            for name in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb'):
                self.assertEqual(int(next(line.split()[1] for line in status.splitlines() if line.startswith(name+':')), 16), 0)
            self.assertIn('NoNewPrivs:\t1', status)
            env = child.joinpath('environ').read_bytes()
            for value in (b'relay-parent-secret', b'/desktop-private', b'HOME='):
                self.assertNotIn(value, env)
            # Positive anchors: the actual parent descriptors remain alive.
            witnesses = {(os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in (inherited.fileno(), forbidden.fileno())}
            self.assertEqual(len(witnesses), 2)
            for descriptor in (child/'fd').iterdir():
                try: entry=descriptor.stat()
                except FileNotFoundError: continue
                self.assertNotIn((entry.st_dev, entry.st_ino), witnesses)
            self.assertNotIn(owner.credential, child.joinpath('cmdline').read_text())
            stream, relay, auth, key = owner.allocate(); self.addCleanup(stream.close)
            self.assertIn(dict(address=relay[0], port=relay[1]), owner.inspect()['allocations'])
            self.assertTrue(any(protocol=='udp' and int(address.rsplit(':',1)[1],16)==relay[1] for protocol,address in sockets(owner.child)))
            self.assertIsNone(exchange(stream, 8, peer('127.0.0.1', allowed.getsockname()[1])+auth, key)[2])
            stream.sendall(packet(0x16, peer('127.0.0.1', allowed.getsockname()[1])+attribute(0x13,b'positive-anchor'))[0])
            self.assertEqual(allowed.recvfrom(4096)[0], b'positive-anchor')
            # TURN permissions authorize an IP, not a port. The intrinsic port
            # guard rejects ChannelBind and actual Send/ChannelData forwarding.
            channel=attribute(0x0c,struct.pack('!HH',0x4001,0))
            self.assertEqual(exchange(stream, 9, channel+peer('127.0.0.1', forbidden.getsockname()[1])+auth,key)[2], 403)
            stream.sendall(packet(0x16, peer('127.0.0.1', forbidden.getsockname()[1])+attribute(0x13,b'forbidden'))[0])
            self.assertFalse(select.select([forbidden],[],[],.1)[0])
            owner.stop()
            try: self.assertEqual(stream.recv(1), b'')
            except ConnectionResetError: pass
            with socket.socket(type=socket.SOCK_DGRAM) as reclaimed:
                reclaimed.bind(relay)
            with socket.socket() as reclaimed:
                reclaimed.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); reclaimed.bind(('127.0.0.1',owner.port))

    def test_owner_death_removes_live_allocation(self):
        with socket.socket(type=socket.SOCK_DGRAM) as witness:
            witness.bind(('127.0.0.1',0)); owner=Owner(witness.getsockname()[1]); self.addCleanup(owner.close)
            stream,relay,_,_=owner.allocate();self.addCleanup(stream.close)
            self.assertIn(dict(address=relay[0],port=relay[1]),owner.inspect()['allocations'])
            owner.process.kill(); self.assertEqual(owner.process.wait(timeout=5),-9)
            try:self.assertEqual(stream.recv(1),b'')
            except ConnectionResetError:pass
            with socket.socket(type=socket.SOCK_DGRAM) as reclaimed:reclaimed.bind(relay)
            deadline=time.monotonic()+5
            while Path(f'/proc/{owner.child}/stat').exists():
                # The namespace init reaps the orphan. A zombie has no sockets
                # and is terminal, rather than an active probe process.
                if Path(f'/proc/{owner.child}/stat').read_text().split()[2]=='Z':break
                self.assertLess(time.monotonic(),deadline);time.sleep(.01)


if __name__=='__main__':
    from native_test_identity import unprivileged_media_test
    identity=unprivileged_media_test()
    unittest.main()
