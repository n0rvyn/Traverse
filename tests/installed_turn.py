"""Actual installed/relocated private TURN server: auth, ACL, UDP and channel data.

Development test only. It opens temporary loopback sockets, never a public service.
"""
import ctypes
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

COOKIE = 0x2112a442


def attribute(kind, data):
    return struct.pack('!HH', kind, len(data))+data+b'\0'*((-len(data)) % 4)


def packet(kind, attrs, key=None):
    transaction = os.urandom(12)
    header = struct.pack('!HHI12s', kind, len(attrs)+(24 if key else 0), COOKIE, transaction)
    integrity = attribute(8, hmac.new(key, header+attrs, hashlib.sha1).digest()) if key else b''
    return header+attrs+integrity, transaction


def receive(stream, count):
    data = b''
    while len(data) < count:
        chunk = stream.recv(count-len(data))
        assert chunk, 'Unexpected TURN EOF'
        data += chunk
    return data


def read_message(stream, transaction=None, key=None):
    header = receive(stream, 20)
    kind, length, cookie, returned = struct.unpack('!HHI12s', header)
    assert cookie == COOKIE and (transaction is None or returned == transaction)
    body = receive(stream, length)
    attrs, offset, integrity = {}, 0, None
    while offset < len(body):
        tag, size = struct.unpack('!HH', body[offset:offset+4])
        assert offset+4+size <= len(body)
        attrs[tag] = body[offset+4:offset+4+size]
        if tag == 8:
            integrity = offset
        offset += 4+((size+3)//4)*4
    error = attrs.get(9)
    code = (error[2] & 7)*100+error[3] if error else None
    if key and code not in (401, 438):
        assert integrity is not None, f'Authenticated TURN response omitted integrity (error {code})'
        adjusted = struct.pack('!HHI12s', kind, integrity+24, cookie, returned)
        assert hmac.compare_digest(attrs[8], hmac.new(key, adjusted+body[:integrity], hashlib.sha1).digest())
    return kind, attrs, code


def exchange(stream, kind, attrs, key=None):
    data, transaction = packet(kind, attrs, key)
    stream.sendall(data)
    return read_message(stream, transaction, key)


def peer(address, port):
    return attribute(0x12, struct.pack('!BBHI', 0, 1, port ^ (COOKIE >> 16),
                                     int(ipaddress.IPv4Address(address)) ^ COOKIE))


def sockets(pid):
    inodes = set()
    for fd in Path(f'/proc/{pid}/fd').iterdir():
        try:
            link = os.readlink(fd)
            if link.startswith('socket:['):
                inodes.add(link[8:-1])
        except FileNotFoundError:
            pass
    found = []
    for protocol in ['tcp', 'tcp6', 'udp', 'udp6']:
        for line in Path('/proc/net/'+protocol).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[9] in inodes and (protocol.startswith('udp') or fields[3] == '0A'):
                found.append((protocol, fields[1]))
    return found


def main():
    prefix = Path(sys.argv[1] if len(sys.argv) > 1 else '/opt/traverse').resolve()
    manifest = json.loads((prefix/'share/traverse/runtime-manifest.json').read_text())
    version = next(x['version'] for x in manifest['sources'] if x['name'] == 'coturn')
    binary = prefix/'libexec/traverse/turnserver'
    env = dict(os.environ, LD_LIBRARY_PATH=str(prefix/'lib'))
    result = subprocess.run([str(binary), '--version'], env=env, capture_output=True, text=True, timeout=5, check=True)
    assert result.stdout.strip() == version
    with socket.socket(type=socket.SOCK_DGRAM) as route:
        route.connect(('192.0.2.1', 9)) # Select local route, send no packet.
        local_ip = route.getsockname()[0]
    assert not ipaddress.ip_address(local_ip).is_loopback
    with tempfile.TemporaryDirectory(prefix='traverse-installed-turn-') as tmp:
        directory = Path(tmp)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        username, password = 'test-'+secrets.token_hex(8), secrets.token_hex(32)
        config = directory/'turn.conf'
        config.write_text(f'''listening-ip=127.0.0.1
relay-ip={local_ip}
listening-port={port}
no-udp
no-tls
dtls=false
cli=false
web-admin=false
no-tcp-relay
lt-cred-mech
realm=traverse-test.invalid
user={username}:{password}
denied-peer-ip=0.0.0.0-255.255.255.255
denied-peer-ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
allowed-peer-ip={local_ip}
no-multicast-peers
pidfile=turn.pid
userdb=turn.sqlite
log-file=turn.log
simple-log
relay-threads=1
''')
        config.chmod(0o600)
        libc, parent = ctypes.CDLL(None), os.getpid()
        def guard():
            if libc.prctl(1, signal.SIGTERM, 0, 0, 0) or os.getppid() != parent:
                os._exit(125)
        report = {'version': version, 'checks': []}
        with (directory/'output.log').open('w+') as log:
            process = subprocess.Popen([str(binary), '-c', str(config)], env=env, cwd=directory,
                                       stdout=log, stderr=log, preexec_fn=guard)
            try:
                deadline = time.monotonic()+10
                while True:
                    assert process.poll() is None, 'Private TURN process exited at startup'
                    try:
                        connection = socket.create_connection(('127.0.0.1', port), timeout=1)
                        break
                    except OSError:
                        assert time.monotonic() < deadline, 'Private TURN listener did not start'
                        time.sleep(.02)
                with connection as stream, socket.socket(type=socket.SOCK_DGRAM) as witness:
                    stream.settimeout(5)
                    initial = sockets(process.pid)
                    assert set(initial) == {('tcp', f'0100007F:{port:04X}')}, initial
                    report['checks'].append('Only the configured loopback TCP listener; no UDP/TLS/admin/prometheus listeners')
                    witness.bind((local_ip, 0))
                    witness.settimeout(5)
                    witness_port = witness.getsockname()[1]
                    requested = attribute(0x19, b'\x11\0\0\0')
                    _, challenge, code = exchange(stream, 3, requested)
                    assert code == 401
                    auth = attribute(6, username.encode())+attribute(0x14, challenge[0x14])+attribute(0x15, challenge[0x15])
                    wrong = hashlib.md5(username.encode()+b':'+challenge[0x14]+b':test-wrong-password').digest()
                    assert exchange(stream, 3, requested+auth, wrong)[2] == 401
                    key = hashlib.md5(username.encode()+b':'+challenge[0x14]+b':'+password.encode()).digest()
                    kind, allocation, code = exchange(stream, 3, requested+auth, key)
                    assert kind == 0x0103 and code is None and 0x16 in allocation
                    report['checks'].append('Missing/wrong credentials rejected; authenticated allocation and response integrity verified')
                    destination = peer(local_ip, witness_port)
                    assert exchange(stream, 8, destination+auth, key)[0] == 0x0108
                    for address in ['127.0.0.1', '169.254.169.254', '192.0.2.1']:
                        kind, _, code = exchange(stream, 8, peer(address, witness_port)+auth, key)
                        assert kind == 0x0118 and code == 403, (address, kind, code)
                    report['checks'].append('Same-host peer allowed; loopback, metadata and unrelated external peer permissions denied')
                    payload = b'test-real-turn-datagram'
                    stream.sendall(packet(0x0016, destination+attribute(0x13, payload))[0])
                    data, relay = witness.recvfrom(65536)
                    assert data == payload
                    witness.sendto(b'test-udp-reply', relay)
                    kind, attrs, _ = read_message(stream)
                    assert kind == 0x0017 and attrs[0x13] == b'test-udp-reply'
                    channel = 0x4001
                    kind, _, _ = exchange(stream, 9, attribute(0x0c, struct.pack('!HH', channel, 0))+destination+auth, key)
                    assert kind == 0x0109
                    payload = b'test-channel-data'
                    stream.sendall(struct.pack('!HH', channel, len(payload))+payload+b'\0'*((-len(payload)) % 4))
                    data, relay = witness.recvfrom(65536)
                    assert data == payload
                    reply = b'test-channel-reply'
                    witness.sendto(reply, relay)
                    number, size = struct.unpack('!HH', receive(stream, 4))
                    assert number == channel and receive(stream, size) == reply
                    receive(stream, (-size) % 4)
                    report['checks'].append('Real independent UDP echo and bidirectional ChannelData forwarded without corruption')
                    assert exchange(stream, 4, attribute(0x0d, struct.pack('!I', 0))+auth, key)[0] == 0x0104
                    report['checks'].append('Test allocation explicitly released')
            except BaseException:
                log.seek(0)
                diagnostic = log.read()
                for file in directory.glob('turn*.log'):
                    diagnostic += file.read_text(errors='replace')
                print(diagnostic.replace(password, '[redacted]').replace(username, '[test-user]'), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait()
                    raise AssertionError('Owned TURN process did not stop gracefully')
            assert process.returncode == 0
        report['peerBoundary'] = 'IP allowlist; no destination-port isolation claim'
        print(json.dumps(report))


if __name__ == '__main__':
    main()
