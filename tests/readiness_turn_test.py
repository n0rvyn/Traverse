"""Actual private probe coturn port authority; no public services or desktop.

Run as root in an isolated build/test namespace so children can use UID65534.
"""
import hashlib,hmac,ipaddress,json,os,secrets,select,socket,struct,subprocess,tempfile,time,sys
from pathlib import Path
from installed_turn import attribute,exchange,packet,peer,receive,sockets,COOKIE,read_message
BINARY=Path(sys.argv[1]).resolve()

def indication_payload(stream):
    first=receive(stream,4);kind,length=struct.unpack('!HH',first)
    if 0x4000<=kind<=0x7fff:
        return receive(stream,(length+3)&~3)[:length]
    header=first+receive(stream,16)
    assert struct.unpack('!I',header[4:8])[0]==COOKIE
    body=receive(stream,length);offset=0;attrs={}
    while offset<len(body):
        tag,size=struct.unpack('!HH',body[offset:offset+4]);assert offset+4+size<=len(body)
        attrs[tag]=body[offset+4:offset+4+size];offset+=4+((size+3)&~3)
    assert kind==0x0017,kind
    return attrs[0x0013]

def owned_listener(process,port):
    assert process.poll() is None,('Synthetic TURN exited',process.returncode)
    return any(proto=='tcp' and int(address.rsplit(':',1)[1],16)==port for proto,address in sockets(process.pid))

def ipv6_policy():
    # IPv6 XOR-PEER-ADDRESS includes the transaction ID. Build each request with
    # a fresh ID rather than transplanting IPv4 fixture bytes.
    def request(stream,kind,items,key=None):
        transaction=os.urandom(12);attrs=b''
        for tag,value in items:
            if tag==0x12:
                address,port=value;mask=struct.pack('!I',COOKIE)+transaction
                packed=socket.inet_pton(socket.AF_INET6,address)
                value=struct.pack('!BBH',0,2,port^(COOKIE>>16))+bytes(a^b for a,b in zip(packed,mask))
            attrs+=attribute(tag,value)
        header=struct.pack('!HHI12s',kind,len(attrs)+(24 if key else 0),COOKIE,transaction)
        stream.sendall(header+attrs+(attribute(8,hmac.new(key,header+attrs,hashlib.sha1).digest()) if key else b''))
        return transaction
    with tempfile.TemporaryDirectory(prefix='probe-turn-v6-') as temporary:
        root=Path(temporary);root.chmod(0o755);os.chown(root,65534,65534)
        with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as allowed,socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as forbidden,socket.socket() as reserved:
            for witness in (allowed,forbidden):witness.bind(('::1',0));witness.settimeout(3)
            reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1]
            port_a,port_b=allowed.getsockname()[1],forbidden.getsockname()[1]
            username,password='probe-v6-'+secrets.token_hex(8),secrets.token_hex(16)
            config=root/'turn.conf'
            config.write_text(f'listening-ip=127.0.0.1\nlistening-port={port}\nrelay-ip=::1\nno-udp\nno-tls\ndtls=false\ncli=false\nweb-admin=false\nallow-loopback-peers\nlt-cred-mech\nrealm=probe.test\nuser={username}:{password}\ndenied-peer-ip=0.0.0.0-255.255.255.255\ndenied-peer-ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\nallowed-peer-ip=::1\nprobe-peer-port={port_a}\nrelay-threads=1\npidfile=turn.pid\nlog-file=turn.log\nsimple-log\n')
            config.chmod(0o600);os.chown(config,65534,65534);reserved.close()
            with (root/'output').open('w+b') as log:
                process=subprocess.Popen([str(BINARY),'-c',str(config)],cwd=root,user=65534,group=65534,extra_groups=[],stdout=log,stderr=log)
                try:
                    deadline=time.monotonic()+10
                    while not owned_listener(process,port):
                        assert time.monotonic()<deadline;time.sleep(.01)
                    with socket.create_connection(('127.0.0.1',port),timeout=3) as stream:
                        stream.settimeout(3)
                        allocation=[(0x19,b'\x11\0\0\0'),(0x17,b'\x02\0\0\0')]
                        tx=request(stream,3,allocation);_,challenge,error=read_message(stream,tx);assert error==401
                        auth=[(6,username.encode()),(0x14,challenge[0x14]),(0x15,challenge[0x15])]
                        key=hashlib.md5(username.encode()+b':'+challenge[0x14]+b':'+password.encode()).digest()
                        tx=request(stream,3,allocation+auth,key);_,attrs,error=read_message(stream,tx,key);assert error is None,error
                        raw=attrs[0x16];assert raw[1]==2
                        mask=struct.pack('!I',COOKIE)+tx
                        relay=(socket.inet_ntop(socket.AF_INET6,bytes(a^b for a,b in zip(raw[4:],mask))),struct.unpack('!H',raw[2:4])[0]^(COOKIE>>16))
                        tx=request(stream,8,[(0x12,('::1',port_a))]+auth,key);assert read_message(stream,tx,key)[2] is None
                        request(stream,0x16,[(0x12,('::1',port_b)),(0x13,b'wrong-port')])
                        request(stream,0x16,[(0x12,('::1',port_a)),(0x13,b'allowed-v6')])
                        assert allowed.recvfrom(65536)[0]==b'allowed-v6'
                        assert not select.select([forbidden],[],[],0)[0]
                        forbidden.sendto(b'wrong-incoming',relay);allowed.sendto(b'allowed-incoming',relay)
                        assert indication_payload(stream)==b'allowed-incoming'
                        tx=request(stream,9,[(0xc,struct.pack('!HH',0x4001,0)),(0x12,('::1',port_b))]+auth,key)
                        assert read_message(stream,tx,key)[2]==403
                        tx=request(stream,9,[(0xc,struct.pack('!HH',0x4002,0)),(0x12,('::1',port_a))]+auth,key)
                        assert read_message(stream,tx,key)[2] is None
                        stream.sendall(struct.pack('!HH',0x4002,8)+b'channel6')
                        assert allowed.recvfrom(65536)[0]==b'channel6'
                        # Omitting no-tcp-relay from this fixture proves that the
                        # probe role itself rejects TCP allocations.
                    with socket.create_connection(('127.0.0.1',port),timeout=3) as stream:
                        stream.settimeout(3);tcp=[(0x19,b'\x06\0\0\0')]
                        tx=request(stream,3,tcp);_,challenge,error=read_message(stream,tx);assert error==401
                        auth=[(6,username.encode()),(0x14,challenge[0x14]),(0x15,challenge[0x15])]
                        tx=request(stream,3,tcp+auth,key);assert read_message(stream,tx,key)[2]==442
                except BaseException:
                    log.flush();log.seek(0);print(log.read().decode(errors='replace').replace(password,'[redacted]'));raise
                finally:
                    if process.poll() is None:process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        return dict(family='IPv6',wrongPortSendBlocked=True,wrongPortIncomingBlocked=True,wrongPortChannelBindBlocked=True,allowedChannelDataPassed=True,tcpAllocationBlocked=True)

def revocation_policy():
    with tempfile.TemporaryDirectory(prefix='probe-turn-revoke-') as temporary:
        root=Path(temporary);root.chmod(0o755);os.chown(root,65534,65534)
        with socket.socket(type=socket.SOCK_DGRAM) as witness,socket.socket() as reserved:
            witness.bind(('127.0.0.1',0));witness.settimeout(3);peer_port=witness.getsockname()[1]
            reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1];reserved.close()
            old_user,old_password='probe-old-'+secrets.token_hex(8),secrets.token_hex(16)
            identities=[(old_user,old_password),('probe-new-'+secrets.token_hex(8),secrets.token_hex(16))]
            for generation,(username,password) in enumerate(identities):
                config=root/'turn.conf'
                config.write_text(f'listening-ip=127.0.0.1\nlistening-port={port}\nrelay-ip=127.0.0.1\nno-udp\nno-tls\ndtls=false\ncli=false\nweb-admin=false\nno-tcp-relay\nallow-loopback-peers\nlt-cred-mech\nrealm=probe.test\nuser={username}:{password}\ndenied-peer-ip=0.0.0.0-255.255.255.255\ndenied-peer-ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\nallowed-peer-ip=127.0.0.1\nprobe-peer-port={peer_port}\nrelay-threads=1\npidfile=turn.pid\nlog-file=turn.log\nsimple-log\n')
                config.chmod(0o600);os.chown(config,65534,65534)
                with (root/'output').open('w+b') as log:
                    process=subprocess.Popen([str(BINARY),'-c',str(config)],cwd=root,user=65534,group=65534,extra_groups=[],stdout=log,stderr=log)
                    try:
                        deadline=time.monotonic()+10
                        while not owned_listener(process,port):
                            assert time.monotonic()<deadline;time.sleep(.01)
                        if generation:
                            # TURN binds a TCP session to its first username even
                            # after a rejected allocation. Test each identity on
                            # its own connection, as the installed path does.
                            with socket.create_connection(('127.0.0.1',port),timeout=3) as old_stream:
                                old_stream.settimeout(3);requested=attribute(0x19,b'\x11\0\0\0')
                                _,challenge,error=exchange(old_stream,3,requested);assert error==401
                                old_auth=attribute(6,old_user.encode())+attribute(0x14,challenge[0x14])+attribute(0x15,challenge[0x15])
                                old_key=hashlib.md5(old_user.encode()+b':'+challenge[0x14]+b':'+old_password.encode()).digest()
                                assert exchange(old_stream,3,requested+old_auth,old_key)[2]==401
                        with socket.create_connection(('127.0.0.1',port),timeout=3) as stream:
                            stream.settimeout(3);requested=attribute(0x19,b'\x11\0\0\0')
                            _,challenge,error=exchange(stream,3,requested);assert error==401
                            def authorization(user,secret):
                                auth=attribute(6,user.encode())+attribute(0x14,challenge[0x14])+attribute(0x15,challenge[0x15])
                                key=hashlib.md5(user.encode()+b':'+challenge[0x14]+b':'+secret.encode()).digest()
                                return auth,key
                            auth,key=authorization(username,password)
                            _,attrs,error=exchange(stream,3,requested+auth,key);assert error is None
                            raw=attrs[0x16];assert raw[1]==1
                            relay_ip=str(ipaddress.IPv4Address(struct.unpack('!I',raw[4:8])[0]^COOKIE))
                            relay_port=struct.unpack('!H',raw[2:4])[0]^(COOKIE>>16)
                            assert exchange(stream,8,peer('127.0.0.1',peer_port)+auth,key)[2] is None
                            payload=b'old-live' if not generation else b'fresh-lease'
                            stream.sendall(packet(0x16,peer('127.0.0.1',peer_port)+attribute(0x13,payload))[0])
                            assert witness.recvfrom(65536)[0]==payload
                            # Keep this actual allocated connection open across
                            # owner kill; closing the client first proves less.
                            process.kill();assert process.wait(timeout=5)==-9
                            try:assert stream.recv(1)==b''
                            except ConnectionResetError:pass
                            with socket.socket(type=socket.SOCK_DGRAM) as reclaimed:
                                reclaimed.bind((relay_ip,relay_port))
                    except BaseException:
                        log.flush();log.seek(0);text=log.read().decode(errors='replace')
                        for _,secret in identities:text=text.replace(secret,'[redacted]')
                        print(text);raise
                    finally:
                        if process.poll() is None:process.kill()
                        process.wait(timeout=5)
        return dict(liveTcpClosedOnHardKill=True,allocatedUdpPortReclaimed=True,oldCredentialsRejectedAfterRestart=True,freshCredentialsSameListenerPassed=True)

with tempfile.TemporaryDirectory(prefix='probe-turn-egress-') as temporary:
    root=Path(temporary);root.chmod(0o755)
    run=root/'run';run.mkdir(mode=0o700);os.chown(run,65534,65534)
    with socket.socket(type=socket.SOCK_DGRAM) as allowed,socket.socket(type=socket.SOCK_DGRAM) as forbidden,socket.socket() as reserved:
        for witness in (allowed,forbidden):witness.bind(('127.0.0.1',0));witness.settimeout(3)
        reserved.bind(('127.0.0.1',0));listener_port=reserved.getsockname()[1]
        port_a,port_b=allowed.getsockname()[1],forbidden.getsockname()[1]
        username,password='probe-'+secrets.token_hex(8),secrets.token_hex(16)
        reports=[]
        for enforce in (False,True):
            configuration=run/'turn.conf'
            content=f'''listening-ip=127.0.0.1
listening-port={listener_port}
relay-ip=127.0.0.1
no-udp
no-tls
dtls=false
cli=false
web-admin=false
no-tcp-relay
allow-loopback-peers
lt-cred-mech
realm=probe.test
user={username}:{password}
denied-peer-ip=0.0.0.0-255.255.255.255
denied-peer-ip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
allowed-peer-ip=127.0.0.1
relay-threads=1
pidfile=turn.pid
log-file=turn.log
simple-log
'''
            if enforce:content+=f'probe-peer-port={port_a}\n'
            if enforce:
                for conflict in ('server-relay','multiplex-peer'):
                    configuration.write_text(content+conflict+'\n');configuration.chmod(0o600);os.chown(configuration,65534,65534)
                    invalid=subprocess.run([str(BINARY),'-c',str(configuration)],cwd=run,user=65534,group=65534,extra_groups=[],capture_output=True,timeout=5)
                    assert invalid.returncode!=0,conflict
                    assert b'--probe-peer-port cannot use' in invalid.stdout+invalid.stderr,conflict
            configuration.write_text(content);configuration.chmod(0o600);os.chown(configuration,65534,65534)
            if reserved.fileno()!=-1:reserved.close()
            with (root/'synthetic-turn-output').open('w+b') as log:
                process=subprocess.Popen([str(BINARY),'-c',str(configuration)],cwd=run,user=65534,group=65534,extra_groups=[],stdout=log,stderr=log)
                try:
                    deadline=time.monotonic()+10
                    while not owned_listener(process,listener_port):
                        assert time.monotonic()<deadline,'Synthetic TURN listener did not start';time.sleep(.01)
                    with socket.create_connection(('127.0.0.1',listener_port),timeout=3) as stream:
                        stream.settimeout(3)
                        requested=attribute(0x19,b'\x11\0\0\0')
                        _,challenge,error=exchange(stream,3,requested);assert error==401
                        auth=attribute(6,username.encode())+attribute(0x14,challenge[0x14])+attribute(0x15,challenge[0x15])
                        key=hashlib.md5(username.encode()+b':'+challenge[0x14]+b':'+password.encode()).digest()
                        _,allocation,error=exchange(stream,3,requested+auth,key);assert error is None,error
                        raw=allocation[0x16];assert raw[1]==1
                        relay=(str(ipaddress.IPv4Address(struct.unpack('!I',raw[4:8])[0]^COOKIE)),struct.unpack('!H',raw[2:4])[0]^(COOKIE>>16))
                        _,_,error=exchange(stream,8,peer('127.0.0.1',port_a)+auth,key);assert error is None,error
                        def send(destination,payload):stream.sendall(packet(0x0016,peer('127.0.0.1',destination)+attribute(0x13,payload))[0])
                        send(port_b,b'forbidden-send');send(port_a,b'allowed-after-send')
                        assert allowed.recvfrom(65536)[0]==b'allowed-after-send'
                        sent_b=bool(select.select([forbidden],[],[],0)[0])
                        if sent_b:assert forbidden.recvfrom(65536)[0]==b'forbidden-send'
                        assert sent_b != enforce,('Send egress',enforce,sent_b)
                        forbidden.sendto(b'forbidden-inbound',relay);allowed.sendto(b'allowed-inbound',relay)
                        inbound_b=False
                        while True:
                            value=indication_payload(stream)
                            if value==b'allowed-inbound':break
                            assert value==b'forbidden-inbound',value;inbound_b=True
                        assert inbound_b != enforce,('Incoming peer',enforce,inbound_b)
                        bind=attribute(0x000c,struct.pack('!HH',0x4001,0))+peer('127.0.0.1',port_b)
                        _,_,error=exchange(stream,9,bind+auth,key)
                        assert (error==403) if enforce else (error is None),(enforce,error)
                        payload=b'forbidden-channel'
                        stream.sendall(struct.pack('!HH',0x4001,len(payload))+payload+b'\0'*((-len(payload))%4))
                        send(port_a,b'allowed-after-channel')
                        assert allowed.recvfrom(65536)[0]==b'allowed-after-channel'
                        channel_b=bool(select.select([forbidden],[],[],0)[0])
                        if channel_b:assert forbidden.recvfrom(65536)[0]==payload
                        assert channel_b != enforce,('Channel egress',enforce,channel_b)
                        reports.append(dict(intrinsicPortPolicy=enforce,privateBackendDirect=True,validProbeCredential=True,allowedPort=port_a,forbiddenPort=port_b,sendReachedForbidden=sent_b,incomingForbiddenDelivered=inbound_b,channelReachedForbidden=channel_b,allowedAnchorsPassed=True))
                except BaseException:
                    log.flush();log.seek(0);diagnostic=log.read().decode(errors='replace').replace(password,'[redacted]')
                    print(json.dumps(dict(syntheticFixtureFailure=diagnostic,exit=process.poll())),flush=True);raise
                finally:
                    if process.poll() is None:process.terminate()
                    try:process.wait(timeout=5)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        reports.append(ipv6_policy())
        reports.append(revocation_policy())
        print(json.dumps(dict(status='passed',scope='Private-loopback synthetic backend authority control only; no deployed app vulnerability claim',binarySha256=hashlib.sha256(BINARY.read_bytes()).hexdigest(),cases=reports)))
