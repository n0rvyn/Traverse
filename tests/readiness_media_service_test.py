"""Actual adapter, trusted HTTPS media leases, and genuine pairing priority."""
import json
import concurrent.futures
import os
from pathlib import Path
import secrets
import select
import socket
import sys
import time
import threading
import unittest
import ssl
import hashlib
import struct
import ipaddress
import subprocess
import tempfile
from installed_turn import attribute,exchange,COOKIE
WORKER,SERVICE,ADAPTER,OWNER,WEB=sys.argv[1:6]
from readiness_media_transport_test import Worker,config,available_port
import readiness_service_test as fixture
sys.argv=[sys.argv[0]]
fixture.PREFIX=None;fixture.SERVICE=SERVICE;fixture.ADAPTER=ADAPTER;fixture.OWNER=OWNER
fixture.WEB=WEB;fixture.XVFB='/usr/bin/Xvfb'

class MediaServiceTests(fixture.ReadinessServiceFixture):
    media_enabled=True
    def setUp(self):
        self.media_port=available_port()
        super().setUp()
    def spawn(self,arguments):
        previous=self.native_env
        if arguments[0]==SERVICE:
            arguments=arguments+['--media-probe-socket',str(self.private/'mp')]
            self.native_env=dict(previous)
            if os.environ.get('TRAVERSE_MEDIA_DEBUG'):
                self.native_env['GST_DEBUG']='webrtcbin:5'
        try:return super().spawn(arguments)
        finally:self.native_env=previous
    def reserve(self,id=None):
        id=id or secrets.token_hex(16)
        status,row=self.private_call('/media/reserve',dict(schemaVersion=1,id=id))
        self.assertEqual(status,200,row);return row['lease']
    def body(self,lease,**extra):
        return dict(schemaVersion=1,instance=lease['instance'],id=lease['id'],nonce=lease['nonce'],**extra)
    def events(self,lease,cursor=0,token=None):
        return self.public('api/readiness/media/events',self.body(lease,cursor=cursor),token=token or lease['token'])
    def source_pids(self):
        found=[]
        for task in (Path('/proc')/str(self.service.pid)/'task').iterdir():
            for child in (task/'children').read_text().split():
                try:
                    if Path(f'/proc/{child}/exe').resolve()==Path(WORKER).resolve():found.append(int(child))
                except FileNotFoundError:pass
        return found
    def source_pid(self):
        found=self.source_pids();self.assertEqual(len(found),1);return found[0]
    def gather(self,observer):
        offer=None;candidates=[];gathered=False;deadline=time.monotonic()+8
        while not(offer and gathered):
            self.assertLess(time.monotonic(),deadline)
            value=observer.read();self.assertNotEqual(value['type'],'failure',value)
            if value['type']=='description':offer={key:value[key] for key in ('schemaVersion','type','kind','sdp')}
            elif value['type']=='candidate':candidates.append({key:value[key] for key in ('schemaVersion','type','index','candidate')})
            elif value['type']=='gathering' and value['state']==2:gathered=True
        return offer,candidates
    def start_media(self,lease,observer_port=None,extra_peers=(),relay=None,automatic=False):
        observer_port=observer_port or available_port((self.media_port,))
        observer_config=config('observer',observer_port,self.media_port,lease['nonce'])
        if relay:observer_config['relay']=relay
        observer=Worker(observer_config,self.private,environment=self.native_env,identity=self.identity)
        try:
            offer,candidates=self.gather(observer)
            fields=dict(line.split(':',1) for line in Path(f'/proc/{observer.process.pid}/status').read_text().splitlines() if ':' in line)
            self.assertEqual(set(map(int,fields['Uid'].split())),{self.uid})
            for key in ('CapEff','CapPrm','CapInh','CapAmb'):self.assertEqual(int(fields[key],16),0)
            grant=config('source',self.media_port,observer_port,lease['nonce']);grant['peer']=lease['id']
            grant['peers']+=list(extra_peers)
            if relay:
                status,owned=self.private_call('/media/allocations',dict(schemaVersion=1,id=lease['id']))
                self.assertEqual(status,200,owned)
                for peer in owned['peers']:
                    if peer not in grant['peers']:grant['peers'].append(peer)
            if automatic:
                forbidden=available_port(tuple(peer['port'] for peer in grant['peers'])+(self.media_port,observer_port))
                extra=dict(schemaVersion=1,type='candidate',index=0,candidate=f'candidate:unowned 1 UDP 100 127.0.0.1 {forbidden} typ relay')
                status,_=self.public('api/readiness/media/offer',self.body(lease,description=offer,candidates=candidates+[extra]),token=lease['token'])
                self.assertEqual(status,400);self.assertEqual(self.source_pids(),[])
            else:
                status,row=self.private_call('/media/prepare',dict(schemaVersion=1,id=lease['id'],config=grant))
                self.assertEqual(status,200,row)
            status,row=self.public('api/readiness/media/offer',self.body(lease,description=offer,candidates=candidates),token=lease['token'])
            self.assertEqual(status,202,row)
            cursor=0;received={};deadline=time.monotonic()+12
            while len(received)<2 and time.monotonic()<deadline:
                status,row=self.events(lease,cursor);self.assertEqual(status,200,row);cursor=row['cursor']
                for value in row['events']:
                    kind=value['type'];self.assertNotEqual(kind,'failure',value)
                    if kind in ('description','candidate'):
                        keys=('schemaVersion','type','kind','sdp') if kind=='description' else ('schemaVersion','type','index','candidate')
                        observer.send({key:value[key] for key in keys})
                    elif kind=='received':received['source']=value
                if select.select([observer.process.stdout],[],[],0.01)[0]:
                    value=observer.read();self.assertNotEqual(value['type'],'failure',value)
                    if value['type']=='received':received['observer']=value
            self.assertEqual(set(received),{'source','observer'})
            self.assertTrue(received['observer']['videoDecoded'])
            self.last_media_receipts=received;self.last_observer_port=observer_port
            if relay:
                self.assertEqual(received['observer']['transport']['local']['type'],3)
                self.assertEqual(received['source']['transport']['remote']['port'],received['observer']['transport']['local']['port'])
            return observer,self.source_pid()
        except BaseException:observer.close();raise
    def test_purpose_authority_invalid_pair_and_genuine_pair_preemption(self):
        lease=self.reserve();https=self.begin()
        self.assertEqual(self.events(lease,token=https['token'])[0],403)
        self.assertEqual(self.public('api/readiness/challenge',dict(schemaVersion=1,id=https['id'],nonce=https['nonce']),token=lease['token'])[0],403)
        self.assertEqual(self.public('api/pair',dict(code=lease['token']))[0],403)
        observer,pid=self.start_media(lease)
        try:
            self.assertEqual(self.public('api/pair',dict(code='wrong'))[0],403)
            self.assertTrue(Path(f'/proc/{pid}').exists())
            self.assertEqual(self.events(lease)[0],200)
            authority=self.authority();self.assertEqual(authority['codeStatus'],'available')
            status,paired=self.public('api/pair',dict(code=authority['code']));self.assertEqual(status,200,paired)
            self.assertFalse(Path(f'/proc/{pid}').exists(),'Pair replied before synthetic source reap')
            with socket.socket(type=socket.SOCK_DGRAM) as witness:witness.bind(('127.0.0.1',self.media_port))
            self.assertEqual(self.events(lease)[0],403)
            self.assertEqual(self.private_call('/media/reserve',dict(schemaVersion=1,id=secrets.token_hex(16)))[0],409)
            self.assertEqual(self.events(lease,token=paired['token'])[0],403)
            self.assertTrue(self.adapter_state()['paired'])
        finally:observer.close(remote_ended=True)
    def test_cancel_before_reserve_and_frozen_grant(self):
        id=secrets.token_hex(16)
        self.assertEqual(self.private_call('/media/end',dict(schemaVersion=1,id=id))[0],200)
        self.assertEqual(self.private_call('/media/reserve',dict(schemaVersion=1,id=id))[0],409)
        lease=self.reserve();grant=config('source',self.media_port,available_port((self.media_port,)),lease['nonce']);grant['peer']=lease['id']
        self.assertEqual(self.private_call('/media/prepare',dict(schemaVersion=1,id=lease['id'],config=grant))[0],200)
        changed=dict(grant,peers=[dict(address='127.0.0.1',port=available_port((self.media_port,grant['peers'][0]['port'])))])
        self.assertEqual(self.private_call('/media/prepare',dict(schemaVersion=1,id=lease['id'],config=changed))[0],409)
        self.assertEqual(self.private_call('/media/end',dict(schemaVersion=1,id=lease['id']))[0],200)
        self.assertEqual(self.events(lease)[0],403)
    def test_genuine_pair_races_prepared_offer(self):
        lease=self.reserve();observer_port=available_port((self.media_port,))
        observer=Worker(config('observer',observer_port,self.media_port,lease['nonce']),self.private,environment=self.native_env,identity=self.identity)
        try:
            description,candidates=self.gather(observer)
            grant=config('source',self.media_port,observer_port,lease['nonce']);grant['peer']=lease['id']
            self.assertEqual(self.private_call('/media/prepare',dict(schemaVersion=1,id=lease['id'],config=grant))[0],200)
            barrier=threading.Barrier(2);code=self.authority()['code']
            def offer():
                barrier.wait()
                return self.public('api/readiness/media/offer',self.body(lease,description=description,candidates=candidates),token=lease['token'])
            def pair():
                barrier.wait();return self.public('api/pair',dict(code=code))
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                offer_result=pool.submit(offer);pair_result=pool.submit(pair)
                self.assertEqual(pair_result.result()[0],200)
                self.assertIn(offer_result.result()[0],(202,403,409))
            self.assertEqual(self.source_pids(),[],'Source survived acknowledged controller priority')
            self.assertEqual(self.events(lease)[0],403)
            with socket.socket(type=socket.SOCK_DGRAM) as witness:witness.bind(('127.0.0.1',self.media_port))
            self.assertEqual(self.private_call('/media/reserve',dict(schemaVersion=1,id=lease['id']))[0],409)
        finally:observer.close()
    def relay_lifecycle(self,ending):
        frontend=self.spawn([str(Path(SERVICE).parent/'traverse-tls-frontend'),'--host','127.0.0.1','--port','0',
            '--http-port',str(self.port),'--turn-port',str(self.port),'--cert',str(self.certificate),'--key',str(self.key),
            '--expected-domain',fixture.DOMAIN,'--trust-file',str(self.certificate),'--trust-directory','',
            '--probe-socket',str(self.private/'mp'),'--probe-owner-pid',str(self.service.pid)])
        # The normal spawn helper intentionally discards stdout. Inspect the
        # actual child-owned TCP listener rather than introducing a port guess.
        from installed_turn import sockets
        deadline=time.monotonic()+5;public_port=None
        while public_port is None:
            self.assertIsNone(frontend.poll());self.assertLess(time.monotonic(),deadline)
            for protocol,address in sockets(frontend.pid):
                if protocol=='tcp':public_port=int(address.rsplit(':',1)[1],16)
            if public_port is None:time.sleep(.01)
        lease=self.reserve();observer_port=available_port((self.media_port,))
        grant=config('source',self.media_port,observer_port,lease['nonce']);grant['peer']=lease['id']
        status,row=self.private_call('/media/relay',dict(schemaVersion=1,id=lease['id'],config=grant))
        self.assertEqual(status,202,row);relay=row['relay']
        while True:
            status,row=self.events(lease);self.assertEqual(status,200,row)
            if any(event['type']=='relayReady' for event in row['events']):break
            self.assertLess(time.monotonic(),deadline);time.sleep(.01)
        context=ssl.create_default_context(cafile=str(self.certificate));context.set_alpn_protocols([relay['alpn']])
        with context.wrap_socket(socket.create_connection(('127.0.0.1',public_port),timeout=3),server_hostname=fixture.DOMAIN) as allocation:
            self.assertEqual(allocation.selected_alpn_protocol(),relay['alpn'])
            requested=attribute(0x19,b'\x11\0\0\0');_,challenge,error=exchange(allocation,3,requested);self.assertEqual(error,401)
            auth=attribute(6,relay['username'].encode())+attribute(0x14,challenge[0x14])+attribute(0x15,challenge[0x15])
            key=hashlib.md5(relay['username'].encode()+b':'+challenge[0x14]+b':'+relay['credential'].encode()).digest()
            _,answer,error=exchange(allocation,3,requested+auth,key);self.assertIsNone(error)
            raw=answer[0x16];address=str(ipaddress.IPv4Address(struct.unpack('!I',raw[4:8])[0]^COOKIE));port=struct.unpack('!H',raw[2:4])[0]^(COOKIE>>16)
            status,row=self.private_call('/media/allocations',dict(schemaVersion=1,id=lease['id']))
            self.assertEqual(status,200,row);self.assertIn(dict(address=address,port=port),row['peers'])
            bad=dict(grant,peers=grant['peers']+[dict(address='127.0.0.1',port=available_port((port,observer_port,self.media_port)))])
            self.assertEqual(self.private_call('/media/prepare',dict(schemaVersion=1,id=lease['id'],config=bad))[0],400)
            # Native observer TURN client traverses verified TLS on that same
            # frontend, and relay-only policy must decode actual video.
            bridge_error=tempfile.TemporaryFile();self.logs.append(bridge_error)
            bridge_binary=os.environ.get('TRAVERSE_TEST_TLS_RELAY_DRIVER',str(Path(SERVICE).parent/'probe-tls-relay-driver'))
            bridge=subprocess.Popen([bridge_binary],stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,stderr=bridge_error,env=self.native_env,bufsize=0,**self.identity)
            def bridge_command(body):
                bridge.stdin.write((json.dumps(body)+'\n').encode())
                self.assertTrue(select.select([bridge.stdout],[],[],5)[0]);line=bridge.stdout.readline();self.assertTrue(line)
                return json.loads(line)
            def close_bridge():
                try:
                    if bridge.poll() is None:
                        result=bridge_command(dict(op='stop'));self.assertEqual(result['started'],result['finished'])
                        bridge.stdin.close();bridge.stdin=None
                    self.assertEqual(bridge.wait(timeout=5),0)
                    bridge_error.seek(0);self.assertEqual(bridge_error.read(),b'')
                finally:
                    if bridge.poll() is None:bridge.kill();bridge.wait(timeout=5)
                    if bridge.stdin:bridge.stdin.close()
                    bridge.stdout.close()
            self.addCleanup(close_bridge)
            local=bridge_command(dict(address='127.0.0.1',hostname=fixture.DOMAIN,ca=str(self.certificate),alpn=relay['alpn'],port=public_port))
            observer,pid=self.start_media(lease,observer_port,[dict(address=address,port=port)],
                dict(port=local['port'],username=relay['username'],credential=relay['credential']),automatic=True)
            children=[]
            for task in Path(f'/proc/{self.service.pid}/task').iterdir():children+=list(map(int,(task/'children').read_text().split()))
            self.assertEqual(len(children),2)
            try:
                if ending=='pair':
                    self.assertEqual(self.public('api/pair',dict(code=self.authority()['code']))[0],200)
                    for child in children:self.assertFalse(Path(f'/proc/{child}').exists())
                else:
                    self.service.kill();self.assertEqual(self.service.wait(timeout=5),-9)
                    from installed_standalone import alive,wait
                    wait(lambda:not any(alive(child) for child in children),'Owned source/relay survived service death',timeout=5)
                try:self.assertEqual(allocation.recv(1),b'')
                except ConnectionResetError:pass
                for local,used in ((address,port),('127.0.0.1',self.media_port)):
                    with socket.socket(type=socket.SOCK_DGRAM) as reclaimed:reclaimed.bind((local,used))
                with self.assertRaises(ssl.SSLError):
                    with context.wrap_socket(socket.create_connection(('127.0.0.1',public_port),timeout=3),server_hostname=fixture.DOMAIN):pass
            finally:observer.close(remote_ended=True)
    def test_service_relay_owned_grant_and_pair_reaps_every_child(self):
        self.relay_lifecycle('pair')
    def test_service_death_revokes_live_relay_and_source(self):
        self.relay_lifecycle('owner-death')
    def test_genuine_pair_during_relay_setup(self):
        frontend=self.spawn([str(Path(SERVICE).parent/'traverse-tls-frontend'),'--host','127.0.0.1','--port','0',
            '--http-port',str(self.port),'--turn-port',str(self.port),'--cert',str(self.certificate),'--key',str(self.key),
            '--expected-domain',fixture.DOMAIN,'--trust-file',str(self.certificate),'--trust-directory','',
            '--probe-socket',str(self.private/'mp'),'--probe-owner-pid',str(self.service.pid)])
        deadline=time.monotonic()+5
        while not (self.private/'mp').exists():
            self.assertIsNone(frontend.poll());self.assertLess(time.monotonic(),deadline);time.sleep(.01)
        lease=self.reserve();grant=config('source',self.media_port,available_port((self.media_port,)),lease['nonce']);grant['peer']=lease['id']
        self.assertEqual(self.private_call('/media/relay',dict(schemaVersion=1,id=lease['id'],config=grant))[0],202)
        self.assertEqual(self.public('api/pair',dict(code=self.authority()['code']))[0],200)
        from installed_standalone import children
        self.assertEqual(children(self.service.pid),[],'Relay creation survived acknowledged priority')
        self.assertEqual(self.events(lease)[0],403)

if __name__=='__main__':unittest.main()
