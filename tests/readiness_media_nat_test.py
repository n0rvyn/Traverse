"""Native video/data across opaque, same-port IPv4/IPv6 NAT mappings.

Private namespace only. UDP forwarders copy opaque packets between two fixed
tuples; the actual unprivileged workers perform ICE, DTLS, decode and nonce
verification. No STUN service, kernel NAT module or host firewall change.
"""
import json
import os
from pathlib import Path
import secrets
import selectors
import socket
import fcntl
import struct
import sys
import tempfile
import threading
import time
import unittest
WORKER=str(Path(sys.argv[1]).resolve())
from readiness_media_transport_test import Worker,config,available_port
sys.argv=[sys.argv[0]]
V6=('fd12:7472:6176::1','2001:db8:7472::2','fd12:7472:6176::3','2001:db8:7472::4')

def address_ioctl(address,operation):
    # Linux in6_ifreq: in6_addr, u32 prefix length, int interface index.
    # Use the existing IPv6 stack directly; the retained SDK has no ip CLI.
    request=socket.inet_pton(socket.AF_INET6,address)+struct.pack('@Ii',128,socket.if_nametoindex('lo'))
    with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as control:
        fcntl.ioctl(control,operation,request)


class NatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        private=all(os.environ.get('TRAVERSE_TEST_ORIGINAL_'+kind.upper()+'_NS','').startswith(kind+':[')
            and os.readlink('/proc/self/ns/'+kind)!=os.environ['TRAVERSE_TEST_ORIGINAL_'+kind.upper()+'_NS']
            for kind in ('mnt','net','pid'))
        assert os.geteuid()==0 and (Path('/.dockerenv').exists() or private),'Private root test observer required'
        assert Path('/proc/net/if_inet6').read_text().strip(),'Existing IPv6 support required; do not load modules'
        cls.added=[]
        try:
            for address in V6:
                address_ioctl(address,0x8916) # SIOCSIFADDR, verified SDK linux/sockios.h.
                cls.added.append(address)
        except BaseException:
            cls.tearDownClass();raise
    @classmethod
    def tearDownClass(cls):
        for address in reversed(cls.added):
            address_ioctl(address,0x8936) # SIOCDIFADDR.
        cls.added=[]

    def through_mapping(self,addresses,family):
        source_private,source_public,observer_private,observer_public=addresses
        source_port=available_port();observer_port=available_port((source_port,));nonce=secrets.token_hex(32)
        with tempfile.TemporaryDirectory(prefix='traverse-native-nat-') as temporary:
            root=Path(temporary);root.chmod(0o755);cache=root/'cache';cache.mkdir(mode=0o700);os.chown(cache,65534,65534)
            environment=dict(os.environ,HOME=str(cache),XDG_CACHE_HOME=str(cache),GST_REGISTRY=str(cache/'registry.bin'))
            identity=dict(user=65534,group=65534,extra_groups=[])
            with socket.socket(family,socket.SOCK_DGRAM) as source_mapping,socket.socket(family,socket.SOCK_DGRAM) as observer_mapping:
                source_mapping.bind((source_public,source_port));observer_mapping.bind((observer_public,observer_port))
                watched=selectors.DefaultSelector();watched.register(source_mapping,selectors.EVENT_READ,'observer')
                watched.register(observer_mapping,selectors.EVENT_READ,'source')
                stopped=threading.Event();counts={'source':0,'observer':0};errors=[]
                def forward():
                    try:
                        while not stopped.is_set():
                            for key,_ in watched.select(.05):
                                packet,sender=key.fileobj.recvfrom(65536)
                                if key.data=='observer':
                                    self.assertEqual(sender[:2],(observer_private,observer_port))
                                    observer_mapping.sendto(packet,(source_private,source_port))
                                else:
                                    self.assertEqual(sender[:2],(source_private,source_port))
                                    source_mapping.sendto(packet,(observer_private,observer_port))
                                counts[key.data]+=1
                    except BaseException as error:errors.append(error)
                thread=threading.Thread(target=forward);thread.start();workers=[];selector=selectors.DefaultSelector()
                try:
                    source=config('source',source_port,observer_port,nonce)
                    source.update(addresses=[source_private],advertisedAddress=source_public,peers=[dict(address=observer_public,port=observer_port)])
                    observer=config('observer',observer_port,source_port,nonce)
                    observer.update(addresses=[observer_private],advertisedAddress=observer_public,peers=[dict(address=source_public,port=source_port)])
                    for name,settings in (('source',source),('observer',observer)):
                        worker=Worker(settings,root,environment=environment,identity=identity);workers.append(worker)
                        selector.register(worker.process.stdout,selectors.EVENT_READ,name)
                    received={};events=[];deadline=time.monotonic()+15
                    while len(received)<2 and time.monotonic()<deadline:
                        self.assertEqual(errors,[])
                        for key,_ in selector.select(max(0,deadline-time.monotonic())):
                            role=key.data;worker=workers[0 if role=='source' else 1];other=workers[1 if role=='source' else 0]
                            value=worker.read();kind=value['type'];events.append((role,kind));self.assertNotEqual(kind,'failure',value)
                            if kind in ('description','candidate'):
                                keys=('schemaVersion','type','kind','sdp') if kind=='description' else ('schemaVersion','type','index','candidate')
                                if kind=='candidate' and value['candidate']:
                                    self.assertEqual(value['candidate'].split()[4],source_public if role=='source' else observer_public)
                                other.send({field:value[field] for field in keys})
                            elif kind=='received':received[role]=value
                    self.assertEqual(set(received),{'source','observer'},events)
                    for role,value in received.items():
                        self.assertEqual(value['nonce'],nonce);self.assertTrue(value['dtlsConnected'] and value['dataVerified'])
                        self.assertEqual(value['transport']['remote']['address'],observer_public if role=='source' else source_public)
                    self.assertTrue(received['observer']['videoDecoded'])
                    self.assertTrue(all(counts.values()),counts)
                    for worker in workers:
                        fields=dict(line.split(':',1) for line in Path(f'/proc/{worker.process.pid}/status').read_text().splitlines() if ':' in line)
                        self.assertEqual(set(map(int,fields['Uid'].split())),{65534})
                        for key in ('CapEff','CapPrm','CapInh','CapAmb'):self.assertEqual(int(fields[key],16),0)
                    print(json.dumps({'family':'IPv6' if family==socket.AF_INET6 else 'IPv4','samePortNat':True,'decodedVideo':True,'opaqueDatagrams':counts}),flush=True)
                finally:
                    selector.close()
                    try:
                        for worker in workers:worker.close()
                    finally:
                        stopped.set();thread.join(timeout=3);self.assertFalse(thread.is_alive());watched.close()
                    self.assertEqual(errors,[])
                for address,port in ((source_private,source_port),(observer_private,observer_port)):
                    with socket.socket(family,socket.SOCK_DGRAM) as reclaimed:reclaimed.bind((address,port))

    def test_ipv4_same_port_nat(self):
        self.through_mapping(('127.0.0.1','127.0.0.2','127.0.0.3','127.0.0.4'),socket.AF_INET)
    def test_ipv6_same_port_nat(self):
        self.through_mapping(V6,socket.AF_INET6)


if __name__=='__main__':
    if os.geteuid()!=0:
        print('Private namespace address setup requires root; native workers remain unprivileged')
        raise SystemExit(77)
    unittest.main()
