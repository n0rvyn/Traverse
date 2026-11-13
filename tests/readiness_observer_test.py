"""Owned DNS/TLS/native observer boundary. All timeouts are test watchdogs."""
import argparse
import copy
import ctypes
import json
import http.client
import http.server
import ssl
import shutil
import hashlib
import os
from pathlib import Path
import selectors
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager

@contextmanager
def hosts_file(entries,remove=()):
    from installed_managed_certificates import require_disposable_environment
    require_disposable_environment()
    path=Path('/etc/hosts');original=path.read_bytes()
    rows=[]
    for line in original.decode().splitlines():
        names=line.partition('#')[0].split()[1:]
        if not any(name.lower().rstrip('.') in remove for name in names):rows.append(line)
    try:
        path.write_text('\n'.join(rows)+'\n'+entries+'\n')
        yield path
    finally:path.write_bytes(original)

class DNS:
    def __init__(self):
        from installed_managed_certificates import require_disposable_environment
        require_disposable_environment()
        self.resolver=Path('/etc/resolv.conf');self.original_resolver=self.resolver.read_bytes()
        self.resolver.write_bytes(b'nameserver 127.0.0.1\noptions attempts:1 timeout:5\n')
        self.records={};self.queries=[];self.transports=[];self.query_counts={};self.lock=threading.Lock();owner=self
        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                data,stream=self.request;answer=owner.answer(data)
                if answer is not None:stream.sendto(answer,self.client_address)
        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                stream=self.request;stream.settimeout(3)
                length=b''
                while len(length)<2:
                    part=stream.recv(2-len(length))
                    if not part:return
                    length+=part
                count=struct.unpack('!H',length)[0];data=b''
                while len(data)<count:
                    part=stream.recv(count-len(data))
                    if not part:return
                    data+=part
                answer=owner.answer(data,'tcp')
                if answer is not None:stream.sendall(struct.pack('!H',len(answer))+answer)
        class UDPServer(socketserver.ThreadingUDPServer):daemon_threads=True;allow_reuse_address=True
        class TCPServer(socketserver.ThreadingTCPServer):daemon_threads=True;allow_reuse_address=True
        self.servers=[];self.threads=[]
        try:
            self.servers.append(UDPServer(('127.0.0.1',53),UDP))
            self.servers.append(TCPServer(('127.0.0.1',53),TCP))
            for server in self.servers:
                thread=threading.Thread(target=server.serve_forever);thread.start();self.threads.append(thread)
        except BaseException:
            self.close();raise
    def answer(self,data,transport='udp'):
        if len(data)<12:return None
        offset=12;labels=[]
        while offset<len(data) and data[offset]:
            size=data[offset]
            if size>63 or offset+size+1>len(data):return None
            labels.append(data[offset+1:offset+size+1].decode('ascii'));offset+=size+1
        offset+=1
        if offset+4>len(data):return None
        kind,category=struct.unpack('!HH',data[offset:offset+4]);name='.'.join(labels).lower()
        with self.lock:
            self.queries.append((name,kind));record=self.records.get(name)
            self.transports.append((name,kind,transport))
            key=(name,kind);self.query_counts[key]=self.query_counts.get(key,0)+1
            attempt=self.query_counts[key]
            values=record.get(kind,[]) if record is not None else None
        if isinstance(values,dict) and 'afterFirst' in values:
            values=values['first'] if attempt==1 else values['afterFirst']
        if values=='drop':return None
        code=3 if values is None else 2 if values=='fail' else 0
        mode=values if isinstance(values,dict) else {}
        if mode.get('truncated') and transport=='udp':
            return data[:2]+struct.pack('!HHHHH',0x8380,1,0,0,0)+data[12:offset+4]
        def wire_name(value):return b''.join(bytes([len(label)])+label.encode() for label in value.split('.'))+b'\0'
        rows=mode.get('addresses',[]) if mode else values if isinstance(values,list) else []
        records=[]
        owner_name=mode.get('owner',name)
        if mode.get('cname'):
            alias=wire_name(mode['cname']);records.append(b'\xc0\x0c'+struct.pack('!HHIH',5,category,1,len(alias))+alias)
            owner_name=mode['cname']
        for address in rows:
            raw=socket.inet_pton(socket.AF_INET if kind==1 else socket.AF_INET6,address)
            size=len(raw)+(1 if mode.get('malformed') else 0)
            records.append(wire_name(owner_name)+struct.pack('!HHIH',kind,category,1,size)+raw)
        return data[:2]+struct.pack('!HHHHH',0x8180|code,1,len(records),0,0)+data[12:offset+4]+b''.join(records)
    def set(self,name,ipv4=None,ipv6=None):
        with self.lock:self.records[name]={1:[] if ipv4 is None else ipv4,28:[] if ipv6 is None else ipv6}
    def count(self):
        with self.lock:return len(self.queries)
    def close(self):
        try:
            for server,thread in zip(self.servers,self.threads):server.shutdown()
            for server in self.servers:server.server_close()
            for thread in self.threads:thread.join(timeout=5)
        finally:self.resolver.write_bytes(self.original_resolver)

def wait(predicate,message,timeout=5):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.01)
    raise AssertionError(message)

def clean_environment():
    env=dict(os.environ)
    for key in ('LD_LIBRARY_PATH','TRAVERSE_RUNTIME_PREFIX','GST_PLUGIN_PATH_1_0',
                'GST_PLUGIN_SYSTEM_PATH_1_0','GST_PLUGIN_SCANNER','GST_REGISTRY'):
        env.pop(key,None)
    return env

def native_environment():
    if not ARGS.prefix:return dict(os.environ)
    profile=subprocess.run([str(Path(ARGS.prefix)/'bin/traverse'),'--runtime-environment'],
        env=clean_environment(),text=True,capture_output=True,check=True)
    return dict(clean_environment(),**json.loads(profile.stdout)['environment'])

class Resolver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Refuse to bind DNS53 on the actual host. Driver supplies verified
        # original namespace identities and mounts synthetic resolver config.
        from installed_managed_certificates import require_disposable_environment
        require_disposable_environment()
        cls.dns=DNS()
    @classmethod
    def tearDownClass(cls):cls.dns.close()
    def setUp(self):self.workers=[];self.addCleanup(self.close)
    def worker(self,host,addresses):
        row=dict(schemaVersion=2,operation='resolve',target=dict(host=host,allowedAddresses=addresses))
        p=subprocess.Popen([ARGS.worker],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=native_environment(),
            user=65534,group=65534,extra_groups=[])
        self.workers.append(p);p.stdin.write(json.dumps(row).encode());p.stdin.close();p.stdin=None
        return p
    def resolve(self,host,addresses,status):
        p=self.worker(host,addresses);out,err=p.communicate(timeout=8)
        self.assertEqual(err,b'');row=json.loads(out);self.assertEqual(row['schemaVersion'],2)
        if row['status']!=status and os.environ.get('TRAVERSE_TEST_DNS_DIAGNOSTICS')=='1':
            # Passive failure evidence only; keep the worker's original verdict/assertion.
            code='''import ctypes,json,socket
libc=ctypes.CDLL(None,use_errno=True)
class Addrinfo(ctypes.Structure):pass
Addrinfo._fields_=[('flags',ctypes.c_int),('family',ctypes.c_int),('socktype',ctypes.c_int),('protocol',ctypes.c_int),('addrlen',ctypes.c_uint),('addr',ctypes.c_void_p),('canonname',ctypes.c_void_p),('next',ctypes.POINTER(Addrinfo))]
libc.getaddrinfo.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.POINTER(Addrinfo),ctypes.POINTER(ctypes.POINTER(Addrinfo))]
libc.freeaddrinfo.argtypes=[ctypes.POINTER(Addrinfo)]
libc.__h_errno_location.restype=ctypes.POINTER(ctypes.c_int)
for family in (socket.AF_INET,socket.AF_INET6):
    hints=Addrinfo();hints.family=family;hints.socktype=socket.SOCK_STREAM;answer=ctypes.POINTER(Addrinfo)()
    ctypes.set_errno(0);libc.__h_errno_location()[0]=0
    result=libc.getaddrinfo(HOST.encode(),None,ctypes.byref(hints),ctypes.byref(answer))
    receipt=dict(family=family,eai=result,errno=ctypes.get_errno(),h_errno=libc.__h_errno_location()[0])
    if answer:libc.freeaddrinfo(answer)
    print(json.dumps(receipt),flush=True)
'''
            probe=subprocess.run([sys.executable,'-c','HOST='+repr(host)+'\n'+code],
                user=65534,group=65534,extra_groups=[],env=clean_environment(),text=True,capture_output=True,timeout=8)
            files={}
            for name in ('/etc/nsswitch.conf','/etc/authselect/nsswitch.conf','/etc/resolv.conf','/usr/share/authselect/default/local/nsswitch.conf'):
                try:files[name]=Path(name).read_text()
                except OSError as error:files[name]=str(error)
            print(json.dumps(dict(dnsDiagnostic=True,expected=status,actual=row['status'],files=files,
                libc=os.confstr('CS_GNU_LIBC_VERSION'),
                probeExit=probe.returncode,probeStdout=probe.stdout,probeStderr=probe.stderr,
                records=self.dns.records[host],queries=self.dns.queries)),flush=True)
        self.assertEqual(row['status'],status);self.assertEqual(p.returncode,0 if status=='resolved' else 1)
        if status!='resolved':self.assertNotIn('addresses',row)
        return row
    def test_actual_A_AAAA_policy_and_partial_failure(self):
        host='observer-dns.example.test';self.dns.set(host,['127.0.0.1'],['::1'])
        row=self.resolve(host,['::1','127.0.0.1'],'resolved');self.assertEqual(set(row['addresses']),{'::1','127.0.0.1'})
        self.resolve(host,['127.0.0.1'],'dnsMismatch')
        self.dns.set(host,['127.0.0.1']);self.resolve(host,['127.0.0.1'],'resolved')
        self.dns.set(host,['127.0.0.1'],'fail')
        partial=self.resolve(host,['127.0.0.1'],'resolved')
        self.assertEqual(partial['resolution']['dns']['a']['status'],'answered')
        self.assertEqual(partial['resolution']['dns']['aaaa']['status'],'failed')
        self.dns.set(host,'fail',['::1'])
        partial=self.resolve(host,['::1'],'resolved')
        self.assertEqual(partial['resolution']['dns']['a']['status'],'failed')
        self.assertEqual(partial['resolution']['dns']['aaaa']['status'],'answered')
        self.dns.set(host,[],['::1']);self.resolve(host,['::1'],'resolved')
        self.resolve('absent-observer.example.test',['127.0.0.1'],'dnsFailed')
    def test_hosts_aliases_work_with_zero_dns_queries(self):
        host='observer-hosts.example.test';self.dns.set(host,'drop','drop')
        before=self.dns.count()
        for entries,addresses in (
            ('127.0.0.1 canonical.example.test OBSERVER-HOSTS.EXAMPLE.TEST # exact alias', ['127.0.0.1']),
            ('::1 observer-hosts.example.test', ['::1']),
            ('127.0.0.1 observer-hosts.example.test\n::1 observer-hosts.example.test', ['127.0.0.1','::1'])):
            with hosts_file(entries):
                row=self.resolve(host,addresses,'resolved')
                self.assertEqual(set(row['addresses']),set(addresses));self.assertEqual(row['resolution']['basis'],'hosts')
                for family in ('a','aaaa'):self.assertEqual(row['resolution']['dns'][family],dict(status='notChecked',addresses=[]))
        self.assertEqual(self.dns.count(),before,'Hosts-only lookup contacted DNS')
    def test_hosts_extra_address_and_changes_are_not_ignored(self):
        host='observer-hosts-policy.example.test';self.dns.set(host,'drop','drop')
        with hosts_file('127.0.0.1 '+host+'\n127.0.0.2 '+host):self.resolve(host,['127.0.0.1'],'dnsMismatch')
        with hosts_file('127.0.0.1 '+host):self.assertEqual(self.resolve(host,['127.0.0.1'],'resolved')['resolution']['basis'],'hosts')
        with hosts_file('127.0.0.2 '+host):self.resolve(host,['127.0.0.1'],'dnsMismatch')
    def test_other_nss_names_remain_available_without_dns_records(self):
        hosts_line=next(line for line in Path('/etc/nsswitch.conf').read_text().splitlines() if line.startswith('hosts:'))
        if 'myhostname' not in hosts_line.split():self.skipTest('This fixture has no myhostname NSS provider')
        host=socket.gethostname().lower().rstrip('.');self.dns.set(host,[],[])
        with hosts_file('',remove=(host,)):
            addresses=sorted({row[4][0] for row in socket.getaddrinfo(host,None,socket.AF_UNSPEC,socket.SOCK_STREAM)})
            row=self.resolve(host,addresses,'resolved');self.assertEqual(set(row['addresses']),set(addresses))
            self.assertEqual(row['resolution']['basis'],'system')
            for family in ('a','aaaa'):self.assertEqual(row['resolution']['dns'][family]['status'],'absent')
    def test_suppressed_aaaa_is_not_reported_as_complete_dns(self):
        libc=ctypes.CDLL(None);libc.gnu_get_libc_version.restype=ctypes.c_char_p
        version=tuple(map(int,libc.gnu_get_libc_version().decode().split('.')[:2]))
        if version<(2,36):self.skipTest('This libc predates the no-aaaa resolver option')
        host='observer-suppressed.example.test';self.dns.set(host,['127.0.0.1'],['::1'])
        previous=os.environ.get('RES_OPTIONS')
        try:
            os.environ['RES_OPTIONS']='no-aaaa'
            row=self.resolve(host,['127.0.0.1'],'resolved')
            self.assertEqual(row['resolution']['dns']['aaaa']['status'],'failed')
        finally:
            if previous is None:os.environ.pop('RES_OPTIONS',None)
            else:os.environ['RES_OPTIONS']=previous
    def test_actual_dns_cname_continuation_and_tcp_fallback(self):
        host='observer-cname.example.test';alias='observer-alias.example.test'
        self.dns.set(alias,['127.0.0.1'])
        self.dns.set(host,dict(first=['127.0.0.1'],afterFirst=dict(cname=alias)))
        row=self.resolve(host,['127.0.0.1'],'resolved')
        self.assertEqual(row['resolution']['dns']['a'],dict(status='answered',addresses=['127.0.0.1']))
        self.assertIn((alias,1),self.dns.queries,'Native resolver never followed CNAME')
        host='observer-tcp.example.test'
        self.dns.set(host,dict(first=['127.0.0.1'],afterFirst=dict(truncated=True,addresses=['127.0.0.1'])))
        row=self.resolve(host,['127.0.0.1'],'resolved')
        self.assertEqual(row['resolution']['dns']['a']['status'],'answered')
        self.assertIn((host,1,'tcp'),self.dns.transports,'Truncated UDP answer did not use TCP')
    def test_actual_dns_malformed_foreign_owner_and_cname_loop_fail(self):
        for suffix,answer in (
            ('malformed',dict(malformed=True,addresses=['127.0.0.1'])),
            ('foreign',dict(owner='unrelated.example.test',addresses=['127.0.0.1'])),
            ('loop',dict(cname='observer-loop-alias.example.test'))):
            host='observer-wire-'+suffix+'.example.test'
            if suffix=='loop':self.dns.set('observer-loop-alias.example.test',dict(cname=host))
            self.dns.set(host,dict(first=['127.0.0.1'],afterFirst=answer))
            row=self.resolve(host,['127.0.0.1'],'resolved')
            self.assertEqual(row['resolution']['dns']['a']['status'],'failed',suffix)
    def test_pending_real_resolver_cancelled(self):
        host='pending-observer.example.test';self.dns.set(host,'drop','drop');before=self.dns.count()
        p=self.worker(host,['127.0.0.1']);wait(lambda:self.dns.count()>before,'Actual native resolver query absent')
        self.assertIsNone(p.poll());p.terminate();out,err=p.communicate(timeout=5)
        self.assertEqual(p.returncode,-15);self.assertEqual(out,b'');self.assertEqual(err,b'')
    def close(self):
        for p in self.workers:
            if p.poll() is None:p.kill()
            p.wait(timeout=5)
            for pipe in (p.stdin,p.stdout,p.stderr):
                if pipe:pipe.close()

OBS_DOMAIN='observer-api.example.test'
TARGET_DOMAIN='observer-target.example.test'
REG_ID='1'*32
REG_TOKEN='2'*64
LEASE=dict(instance='a'*32,id='b'*32,token='c'*64,nonce='d'*64)

class TargetHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get('Content-Length','0')))
        self.server.observed.append((self.path,dict(self.headers),body))
        if self.server.mode=='hold':
            self.server.hold_received.set();self.connection.settimeout(5)
            try:
                while self.connection.recv(4096):pass
                self.server.hold_eof.set()
            except OSError:pass
            return
        receipt={key:value for key,value in LEASE.items() if key!='token'}
        receipt['observedMonotonicMs']=123
        if self.server.mode=='wrong':receipt['instance']='0'*32
        output=json.dumps(dict(schemaVersion=1,receipt=receipt)).encode()
        self.send_response(200);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(output)));self.end_headers();self.wfile.write(output)

class ObserverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from installed_managed_certificates import require_disposable_environment
        require_disposable_environment();cls.dns=DNS();cls.temp=tempfile.TemporaryDirectory(prefix='observer-server-')
        cls.root=Path(cls.temp.name);cls.root.chmod(0o755)
        def certificate(name,stem):
            cert=cls.root/(stem+'.pem');key=cls.root/(stem+'.key')
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN='+name,
                '-addext','subjectAltName=DNS:'+name,'-addext','basicConstraints=critical,CA:TRUE',
                '-keyout',str(key),'-out',str(cert)],check=True,env=clean_environment(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for p in (cert,key):p.chmod(0o600);os.chown(p,65534,65534)
            return cert,key
        cls.cert,cls.key=certificate(OBS_DOMAIN,'observer');cls.target_cert,cls.target_key=certificate(TARGET_DOMAIN,'target')
    @classmethod
    def tearDownClass(cls):cls.dns.close();cls.temp.cleanup()
    def setUp(self):
        self.processes=[];self.connections=[];self.targets=[];self.orphans=[]
        self.local=tempfile.TemporaryDirectory(prefix='observer-case-',dir=self.root);self.case=Path(self.local.name)
        self.case.chmod(0o700);os.chown(self.case,65534,65534);self.addCleanup(self.close)
        self.dns.set(TARGET_DOMAIN,['127.0.0.1'])
        self.target=http.server.ThreadingHTTPServer(('127.0.0.1',0),TargetHandler)
        self.target.daemon_threads=False;self.target.block_on_close=True
        self.target.observed=[];self.target.mode='normal';self.target.hold_received=threading.Event();self.target.hold_eof=threading.Event()
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(self.target_cert),str(self.target_key))
        self.target.socket=context.wrap_socket(self.target.socket,server_side=True)
        thread=threading.Thread(target=self.target.serve_forever);thread.start();self.targets.append((self.target,thread))
        with socket.socket() as s:s.bind(('127.0.0.1',0));self.port=s.getsockname()[1]
        row=dict(id=REG_ID,token=REG_TOKEN,target=dict(host=TARGET_DOMAIN,port=self.target.server_port,
            basePath='/traverse/v1.2/',caFile=str(self.target_cert),allowedAddresses=['127.0.0.1']))
        second=copy.deepcopy(row);second['id']='3'*32;second['token']='4'*64
        self.config=dict(schemaVersion=1,listenAddress='127.0.0.1',port=self.port,certificate=str(self.cert),
            privateKey=str(self.key),registrations=[row,second])
        self.path=self.case/'config.json';self.path.write_text(json.dumps(self.config));self.path.chmod(0o600);os.chown(self.path,65534,65534)
        self.server=self.start()
    def start(self,binary=None):
        p=subprocess.Popen([binary or ARGS.observer,'--config',str(self.path)],stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env=native_environment(),user=65534,group=65534,extra_groups=[]);self.processes.append(p)
        def ready():
            if p.poll() is not None:raise AssertionError('Native observer exited before trusted TLS readiness')
            try:return self.api('/v1/resolve',{},headers=[])[0]==403
            except (OSError,ssl.SSLError,http.client.HTTPException):return False
        wait(ready,'Native observer TLS startup')
        self.assertEqual(Path(f'/proc/{p.pid}/exe').resolve(),Path(binary or ARGS.observer).resolve())
        self.assertNotIn(REG_TOKEN,Path(f'/proc/{p.pid}/cmdline').read_bytes().decode())
        if ARGS.prefix:
            paths=[line.split()[-1] for line in Path(f'/proc/{p.pid}/maps').read_text().splitlines()
                if '/' in line and any(name in line.split()[-1] for name in ('libssl.so','libcrypto.so','libcpp-httplib'))]
            self.assertTrue(paths,'Installed observer TLS loading positive control absent')
            self.assertTrue(all(Path(path).is_relative_to(Path(ARGS.prefix).resolve()) for path in paths),
                'Observer TLS escaped installed package')
        return p
    def open_request(self,path,body,headers=None,encoded=False):
        context=ssl.create_default_context(cafile=str(self.cert))
        c=http.client.HTTPSConnection(OBS_DOMAIN,self.port,context=context,timeout=5)
        c.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',self.port),timeout=5),server_hostname=OBS_DOMAIN)
        self.connections.append(c)
        headers=[('X-Traverse-Registration',REG_ID),('Authorization','Bearer '+REG_TOKEN)] if headers is None else headers
        payload=body.encode() if encoded else json.dumps(body).encode()
        c.putrequest('POST',path)
        for key,value in headers:c.putheader(key,value)
        c.putheader('Content-Type','application/json');c.putheader('Content-Length',str(len(payload)));c.endheaders(payload)
        return c
    def api(self,path,body,headers=None,encoded=False):
        c=self.open_request(path,body,headers,encoded)
        try:
            response=c.getresponse();out=response.read();row=json.loads(out)
            self.assertEqual(response.getheader('Cache-Control'),'no-store')
            self.assertNotIn(REG_TOKEN.encode(),out,'Registration credential leaked')
            self.assertNotIn(LEASE['token'].encode(),out,'Probe credential leaked')
            return response.status,row
        finally:c.close()
    def child_pids(self,pid=None):
        from installed_standalone import children
        return children(pid or self.server.pid)
    def check_body(self,address='127.0.0.1'):return dict(schemaVersion=1,address=address,lease=dict(LEASE))
    def test_auth_before_decode_and_target_selection(self):
        before=self.dns.count();target_before=len(self.target.observed)
        bad_headers=[[],[('X-Traverse-Registration',REG_ID),('Authorization','Bearer bad')],
            [('X-Traverse-Registration','0'*32),('Authorization','Bearer '+REG_TOKEN)],
            [('X-Traverse-Registration','3'*32),('Authorization','Bearer '+REG_TOKEN)],
            [('X-Traverse-Registration',REG_ID),('Authorization','Bearer '+REG_TOKEN),('Authorization','Bearer '+REG_TOKEN)],
            [('X-Traverse-Registration',REG_ID),('X-Traverse-Registration',REG_ID),('Authorization','Bearer '+REG_TOKEN)],
            [('X-Traverse-Registration',REG_ID),('Authorization','Bearer '+REG_TOKEN),('Origin','https://foreign.example.test')]]
        for headers in bad_headers:self.assertEqual(self.api('/v1/check','{',headers,encoded=True)[0],403)
        self.assertEqual(self.api('/v1/check','{',encoded=True)[0],400)
        for change in (dict(address='127.0.0.2'),dict(url='https://other.example.test'),dict(caFile='/tmp/foreign')):
            body=self.check_body();body.update(change);self.assertEqual(self.api('/v1/check',body)[0],400)
        self.assertEqual(self.dns.count(),before);self.assertEqual(len(self.target.observed),target_before)
        self.assertEqual(self.child_pids(),[])
    def test_resolve_and_pinned_receipt_then_changed_DNS(self):
        code,row=self.api('/v1/resolve',dict(schemaVersion=1));self.assertEqual(code,200)
        self.assertEqual(row['status'],'resolved');self.assertEqual(row['addresses'],['127.0.0.1'])
        identity=row['observerInstance']
        code,row=self.api('/v1/check',self.check_body());self.assertEqual(code,200);self.assertEqual(row['status'],'received')
        self.assertEqual(row['observerInstance'],identity)
        self.assertTrue(all(row['receipt'][key]==LEASE[key] for key in ('id','instance','nonce')),'Observer receipt mismatch')
        self.assertEqual(self.target.observed[-1][0],'/traverse/v1.2/api/readiness/challenge')
        self.assertEqual(self.target.observed[-1][1]['Origin'],f'https://{TARGET_DOMAIN}:{self.target.server_port}')
        previous=len(self.target.observed);self.dns.set(TARGET_DOMAIN,['127.0.0.2'])
        self.assertEqual(self.api('/v1/check',self.check_body())[1]['status'],'dnsMismatch')
        self.assertEqual(len(self.target.observed),previous)
        self.dns.set(TARGET_DOMAIN,['127.0.0.1'],['::1'])
        self.assertEqual(self.api('/v1/resolve',dict(schemaVersion=1))[1]['status'],'dnsMismatch')
        self.dns.set(TARGET_DOMAIN,['127.0.0.1'],'fail')
        partial=self.api('/v1/resolve',dict(schemaVersion=1))[1]
        self.assertEqual(partial['status'],'resolved')
        self.assertEqual(partial['resolution']['dns']['aaaa']['status'],'failed')
        checked=self.api('/v1/check',self.check_body())[1]
        self.assertEqual(checked['status'],'received')
        self.assertEqual(checked['resolution'],partial['resolution'])
        self.assertEqual(self.child_pids(),[])
    def test_hosts_backed_receipt_needs_no_dns_and_rechecks_changes(self):
        self.dns.set(TARGET_DOMAIN,'drop','drop');before=self.dns.count()
        with hosts_file('127.0.0.1 canonical.example.test '+TARGET_DOMAIN):
            resolved=self.api('/v1/resolve',dict(schemaVersion=1))[1]
            self.assertEqual(resolved['status'],'resolved');self.assertEqual(resolved['resolution']['basis'],'hosts')
            checked=self.api('/v1/check',self.check_body())[1]
            self.assertEqual(checked['status'],'received');self.assertEqual(checked['resolution'],resolved['resolution'])
        self.assertEqual(self.dns.count(),before,'Hosts-backed HTTPS contacted DNS')
        contacts=len(self.target.observed)
        with hosts_file('127.0.0.2 '+TARGET_DOMAIN):
            self.assertEqual(self.api('/v1/check',self.check_body())[1]['status'],'dnsMismatch')
        self.assertEqual(len(self.target.observed),contacts,'Changed hosts contacted an unapproved target')
    def test_client_disconnect_stops_pending_DNS_and_response(self):
        self.dns.set(TARGET_DOMAIN,'drop','drop');before=self.dns.count()
        c=self.open_request('/v1/resolve',dict(schemaVersion=1))
        wait(lambda:self.dns.count()>before and self.child_pids(),'Actual observer resolver not observed')
        resolver=self.child_pids();c.close()
        wait(lambda:not self.child_pids(),'Disconnected observer resolver survived',timeout=3)
        self.assertTrue(all(not Path(f'/proc/{pid}').exists() for pid in resolver))
        self.dns.set(TARGET_DOMAIN,['127.0.0.1']);self.target.mode='hold'
        c=self.open_request('/v1/check',self.check_body())
        self.assertTrue(self.target.hold_received.wait(5),'Actual native target request absent');workers=self.child_pids()
        self.assertEqual(len(workers),1);c.close()
        wait(lambda:not self.child_pids(),'Disconnected observer HTTPS worker survived',timeout=3)
        self.assertTrue(self.target.hold_eof.wait(3),'Target did not observe worker socket EOF')
        self.assertTrue(all(not Path(f'/proc/{pid}').exists() for pid in workers))
    def test_client_disconnect_during_target_TLS(self):
        received=threading.Event();eof=threading.Event()
        class Raw(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(5)
                try:
                    if self.request.recv(4096):received.set()
                    while self.request.recv(4096):pass
                    eof.set()
                except OSError:pass
        raw=socketserver.ThreadingTCPServer(('127.0.0.1',0),Raw)
        thread=threading.Thread(target=raw.serve_forever);thread.start();self.targets.append((raw,thread))
        self.server.terminate();self.server.wait(timeout=8)
        self.config['registrations'][0]['target']['port']=raw.server_address[1]
        self.path.write_text(json.dumps(self.config));self.server=self.start()
        c=self.open_request('/v1/check',self.check_body())
        self.assertTrue(received.wait(5),'Actual target TLS ClientHello missing')
        workers=self.child_pids();self.assertEqual(len(workers),1)
        self.assertEqual(Path(f'/proc/{workers[0]}/exe').resolve(),Path(ARGS.worker).resolve())
        c.close();wait(lambda:not self.child_pids(),'TLS-pending worker survived disconnect',timeout=3)
        self.assertTrue(eof.wait(3),'Raw target socket did not close')
    def test_observer_SIGTERM_and_SIGKILL_stop_exact_workers(self):
        for kill in (False,True):
            with self.subTest(kill=kill):
                self.dns.set(TARGET_DOMAIN,'drop','drop');before=self.dns.count()
                c=self.open_request('/v1/resolve',dict(schemaVersion=1))
                wait(lambda:self.dns.count()>before and self.child_pids(),'Pending actual observer child missing')
                workers=self.child_pids();self.assertEqual(len(workers),1)
                if kill:self.server.kill()
                else:self.server.terminate()
                self.server.wait(timeout=8);self.assertEqual(self.server.returncode,-9 if kill else 0)
                c.close()
                if kill:
                    pid=workers[0];self.orphans.append(pid);outcome=[]
                    def reaped():
                        result,status=os.waitpid(pid,os.WNOHANG)
                        if result:outcome.append(status);return True
                        return False
                    wait(reaped,'Parent-death worker did not exit/reap',timeout=3)
                    self.orphans.remove(pid);self.assertTrue(os.WIFSIGNALED(outcome[0]));self.assertEqual(os.WTERMSIG(outcome[0]),15)
                else:self.assertTrue(all(not Path(f'/proc/{pid}').exists() for pid in workers))
                if not kill:self.server=self.start()
    def test_wrong_target_receipt_and_malformed_worker_result(self):
        self.target.mode='wrong';self.assertEqual(self.api('/v1/check',self.check_body())[1]['status'],'invalidReceipt')
        self.server.terminate();self.server.wait(timeout=8)
        directory=self.case/'bin';directory.mkdir();directory.chmod(0o755)
        copied=directory/'traverse-readiness-observer';shutil.copy2(ARGS.observer,copied)
        self.assertEqual(hashlib.sha256(copied.read_bytes()).digest(),hashlib.sha256(Path(ARGS.observer).read_bytes()).digest())
        stub=directory/'traverse-readiness-verifier';stub.write_text('#!/bin/sh\ncat >/dev/null\nprintf bogus\n');stub.chmod(0o755)
        self.server=self.start(str(copied));code,row=self.api('/v1/resolve',dict(schemaVersion=1))
        self.assertEqual(code,503);self.assertEqual(row['status'],'internalFailure');self.assertEqual(self.child_pids(),[])
    def test_unsafe_configuration_rejected_without_listener(self):
        self.server.terminate();self.server.wait(timeout=8)
        for mode in ('public','symlink','duplicate'):
            with self.subTest(mode=mode):
                path=self.path
                if mode=='public':path.chmod(0o644)
                elif mode=='symlink':
                    self.path.chmod(0o600);path=self.case/'config-link';path.symlink_to(self.path)
                else:
                    bad=copy.deepcopy(self.config);bad['registrations'].append(copy.deepcopy(bad['registrations'][0]))
                    self.path.write_text(json.dumps(bad));self.path.chmod(0o600)
                p=subprocess.Popen([ARGS.observer,'--config',str(path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    env=native_environment(),user=65534,group=65534,extra_groups=[]);self.processes.append(p)
                out,err=p.communicate(timeout=5);self.assertEqual(p.returncode,1);self.assertEqual(out,b'')
                self.assertEqual(err,b'Observer startup or listener failed\n')
    def close(self):
        for c in self.connections:c.close()
        for p in reversed(self.processes):
            if p.poll() is None:p.terminate()
            try:p.wait(timeout=8)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5);raise
            for pipe in (p.stdin,p.stdout,p.stderr):
                if pipe:pipe.close()
        for pid in self.orphans:
            try:os.kill(pid,9);os.waitpid(pid,0)
            except ProcessLookupError:pass
        for server,thread in self.targets:server.shutdown();server.server_close();thread.join(timeout=5)
        self.local.cleanup()

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--worker');parser.add_argument('--observer');parser.add_argument('--prefix')
    ARGS=parser.parse_args()
    if ARGS.prefix:
        ARGS.worker=str(Path(ARGS.prefix)/'libexec/traverse/traverse-readiness-verifier')
        ARGS.observer=str(Path(ARGS.prefix)/'libexec/traverse/traverse-readiness-observer')
    if not ARGS.worker:parser.error('--worker or --prefix required')
    if ctypes.CDLL(None).prctl(36,1,0,0,0):raise RuntimeError('Owned fixture subreaper setup failed')
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Resolver)
    if ARGS.observer:suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ObserverTests))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():raise SystemExit(1)
