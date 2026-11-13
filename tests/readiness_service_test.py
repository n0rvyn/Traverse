"""Actual native owner/adapter + explicitly trusted TLS readiness isolation.
All subprocess timeouts are test watchdogs. No public CA or client trust changes.
"""
import argparse
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import selectors
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from installed_standalone import free_port, wait
from owner_authority_test import UnixHTTP

DOMAIN='readiness.example.test'

class ReadinessServiceFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.clean_env=dict(os.environ)
        for key in ('LD_LIBRARY_PATH','TRAVERSE_RUNTIME_PREFIX','GST_PLUGIN_PATH_1_0',
                    'GST_PLUGIN_SYSTEM_PATH_1_0','GST_PLUGIN_SCANNER','GST_REGISTRY'):
            cls.clean_env.pop(key,None)
        cls.xlog=tempfile.TemporaryFile(mode='w+')
        cls.xvfb=subprocess.Popen([XVFB,'-displayfd','1','-screen','0','640x480x24',
            '-nolisten','tcp','-ac'],env=cls.clean_env,stdout=subprocess.PIPE,stderr=cls.xlog,text=True)
        selector=selectors.DefaultSelector()
        try:
            selector.register(cls.xvfb.stdout,selectors.EVENT_READ)
            assert selector.select(5),'Owned Xvfb readiness missing'
            number=cls.xvfb.stdout.readline().strip();assert number.isdecimal(),'Owned Xvfb failed'
            cls.display=':'+number
        except BaseException:
            cls.xvfb.kill();cls.xvfb.wait(timeout=5);cls.xvfb.stdout.close();cls.xlog.close();raise
        finally:selector.close()
    @classmethod
    def tearDownClass(cls):
        if cls.xvfb.poll() is None:cls.xvfb.terminate()
        cls.xvfb.wait(timeout=5);cls.xvfb.stdout.close();cls.xlog.close()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='readiness-service-')
        self.root=Path(self.temp.name);self.root.chmod(0o755)
        self.private=self.root/'p';self.private.mkdir(mode=0o700)
        self.uid=65534 if os.getuid()==0 else os.getuid()
        self.identity=dict(user=self.uid,group=self.uid,extra_groups=[]) if os.getuid()==0 else {}
        if os.getuid()==0:os.chown(self.private,self.uid,self.uid)
        self.port=free_port();self.origin=f'https://{DOMAIN}:{self.port}';self.base='/traverse/v1.2/'
        self.adapter_socket=self.private/'a';self.owner_socket=self.private/'s'
        self.processes=[];self.logs=[];self.service=None
        self.addCleanup(self.close)
        self.native_env=dict(os.environ)
        if PREFIX:
            profile=subprocess.run([str(Path(PREFIX)/'bin/traverse'),'--runtime-environment'],
                env=self.clean_env,text=True,capture_output=True,check=True)
            self.native_env.update(json.loads(profile.stdout)['environment'])
        self.native_env.update(DISPLAY=self.display,HOME=str(self.private),
            XDG_CACHE_HOME=str(self.private/'cache'),GST_REGISTRY=str(self.private/'registry.bin'))
        self.native_env.pop('XAUTHORITY',None)
        certificate=self.private/'certificate.pem';key=self.private/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj',f'/CN={DOMAIN}','-addext',f'subjectAltName=DNS:{DOMAIN}',
            '-addext','basicConstraints=critical,CA:TRUE','-keyout',str(key),'-out',str(certificate)],
            env=self.clean_env,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for path in (key,certificate):
            path.chmod(0o600)
            if os.getuid()==0:os.chown(path,self.uid,self.uid)
        self.certificate=certificate;self.key=key
        self.context=ssl.create_default_context(cafile=str(certificate))
        self.adapter=self.spawn([ADAPTER,'--display',self.display,'--socket',str(self.adapter_socket),'--no-dialog'])
        wait(lambda:self.adapter.poll() is None and self.adapter_socket.exists(),'Actual adapter socket')
        wait(lambda:self.adapter_state()['armed'],'Actual adapter authority')
        self.start_service()
    def spawn(self,arguments):
        log=tempfile.TemporaryFile(mode='w+');self.logs.append(log)
        p=subprocess.Popen(arguments,env=self.native_env,stdout=subprocess.DEVNULL,stderr=log,**self.identity)
        self.processes.append(p);return p
    def start_service(self):
        arguments=[SERVICE,'--host','127.0.0.1','--port',str(self.port),
            '--origin',self.origin,'--base-path',self.base,'--cert',str(self.certificate),'--key',str(self.key),
            '--web',WEB,'--socket',str(self.adapter_socket),'--owner-socket',str(self.owner_socket),
            '--stun','','--supervisor-pid',str(os.getpid())]
        if getattr(self,'media_enabled',False):arguments+=['--media-readiness']
        if hasattr(self,'media_port'):arguments+=['--udp-port',str(self.media_port),'--udp-only']
        self.service=self.spawn(arguments)
        def ready():
            if self.service.poll() is not None:raise AssertionError('Actual TLS service exited during startup')
            if not self.owner_socket.exists():return False
            try:return self.public('',method='GET')[0]==200
            except (OSError,ssl.SSLError,http.client.HTTPException):return False
        wait(ready,'Actual trusted TLS readiness service',timeout=15)
        self.assertTrue(Path(f'/proc/{self.service.pid}/exe').resolve()==Path(SERVICE).resolve(),
            'Readiness fixture executed a different service binary')
        if PREFIX:
            mappings=Path(f'/proc/{self.service.pid}/maps').read_text().splitlines()
            selected=[line.split()[-1] for line in mappings if '/' in line and
                any(name in line.split()[-1] for name in ('libgstreamer-','libnice.so','libssl.so','libcpp-httplib'))]
            self.assertTrue(selected,'Installed media/TLS loading positive control missing')
            self.assertTrue(all(Path(name).is_relative_to(Path(PREFIX).resolve()) for name in selected),
                'Installed readiness service loaded a media/TLS dependency outside its package')
    def private_call(self,route,body):
        result=subprocess.run([OWNER,str(self.owner_socket),str(self.service.pid),route],
            input=json.dumps(body),env=self.native_env,text=True,capture_output=True,timeout=8,**self.identity)
        self.assertEqual(result.returncode,0,'Native same-UID owner rejected response identity')
        row=json.loads(result.stdout);self.assertEqual(row['response']['pid'],self.service.pid)
        return row['status'],row['response']
    def begin(self):
        status,row=self.private_call('/readiness/begin',{'schemaVersion':1});self.assertEqual(status,200)
        return row['lease']
    def inspect(self,lease):return self.private_call('/readiness/inspect',{'schemaVersion':1,'id':lease['id']})
    def end(self,lease):return self.private_call('/readiness/end',{'schemaVersion':1,'id':lease['id']})
    def public(self,route,body=None,token=None,method='POST',origin=True,absolute=False,encoded=False):
        connection=http.client.HTTPSConnection(DOMAIN,self.port,context=self.context,timeout=5)
        raw=socket.create_connection(('127.0.0.1',self.port),timeout=5)
        connection.sock=self.context.wrap_socket(raw,server_hostname=DOMAIN)
        headers={'Content-Type':'application/json'}
        if origin is True:headers['Origin']=self.origin
        elif isinstance(origin,str):headers['Origin']=origin
        if token:headers['Authorization']='Bearer '+token
        try:
            connection.request(method,route if absolute else self.base+route,
                body=None if body is None else body if encoded else json.dumps(body),headers=headers)
            response=connection.getresponse();data=response.read()
            return response.status,json.loads(data) if data and response.getheader('Content-Type','').startswith('application/json') else None
        finally:connection.close()
    def challenge(self,lease,**arguments):
        return self.public('api/readiness/challenge',{'schemaVersion':1,'id':lease['id'],'nonce':lease['nonce']},
            token=arguments.pop('token',lease['token']),**arguments)
    def native_challenge(self,lease):
        request=dict(schemaVersion=1,target=dict(host=DOMAIN,port=self.port,basePath=self.base,
            address='127.0.0.1',caFile=str(self.certificate)),lease=lease)
        process=subprocess.Popen([VERIFIER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env=self.native_env,**self.identity)
        self.processes.append(process)
        try:
            def loaded():
                if process.poll() is not None:raise AssertionError('Native verifier exited before private request')
                if Path(f'/proc/{process.pid}/exe').resolve()!=Path(VERIFIER).resolve():return False
                if not PREFIX:return True
                selected=[line.split()[-1] for line in Path(f'/proc/{process.pid}/maps').read_text().splitlines()
                    if '/' in line and any(name in line.split()[-1] for name in ('libssl.so','libcrypto.so','libcpp-httplib'))]
                if not selected:return False
                self.assertTrue(all(Path(name).is_relative_to(Path(PREFIX).resolve()) for name in selected),
                    'Installed verifier TLS dependency escaped package')
                return True
            wait(loaded,'Exact native verifier loading identity')
            out,err=process.communicate(json.dumps(request).encode(),timeout=8)
            self.assertEqual(process.returncode,0,'Native verifier failed to receive valid receipt')
            self.assertEqual(err,b'','Native verifier emitted private diagnostics')
            row=json.loads(out);self.assertEqual(row['status'],'received')
            self.assertTrue(row['receipt']==self.inspect(lease)[1]['probe']['receipt'],
                'Native verifier receipt differs from native owner observation')
            return row
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=5)
            for pipe in (process.stdin,process.stdout,process.stderr):
                if pipe:pipe.close()
    def adapter_call(self,route,body=None,token=None):
        connection=UnixHTTP(str(self.adapter_socket))
        try:
            headers={'Content-Type':'application/json'}
            if token:headers['Authorization']='Bearer '+token
            connection.request('POST' if body is not None else 'GET',route,
                None if body is None else json.dumps(body),headers)
            response=connection.getresponse();self.assertEqual(response.status,200)
            return json.loads(response.read())
        finally:connection.close()
    def adapter_state(self):return self.adapter_call('/state')
    def authority(self):
        value=self.adapter_call('/owner/authority')
        return {key:value.get(key) for key in ('armed','paired','codeStatus','code','expiresMonotonicMs')}
    def query(self):
        env=dict(self.clean_env,DISPLAY=self.display);env.pop('XAUTHORITY',None)
        return json.loads(subprocess.check_output([X11_PROBE,'query'],env=env,text=True))
    def close(self):
        for p in reversed(self.processes):
            if p.poll() is None:p.terminate()
            try:p.wait(timeout=10)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5);raise
        for log in self.logs:log.close()
        self.temp.cleanup()

class ReadinessServiceTests(ReadinessServiceFixture):
    def test_real_tls_scope_replay_and_live_controller_isolation(self):
        before=self.adapter_state();authority=self.authority();lease=self.begin()
        self.assertFalse(before['capturing']);self.assertFalse(before['paired'])
        self.assertEqual(self.inspect(lease)[1]['probe']['state'],'issued')
        self.assertEqual(self.public('api/readiness/challenge','{','not-a-lease',encoded=True)[0],403)
        self.assertEqual(self.public('api/readiness/challenge','{',lease['token'],encoded=True)[0],400)
        # Correct JSON and credential in an incomplete HTTP message must not
        # consume authority before the declared body has actually arrived.
        fragment=json.dumps({'schemaVersion':1,'id':lease['id'],'nonce':lease['nonce']}).encode()
        with socket.create_connection(('127.0.0.1',self.port),timeout=5) as raw:
            with self.context.wrap_socket(raw,server_hostname=DOMAIN) as stream:
                headers=(f'POST {self.base}api/readiness/challenge HTTP/1.1\r\nHost: {DOMAIN}\r\n'
                    f'Origin: {self.origin}\r\nAuthorization: Bearer {lease["token"]}\r\n'
                    f'Content-Type: application/json\r\nContent-Length: {len(fragment)+1}\r\nConnection: close\r\n\r\n').encode()
                stream.sendall(headers+fragment)
        for body in ({},{'schemaVersion':1.0},{'schemaVersion':1,'extra':True}):
            self.assertEqual(self.private_call('/readiness/begin',body)[0],400)
        with self.assertRaises(ssl.SSLCertVerificationError):
            with socket.create_connection(('127.0.0.1',self.port),timeout=5) as raw:
                ssl.create_default_context().wrap_socket(raw,server_hostname=DOMAIN)
        with self.assertRaises(ssl.SSLCertVerificationError):
            with socket.create_connection(('127.0.0.1',self.port),timeout=5) as raw:
                self.context.wrap_socket(raw,server_hostname='different.example.test')
        for path in ('readiness/begin','owner/readiness/begin','api/readiness/begin'):
            self.assertNotEqual(self.public(path,{'schemaVersion':1})[0],200)
        for wrong in ('wrong-bearer',''):
            self.assertEqual(self.challenge(lease,token=wrong)[0],403)
        for origin in (False,'https://foreign.example.test'):
            self.assertEqual(self.challenge(lease,origin=origin)[0],403)
        for body in ({}, {'schemaVersion':1.0,'id':lease['id'],'nonce':lease['nonce']},
                     {'schemaVersion':1,'id':lease['id'],'nonce':lease['nonce'],'extra':True}):
            self.assertEqual(self.public('api/readiness/challenge',body,lease['token'])[0],400)
        wrong=dict(lease,nonce='0'*64);self.assertEqual(self.challenge(wrong)[0],403)
        self.assertIn(self.public('api/readiness/challenge',method='GET')[0],(404,405))
        self.assertIn(self.public('/api/readiness/challenge',{'schemaVersion':1},absolute=True)[0],(404,405))
        self.assertEqual(self.inspect(lease)[1]['probe']['state'],'issued')
        row=self.native_challenge(lease)
        self.assertEqual(set(row),{'schemaVersion','status','receipt'})
        self.assertEqual(set(row['receipt']),{'id','instance','nonce','observedMonotonicMs'})
        for field in ('id','instance','nonce'):
            self.assertTrue(row['receipt'][field]==lease[field],'Receipt identity mismatch: '+field)
        self.assertTrue(self.inspect(lease)[1]['probe']['receipt']==row['receipt'],'Owner receipt mismatch')
        self.assertEqual(self.challenge(lease)[0],403)
        self.assertEqual(self.adapter_state(),before)
        self.assertTrue(self.authority()==authority,'Probe changed unpaired authority')
        self.assertEqual(self.end(lease)[0],200);self.assertEqual(self.inspect(lease)[0],404)
        cancelled=self.begin();self.assertEqual(self.end(cancelled)[0],200);self.assertEqual(self.challenge(cancelled)[0],403)
        live=self.begin()
        status,pair=self.public('api/pair',{'code':authority['code']});self.assertEqual(status,200)
        controller=pair['token'];paired=self.authority()
        self.assertEqual(self.challenge(live,token=controller)[0],403)
        self.assertEqual(self.public('api/stats',token=live['token'],method='GET')[0],403)
        self.assertEqual(self.public('api/offer',{'type':'offer','sdp':''},live['token'])[0],403)
        self.adapter_call('/input',{'type':'key','code':'ShiftLeft','down':True},controller)
        self.assertEqual(self.query()['shift'],1)
        try:
            self.native_challenge(live)
            self.assertEqual(self.query()['shift'],1)
            self.assertTrue(self.authority()==paired,'Probe changed active controller authority')
            self.assertEqual(self.public('api/disconnect',{},live['token'])[0],403)
            self.assertEqual(self.public('api/stats',token=controller,method='GET')[0],200)
        finally:self.adapter_call('/input',{'type':'release'},controller)
        self.assertEqual(self.query()['shift'],0);self.assertEqual(self.end(live)[0],200)
        racing=self.begin()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(lambda _:self.challenge(racing)[0],range(8)))
        self.assertEqual(results.count(200),1);self.assertEqual(results.count(403),7)
        self.assertEqual(self.end(racing)[0],200)
        # Synthetic observer traffic must not renew the existing three-second
        # input safety lifetime. No controller heartbeat is sent in this check.
        self.adapter_call('/input',{'type':'key','code':'ShiftLeft','down':True},controller)
        self.assertEqual(self.query()['shift'],1)
        watchdog=time.monotonic()+5
        while self.query()['shift']:
            self.assertLess(time.monotonic(),watchdog,'Readiness traffic renewed input holds')
            observation=self.begin();self.assertEqual(self.challenge(observation)[0],200)
            self.assertEqual(self.end(observation)[0],200)
            time.sleep(.05)
        self.assertTrue(self.authority()==paired,'Idle safety changed controller authority')
    def test_authenticated_observer_real_owner_receipt_and_control_isolation(self):
        from readiness_observer_test import DNS
        from installed_standalone import children
        dns=DNS();observer=None
        try:
            dns.set(DOMAIN,['127.0.0.1']);observer_port=free_port()
            registration='1'*32;credential='2'*64
            configuration=dict(schemaVersion=1,listenAddress='127.0.0.1',port=observer_port,
                certificate=str(self.certificate),privateKey=str(self.key),registrations=[
                    dict(id=registration,token=credential,target=dict(host=DOMAIN,port=self.port,
                        basePath=self.base,caFile=str(self.certificate),allowedAddresses=['127.0.0.1','127.0.0.2']))])
            path=self.private/'observer.json';path.write_text(json.dumps(configuration));path.chmod(0o600)
            if os.getuid()==0:os.chown(path,self.uid,self.uid)
            def start():return self.spawn([OBSERVER,'--config',str(path)])
            def request(route,body):
                c=http.client.HTTPSConnection(DOMAIN,observer_port,context=self.context,timeout=5)
                c.sock=self.context.wrap_socket(socket.create_connection(('127.0.0.1',observer_port),timeout=5),server_hostname=DOMAIN)
                c.request('POST','/v1/'+route,json.dumps(body),dict(Authorization='Bearer '+credential,
                    **{'X-Traverse-Registration':registration,'Content-Type':'application/json'}))
                return c
            def api(route,body):
                c=request(route,body)
                try:
                    response=c.getresponse();self.assertEqual(response.status,200)
                    return json.loads(response.read())
                finally:c.close()
            def ready():
                if observer.poll() is not None:raise AssertionError('Actual observer exited')
                try:return api('resolve',dict(schemaVersion=1))['status']=='resolved'
                except (OSError,ssl.SSLError,http.client.HTTPException):return False
            observer=start();wait(ready,'Actual observer trusted TLS/DNS startup')
            self.assertEqual(Path(f'/proc/{observer.pid}/exe').resolve(),Path(OBSERVER).resolve())
            self.assertGreater(dns.count(),0,'Observer integration bypassed actual DNS')
            original=self.authority();before=self.adapter_state();lease=self.begin()
            def agent(request,expected=0,binary=None):
                process=subprocess.Popen([binary or AGENT,'--supervisor-pid',str(os.getpid())],stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.native_env,**self.identity)
                self.processes.append(process)
                output,errors=process.communicate(json.dumps(request).encode(),timeout=12)
                self.assertEqual(process.returncode,expected,errors.decode())
                self.assertNotIn(credential.encode(),output+errors)
                return [json.loads(line) for line in output.splitlines()]
            if AGENT:
                token_file=self.private/'registration.key';token_file.write_text(credential+'\n');token_file.chmod(0o600)
                if os.getuid()==0:os.chown(token_file,self.uid,self.uid)
                metadata=dict(host=DOMAIN,port=observer_port,caFile=str(self.certificate),registrationId=registration,
                    tokenFile=str(token_file),timeoutMs=10000)
                owner=dict(socket=str(self.owner_socket),pid=self.service.pid)
                resolved=agent(dict(schemaVersion=1,operation='resolve',observer=metadata))[0]
                self.assertEqual(resolved['status'],'resolved');self.assertEqual(resolved['addresses'],['127.0.0.1'])
                probe=dict(id='c'*32,address='127.0.0.1')
                checked=agent(dict(schemaVersion=1,operation='check',observer=metadata,owner=owner,
                    observerInstance=resolved['observerInstance'],probes=[probe],resolution=resolved['resolution']))[0]
                self.assertEqual(checked['status'],'received')
                finished=agent(dict(schemaVersion=1,operation='finish',owner=owner,
                    probes=[dict(id=probe['id'],receipt=checked['receipt'])]))[0]
                self.assertEqual(finished['status'],'verified');self.assertIs(finished['cancelled'],True)
                self.assertEqual(self.private_call('/readiness/inspect',dict(schemaVersion=1,id=probe['id']))[0],404)
                self.assertEqual(self.private_call('/readiness/reserve',dict(schemaVersion=1,id=probe['id']))[0],409)
                # A missing batch response still leaves a parent-known ID which the finishing agent can revoke.
                lost_id='d'*32
                self.assertEqual(self.private_call('/readiness/reserve',dict(schemaVersion=1,id=lost_id))[0],200)
                cleanup=agent(dict(schemaVersion=1,operation='finish',owner=owner,probes=[dict(id=lost_id)]))[0]
                self.assertIs(cleanup['cancelled'],True);self.assertEqual(cleanup['status'],'notObserved')
                self.assertEqual(self.private_call('/readiness/reserve',dict(schemaVersion=1,id=lost_id))[0],409)
                wrong=dict(metadata,registrationId='f'*32)
                self.assertEqual(agent(dict(schemaVersion=1,operation='resolve',observer=wrong))[0]['status'],'unauthorized')
                untrusted=dict(metadata,caFile='')
                self.assertEqual(agent(dict(schemaVersion=1,operation='resolve',observer=untrusted),1)[0]['status'],'agentFailed')
                if MANAGER:
                    for invalidate in (False,True):
                        managed=agent(dict(observer=metadata,owner=owner,agent=AGENT,invalidate=invalidate),binary=MANAGER)[0]
                        self.assertEqual(managed['snapshot']['status'],'verified')
                        self.assertEqual(managed['invalidated'],invalidate)
                        self.assertEqual(managed['snapshot']['externalReachability'],'unknown')
                        self.assertEqual(managed['snapshot']['media'],'unknown')
                        self.assertNotIn(str(token_file),json.dumps(managed))
                        self.assertNotIn('receipt',json.dumps(managed))
                        print('Actual native manager maximum tick microseconds:',managed['maximumTickUs'],flush=True)
                    timed=agent(dict(observer=dict(metadata,timeoutMs=1),owner=owner,agent=AGENT),binary=MANAGER)[0]
                    self.assertEqual(timed['snapshot']['reason'],'timeout')
                    self.assertNotEqual(timed['snapshot']['status'],'verified')
                    dns.set(DOMAIN,['127.0.0.1','127.0.0.2'])
                    partial=agent(dict(observer=metadata,owner=owner,agent=AGENT),binary=MANAGER)[0]['snapshot']
                    self.assertEqual(partial['status'],'partial')
                    self.assertEqual(sum(row['status']=='verified' for row in partial['addresses']),1)
                    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as stalled_tls:
                        stalled_tls.bind(('127.0.0.2',self.port));stalled_tls.listen(1)
                        stalled=agent(dict(observer=dict(metadata,timeoutMs=1000),owner=owner,agent=AGENT),binary=MANAGER)[0]['snapshot']
                        self.assertEqual(stalled['status'],'partial');self.assertEqual(stalled['reason'],'timeout')
                        self.assertEqual(sum(row['status']=='verified' for row in stalled['addresses']),1)
                    wait(lambda:not children(observer.pid),'Stalled-address observer worker survived batch cancellation',timeout=3)
                    dns.set(DOMAIN,['127.0.0.1'])
                    # Positive real HTTPS receipts must not conceal a failed DNS family.
                    dns.set(DOMAIN,['127.0.0.1'],'fail')
                    dns_partial=agent(dict(observer=metadata,owner=owner,agent=AGENT),binary=MANAGER)[0]['snapshot']
                    self.assertEqual(dns_partial['status'],'partial');self.assertEqual(dns_partial['reason'],'dnsFailed')
                    self.assertTrue(all(row['status']=='verified' for row in dns_partial['addresses']))
                    self.assertEqual(dns_partial['resolution']['dns']['aaaa']['status'],'failed')
                    dns.set(DOMAIN,'drop','drop');count=dns.count()
                    from readiness_observer_test import hosts_file
                    with hosts_file('127.0.0.1 '+DOMAIN):
                        lan=agent(dict(observer=metadata,owner=owner,agent=AGENT),binary=MANAGER)[0]['snapshot']
                        self.assertEqual(lan['status'],'verified');self.assertEqual(lan['resolution']['basis'],'hosts')
                        self.assertEqual(lan['resolution']['dns']['a']['status'],'notChecked')
                        self.assertEqual(dns.count(),count,'LAN check contacted DNS')
                    dns.set(DOMAIN,['127.0.0.1'])
                    # Boundary-only inherited-channel faults. The wrapper delegates
                    # real reservations/HTTPS/cleanup to the actual native agent.
                    for fault in ('duplicate','wrong-id','wrong-receipt','incomplete','exit-failure','cleanup-failure','missing-resolution','changed-resolution'):
                        wrapper=self.private/('agent-'+fault);witness=self.private/('ids-'+fault)
                        wrapper.write_text('''#!/usr/bin/python3
import json,os,subprocess,sys
from pathlib import Path
request=json.load(sys.stdin)
result=subprocess.run([AGENT,'--supervisor-pid',str(os.getpid())],input=json.dumps(request),text=True,capture_output=True)
output=result.stdout
if request['operation']=='check':
    path=Path(WITNESS)
    previous=json.loads(path.read_text()) if path.exists() else []
    path.write_text(json.dumps(previous+[p['id'] for p in request['probes']]))
    if FAULT=='duplicate':output+=output
    if FAULT in ('missing-resolution','changed-resolution'):
        rows=[json.loads(line) for line in output.splitlines()]
        for row in rows:
            if row['status']=='received':
                if FAULT=='missing-resolution':row.pop('resolution')
                else:row['resolution']['dns']['aaaa']['status']='failed'
        output=''.join(json.dumps(row)+'\\n' for row in rows)
    if FAULT=='wrong-id':
        rows=[json.loads(line) for line in output.splitlines()]
        for row in rows:row['id']='0'*32
        output=''.join(json.dumps(row)+'\\n' for row in rows)
    if FAULT=='wrong-receipt':
        rows=[json.loads(line) for line in output.splitlines()]
        for row in rows:
            if 'receipt' in row:row['receipt']['nonce']='0'*64 if row['receipt']['nonce']!='0'*64 else '1'*64
        output=''.join(json.dumps(row)+'\\n' for row in rows)
    if FAULT=='incomplete':output=''
if request['operation']=='finish' and FAULT=='cleanup-failure' and not Path(WITNESS+'.failed').exists():
    Path(WITNESS+'.failed').touch()
    rows=[json.loads(line) for line in output.splitlines()]
    for row in rows:row['cancelled']=False
    output=''.join(json.dumps(row)+'\\n' for row in rows)
sys.stdout.write(output)
sys.exit(7 if FAULT=='exit-failure' and request['operation']=='check' else result.returncode)
'''.replace('AGENT',repr(AGENT)).replace('WITNESS',repr(str(witness))).replace('FAULT',repr(fault)))
                        wrapper.chmod(0o700)
                        if os.getuid()==0:os.chown(wrapper,self.uid,self.uid)
                        managed=agent(dict(observer=metadata,owner=owner,agent=str(wrapper),retryCleanup=fault=='cleanup-failure'),binary=MANAGER)[0]
                        rejected=managed['snapshot']
                        if fault=='cleanup-failure':
                            self.assertIs(managed['cleanupRetried'],True);self.assertEqual(rejected['status'],'verified')
                        else:self.assertNotEqual(rejected['status'],'verified',fault)
                        self.assertNotEqual(rejected['status'],'cleanupPending',fault)
                        for identifier in json.loads(witness.read_text()):
                            self.assertEqual(self.private_call('/readiness/inspect',dict(schemaVersion=1,id=identifier))[0],404)
                            self.assertEqual(self.private_call('/readiness/reserve',dict(schemaVersion=1,id=identifier))[0],409)
            def check(lease):return api('check',dict(schemaVersion=1,address='127.0.0.1',lease=lease))
            row=check(lease);self.assertEqual(row['status'],'received');identity=row['observerInstance']
            self.assertTrue(row['receipt']==self.inspect(lease)[1]['probe']['receipt'],'Observer/native owner receipt mismatch')
            self.assertEqual(check(lease)['status'],'httpRejected');self.assertEqual(self.end(lease)[0],200)
            self.assertTrue(self.authority()==original,'Observer consumed unpaired authority');self.assertEqual(self.adapter_state(),before)
            status,pair=self.public('api/pair',{'code':original['code']});self.assertEqual(status,200)
            controller=pair['token'];paired=self.authority();live=self.begin()
            self.adapter_call('/input',{'type':'key','code':'ShiftLeft','down':True},controller)
            try:
                self.assertEqual(self.query()['shift'],1);self.assertEqual(check(live)['status'],'received')
                if AGENT and MANAGER:
                    managed=agent(dict(observer=metadata,owner=owner,agent=AGENT),binary=MANAGER)[0]
                    self.assertEqual(managed['snapshot']['status'],'verified')
                self.assertEqual(self.query()['shift'],1);self.assertTrue(self.authority()==paired,'Observer changed controller')
                self.assertEqual(self.public('api/stats',token=controller,method='GET')[0],200)
            finally:self.adapter_call('/input',{'type':'release'},controller)
            self.assertEqual(self.end(live)[0],200)
            if AGENT:
                known='e'*32;dns.set(DOMAIN,'drop','drop');count=dns.count()
                pending=subprocess.Popen([AGENT,'--supervisor-pid',str(os.getpid())],stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.native_env,**self.identity)
                self.processes.append(pending)
                request_body=dict(schemaVersion=1,operation='check',observer=metadata,owner=owner,
                    observerInstance=identity,probes=[dict(id=known,address='127.0.0.1')],resolution=resolved['resolution'])
                pending.stdin.write(json.dumps(request_body).encode());pending.stdin.close();pending.stdin=None
                wait(lambda:dns.count()>count and pending.poll() is None and
                    self.private_call('/readiness/inspect',dict(schemaVersion=1,id=known))[0]==200,
                    'Actual pending agent DNS and known owner reservation')
                print('Agent DNS cancellation boundary: live agent, DNS queries, reserved owner ID; observer workers:',len(children(observer.pid)),flush=True)
                self.assertEqual(self.private_call('/readiness/inspect',dict(schemaVersion=1,id=known))[0],200)
                self.assertNotIn(credential.encode(),Path(f'/proc/{pending.pid}/cmdline').read_bytes())
                self.assertNotIn(credential.encode(),Path(f'/proc/{pending.pid}/environ').read_bytes())
                pending.kill();out,err=pending.communicate(timeout=8);self.assertEqual(pending.returncode,-9)
                self.assertNotIn(credential.encode(),out+err)
                wait(lambda:not children(observer.pid),'Observer worker survived actual agent kill',timeout=3)
                cleaned=agent(dict(schemaVersion=1,operation='finish',owner=owner,probes=[dict(id=known)]))[0]
                self.assertIs(cleaned['cancelled'],True)
                self.assertEqual(self.private_call('/readiness/reserve',dict(schemaVersion=1,id=known))[0],409)
                self.assertTrue(self.authority()==paired,'Agent SIGKILL or cleanup changed controller')
                dns.set(DOMAIN,['127.0.0.1'])
            cancelled=self.begin();dns.set(DOMAIN,'drop','drop');count=dns.count()
            c=request('check',dict(schemaVersion=1,address='127.0.0.1',lease=cancelled))
            try:
                wait(lambda:dns.count()>count and children(observer.pid),'Real pending observer worker missing')
            finally:c.close()
            wait(lambda:not children(observer.pid),'Observer worker survived caller cancellation',timeout=3)
            self.assertEqual(self.end(cancelled)[0],200);self.assertEqual(self.challenge(cancelled)[0],403)
            dns.set(DOMAIN,['127.0.0.1']);observer.terminate();observer.wait(timeout=8)
            self.assertEqual(observer.returncode,0);observer=start();wait(ready,'Observer restart trusted startup')
            fresh=self.begin();row=check(fresh);self.assertEqual(row['status'],'received')
            self.assertNotEqual(row['observerInstance'],identity)
            self.assertTrue(row['receipt']==self.inspect(fresh)[1]['probe']['receipt'],'Restarted observer receipt mismatch')
            self.assertEqual(self.end(fresh)[0],200);self.assertEqual(children(observer.pid),[])
            if AGENT:
                current_instance=row['observerInstance']
                for identifier,expected_instance,changed_dns in (('8'*32,identity,False),('9'*32,current_instance,True)):
                    if changed_dns:dns.set(DOMAIN,['127.0.0.1','127.0.0.2'])
                    rejected=agent(dict(schemaVersion=1,operation='check',observer=metadata,owner=owner,
                        observerInstance=expected_instance,probes=[dict(id=identifier,address='127.0.0.1')],resolution=resolved['resolution']))[0]
                    self.assertEqual(rejected['status'],'agentFailed')
                    # Arrival at the owner alone must not make a rejected observer reply succeed.
                    inspected=self.private_call('/readiness/inspect',dict(schemaVersion=1,id=identifier))
                    self.assertEqual(inspected[1]['probe']['state'],'observed')
                    cleanup=agent(dict(schemaVersion=1,operation='finish',owner=owner,probes=[dict(id=identifier)]))[0]
                    self.assertEqual(cleanup['status'],'notObserved');self.assertIs(cleanup['cancelled'],True)
                    self.assertEqual(self.private_call('/readiness/reserve',dict(schemaVersion=1,id=identifier))[0],409)
                    dns.set(DOMAIN,['127.0.0.1'])
        finally:
            if observer is not None and observer.poll() is None:observer.terminate();observer.wait(timeout=8)
            dns.close()
    def test_cancelled_native_worker_then_owner_end_revokes_lease(self):
        lease=self.begin();before=self.authority()
        process=subprocess.Popen([VERIFIER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env=self.native_env,**self.identity)
        self.processes.append(process)
        try:
            wait(lambda:process.poll() is None and Path(f'/proc/{process.pid}/exe').resolve()==Path(VERIFIER).resolve(),
                'Exact pending verifier process')
            self.assertEqual(self.inspect(lease)[1]['probe']['state'],'issued')
            process.terminate();out,err=process.communicate(timeout=5)
            self.assertEqual(process.returncode,-15);self.assertEqual(out,b'');self.assertEqual(err,b'')
            self.assertEqual(self.end(lease)[0],200);self.assertEqual(self.challenge(lease)[0],403)
            self.assertTrue(self.authority()==before,'Cancelling readiness changed pairing authority')
            self.assertFalse(self.adapter_state()['capturing'])
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=5)
            for pipe in (process.stdin,process.stdout,process.stderr):
                if pipe:pipe.close()
    def test_known_reservations_cancel_before_creation_and_revoke_bearers(self):
        identifier='a'*32
        request={'schemaVersion':1,'id':identifier}
        for _ in range(2):self.assertEqual(self.private_call('/readiness/cancel',request)[0],200)
        self.assertEqual(self.private_call('/readiness/reserve',request)[0],409)
        self.assertEqual(self.private_call('/readiness/inspect',request)[0],404)
        identifier='b'*32;request={'schemaVersion':1,'id':identifier}
        status,row=self.private_call('/readiness/reserve',request)
        self.assertEqual(status,200);lease=row['lease'];self.assertEqual(lease['id'],identifier)
        self.assertEqual(self.private_call('/readiness/reserve',request)[0],409)
        self.assertEqual(self.challenge(lease)[0],200)
        self.assertEqual(self.private_call('/readiness/cancel',request)[0],200)
        self.assertEqual(self.challenge(lease)[0],403)
        self.assertEqual(self.private_call('/readiness/reserve',request)[0],409)
        classic=self.begin()
        self.assertEqual(self.private_call('/readiness/cancel',{'schemaVersion':1,'id':classic['id']})[0],409)
        self.assertEqual(self.challenge(classic)[0],200);self.assertEqual(self.end(classic)[0],200)
        for route in ('readiness/reserve','readiness/cancel','api/readiness/reserve','api/readiness/cancel'):
            self.assertNotEqual(self.public(route,request)[0],200)
        for route in ('/readiness/reserve','/readiness/cancel'):
            self.assertEqual(self.private_call(route,{'schemaVersion':1,'id':'invalid'})[0],400)

    def test_service_restart_revokes_old_instance(self):
        old=self.begin();self.service.terminate();self.service.wait(timeout=8)
        self.assertEqual(self.service.returncode,0);self.assertFalse(self.owner_socket.exists())
        self.start_service();fresh=self.begin()
        self.assertNotEqual(fresh['instance'],old['instance']);self.assertEqual(self.challenge(old)[0],403)
        self.assertEqual(self.inspect(old)[0],404);self.assertEqual(self.challenge(fresh)[0],200)
        self.assertEqual(self.end(fresh)[0],200);self.assertFalse(self.adapter_state()['capturing'])

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    prefix=os.environ.get('TRAVERSE_TEST_PREFIX','/opt/traverse')
    build=Path(os.environ.get('TRAVERSE_NATIVE_TEST_BUILD','/src/.work/build-native'))
    parser.add_argument('--prefix');parser.add_argument('--service');parser.add_argument('--verifier');parser.add_argument('--observer')
    parser.add_argument('--adapter');parser.add_argument('--web');parser.add_argument('--agent');parser.add_argument('--manager-probe')
    parser.add_argument('--owner-probe',default=str(build/'owner-state-probe'))
    parser.add_argument('--x11-probe',default='/tmp/x11-probe');parser.add_argument('--xvfb',default='/usr/bin/Xvfb')
    args=parser.parse_args();PREFIX=args.prefix;selected=args.prefix or prefix
    SERVICE=args.service or selected+'/libexec/traverse/traverse-service'
    ADAPTER=args.adapter or selected+'/libexec/traverse/traverse-adapter';WEB=args.web or selected+'/share/traverse/web'
    VERIFIER=args.verifier or selected+'/libexec/traverse/traverse-readiness-verifier'
    OBSERVER=args.observer or selected+'/libexec/traverse/traverse-readiness-observer'
    AGENT=args.agent
    MANAGER=args.manager_probe
    OWNER=args.owner_probe;X11_PROBE=args.x11_probe;XVFB=args.xvfb
    unittest.main(argv=[sys.argv[0]])
