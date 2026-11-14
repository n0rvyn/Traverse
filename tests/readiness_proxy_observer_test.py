"""Actual native observer through final gateway with distinct public/probe roots."""
from pathlib import Path
import http.client,json,os,ssl,subprocess,sys,unittest
GATEWAY=Path(sys.argv[9]).resolve()
import readiness_observer_media_test as source
from installed_standalone import wait
from issuer_native import free_port

class GatewayObserverTests(source.ObserverMediaTests):
    trust_case='separate'
    def spawn(self,arguments):
        if arguments[0]==source.OBSERVER:
            path=Path(arguments[2]);configuration=json.loads(path.read_text())
            target=configuration['registrations'][0]['target']
            target['caFile']=str(self.backend_certificate if self.trust_case=='wrong-https' else self.gateway_certificate)
            target['relayCaFile']=str(self.gateway_certificate if self.trust_case=='wrong-probe' else self.backend_certificate)
            path.write_text(json.dumps(configuration))
        return super().spawn(arguments)
    def start_service(self):
        self.media_port=self.port;backend=free_port();frontend=free_port()
        self.backend_certificate=self.certificate;self.backend_context=self.context
        self.service=self.spawn([source.media.SERVICE,'--internal-http','--host','127.0.0.1','--port',str(backend),
            '--origin',self.origin,'--base-path',self.base,'--web',source.media.WEB,'--socket',str(self.adapter_socket),
            '--owner-socket',str(self.owner_socket),'--stun','','--udp-port',str(self.media_port),'--udp-only',
            '--media-readiness','--supervisor-pid',str(os.getpid())])
        wait(lambda:self.service.poll() is None and self.owner_socket.exists(),'Actual native source owner')
        self.frontend=self.spawn([str(Path(source.media.SERVICE).parent/'traverse-tls-frontend'),'--host','127.0.0.1',
            '--port',str(frontend),'--http-port',str(backend),'--turn-port',str(backend),'--cert',str(self.certificate),
            '--key',str(self.key),'--expected-domain',source.media.fixture.DOMAIN,'--trust-file',str(self.certificate),
            '--trust-directory','','--probe-socket',str(self.private/'mp'),'--probe-owner-pid',str(self.service.pid)])
        cert=self.private/'gateway.pem';key=self.private/'gateway.key';self.gateway_certificate=cert
        subprocess.run(['openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','1',
            '-subj','/CN='+source.media.fixture.DOMAIN,'-addext','subjectAltName=DNS:'+source.media.fixture.DOMAIN,
            '-addext','basicConstraints=critical,CA:TRUE','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        for path in (cert,key):path.chmod(0o600);os.chown(path,self.uid,self.uid)
        if os.environ.get('TRAVERSE_GATEWAY_SAME_CA')=='1':
            cert=self.certificate;key=self.key;self.gateway_certificate=cert
        self.context=ssl.create_default_context(cafile=str(cert))
        routes=[{'match':[{'tls':{'traverse_probe':{}}}],
                 'handle':[{'handler':'proxy','upstreams':[{'dial':['127.0.0.1:'+str(frontend)]}]}]},
                {'handle':[{'handler':'tls','connection_policies':[{'alpn':['h2','http/1.1']}]}]}]
        proxy={'handler':'reverse_proxy','upstreams':[{'dial':'127.0.0.1:'+str(frontend)}],
               'transport':{'protocol':'http','tls':{'server_name':source.media.fixture.DOMAIN,
                            'ca':{'provider':'file','pem_files':[str(self.backend_certificate)]}}}}
        configuration={'admin':{'disabled':True},'storage':{'module':'file_system','root':str(self.private/'storage')},'apps':{
            'tls':{'certificates':{'load_files':[{'certificate':str(cert),'key':str(key)}]}},
            'http':{'servers':{'gateway':{'listen':['127.0.0.1:'+str(self.port)],'protocols':['h1','h2'],
                'automatic_https':{'disable':True},'logs':{},'listener_wrappers':[{'wrapper':'layer4','routes':routes}],
                'routes':[{'match':[{'path':[self.base+'*']}],'handle':[proxy]}]}}}}}
        path=self.private/'gateway.json';path.write_text(json.dumps(configuration));os.chown(path,self.uid,self.uid)
        self.gateway=self.spawn([str(GATEWAY),'run','--config',str(path)])
        self.gateway_log=self.logs[-1]
        def ready():
            self.assertIsNone(self.gateway.poll());self.assertIsNone(self.frontend.poll())
            try:return self.public('',method='GET')[0]==200
            except (OSError,ssl.SSLError,http.client.HTTPException):return False
        wait(ready,'Gateway HTTPS with strict independent backend root')
    def test_interim_header_wire(self):
        import socket
        body=json.dumps({'padding':'x'*2048}).encode()
        with self.context.wrap_socket(socket.create_connection(('127.0.0.1',self.port),timeout=3),server_hostname=source.media.fixture.DOMAIN) as stream:
            stream.sendall(('POST '+self.base+'api/readiness/media/offer HTTP/1.1\r\nHost: '+source.media.fixture.DOMAIN+':'+str(self.port)+'\r\nOrigin: '+self.origin+'\r\nExpect: 100-continue\r\nContent-Type: application/json\r\nContent-Length: '+str(len(body))+'\r\nConnection: close\r\n\r\n').encode())
            reader=stream.makefile('rb');sent=False;responses=[]
            for _ in range(4):
                line=reader.readline();self.assertTrue(line)
                status=int(line.split()[1]);names=[]
                while True:
                    header=reader.readline();self.assertTrue(header)
                    if header==b'\r\n':break
                    names.append(header.split(b':',1)[0].decode())
                responses.append({'status':status,'headerNames':names})
                if status>=200:break
                if not sent:stream.sendall(body);sent=True
            print(json.dumps({'actualGatewayInterimResponses':responses}),flush=True)
            self.assertGreaterEqual(responses[-1]['status'],200)
    def manager_result(self,process):
        try:return super().manager_result(process)
        finally:
            self.gateway_log.flush();self.gateway_log.seek(0)
            for line in self.gateway_log:
                try:row=json.loads(line)
                except ValueError:continue
                request=row.get('request',{})
                safe={key:row[key] for key in ('msg','status','duration','error') if key in row}
                if request:safe['request']={key:request[key] for key in ('method','uri','proto') if key in request}
                print(json.dumps(safe),flush=True)
    def observer_api(self,*args,**kwargs):
        previous=self.context;self.context=self.backend_context
        try:return super().observer_api(*args,**kwargs)
        finally:self.context=previous
    def test_wrong_probe_root_cannot_verify_relay(self):
        snapshot=self.manager_result(self.start_manager())
        self.assertEqual(snapshot['status'],'verified',snapshot)
        self.assertNotEqual(snapshot['media'],'verified',snapshot)
        rows=snapshot['mediaChecks']['addresses']
        self.assertTrue(any(row['mode']=='relay' and row['status']!='verified' for row in rows),snapshot)
        self.assertEqual(source.children(self.service.pid),[]);self.assertEqual(source.children(self.observer.pid),[])
    def test_wrong_https_root_cannot_be_rescued_by_probe_root(self):
        snapshot=self.manager_result(self.start_manager())
        self.assertNotEqual(snapshot['status'],'verified',snapshot)
        self.assertTrue(any(row['status']=='tlsFailed' for row in snapshot['addresses']),snapshot)
        self.assertEqual(source.children(self.service.pid),[]);self.assertEqual(source.children(self.observer.pid),[])

suite=unittest.TestSuite()
for name,trust in [('test_actual_manager_checks_both_paths_and_cleans','separate'),
                   ('test_genuine_pair_preempts_manager_and_cleans_all_known_ids','separate'),
                   ('test_wrong_probe_root_cannot_verify_relay','wrong-probe'),
                   ('test_wrong_https_root_cannot_be_rescued_by_probe_root','wrong-https')]:
    case=GatewayObserverTests(name);case.trust_case=trust;suite.addTest(case)
assert suite.countTestCases()==4
if os.environ.get('TRAVERSE_GATEWAY_WIRE')=='1':
    suite=unittest.TestSuite([GatewayObserverTests('test_interim_header_wire')])
elif os.environ.get('TRAVERSE_GATEWAY_SAME_CA')=='1':
    suite=unittest.TestSuite([GatewayObserverTests('test_actual_manager_checks_both_paths_and_cleans')])
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(not result.wasSuccessful())
