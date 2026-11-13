"""Configured native observer -> trusted shared frontend -> real video/data.

All application processes use UID65534; root owns only private DNS and the
test fixture. This proves the actual observer API, not an outside-WAN vantage.
"""
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import ssl
import socket
import sys
import time
import unittest
import subprocess
import signal
import threading
OBSERVER,AGENT,MANAGER=sys.argv[6:9]
import readiness_media_service_test as media
from readiness_observer_test import DNS
from installed_standalone import children,wait


class ObserverMediaTests(media.MediaServiceTests):
    def start_service(self):
        self.media_port=self.port;backend=media.fixture.free_port()
        self.service=self.spawn([media.SERVICE,'--internal-http','--host','127.0.0.1','--port',str(backend),
            '--origin',self.origin,'--base-path',self.base,'--web',media.WEB,'--socket',str(self.adapter_socket),
            '--owner-socket',str(self.owner_socket),'--stun','','--udp-port',str(self.media_port),'--udp-only',
            '--media-readiness','--supervisor-pid',str(os.getpid())])
        wait(lambda:self.service.poll() is None and self.owner_socket.exists(),'Actual media source owner')
        self.frontend=self.spawn([str(Path(media.SERVICE).parent/'traverse-tls-frontend'),'--host','127.0.0.1',
            '--port',str(self.port),'--http-port',str(backend),'--turn-port',str(backend),'--cert',str(self.certificate),
            '--key',str(self.key),'--expected-domain',media.fixture.DOMAIN,'--trust-file',str(self.certificate),
            '--trust-directory','','--probe-socket',str(self.private/'mp'),'--probe-owner-pid',str(self.service.pid)])
        def ready():
            self.assertIsNone(self.service.poll());self.assertIsNone(self.frontend.poll())
            try:return self.public('',method='GET')[0]==200
            except (OSError,ssl.SSLError,http.client.HTTPException):return False
        wait(ready,'Actual shared media TLS frontend')

    def setUp(self):
        super().setUp()
        self.dns=DNS();self.dns.set(media.fixture.DOMAIN,['127.0.0.1']);self.addCleanup(self.dns.close)
        self.registration=secrets.token_hex(16);self.credential=secrets.token_hex(32)
        self.observer_port=media.fixture.free_port()
        config=self.private/'observer.json'
        config.write_text(json.dumps(dict(schemaVersion=1,listenAddress='127.0.0.1',port=self.observer_port,
            certificate=str(self.certificate),privateKey=str(self.key),registrations=[dict(id=self.registration,
                token=self.credential,target=dict(host=media.fixture.DOMAIN,port=self.port,basePath=self.base,
                caFile=str(self.certificate),allowedAddresses=['127.0.0.1']))])))
        config.chmod(0o600);os.chown(config,self.uid,self.uid)
        self.observer=self.spawn([OBSERVER,'--config',str(config),'--supervisor-pid',str(os.getpid())])
        def ready():
            self.assertIsNone(self.observer.poll())
            try:return self.observer_api('/v2/resolve',dict(schemaVersion=2))[0]==200
            except (OSError,ssl.SSLError,http.client.HTTPException):return False
        wait(ready,'Actual configured native media observer')

    def observer_api(self,path,body,credential=None,timeout=12):
        stream=self.context.wrap_socket(socket.create_connection(('127.0.0.1',self.observer_port),timeout=timeout),
            server_hostname=media.fixture.DOMAIN)
        connection=http.client.HTTPConnection(media.fixture.DOMAIN,self.observer_port,timeout=timeout);connection.sock=stream
        try:
            connection.request('POST',path,json.dumps(body),{'Content-Type':'application/json',
                'Authorization':'Bearer '+(credential or self.credential),'X-Traverse-Registration':self.registration})
            response=connection.getresponse();return response.status,json.loads(response.read())
        finally:connection.close()

    def finish_media(self,probes):
        request=dict(schemaVersion=1,operation='finishMedia',
            owner=dict(socket=str(self.owner_socket),pid=self.service.pid),probes=probes)
        process=subprocess.run([AGENT,'--supervisor-pid',str(os.getpid())],input=json.dumps(request),
            text=True,capture_output=True,timeout=12,env=self.native_env,**self.identity)
        self.assertEqual(process.returncode,0,process.stderr);self.assertEqual(process.stderr,'')
        return [json.loads(line) for line in process.stdout.splitlines()]

    def start_manager(self,observer_port=None,agent=None,**extra):
        token=self.private/'observer-token';token.write_text(self.credential+'\n');token.chmod(0o600);os.chown(token,self.uid,self.uid)
        request=dict(observer=dict(host=media.fixture.DOMAIN,port=observer_port or self.observer_port,caFile=str(self.certificate),
            registrationId=self.registration,tokenFile=str(token),timeoutMs=None),agent=agent or AGENT,
            owner=dict(socket=str(self.owner_socket),pid=self.service.pid),mediaPort=self.media_port,**extra)
        process=subprocess.Popen([MANAGER,'--supervisor-pid',str(os.getpid())],stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=self.native_env,**self.identity)
        self.processes.append(process);process.stdin.write(json.dumps(request).encode());process.stdin.close();process.stdin=None
        return process

    def manager_result(self,process):
        out,err=process.communicate(timeout=30);self.assertEqual(process.returncode,0,err.decode());self.assertEqual(err,b'')
        return json.loads(out)['snapshot']

    def test_actual_manager_checks_both_paths_and_cleans(self):
        snapshot=self.manager_result(self.start_manager())
        self.assertEqual(snapshot['status'],'verified',snapshot);self.assertEqual(snapshot['media'],'verified',snapshot)
        self.assertEqual(snapshot['externalReachability'],'unknown')
        self.assertEqual(snapshot['mediaChecks']['addresses'],[
            dict(address='127.0.0.1',mode='relay',status='verified'),dict(address='127.0.0.1',mode='direct',status='verified')])
        self.assertEqual(children(self.service.pid),[]);self.assertEqual(children(self.observer.pid),[])

    def test_invalid_agent_with_no_source_addresses_cannot_verify_media(self):
        # Contract boundary fixture, not a network-reachability proof.
        row=dict(schemaVersion=1,event='resolved',status='resolved',observerInstance='a'*32,addresses=[],
            resolution=dict(schemaVersion=1,basis='literal',dns={key:dict(status='notChecked',addresses=[]) for key in ('a','aaaa')}),
            media=dict(status='available',port=12345,addresses=['127.0.0.1']))
        agent=self.private/'invalid-agent.py'
        agent.write_text('#!/usr/bin/python3\nimport sys\nsys.stdin.read()\nprint('+repr(json.dumps(row))+')\n')
        agent.chmod(0o755);os.chown(agent,self.uid,self.uid)
        snapshot=self.manager_result(self.start_manager(agent=str(agent)))
        self.assertEqual(snapshot['status'],'unavailable',snapshot)
        self.assertEqual(snapshot['media'],'unavailable',snapshot)
        self.assertEqual(snapshot['mediaChecks']['addresses'],[])

    def test_manager_preserves_unreachable_url_reason_when_broker_is_gone(self):
        self.frontend.terminate();self.frontend.wait(timeout=8)
        snapshot=self.manager_result(self.start_manager())
        # This frontend also owns the relay broker. No drain acknowledgement
        # can be obtained after its death, so preserve the cleanup safety latch.
        self.assertEqual(snapshot['status'],'cleanupPending',snapshot)
        self.assertEqual(snapshot['addresses'],[dict(address='127.0.0.1',status='connectionFailed')])
        self.assertEqual(snapshot['media'],'cleanupPending',snapshot)
        self.assertEqual(children(self.service.pid),[])

    def test_older_observer_keeps_https_without_fabricating_media(self):
        # A wire boundary models only an older server's missing v2 routes.
        # Every v1 request still goes through the actual authenticated observer.
        owner=self
        class LegacyRoutes(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                body=self.rfile.read(int(self.headers.get('Content-Length','0')))
                if self.path.startswith('/v2/'):
                    status,data=404,b'{}'
                else:
                    raw=owner.context.wrap_socket(socket.create_connection(('127.0.0.1',owner.observer_port),timeout=8),server_hostname=media.fixture.DOMAIN)
                    connection=http.client.HTTPConnection(media.fixture.DOMAIN,owner.observer_port,timeout=8);connection.sock=raw
                    try:
                        connection.request('POST',self.path,body,dict(self.headers));response=connection.getresponse()
                        status,data=response.status,response.read()
                    finally:connection.close()
                self.send_response(status);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),LegacyRoutes);server.daemon_threads=True
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(self.certificate,self.key)
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever);thread.start()
        try:
            snapshot=self.manager_result(self.start_manager(observer_port=server.server_port))
            self.assertEqual(snapshot['status'],'verified',snapshot);self.assertEqual(snapshot['media'],'unavailable',snapshot)
            self.assertEqual(snapshot['mediaChecks']['addresses'],[])
            self.assertEqual(children(self.service.pid),[])
        finally:server.shutdown();server.server_close();thread.join()

    def test_unreachable_udp_fails_from_ice_and_cleans(self):
        _,resolved=self.observer_api('/v2/resolve',dict(schemaVersion=2));port=resolved['media']['port']
        lease=self.reserve();grant=media.config('source',self.media_port,port,lease['nonce']);grant['peer']=lease['id']
        # Source grants only .2, while the receiver really binds .1. There is
        # no NAT forwarder, so neither admitted ICE path can complete.
        grant['peers'][0]['address']='127.0.0.2'
        self.assertEqual(self.private_call('/media/prepare',dict(schemaVersion=1,id=lease['id'],config=grant))[0],200)
        try:
            status,row=self.observer_api('/v2/media',dict(schemaVersion=2,address='127.0.0.1',lease=lease,
                mode='direct',observerAddress='127.0.0.2',observerPort=port),timeout=70)
            self.assertEqual(status,200,row);self.assertEqual(row['status'],'mediaFailed',row)
            self.assertEqual(children(self.observer.pid),[])
            _,state=self.events(lease)
            self.assertTrue(any(event.get('reason')=='connectionFailed' for event in state['events']),state)
        finally:self.assertEqual(self.private_call('/media/end',dict(schemaVersion=1,id=lease['id']))[0],200)
        self.assertEqual(children(self.service.pid),[])
        with socket.socket(type=socket.SOCK_DGRAM) as witness:witness.bind(('127.0.0.1',self.media_port))

    def test_genuine_pair_preempts_manager_and_cleans_all_known_ids(self):
        process=self.start_manager(priorityFromSignal=True)
        wait(lambda:self.source_pids(),'Actual manager-owned media relay/source')
        authority=self.authority();status,row=self.public('api/pair',dict(code=authority['code']))
        self.assertEqual(status,200,row)
        process.send_signal(signal.SIGUSR1)
        snapshot=self.manager_result(process)
        self.assertEqual(snapshot['status'],'controllerPriority',snapshot)
        self.assertEqual(snapshot['media'],'activeSession',snapshot)
        self.assertEqual(children(self.service.pid),[])
        wait(lambda:not children(self.observer.pid),'Observer cancellation after genuine pairing')
        with socket.socket(type=socket.SOCK_DGRAM) as witness:witness.bind(('127.0.0.1',self.media_port))

    def run_media(self,mode,tamper=False):
        status,resolved=self.observer_api('/v2/resolve',dict(schemaVersion=2));self.assertEqual(status,200,resolved)
        self.assertEqual(resolved['addresses'],['127.0.0.1']);port=resolved['media']['port'];self.assertGreater(port,1023)
        lease=self.reserve();grant=media.config('source',self.media_port,port,lease['nonce']);grant['peer']=lease['id']
        body=dict(schemaVersion=2,address='127.0.0.1',lease=lease,mode=mode,observerAddress='127.0.0.1',observerPort=port)
        if mode=='relay':
            status,row=self.private_call('/media/relay',dict(schemaVersion=1,id=lease['id'],config=grant))
            self.assertEqual(status,202,row);body['relay']=row['relay']
            deadline=time.monotonic()+5
            while True:
                status,row=self.events(lease);self.assertEqual(status,200,row)
                if any(event['type']=='relayReady' for event in row['events']):break
                self.assertLess(time.monotonic(),deadline);time.sleep(.01)
        else:self.assertEqual(self.private_call('/media/prepare',dict(schemaVersion=1,id=lease['id'],config=grant))[0],200)
        status,row=self.observer_api('/v2/media',body);self.assertEqual(status,200,row)
        self.assertEqual(row['status'],'received',row);self.assertEqual(row['observerInstance'],resolved['observerInstance'])
        receipt=row['receipt'];self.assertTrue(receipt['cleanup']);self.assertEqual(receipt['mode'],mode)
        for key in ('instance','id','nonce'):self.assertEqual(receipt[key],lease[key])
        native=receipt['media'];self.assertTrue(native['videoDecoded'] and native['dataVerified'] and native['dtlsConnected'])
        self.assertEqual(native['nonce'],lease['nonce']);self.assertEqual(native['transport']['local']['type']==3,mode=='relay')
        self.assertEqual(children(self.observer.pid),[],'Observer replied before native worker reap')
        if tamper:receipt['media']['nonce']='0'*64
        results=self.finish_media([dict(id=lease['id'],mode=mode,observerPort=port,
                                       sourcePort=self.media_port,receipt=receipt)])
        self.assertEqual(results,[dict(schemaVersion=1,event='mediaFinished',id=lease['id'],
            status='receiptMismatch' if tamper else 'verified',ended=True)])
        self.assertEqual(children(self.service.pid),[],'Host cleanup left a probe child')
        return row

    def test_actual_direct_and_relay_observer(self):
        self.run_media('direct');self.run_media('relay')

    def test_host_rejects_forged_receipt_and_ends_unknown_parent_id(self):
        self.run_media('relay',tamper=True)
        id=secrets.token_hex(16)
        results=self.finish_media([dict(id=id,mode='direct',observerPort=12345,sourcePort=self.media_port)])
        self.assertEqual(results,[dict(schemaVersion=1,event='mediaFinished',id=id,status='notObserved',ended=True)])
        self.assertEqual(self.private_call('/media/reserve',dict(schemaVersion=1,id=id))[0],409)

    def test_authentication_and_endpoint_epoch(self):
        status,_=self.observer_api('/v2/resolve',dict(schemaVersion=2),credential='not-authorized')
        self.assertEqual(status,403)
        status,resolved=self.observer_api('/v2/resolve',dict(schemaVersion=2));self.assertEqual(status,200)
        lease=self.reserve();status,row=self.observer_api('/v2/media',dict(schemaVersion=2,address='127.0.0.1',
            lease=lease,mode='direct',observerAddress='127.0.0.1',observerPort=media.available_port((resolved['media']['port'],))))
        self.assertEqual(status,200,row);self.assertEqual(row['status'],'endpointChanged')
        self.assertEqual(children(self.observer.pid),[])
        self.assertEqual(self.private_call('/media/end',dict(schemaVersion=1,id=lease['id']))[0],200)


if __name__=='__main__':
    unittest.main(defaultTest=['ObserverMediaTests.test_actual_direct_and_relay_observer',
                              'ObserverMediaTests.test_actual_manager_checks_both_paths_and_cleans',
                              'ObserverMediaTests.test_invalid_agent_with_no_source_addresses_cannot_verify_media',
                              'ObserverMediaTests.test_manager_preserves_unreachable_url_reason_when_broker_is_gone',
                              'ObserverMediaTests.test_older_observer_keeps_https_without_fabricating_media',
                              'ObserverMediaTests.test_unreachable_udp_fails_from_ice_and_cleans',
                              'ObserverMediaTests.test_genuine_pair_preempts_manager_and_cleans_all_known_ids',
                              'ObserverMediaTests.test_host_rejects_forged_receipt_and_ends_unknown_parent_id',
                              'ObserverMediaTests.test_authentication_and_endpoint_epoch'])
