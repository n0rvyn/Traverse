"""Real native HTTPS worker. All deadlines below are test watchdogs only."""
import copy
import http.server
import json
import os
from pathlib import Path
import selectors
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

WORKER=sys.argv[1]
DOMAIN='verifier.example.test'
LEASE=dict(instance='a'*32,id='b'*32,token='c'*64,nonce='d'*64)

def request(port,ca):
    return dict(schemaVersion=1,target=dict(host=DOMAIN,port=port,basePath='/traverse/v1.2/',
        address='127.0.0.1',caFile=str(ca)),lease=dict(LEASE))

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        body=self.rfile.read(int(self.headers['Content-Length']))
        self.server.observed.append((self.path,dict(self.headers),json.loads(body)))
        mode=self.server.mode
        if mode=='drop':return
        if mode=='redirect':
            self.send_response(307);self.send_header('Location',self.server.location);self.send_header('Content-Length','0');self.end_headers();return
        row=dict(schemaVersion=1,receipt={key:value for key,value in LEASE.items() if key!='token'})
        row['receipt']['observedMonotonicMs']=123
        if mode=='wrong':row['receipt']['instance']='0'*32
        if mode=='float':row['receipt']['observedMonotonicMs']=123.0
        output=b'not JSON '+LEASE['token'].encode() if mode=='malformed' else json.dumps(row).encode()
        self.send_response(403 if mode=='deny' else 200)
        self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(output)))
        self.end_headers();self.wfile.write(output)

class Verifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='readiness-verifier-');cls.root=Path(cls.temp.name)
        cls.cert=cls.root/'cert';cls.key=cls.root/'key';cls.expired=cls.root/'expired'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN='+DOMAIN,'-addext','subjectAltName=DNS:'+DOMAIN,
            '-keyout',str(cls.key),'-out',str(cls.cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['openssl','x509','-in',str(cls.cert),'-signkey',str(cls.key),'-days','-1',
            '-out',str(cls.expired)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def setUp(self):
        self.servers=[];self.workers=[];self.sockets=[]
        self.addCleanup(self.close)
    def server(self,cert=None):
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        server.daemon_threads=True;server.mode='ok';server.observed=[];server.sni=[]
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(cert or self.cert),str(self.key))
        context.set_servername_callback(lambda stream,name,ctx:server.sni.append(name))
        server.socket=context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever);thread.start();self.servers.append((server,thread))
        return server
    def worker(self,row):
        p=subprocess.Popen([WORKER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.workers.append(p);p.stdin.write(json.dumps(row).encode());p.stdin.close();p.stdin=None
        return p
    def result(self,row,status):
        p=self.worker(row);out,err=p.communicate(timeout=8)
        self.assertEqual(err,b'','Worker emitted private error details')
        result=json.loads(out);self.assertEqual(result['status'],status)
        self.assertEqual(p.returncode,0 if status=='received' else 1)
        if status!='received':self.assertEqual(set(result),{'schemaVersion','status'})
        self.assertNotIn(LEASE['token'].encode(),out,'Credential leaked into worker result')
        return result
    def test_tls_pinning_headers_receipt_and_negative_responses(self):
        server=self.server();row=request(server.server_port,self.cert)
        result=self.result(row,'received')
        self.assertTrue(result['receipt']['nonce']==LEASE['nonce'],'Receipt nonce mismatch')
        path,headers,body=server.observed[-1]
        self.assertEqual(path,'/traverse/v1.2/api/readiness/challenge')
        self.assertEqual(headers['Host'],DOMAIN+':'+str(server.server_port))
        self.assertEqual(headers['Origin'],'https://'+DOMAIN+':'+str(server.server_port))
        self.assertTrue(headers['Authorization']=='Bearer '+LEASE['token'],'Bearer mismatch')
        self.assertEqual(server.sni,[DOMAIN]);self.assertEqual(set(body),{'schemaVersion','id','nonce'})
        for mode,status in [('wrong','invalidReceipt'),('float','invalidReceipt'),('malformed','invalidReceipt'),
                            ('deny','httpRejected'),('drop','connectionFailed')]:
            server.mode=mode;self.result(row,status)
        server.mode='ok'
        untrusted=copy.deepcopy(row);untrusted['target']['caFile']='';self.result(untrusted,'tlsFailed')
        wrong=copy.deepcopy(row);wrong['target']['host']='wrong.example.test';self.result(wrong,'tlsFailed')
        expired=self.server(self.expired);self.result(request(expired.server_port,self.expired),'tlsFailed')
    def test_redirect_never_contacts_other_target(self):
        source=self.server();trap=self.server();source.mode='redirect'
        source.location=f'https://{DOMAIN}:{trap.server_port}/trap'
        self.result(request(source.server_port,self.cert),'httpRejected')
        self.assertEqual(len(source.observed),1);self.assertEqual(trap.observed,[])
    def test_cancel_during_tls_and_response_read(self):
        for tls in (False,True):
            with self.subTest(tls=tls):
                listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(5)
                self.sockets.append(listener);p=self.worker(request(listener.getsockname()[1],self.cert))
                connection,_=listener.accept();connection.settimeout(5);self.sockets.append(connection)
                if tls:
                    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(self.cert),str(self.key))
                    stream=context.wrap_socket(connection,server_side=True);self.sockets.append(stream)
                    received=b''
                    while b'\r\n\r\n' not in received:received+=stream.recv(4096)
                else:
                    stream=connection;self.assertTrue(stream.recv(4096),'TLS ClientHello not observed')
                if tls:p.kill()
                else:p.terminate()
                out,err=p.communicate(timeout=5);self.assertEqual(out,b'');self.assertEqual(err,b'')
                self.assertEqual(p.returncode,-9 if tls else -15)
                # Drain buffered request bytes until EOF; successful termination
                # closes the connection even when no server response arrives.
                while stream.recv(4096):pass
    def test_cancel_connect_and_invalid_private_request(self):
        row=request(443,self.cert);row['target']['address']='192.0.2.254'
        p=self.worker(row)
        watchdog=time.monotonic()+5
        observed=False
        while p.poll() is None and time.monotonic()<watchdog:
            inodes=set()
            for fd in Path(f'/proc/{p.pid}/fd').iterdir():
                try:
                    link=os.readlink(fd)
                    if link.startswith('socket:['):inodes.add(link[8:-1])
                except FileNotFoundError:pass
            for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
                fields=line.split()
                if fields[2]=='FE0200C0:01BB' and fields[3]=='02' and fields[9] in inodes:
                    observed=True;break
            if observed:break
            time.sleep(.01)
        self.assertTrue(observed,'Actual worker SYN_SENT to isolated blackhole not observed')
        p.terminate()
        out,err=p.communicate(timeout=5)
        self.assertNotEqual(p.returncode,0);self.assertNotIn(b'"received"',out)
        invalid=copy.deepcopy(row);invalid['lease']['token']='bad\r\nHeader: secret'
        self.result(invalid,'invalidRequest')
    def close(self):
        for p in self.workers:
            if p.poll() is None:p.kill()
            p.wait(timeout=5)
            for stream in (p.stdin,p.stdout,p.stderr):
                if stream:stream.close()
        for stream in reversed(self.sockets):stream.close()
        for server,thread in reversed(self.servers):
            server.shutdown();server.server_close();thread.join(timeout=5);self.assertFalse(thread.is_alive())

if __name__=='__main__':unittest.main(argv=[sys.argv[0]])
