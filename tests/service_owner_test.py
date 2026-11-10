"""Separate private service status and public HTTP negatives with real sockets."""
import argparse
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import time
import unittest

from installed_standalone import free_port
from owner_authority_test import UnixHTTP


class ServiceOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='traverse-service-owner-')
        self.root=Path(self.temporary.name);self.root.chmod(0o755)
        self.private=self.root/'private';self.private.mkdir(mode=0o700)
        self.uid=65534 if os.getuid()==0 else os.getuid()
        if os.getuid()==0:os.chown(self.private,self.uid,self.uid)
        self.owner=self.private/'s';self.process=None;self.port=free_port()
        self.addCleanup(self.close)

    def start(self,path=None):
        if self.process is not None:
            self.assertIsNotNone(self.process.poll(),'Previous owned service is still active')
            self.process.stderr.close()
        identity={'user':self.uid,'group':self.uid,'extra_groups':[]} if os.getuid()==0 else {}
        environment=dict(os.environ,HOME=str(self.private),XDG_CACHE_HOME=str(self.private/'cache'))
        self.process=subprocess.Popen([SERVICE,'--internal-http','--host','127.0.0.1','--port',str(self.port),
            '--origin','https://owner.example.test','--socket',str(self.private/'absent-adapter'),
            '--web',WEB,'--stun','','--owner-socket',str(self.owner if path is None else path),
            '--supervisor-pid',str(os.getpid())],env=environment,stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,text=True,**identity)

    def ready(self):
        end=time.monotonic()+15
        while True:
            if self.process.poll() is not None:
                self.fail('Synthetic service startup: '+self.process.communicate(timeout=2)[1])
            try:
                value=self.private_state()
                if value['pid']==self.process.pid and self.http('/')[0]==200:
                    return value
            except (OSError,http.client.HTTPException):
                pass
            self.assertLess(time.monotonic(),end,'Private/public positive controls did not become ready')
            time.sleep(.02)

    def private_state(self):
        connection=UnixHTTP(str(self.owner))
        try:
            connection.request('GET','/state');response=connection.getresponse()
            self.assertEqual(response.status,200)
            return json.loads(response.read())
        finally:connection.close()

    def producer_probe(self,path,expected):
        identity={'user':self.uid,'group':self.uid,'extra_groups':[]} if os.getuid()==0 else {}
        environment=dict(os.environ,HOME=str(self.private),XDG_CACHE_HOME=str(self.private/'cache'))
        if os.environ.get('TRAVERSE_TEST_PROBE_LIBRARY_PATH'):
            environment['LD_LIBRARY_PATH']=os.environ['TRAVERSE_TEST_PROBE_LIBRARY_PATH']
        return subprocess.run([PROBE,str(path),str(expected)],env=environment,
            capture_output=True,text=True,timeout=8,**identity)

    def http(self,path,method='GET',origin='https://owner.example.test'):
        connection=http.client.HTTPConnection('127.0.0.1',self.port,timeout=3)
        try:
            connection.request(method,path,body='{}' if method=='POST' else None,
                headers={'Origin':origin,'X-Forwarded-For':'127.0.0.1','X-Forwarded-Host':'localhost'})
            response=connection.getresponse();return response.status,response.read()
        finally:connection.close()

    def stop(self):
        self.process.terminate();self.process.wait(timeout=10)
        self.assertEqual(self.process.returncode,0)

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate();self.process.wait(timeout=10)
        if self.process is not None and self.process.stderr:
            self.process.stderr.close()
        self.temporary.cleanup()

    def test_private_positive_public_negative_and_normal_cleanup(self):
        self.start();value=self.ready()
        self.assertEqual(set(value),{'schemaVersion','pid','observedMonotonicMs','generation','peerPresent','peerActive','rtcState','controlOpen'})
        self.assertEqual(value['schemaVersion'],1)
        self.assertFalse(value['peerPresent']);self.assertFalse(value['peerActive']);self.assertFalse(value['controlOpen'])
        self.assertEqual(value['rtcState'],'none');self.assertEqual(value['generation'],0)
        metadata=self.owner.lstat();self.assertTrue(stat.S_ISSOCK(metadata.st_mode))
        self.assertEqual(metadata.st_uid,self.uid);self.assertEqual(stat.S_IMODE(metadata.st_mode),0o600)
        checked=self.producer_probe(self.owner,self.process.pid)
        self.assertEqual(checked.returncode,0,checked.stderr)
        self.assertEqual(json.loads(checked.stdout)['verifiedProducerPid'],self.process.pid)
        self.assertNotEqual(self.producer_probe(self.owner,os.getpid()).returncode,0)
        for path in ('/state','/owner/state','/owner/authority','/api/owner/state','/%6fwner/state','/api/%2e%2e/owner/state'):
            for method in ('GET','POST'):
                for origin in ('https://owner.example.test','https://wrong.example.test'):
                    status,data=self.http(path,method,origin)
                    self.assertIn(status,(403,404));self.assertNotIn(b'rtcState',data);self.assertNotIn(b'codeStatus',data)
        if os.getuid()==0:
            probe='import socket,sys;s=socket.socket(socket.AF_UNIX);\ntry:s.connect(sys.argv[1])\nexcept PermissionError:sys.exit(0)\nsys.exit(1)'
            denied=subprocess.run(['/usr/bin/python3','-c',probe,str(self.owner)],user=65533,group=65533,
                extra_groups=[],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
            self.assertEqual(denied.returncode,0,'Another UID reached the private owner socket')
        self.stop();self.assertFalse(self.owner.exists())

    def test_preexisting_file_and_socket_are_preserved(self):
        self.owner.write_text('synthetic-owned-sentinel')
        self.start();self.process.wait(timeout=10);self.assertNotEqual(self.process.returncode,0)
        self.assertEqual(self.owner.read_text(),'synthetic-owned-sentinel');self.owner.unlink()
        with socket.socket(socket.AF_UNIX) as existing:
            existing.bind(str(self.owner));existing.listen()
            identity=self.owner.stat()
            self.start();self.process.wait(timeout=10);self.assertNotEqual(self.process.returncode,0)
            self.assertEqual(self.owner.stat().st_ino,identity.st_ino)
            with socket.socket(socket.AF_UNIX) as peer:peer.connect(str(self.owner))
        self.owner.unlink()

    def test_foreign_parent_and_public_conflict_cleanup(self):
        foreign=self.root/'foreign';foreign.mkdir(mode=0o700)
        if os.getuid()==0:
            self.start(foreign/'s');self.process.wait(timeout=10);self.assertNotEqual(self.process.returncode,0)
            self.assertFalse((foreign/'s').exists())
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1',self.port));occupied.listen()
            self.start();self.process.wait(timeout=10);self.assertNotEqual(self.process.returncode,0)
            self.assertFalse(self.owner.exists());self.assertEqual(occupied.getsockname()[1],self.port)

    def test_cleanup_does_not_unlink_a_replacement(self):
        self.start();self.ready();self.owner.unlink()
        with socket.socket(socket.AF_UNIX) as replacement:
            replacement.bind(str(self.owner));replacement.listen();identity=self.owner.stat()
            self.stop();self.assertEqual(self.owner.stat().st_ino,identity.st_ino)
            with socket.socket(socket.AF_UNIX) as peer:peer.connect(str(self.owner))
        self.owner.unlink()

    def test_native_consumer_rejects_forged_pid_and_stale_authenticated_snapshot(self):
        self.start();self.ready()
        program='''import json,os,socket,sys,time
path,claim,age=sys.argv[1:]
listener=socket.socket(socket.AF_UNIX);listener.bind(path);os.chmod(path,0o600);listener.listen()
print('ready',flush=True)
connection,_=listener.accept()
headers=b''
while not headers.endswith(b'\\r\\n\\r\\n'):
 data=connection.recv(1)
 if not data:sys.exit(1)
 headers+=data
body=json.dumps({'schemaVersion':1,'pid':os.getpid() if claim=='self' else int(claim),
 'observedMonotonicMs':int((time.monotonic()-float(age))*1000)}).encode()
connection.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nConnection: keep-alive\\r\\nContent-Length: '+str(len(body)).encode()+b'\\r\\n\\r\\n'+body)
while connection.recv(1024):pass
'''
        identity={'user':self.uid,'group':self.uid,'extra_groups':[]} if os.getuid()==0 else {}
        for claim,age in ((str(self.process.pid),'0'),('self','10')):
            path=self.private/'f'
            fake=subprocess.Popen(['/usr/bin/python3','-c',program,str(path),claim,age],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,**identity)
            try:
                self.assertEqual(fake.stdout.readline().strip(),'ready')
                expected=self.process.pid if claim!='self' else fake.pid
                self.assertNotEqual(self.producer_probe(path,expected).returncode,0)
                fake.wait(timeout=5)
            finally:
                if fake.poll() is None:fake.terminate();fake.wait(timeout=5)
                fake.stdout.close();fake.stderr.close()
                if path.exists():path.unlink()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--service',required=True);parser.add_argument('--web',required=True)
    parser.add_argument('--probe',required=True)
    args,remaining=parser.parse_known_args();SERVICE=args.service;WEB=args.web;PROBE=args.probe
    unittest.main(argv=[__file__,*remaining])
