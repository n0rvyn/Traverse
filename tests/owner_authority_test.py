"""Real private adapter authority; run inside the disposable X11 SDK fixture."""
import argparse
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from installed_standalone import descendants

RUN_EXPIRY=False

class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(8)
        self.sock.connect(self.host)


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='traverse-owner-')
        self.root=Path(self.temporary.name);self.root.chmod(0o700)
        if os.getuid()==0:
            os.chown(self.root,65534,65534)
        self.path=self.root/'adapter.sock'
        authority=self.root/'Xauthority';shutil.copyfile(os.environ['XAUTHORITY'],authority)
        authority.chmod(0o600)
        if os.getuid()==0:
            os.chown(authority,65534,65534)
        self.environment=dict(os.environ,XAUTHORITY=str(authority),XDG_CACHE_HOME=str(self.root/'cache'))
        identity={'user':65534,'group':65534,'extra_groups':[]} if os.getuid()==0 else {}
        options=[] if self._testMethodName=='test_dialog_secrecy_and_actual_local_stop' else ['--no-dialog']
        self.process=subprocess.Popen([ADAPTER,'--display',os.environ['DISPLAY'],'--socket',str(self.path),*options],
            env=self.environment,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,**identity)
        self.addCleanup(self.close)
        end=time.monotonic()+15
        while True:
            self.assertIsNone(self.process.poll(),'Owned adapter exited before authority readiness')
            try:
                status,state=self.call('/state')
                if status==200:
                    self.assertEqual(state['pid'],self.process.pid)
                    break
            except OSError:
                pass
            self.assertLess(time.monotonic(),end,'Private adapter did not become ready')
            time.sleep(.02)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=12)
        self.temporary.cleanup()

    def call(self,route,body=None,token=None):
        connection=UnixHTTP(str(self.path))
        headers={'Content-Type':'application/json'}
        if token:headers['Authorization']='Bearer '+token
        try:
            connection.request('GET' if body is None else 'POST',route,
                None if body is None else json.dumps(body),headers)
            response=connection.getresponse()
            data=response.read()
            return response.status,json.loads(data) if data else {}
        finally:
            connection.close()

    def current(self):
        status,value=self.call('/owner/authority');self.assertEqual(status,200)
        self.assertEqual(value['schemaVersion'],1)
        self.assertEqual(value['pid'],self.process.pid)
        return value

    def pair(self,code):
        status,result=self.call('/pair',{'code':code});self.assertEqual(status,200)
        return result['token']

    def assert_controller(self,token):
        self.assertEqual(self.call('/input',{'type':'heartbeat'},token)[0],200)
        value=self.current();self.assertTrue(value['paired']);self.assertEqual(value['codeStatus'],'used')
        self.assertNotIn('code',value);self.assertNotIn('token',value)
        self.assertNotIn('code',self.call('/state')[1])

    def test_private_code_refresh_and_input_contract(self):
        before=self.current();self.assertEqual(before['codeStatus'],'available')
        self.assertGreater(before['expiresMonotonicMs'],before['observedMonotonicMs'])
        self.assertNotIn('code',self.call('/state')[1])
        status,after=self.call('/owner/new-code',{});self.assertEqual(status,200)
        self.assertNotEqual(after['code'],before['code'])
        self.assertEqual(self.call('/pair',{'code':before['code']})[0],403)
        token=self.pair(after['code'])
        self.assertEqual(self.call('/owner/new-code',{})[0],409)
        self.assert_controller(token)

    def test_rejects_fields_without_changing_authority(self):
        before=self.current()
        for value in ({'force':True},[],{'code':'synthetic'}):
            self.assertEqual(self.call('/owner/new-code',value)[0],400)
            self.assertEqual(self.current()['code'],before['code'])
        self.assert_controller(self.pair(before['code']))

    def test_concurrent_pair_refresh_preserves_the_winner(self):
        before=self.current();barrier=threading.Barrier(3)
        def request(route,body):
            barrier.wait(timeout=5)
            return self.call(route,body)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            pairing=executor.submit(request,'/pair',{'code':before['code']})
            refresh=executor.submit(request,'/owner/new-code',{})
            barrier.wait(timeout=5)
            pair_status,pair_result=pairing.result(timeout=10)
            refresh_status,refresh_result=refresh.result(timeout=10)
        if pair_status==200:
            self.assertEqual(refresh_status,409)
            token=pair_result['token']
        else:
            self.assertEqual(pair_status,403);self.assertEqual(refresh_status,200)
            token=self.pair(refresh_result['code'])
        self.assertEqual(self.call('/owner/new-code',{})[0],409)
        self.assert_controller(token)

    def test_stopped_and_explicit_legacy_arm(self):
        token=self.pair(self.current()['code'])
        self.assertEqual(self.call('/revoke',{})[0],200)
        value=self.current();self.assertEqual(value['codeStatus'],'unarmed');self.assertNotIn('code',value)
        self.assertEqual(self.call('/owner/new-code',{})[0],409)
        self.assertEqual(self.call('/input',{'type':'heartbeat'},token)[0],403)
        status,value=self.call('/arm',{});self.assertEqual(status,200)
        token=self.pair(value['code'])
        status,value=self.call('/arm',{});self.assertEqual(status,200)
        self.assertEqual(self.call('/input',{'type':'heartbeat'},token)[0],403)
        self.assert_controller(self.pair(value['code']))

    def test_dialog_secrecy_and_actual_local_stop(self):
        self.assertEqual(self.current()['codeStatus'],'available')
        status,value=self.call('/owner/new-code',{});self.assertEqual(status,200)
        probe=os.environ.get('TRAVERSE_TEST_X11_PROBE','/tmp/x11-probe')
        def x11(*arguments):
            return json.loads(subprocess.check_output([probe,*arguments],env=self.environment,
                stderr=subprocess.DEVNULL,text=True))
        end=time.monotonic()+10
        while True:
            try:
                dialog=x11('focus','Traverse sharing')
                if dialog['mapped']:break
            except subprocess.CalledProcessError:
                pass
            self.assertLess(time.monotonic(),end,'Real local dialog did not map')
            time.sleep(.02)
        owned=descendants(self.process.pid)
        messages=[pid for pid in owned if Path(f'/proc/{pid}/exe').resolve().name=='xmessage']
        self.assertEqual(len(messages),1,'No positive xmessage process witness')
        for pid in owned:
            argv=Path(f'/proc/{pid}/cmdline').read_bytes()
            self.assertFalse(value['code'].encode() in argv,'Pairing code leaked into owned process arguments')
            self.assertFalse(b'--dialog-text' in argv,'Code-bearing dialog option survived')
        argv=Path(f'/proc/{messages[0]}/cmdline').read_bytes().split(b'\x00')
        self.assertIn(b'-file',argv);self.assertIn(b'-',argv)
        token=self.pair(value['code'])
        self.assertEqual(self.call('/input',{'type':'key','code':'ShiftLeft','down':True},token)[0],200)
        self.assertEqual(x11('query')['shift'],1)
        screenshot=os.environ.get('TRAVERSE_TEST_DIALOG_SCREENSHOT')
        if screenshot:
            # The displayed synthetic code is already used, in a network-isolated
            # fixture. No reusable operator key enters the rendered artifact.
            subprocess.run(['/tmp/x11-capture',screenshot],env=self.environment,check=True)
        subprocess.run([probe,'move',str(dialog['x']+40),str(dialog['y']+dialog['height']-15)],
            env=self.environment,check=True,stdout=subprocess.DEVNULL)
        subprocess.run([probe,'click'],env=self.environment,check=True,stdout=subprocess.DEVNULL)
        end=time.monotonic()+10
        while self.call('/state')[1]['armed']:
            self.assertLess(time.monotonic(),end,'Actual Stop sharing did not revoke')
            time.sleep(.02)
        self.assertEqual(x11('query')['shift'],0)
        self.assertEqual(self.call('/input',{'type':'heartbeat'},token)[0],403)

    def test_real_code_expiry_and_recovery(self):
        if not RUN_EXPIRY:
            self.skipTest('Explicit --expiry runs the unchanged real five-minute lifetime')
        value=self.current();self.assertEqual(value['codeStatus'],'available')
        remaining=(value['expiresMonotonicMs']-value['observedMonotonicMs'])/1000
        threading.Event().wait(remaining+.05)
        self.assertIsNone(self.process.poll())
        expired=self.current();self.assertEqual(expired['codeStatus'],'expired')
        self.assertNotIn('code',expired)
        self.assertEqual(self.call('/pair',{'code':value['code']})[0],403)
        status,fresh=self.call('/owner/new-code',{});self.assertEqual(status,200)
        self.assertNotEqual(fresh['code'],value['code'])
        self.assert_controller(self.pair(fresh['code']))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--adapter',required=True)
    parser.add_argument('--expiry',action='store_true')
    arguments,remaining=parser.parse_known_args();ADAPTER=arguments.adapter
    RUN_EXPIRY=arguments.expiry
    unittest.main(argv=[__file__,*remaining])
