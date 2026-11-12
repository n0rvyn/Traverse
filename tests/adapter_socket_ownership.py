"""Actual adapter/pair/revoke socket ownership on an owned Xvfb display."""
import argparse
import http.client
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import subprocess
import tempfile
import time
import unittest

class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(5);self.sock.connect(self.host)

class SocketOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.xlog=tempfile.TemporaryFile(mode='w+')
        # Synthetic server only; no existing user display or host listener.
        cls.xvfb=subprocess.Popen([XVFB,'-displayfd','1',
            '-screen','0','640x480x24','-nolisten','tcp','-ac'],stdout=subprocess.PIPE,stderr=cls.xlog,text=True)
        selector=selectors.DefaultSelector()
        try:
            selector.register(cls.xvfb.stdout,selectors.EVENT_READ)
            if not selector.select(5):raise RuntimeError('Owned Xvfb did not publish readiness')
            value=cls.xvfb.stdout.readline().strip()
            if not value.isdigit():raise RuntimeError('Owned Xvfb failed: '+value)
            cls.display=':'+value
        except BaseException:
            cls.xvfb.kill();cls.xvfb.wait(timeout=5);cls.xvfb.stdout.close();cls.xlog.close();raise
        finally:selector.close()
    @classmethod
    def tearDownClass(cls):
        if cls.xvfb.poll() is None:cls.xvfb.terminate()
        try:cls.xvfb.wait(timeout=5)
        except subprocess.TimeoutExpired:cls.xvfb.kill();cls.xvfb.wait(timeout=5)
        cls.xvfb.stdout.close();cls.xlog.close()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='adapter-socket-')
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.path=self.root/'a';self.log=tempfile.TemporaryFile(mode='w+')
        env=dict(os.environ,DISPLAY=self.display,GST_REGISTRY=str(self.root/'registry.bin'))
        env.pop('XAUTHORITY',None)
        self.process=subprocess.Popen([ADAPTER,'--display',self.display,'--socket',str(self.path),
            '--no-dialog'],env=env,stdout=subprocess.DEVNULL,stderr=self.log)
        self.addCleanup(self.close)
        deadline=time.monotonic()+5
        while True:
            self.assertIsNone(self.process.poll(),'Owned adapter exited before readiness')
            try:
                if self.call('/state')[0]==200:break
            except (OSError,http.client.HTTPException):pass
            self.assertLess(time.monotonic(),deadline,'Owned adapter never became ready')
            time.sleep(.02)
    def close(self):
        if self.process.poll() is None:self.process.terminate()
        try:self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5)
        self.log.close();self.temp.cleanup()
    def call(self,route,body=None):
        client=UnixHTTP(str(self.path),timeout=5)
        try:
            client.request('GET' if body is None else 'POST',route,
                None if body is None else json.dumps(body),{'Content-Type':'application/json'})
            response=client.getresponse();return response.status,json.loads(response.read())
        finally:client.close()
    def pair(self):
        status,authority=self.call('/owner/authority');self.assertEqual(status,200)
        self.assertEqual(self.call('/pair',{'code':authority['code']})[0],200)
        frame=Path(self.call('/state')[1]['frameSocket'])
        self.assertTrue(stat.S_ISSOCK(frame.stat().st_mode),'Actual frame listener did not bind')
        return frame
    def test_stop_preserves_a_replacement_control_file(self):
        self.path.rename(self.root/'old-control')
        self.path.write_text('preserve replacement control\n')
        self.process.send_signal(signal.SIGTERM);self.assertEqual(self.process.wait(timeout=5),0)
        self.assertTrue(self.path.exists(),'Stop deleted a replacement control file')
        self.assertEqual(self.path.read_text(),'preserve replacement control\n')
    def test_revoke_preserves_an_unpaired_frame_file(self):
        frame=Path(self.call('/state')[1]['frameSocket']);frame.write_text('preserve idle frame file\n')
        self.assertEqual(self.call('/revoke',{})[0],200)
        self.assertTrue(frame.exists(),'Revoke deleted a frame file it never created')
        self.assertEqual(frame.read_text(),'preserve idle frame file\n')
    def test_revoke_preserves_a_replacement_paired_frame_file(self):
        frame=self.pair();frame.rename(self.root/'old-frame')
        frame.write_text('preserve replacement frame\n')
        self.assertEqual(self.call('/revoke',{})[0],200)
        self.assertTrue(frame.exists(),'Revoke deleted a replacement frame file')
        self.assertEqual(frame.read_text(),'preserve replacement frame\n')
    def test_normal_revoke_removes_the_owned_frame_socket(self):
        frame=self.pair();self.assertEqual(self.call('/revoke',{})[0],200)
        self.assertFalse(frame.exists(),'Owned frame listener was not retired')

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--adapter',required=True);parser.add_argument('--xvfb',required=True)
    args,remaining=parser.parse_known_args();ADAPTER=args.adapter;XVFB=args.xvfb
    if os.geteuid()==0:os.setgroups([]);os.setgid(65534);os.setuid(65534)
    unittest.main(argv=[__file__,*remaining])
