"""Actual worker socket -> owned XTest server -> independent XKB receiver."""
import json,os,pathlib,re,selectors,signal,socket,subprocess,sys,tempfile,threading,time,unittest
PROBE,XVFB,SETXKBMAP,XKBCOMP=sys.argv[1:5];del sys.argv[1:5]

class Records:
    def __init__(self,process):
        self.process=process;self.items=[];self.condition=threading.Condition()
        self.thread=threading.Thread(target=self.read);self.thread.start()
    def read(self):
        for line in self.process.stdout:
            row=json.loads(line)
            with self.condition:self.items.append(row);self.condition.notify_all()
    def wait(self,predicate):
        end=time.monotonic()+5
        with self.condition:
            while True:
                for row in reversed(self.items):
                    if predicate(row):return row
                remaining=end-time.monotonic()
                if remaining<=0:raise AssertionError('Receiver event missing: '+repr(self.items))
                self.condition.wait(remaining)

class HostLayout(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='traverse-host-layout-');self.root=pathlib.Path(self.directory.name)
        self.env=dict(os.environ,LANG='C.UTF-8');self.env.pop('XAUTHORITY',None)
        self.logs={name:open(self.root/(name+'.log'),'w+') for name in ('xvfb','worker','receiver')}
        self.receiver=self.worker=self.server=None;self.connection=self.responses=None;self.records=None;self.sequence=0
        self.addCleanup(self.close)
        self.server=subprocess.Popen([XVFB,'-displayfd','1','-screen','0','800x600x24','-nolisten','tcp','-noreset','-ac'],stdout=subprocess.PIPE,stderr=self.logs['xvfb'],text=True,env=self.env)
        ready=selectors.DefaultSelector();ready.register(self.server.stdout,selectors.EVENT_READ)
        try:self.assertTrue(ready.select(5));number=self.server.stdout.readline().strip();self.assertTrue(number.isdigit(),number)
        finally:ready.close()
        self.display=':'+number;self.env['DISPLAY']=self.display
        self.layout('us')
        self.receiver=subprocess.Popen([PROBE,self.display],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=self.logs['receiver'],text=True,env=self.env)
        self.records=Records(self.receiver);self.records.wait(lambda r:r.get('event')=='ready')
        self.start_worker()
    def start_worker(self):
        self.connection,exported=socket.socketpair();self.connection.settimeout(5)
        try:self.worker=subprocess.Popen([PROBE,'--worker',self.display],stdin=exported,stdout=subprocess.DEVNULL,stderr=self.logs['worker'],env=self.env)
        finally:exported.close()
        self.responses=self.connection.makefile('r')
        self.send(type='heartbeat')
    def close_worker(self):
        if self.responses:self.responses.close();self.responses=None
        if self.connection:self.connection.close();self.connection=None
        if self.worker:
            if self.worker.poll() is None:
                try:self.worker.wait(timeout=5)
                except subprocess.TimeoutExpired:self.worker.terminate();self.worker.wait(timeout=5)
            self.assertEqual(self.worker.returncode,0)
            self.worker=None
    def close(self):
        try:
            self.close_worker()
            if self.receiver:
                if self.receiver.poll() is None:self.receiver.stdin.write('{"op":"quit"}\n');self.receiver.stdin.flush();self.receiver.stdin.close()
                self.assertEqual(self.receiver.wait(timeout=5),0)
                self.records.thread.join(5);self.assertFalse(self.records.thread.is_alive());self.receiver.stdout.close()
        finally:
            for process in (self.worker,self.receiver,self.server):
                if process and process.poll() is None:process.kill();process.wait(timeout=5)
            if self.server and self.server.stdout:self.server.stdout.close()
            for file in self.logs.values():file.close()
            self.directory.cleanup()
    def layout(self,name):
        subprocess.run([SETXKBMAP,'-display',self.display,'-layout',name],env=self.env,check=True,capture_output=True,text=True)
    def send(self,**event):
        self.connection.sendall((json.dumps(event)+'\n').encode());line=self.responses.readline();self.assertTrue(line,'Worker exited')
        return json.loads(line)
    def key(self,name,down):self.assertTrue(self.send(type='key',code=name,down=down)['ok'])
    def control(self,op='state',**values):
        self.sequence+=1;request=dict(op=op,id=self.sequence,**values)
        self.receiver.stdin.write(json.dumps(request)+'\n');self.receiver.stdin.flush()
        return self.records.wait(lambda r:r.get('event')=='state' and r.get('id')==self.sequence)
    def dump_map(self):return subprocess.check_output([XKBCOMP,'-xkb',self.display,'-'],env=self.env,text=True,stderr=subprocess.PIPE)
    def load_map(self,text):subprocess.run([XKBCOMP,'-',self.display],input=text,env=self.env,text=True,check=True,capture_output=True)
    def press(self,name):self.key(name,True);self.key(name,False)
    def observed_down(self,after,code,symbol,shift=False):
        self.control()
        rows=self.records.items[after:]
        self.assertTrue(any(r.get('event')=='key' and r['down'] and r['code']==code and r['symbol']==symbol and bool(r['state']&1)==shift for r in rows),rows)
    def test_us_french_and_live_layout_switch(self):
        for layout,symbol in (('us',0x61),('fr',0x71),('us',0x61)):
            self.layout(layout);start=len(self.records.items);self.press('KeyA');self.observed_down(start,38,symbol)
        self.layout('fr');start=len(self.records.items)
        self.key('ShiftLeft',True);self.press('KeyA');self.key('ShiftLeft',False)
        self.observed_down(start,38,0x51,True)
        start=len(self.records.items);self.press('KeyQ');self.observed_down(start,24,0x61)
        self.assertEqual(self.control()['held'],[])
    def test_permuted_physical_names_do_not_assume_evdev_offset(self):
        text=self.dump_map()
        text,count=re.subn(r'(<AC01>\s*=\s*)38;',r'\g<1>24;',text);self.assertEqual(count,1)
        text,count=re.subn(r'(<AD01>\s*=\s*)24;',r'\g<1>38;',text);self.assertEqual(count,1)
        self.load_map(text);self.assertEqual(self.control()['names']['AC01'],24)
        start=len(self.records.items);self.press('KeyA');self.observed_down(start,24,0x61)
    def test_release_uses_admitted_code_when_name_disappears(self):
        self.key('KeyA',True);self.key('KeyB',True);self.assertEqual(self.control()['held'],[38,56])
        self.load_map(self.dump_map().replace('<AC01>','<ZZZZ>'))
        self.assertNotIn('AC01',self.control()['names'])
        self.key('KeyA',False);self.assertEqual(self.control()['held'],[56])
        self.key('KeyB',False);self.assertEqual(self.control()['held'],[])
    def test_physical_alias_resolves_actual_host_code(self):
        text=self.dump_map().replace('<AC01>','<ZZZZ>')
        text,count=re.subn(r'(xkb_keycodes[^\{]*\{.*?)(\};)',r'\1 alias <AC01> = <ZZZZ>;\n\2',text,count=1,flags=re.S)
        self.assertEqual(count,1);self.load_map(text)
        self.assertNotIn('AC01',self.control()['names'])
        start=len(self.records.items);self.press('KeyA');self.observed_down(start,38,0x61)
    def test_missing_physical_name_rejects_new_press(self):
        self.load_map(self.dump_map().replace('<AC01>','<ZZZZ>'))
        self.assertNotIn('AC01',self.control()['names'])
        self.assertFalse(self.send(type='key',code='KeyA',down=True)['ok'])
        self.assertEqual(self.control()['held'],[])
    def test_external_held_key_is_not_acquired_or_released(self):
        self.assertEqual(self.control('external',code=38,down=True)['held'],[38])
        self.key('KeyA',True);self.key('KeyA',False);self.assertEqual(self.control()['held'],[38])
        self.assertEqual(self.control('external',code=38,down=False)['held'],[])
    def test_release_error_stop_and_eof_clear_owned_input(self):
        for mode in ('release','error','stop','eof'):
            with self.subTest(mode=mode):
                self.key('ShiftLeft',True);self.key('KeyA',True);self.assertEqual(self.control()['held'],[38,50])
                if mode=='release':self.assertTrue(self.send(type='release')['ok'])
                elif mode=='error':self.assertFalse(self.send(type='key',code='Unidentified',down=True)['ok'])
                elif mode=='stop':self.worker.send_signal(signal.SIGTERM);self.worker.wait(timeout=5)
                else:self.close_worker()
                self.assertEqual(self.control()['held'],[])
                self.close_worker();self.start_worker()

if __name__=='__main__':unittest.main()
