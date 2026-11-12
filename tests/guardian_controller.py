"""Shared controller for the actual inherited native guardian socket."""
import json,os,socket,subprocess,tempfile,time

class Controller:
    def __init__(self,binary,environment,parent=None,small_buffer=False,start_new_session=False):
        self.socket,exported=socket.socketpair()
        if small_buffer:exported.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,2048)
        self.socket.settimeout(8)
        self.log=tempfile.TemporaryFile(mode='w+')
        try:self.process=subprocess.Popen([binary,str(os.getpid() if parent is None else parent)],
            stdin=exported,stdout=subprocess.DEVNULL,stderr=self.log,env=environment,start_new_session=start_new_session)
        finally:exported.close()
        self.reader=self.socket.makefile('r');self.index=0;self.saved={};self.events=[];self.stop_sent=False;self.event_cursors={}

    def started(self):
        row=json.loads(self.reader.readline());assert row['event']=='started' and row['ok'],row
        return row

    def send(self,op,**data):
        self.index+=1
        try:self.socket.sendall((json.dumps(dict(schemaVersion=1,id=self.index,op=op,**data))+'\n').encode())
        except OSError as error:
            self.log.seek(0)
            raise AssertionError('Guardian send failed: '+repr(self.events)+'; '+self.log.read()) from error
        if op=='stop':self.stop_sent=True
        return self.index

    def receive(self,index):
        while index not in self.saved:
            self.read_message()
        return self.saved.pop(index)

    def read_message(self):
        line=self.reader.readline()
        if not line:
            self.log.seek(0);raise AssertionError('Guardian IPC ended: '+repr(self.events)+'; '+self.log.read())
        row=json.loads(line)
        if row.get('id') is None:
            self.events.append(row)
            if row.get('event')=='ended':self.stop_sent=True
        else:self.saved[row['id']]=row

    def wait_event(self,name,predicate=lambda row:True):
        while True:
            cursor=self.event_cursors.get(name,0)
            while cursor<len(self.events):
                row=self.events[cursor];cursor+=1;self.event_cursors[name]=cursor
                if row.get('event')==name and predicate(row):return row
            self.read_message()

    def call(self,op,**data):return self.receive(self.send(op,**data))

    def terminal(self):
        while not any(row.get('event')=='ended' for row in self.events):
            self.read_message()
        self.stop_sent=True
        return next(row for row in reversed(self.events) if row.get('event')=='ended')

    def close(self):
        self.reader.close();self.socket.close()
        try:self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5);raise
        finally:self.log.close()


class GuardianActions:
    def state(self,peer,predicate):
        end=time.monotonic()+5
        while True:
            row=peer.call('snapshot');self.assertTrue(row['ok'],row)
            state=row['snapshot']
            if predicate(state):return state
            self.assertLess(time.monotonic(),end,state)
            time.sleep(.01)

    def grant(self,peer):
        self.state(peer,lambda row:row['state']=='capabilities-ready')
        self.assertTrue(peer.call('request',request=dict(devices=3,sourceTypes=1,cursorMode=2,multiple=False,parentWindow=''))['ok'])
        self.state(peer,lambda row:row['granted'])
        self.assertTrue(peer.call('select-stream',index=0)['ok'])
        state=self.state(peer,lambda row:row['inputReady'])
        self.assertEqual(state['grantedDevices'],3)
        return state

    def event(self,peer,**event):
        result=peer.call('input',event=event);self.assertTrue(result['ok'],result);return result
