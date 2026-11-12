"""Test observer for C++ probe JSON only; owns no guardian socket or desktop grant.
All timeouts are test watchdogs.
"""
import json,queue,subprocess,tempfile,threading

class Peer:
    def __init__(self,owner,path,environment,pass_fds=(),start_new_session=False):
        self.log=tempfile.TemporaryFile(mode='w+')
        self.process=subprocess.Popen([owner,path],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=self.log,text=True,env=environment,pass_fds=pass_fds,start_new_session=start_new_session)
        self.rows=queue.Queue();self.history=[];self.index=0;self.latest={};self.eof=False
        def read():
            try:
                for line in self.process.stdout:self.rows.put(json.loads(line))
            finally:self.rows.put(None)
        self.reader=threading.Thread(target=read);self.reader.start()
    def record(self,row):
        if row is None:self.eof=True;return
        self.history.append(row)
        if row.get('event')=='state':self.latest=row
    def pump(self):
        while True:
            try:self.record(self.rows.get_nowait())
            except queue.Empty:return
    def wait(self,predicate,after=0):
        for row in self.history[after:]:
            if predicate(row):return row
        while True:
            row=None if self.eof else self.rows.get(timeout=8)
            if row is None:
                self.eof=True
                self.log.seek(0);raise AssertionError('Owner ended: '+self.log.read()+repr(self.history))
            self.record(row)
            if predicate(row):return row
    def state(self,predicate,after=0):return self.wait(lambda row:row.get('event')=='state' and predicate(row),after)
    def started(self):return self.state(lambda row:row['pid']>0 and row['accepting'])
    def send(self,command,**arguments):
        if isinstance(command,str):command=dict(op=command,**arguments)
        self.index+=1;self.write(dict(token=self.index,command=command));return self.index
    def write(self,row):self.process.stdin.write(json.dumps(row)+'\n');self.process.stdin.flush()
    def reply(self,token):return self.wait(lambda row:row.get('event')=='reply' and row['token']==token)
    def receive(self,token):
        row=self.reply(token)
        assert 'reply' in row,row
        return row['reply']
    def call(self,op,**arguments):return self.receive(self.send(op,**arguments))
    def stop(self):
        self.write(dict(action='stop'))
        row=self.wait(lambda row:row.get('event')=='stop-fenced')
        assert row['accepting'] is False,row
        return self.wait(lambda row:row.get('event')=='stopped')
    def close(self):
        if self.process.poll() is None:self.process.stdin.close()
        try:self.process.wait(timeout=8)
        except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=5);raise
        finally:
            self.reader.join(5);self.process.stdout.close()
            if not self.process.stdin.closed:self.process.stdin.close()
            self.log.close()
