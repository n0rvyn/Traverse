"""Real Chrome loading guard; dummy code and private profiles, no host authority."""
import argparse
import base64
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
from urllib.parse import parse_qs
from chrome_fixture import CDP, CLIENT_UID, CLIENT_GID, ensure_client_identity
from issuer_native import wait_for
from installed_standalone import alive, descendants

DUMMY='LOADING_GUARD_FIXTURE'


def verify_loading_guard(assets,evidence,chrome=Path('/usr/bin/google-chrome-stable')):
    assets,evidence=Path(assets).resolve(),Path(evidence);evidence.mkdir(parents=True,exist_ok=True)
    identity={}
    if os.geteuid()==0:
        ensure_client_identity();identity=dict(user=CLIENT_UID,group=CLIENT_GID,extra_groups=[])
    results=[]
    for mode in ('click','fallback'):
        release=threading.Event();module=threading.Event();paired=threading.Event();fallback=threading.Event()
        state={'mode':mode,'querySeen':False,'pairPosts':0,'fallbackPosts':0}
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def reply(self,data,kind='text/html; charset=utf-8',status=200):
                self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(data)));self.end_headers()
                try:self.wfile.write(data)
                except (BrokenPipeError,ConnectionResetError):pass
            def do_GET(self):
                state.setdefault('requests',[]).append(self.path.split('?',1)[0])
                if '?' in self.path:state['querySeen']=True
                if self.path=='/client.js':
                    module.set();release.wait(30);self.reply((assets/'client.js').read_bytes(),'application/javascript');return
                if self.path in ('/','/style.css'):
                    name='index.html' if self.path=='/' else 'style.css'
                    self.reply((assets/name).read_bytes(),'text/css' if name=='style.css' else 'text/html; charset=utf-8');return
                self.reply(b'',status=404)
            def do_POST(self):
                if '?' in self.path:state['querySeen']=True
                data=self.rfile.read(int(self.headers.get('Content-Length','0')))
                if self.path=='/api/pair':
                    assert json.loads(data)=={'code':DUMMY}
                    state['pairPosts']+=1;paired.set();self.reply(b'{"error":"Loading guard diagnostic complete"}','application/json',403);return
                if self.path=='/':
                    assert parse_qs(data.decode())=={'code':[DUMMY]}
                    state['fallbackPosts']+=1;fallback.set();self.reply(b'<p>Safe fallback received.</p>');return
                self.reply(b'',status=404)
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever);thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix='traverse-loading-guard-') as temporary:
                directory=Path(temporary);directory.chmod(0o755)
                profile=directory/'client';profile.mkdir(mode=0o700)
                if identity:os.chown(profile,CLIENT_UID,CLIENT_GID)
                args=[str(chrome),'--no-first-run','--no-default-browser-check','--enable-automation',
                    '--remote-debugging-port=0','--user-data-dir='+str(profile),'--window-size=1280,900','about:blank']
                if os.uname().sysname=='Linux':args=['xvfb-run','-a','-s','-screen 0 1280x900x24',*args]
                environment=os.environ.copy() if os.uname().sysname=='Darwin' else {}
                environment.update(PATH=os.environ.get('PATH','/usr/bin:/bin'),HOME=str(profile),LANG='C.UTF-8')
                if os.environ.get('TMPDIR'):environment['TMPDIR']=os.environ['TMPDIR']
                with (directory/'browser-errors.txt').open('w') as errors:
                    process=subprocess.Popen(args,env=environment,stdout=subprocess.DEVNULL,stderr=errors,start_new_session=True,**identity)
                    channel=None
                    try:
                        def endpoint():
                            assert process.poll() is None,'Owned Chrome exited at startup'
                            path=profile/'DevToolsActivePort'
                            if not path.exists():return None
                            lines=path.read_text().splitlines()
                            return 'ws://127.0.0.1:'+lines[0]+lines[1] if len(lines)==2 else None
                        channel=CDP(wait_for(endpoint,'Loading guard debugger',[process]))
                        arguments=channel.call('Browser.getBrowserCommandLine')['arguments']
                        forbidden=('--ignore-certificate-errors','--allow-insecure-localhost','--no-sandbox','--disable-setuid-sandbox','--disable-web-security')
                        assert not any(any(value==flag or value.startswith(flag+'=') for flag in forbidden) for value in arguments)
                        assert any(value.startswith('--user-data-dir=') and Path(value.split('=',1)[1]).resolve()==profile.resolve() for value in arguments)
                        target=channel.call('Target.createTarget',{'url':'about:blank'})['targetId']
                        session=channel.call('Target.attachToTarget',{'targetId':target,'flatten':True})['sessionId']
                        def send(method,params=None):return channel.call(method,params,session)
                        def evaluate(expression):
                            reply=send('Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':True})
                            assert 'exceptionDetails' not in reply,'Loading guard observer evaluation failed'
                            return reply['result'].get('value')
                        send('Page.enable');send('Runtime.enable')
                        evaluate("setTimeout(()=>location.href="+json.dumps('http://127.0.0.1:'+str(server.server_port)+'/')+",0);true")
                        wait_for(lambda:evaluate("!!document.getElementById('connect') && document.styleSheets.length>0"),'Loading guard form',[process])
                        assert module.wait(10),'Module request absent'
                        snapshot="({disabled:document.getElementById('connect').disabled,label:document.getElementById('state').textContent,method:document.getElementById('pairForm').method,handler:typeof document.getElementById('pairForm').onsubmit==='function'})"
                        state['initial']=evaluate(snapshot)
                        assert state['initial']=={'disabled':True,'label':'Loading…','method':'post','handler':False},state
                        def capture(name):
                            (evidence/name).write_bytes(base64.b64decode(send('Page.captureScreenshot',{'format':'png'})['data']))
                        def click():
                            point=evaluate("(()=>{const r=document.getElementById('connect').getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2};})()")
                            for kind in ('mousePressed','mouseReleased'):send('Input.dispatchMouseEvent',{'type':kind,'button':'left','clickCount':1,**point})
                        if mode=='click':capture('loading-guard-loading.png')
                        evaluate("document.getElementById('code').value="+json.dumps(DUMMY))
                        if mode=='click':
                            click();assert not paired.is_set() and not fallback.is_set()
                            release.set()
                            wait_for(lambda:evaluate("typeof document.getElementById('pairForm').onsubmit==='function' && !document.getElementById('connect').disabled"),'Enabled Connect',[process])
                            state['ready']=evaluate(snapshot)
                            assert state['ready']=={'disabled':False,'label':'Not connected','method':'post','handler':True},state
                            assert evaluate("document.getElementById('code').value")==DUMMY,'Pretyped code was lost'
                            evaluate("document.getElementById('code').value=''");capture('loading-guard-ready.png')
                            evaluate("document.getElementById('code').value="+json.dumps(DUMMY));click()
                            assert paired.wait(10),'Ready button did not send pairing POST'
                            wait_for(lambda:evaluate("document.getElementById('error').textContent==='Loading guard diagnostic complete'"),'Pair response',[process])
                            assert state['pairPosts']==1 and state['fallbackPosts']==0,state
                        else:
                            try:evaluate("document.getElementById('pairForm').requestSubmit()")
                            except AssertionError:assert fallback.wait(10),'Unexpected submission failure'
                            assert fallback.wait(10) and state['pairPosts']==0 and state['fallbackPosts']==1,state
                        assert not state['querySeen'],'Dummy code entered a query string'
                        results.append(state.copy())
                    except BaseException:
                        errors.flush()
                        debugger=profile/'DevToolsActivePort'
                        state['launcherExit']=process.poll()
                        state['debuggerFileExists']=debugger.exists()
                        try:state['debuggerLineCount']=len(debugger.read_text().splitlines())
                        except OSError:state['debuggerLineCount']=None
                        # This profile only visits about:blank and the owned
                        # dummy-code server; it never receives host authority.
                        diagnostic=(directory/'browser-errors.txt').read_text(errors='replace')
                        print(json.dumps({'loadingGuardFailure':state,'browserStderr':diagnostic}),flush=True)
                        (evidence/('loading-guard-'+mode+'-failure.json')).write_text(json.dumps(state,indent=2))
                        (evidence/('loading-guard-'+mode+'-browser-errors.txt')).write_text(diagnostic)
                        raise
                    finally:
                        release.set()
                        owned=descendants(process.pid) if os.uname().sysname=='Linux' else set()
                        if channel:
                            try:channel.call('Browser.close')
                            except Exception:pass
                            channel.close()
                        try:process.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            os.killpg(process.pid,signal.SIGTERM)
                            try:process.wait(timeout=5)
                            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
                        if owned:wait_for(lambda:not any(alive(pid) for pid in owned),'Owned loading guard Chrome children stopped',seconds=10)
        finally:
            release.set();server.shutdown();server.server_close();thread.join(5)
    report={'status':'passed','scope':'Real Chrome loading guard only; dummy code/private profiles; full installed HTTPS/control journey remains separate','cases':results}
    (evidence/'loading-guard-summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets',type=Path,required=True);parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--chrome',type=Path,default=Path('/usr/bin/google-chrome-stable'))
    args=parser.parse_args();verify_loading_guard(args.assets,args.evidence,args.chrome)
