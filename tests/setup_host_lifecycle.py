"""Actual unmodified host main: fresh HOME/XDG setup via external XTest keys.

Uses the exact private portable payload; no handwritten configuration, owner logs,
Chrome, system trust changes or physical-desktop acceptance claims.
"""
from contextlib import nullcontext
from http.client import HTTPConnection
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile

from installed_managed_certificates import PREFIX, prefix_processes, require_disposable_environment
from installed_standalone import alive, descendants, ipc, wait
from issuer_native import DOMAIN
from host_package_fixture import host_command, check_ui_process


def main():
    require_disposable_environment()
    executable=Path(os.environ['TRAVERSE_TEST_HOST_EXECUTABLE']);reports=[];port=int(os.environ.get('TRAVERSE_TEST_SETUP_PORT','9443'))
    origin='https://'+DOMAIN+(':'+str(port) if port!=443 else '')
    for explicit_xdg in (False,True):
        preserved=os.environ.get('TRAVERSE_TEST_PRESERVE_HOST_DATA')
        if preserved:
            parent=Path(preserved);assert parent.is_absolute() and Path('/tmp') in parent.parents and not parent.is_symlink()
            parent.mkdir(mode=0o755,exist_ok=True);assert parent.stat().st_uid==os.geteuid() and parent.stat().st_mode&0o022==0
            parent.chmod(0o755)
            workspace=nullcontext(tempfile.mkdtemp(prefix='setup-main-',dir=parent))
        else:workspace=tempfile.TemporaryDirectory(prefix='setup-main-')
        with workspace as temporary:
            root=Path(temporary);root.chmod(0o755);home=root/'home';home.mkdir(mode=0o700);os.chown(home,65534,65534)
            runtime=home/'runtime';runtime.mkdir(mode=0o700);os.chown(runtime,65534,65534)
            authority=home/'Xauthority';shutil.copyfile(os.environ['XAUTHORITY'],authority);authority.chmod(0o600);os.chown(authority,65534,65534)
            env=dict(os.environ,HOME=str(home),XDG_DATA_HOME=str(home/'data'),XDG_CACHE_HOME=str(home/'cache'),XDG_RUNTIME_DIR=str(runtime),XAUTHORITY=str(authority),QT_QPA_PLATFORM='xcb')
            for key in ('XDG_CONFIG_HOME','LD_LIBRARY_PATH','TRAVERSE_RUNTIME_PREFIX','GST_PLUGIN_PATH_1_0','GST_PLUGIN_SYSTEM_PATH_1_0','GST_PLUGIN_SCANNER','GST_REGISTRY'):env.pop(key,None)
            config_parent=home/'alternate-config' if explicit_xdg else home/'.config'
            if explicit_xdg:env['XDG_CONFIG_HOME']=str(config_parent)
            config=config_parent/'traverse/config.json';adapter=runtime/'traverse/adapter.sock'
            def launch():
                command,application_env=host_command(executable,PREFIX,env)
                return subprocess.Popen(command,env=application_env,user=65534,group=65534,extra_groups=[],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            def x11(*args):
                result=subprocess.run(['/tmp/x11-probe',*args],env=env,text=True,capture_output=True)
                assert result.returncode==0,('Owned X11 operation failed',args,result.stderr)
                return json.loads(result.stdout)
            def window(title):
                result=subprocess.run(['/tmp/x11-probe','window',title],env=env,text=True,capture_output=True)
                return json.loads(result.stdout) if result.returncode==0 else None
            def type_text(text):
                for character in text:x11('press','period' if character=='.' else character)
            process=launch()
            try:
                wait(lambda:window('Traverse setup'),'Actual default-path setup did not appear')
                check_ui_process(process,PREFIX)
                evidence=os.environ.get('TRAVERSE_TEST_SETUP_EVIDENCE')
                if evidence and not explicit_xdg and port==443:
                    image=Path(evidence)/'default-port-fresh-setup.ppm'
                    assert image.parent.is_dir() and not image.exists()
                    # Before Start: no CA or usable pairing code exists.
                    x11('capture',str(image))
                assert not config.exists();x11('close','Traverse setup');process.wait(timeout=5);assert process.returncode==0
                assert not config.exists() and not (home/'data/traverse').exists()
                process=launch();wait(lambda:window('Traverse setup'),'Fresh setup did not reopen')
                x11('focus','Traverse setup');type_text(DOMAIN);x11('press','Tab')
                x11('key','Control_L','down');x11('press','a');x11('key','Control_L','up');type_text(str(port))
                x11('press','Tab')
                if evidence and not explicit_xdg and port==443:
                    image=Path(evidence)/'certificate-method-focused.ppm'
                    assert not image.exists()
                    x11('capture',str(image))
                x11('press','Tab');x11('press','space')
                wait(lambda:config.is_file(),'Actual Start sharing did not create configuration')
                saved=json.loads(config.read_text());assert saved['domain']==DOMAIN and saved['port']==port and saved['certificateSettings']=={'mode':'local'}
                assert config.stat().st_uid==65534 and config.stat().st_mode&0o777==0o600
                wait(lambda:window('Traverse'),'Setup did not hand off to actual sharing window')
                wait(lambda:list((home/'data/traverse/certificates').glob('*/local-ca.pem')),'Local authority not prepared')
                public=next((home/'data/traverse/certificates').glob('*/local-ca.pem'));identity=hashlib.sha256(public.read_bytes()).hexdigest()
                context=ssl.create_default_context(cafile=str(public))
                def http(route='',body=None):
                    connection=HTTPConnection('127.0.0.1');connection.sock=context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=3),server_hostname=DOMAIN)
                    connection.request('POST' if body is not None else 'GET','/'+route,None if body is None else json.dumps(body),{'Origin':origin,'Content-Type':'application/json'})
                    response=connection.getresponse();status=response.status;data=response.read();connection.close();return status,data
                def ready():
                    try:return http()[0]==200 and bool(ipc(adapter,'/owner/authority').get('code'))
                    except OSError:return False
                wait(ready,'First-run owned endpoint did not serve HTTPS',timeout=35)
                check_ui_process(process,PREFIX)
                code=ipc(adapter,'/owner/authority')['code'];status,data=http('api/pair',{'code':code});assert status==200
                token=json.loads(data)['token'];ipc(adapter,'/input',{'type':'key','code':'ShiftLeft','down':True},token);assert x11('query')['shift']==1
                baseline=prefix_processes();owned=descendants(process.pid);assert owned
                print(json.dumps({'safeCloseTarget':window('Traverse'),'phase':'paired-first-run'}),flush=True)
                x11('close','Traverse');wait(lambda:x11('query')['shift']==0,'Actual host main close left held input',timeout=2);process.wait(timeout=15)
                wait(lambda:not any(alive(pid) for pid in owned),'Actual host main close left runtime children',timeout=12)
                assert not prefix_processes()
                process=launch();wait(lambda:window('Traverse'),'Saved host did not reopen without setup')
                wait(ready,'Saved first-run host did not regain HTTPS',timeout=35)
                assert window('Traverse setup') is None and json.loads(config.read_text())==saved
                assert hashlib.sha256(public.read_bytes()).hexdigest()==identity
                assert not ipc(adapter,'/state')['paired']
                x11('close','Traverse');process.wait(timeout=15);wait(lambda:not prefix_processes(),'Relaunch close left runtime children',timeout=12)
                reports.append({'configPath':'XDG_CONFIG_HOME' if explicit_xdg else 'HOME/.config','actualMainWithoutConfigArgument':True,'setupCloseCreatedNoState':True,'externalKeyboardStart':True,'actualHTTPSAndPairing':True,'heldInputReleasedOnMainClose':True,'relaunchSkippedSetupAndPreservedAuthority':True,'runtimeChildrenReaped':True,'port':port,'scope':'Actual entry on explicitly selected fixture port'})
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=15)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
    print(json.dumps({'status':'passed','scope':'Actual fresh-home native host entry + selected exact runtime artifact; isolated X11 UID65534. No export/Chrome/desktop/hardware acceptance.','cases':reports}),flush=True)


if __name__=='__main__':main()
