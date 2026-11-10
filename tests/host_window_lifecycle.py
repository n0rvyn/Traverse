"""Actual UID65534 Qt window/native/private-CA/X11 test, not desktop acceptance."""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time
from installed_managed_certificates import Desktop, PREFIX, prefix_processes, require_disposable_environment
from installed_standalone import alive,descendants,ipc,wait
from managed_ca_fixture import PrivateCA


def main():
    require_disposable_environment()
    driver=Path(os.environ['TRAVERSE_TEST_HOST_DRIVER'])
    pebble=Path(os.environ['TRAVERSE_TEST_PEBBLE'])
    with tempfile.TemporaryDirectory(prefix='traverse-window-') as temporary:
        root=Path(temporary);root.chmod(0o755);ca=PrivateCA(root,pebble,443)
        try:
            desktop=Desktop(root,ca,443)
            environment=dict(desktop.env,TRAVERSE_TEST_HOST_PREFIX=str(PREFIX),
                TRAVERSE_TEST_HOST_CONFIG=str(desktop.path),TRAVERSE_TEST_HOST_IMAGE=str(desktop.home/'window.png'),
                QT_QPA_PLATFORM='xcb')
            for key in ('LD_LIBRARY_PATH','TRAVERSE_RUNTIME_PREFIX','GST_PLUGIN_PATH_1_0','GST_PLUGIN_SYSTEM_PATH_1_0','GST_PLUGIN_SCANNER','GST_REGISTRY'):
                environment.pop(key,None)
            reports=[]
            for ending in ('stop','close','death'):
                baseline=prefix_processes()
                process=subprocess.Popen([str(driver)],user=65534,group=65534,extra_groups=[],env=environment,
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                def read():
                    assert select.select([process.stdout],[],[],15)[0],'Controlled Qt fixture response timeout'
                    line=process.stdout.readline();assert line,'Controlled Qt fixture exited'
                    return json.loads(line)
                def call(action,**values):
                    process.stdin.write(json.dumps(dict(action=action,**values))+'\n');process.stdin.flush();return read()
                def clipboard(expected):
                    result=subprocess.run([str(driver),'--clipboard-probe'],input=json.dumps({'expected':expected})+'\n',
                        user=65534,group=65534,extra_groups=[],env=environment,text=True,capture_output=True,timeout=5)
                    assert result.returncode==0 and json.loads(result.stdout)=={'matches':True},'Actual cross-process clipboard mismatch'
                try:
                    assert read()['fixtureReady']
                    wait(lambda:call('view')['codeAvailable'],'Actual Qt window did not obtain available authority',timeout=45)
                    wait(lambda:call('view')['status']=='Waiting for Chrome','Actual Qt window never verified local HTTPS',timeout=45)
                    assert desktop.http()[0]==200
                    first=ipc(desktop.adapter,'/owner/authority')['code']
                    assert call('click',control='copyUrl')['clicked'];clipboard(desktop.origin+'/')
                    assert call('click',control='copyCode')['clicked'];clipboard(first)
                    if ending=='stop' and os.environ.get('TRAVERSE_TEST_HOST_EXPIRY')=='1':
                        wait(lambda:ipc(desktop.adapter,'/owner/authority')['codeStatus']=='expired',
                            'Real existing five-minute lifetime did not expire',timeout=305)
                        wait(lambda:call('view')['codeExpired'],'Qt code expiry did not update')
                        expired=call('view');assert not expired['codeAvailable'] and expired['newCodeAvailable']
                        assert not call('click',control='copyCode')['clicked']
                    assert call('click',control='newCode')['clicked']
                    def refreshed():
                        value=ipc(desktop.adapter,'/owner/authority')
                        code=value.get('code')
                        return value.get('codeStatus')=='available' and isinstance(code,str) and bool(code) and code!=first
                    wait(refreshed,'Actual New code control did not refresh')
                    current=ipc(desktop.adapter,'/owner/authority')['code']
                    wait(lambda:call('view')['codeAvailable'],'Qt refreshed-code reply not observed')
                    assert call('click',control='copyCode')['clicked'];clipboard(current)
                    status,body=desktop.http('api/pair',{'code':current});assert status==200;token=json.loads(body)['token']
                    wait(lambda:call('view')['codeUsed'],'Qt window did not observe actual pairing without another button action')
                    view=call('view');assert not view['codeAvailable'] and not view['newCodeAvailable']
                    assert view['status']=='Waiting for Chrome to reconnect' and view['stopInsideWindow'] and view['stopOnScreen']
                    assert call('click',control='copyUrl')['clicked'];clipboard(desktop.origin+'/')
                    assert call('snapshot')['saved']
                    if ending=='stop':
                        output=Path(os.environ['TRAVERSE_TEST_HOST_RESULT_IMAGE']);output.write_bytes((desktop.home/'window.png').read_bytes())
                    owned=descendants(process.pid);assert owned and prefix_processes()-baseline
                    gui_sockets=set()
                    for entry in Path(f'/proc/{process.pid}/fd').iterdir():
                        try:
                            target=os.readlink(entry)
                            if target.startswith('socket:['):gui_sockets.add(target)
                        except FileNotFoundError:pass
                    assert gui_sockets,'Actual Qt socket inventory is empty'
                    for pid in owned:
                        try:
                            command=(Path(f'/proc/{pid}/cmdline')).read_bytes().split(b'\0')
                            assert current.encode() not in command and token.encode() not in command
                            for entry in Path(f'/proc/{pid}/fd').iterdir():
                                try:assert os.readlink(entry) not in gui_sockets,'GUI socket inherited by native descendant'
                                except FileNotFoundError:pass
                        except FileNotFoundError:pass
                    maps=Path(f'/proc/{process.pid}/maps').read_text()
                    assert 'libQt6Widgets' in maps and 'libgstreamer' not in maps and str(PREFIX/'lib')+'/' not in maps
                    ipc(desktop.adapter,'/input',{'type':'key','code':'ShiftLeft','down':True},token)
                    assert desktop.x11('query')['shift']==1
                    # Stale UI observation is not permission to revoke a live
                    # controller. Suspend only our owned GUI, keeping the same
                    # real controller heartbeat alive independently of it.
                    if ending=='stop':
                        process.send_signal(signal.SIGSTOP)
                        try:
                            deadline=time.monotonic()+3
                            while time.monotonic()<deadline:
                                ipc(desktop.adapter,'/input',{'type':'heartbeat'},token)
                                time.sleep(.1)
                            assert desktop.x11('query')['shift']==1
                        finally:process.send_signal(signal.SIGCONT)
                        wait(lambda:call('view')['codeUsed'],'Qt did not recover from stale observation')
                        ipc(desktop.adapter,'/input',{'type':'heartbeat'},token)
                        assert desktop.x11('query')['shift']==1
                    before=time.monotonic()
                    if ending=='stop':assert call('click',control='stopSharing')['clicked']
                    elif ending=='close':assert call('close')['closing']
                    else:process.kill()
                    wait(lambda:desktop.x11('query')['shift']==0,'Qt exit left held Shift',timeout=2)
                    released=time.monotonic()-before
                    process.wait(timeout=15)
                    if ending!='death':assert process.returncode==0
                    wait(lambda:not any(alive(pid) for pid in owned),'Qt exit left owned native child',timeout=12)
                    wait(lambda:not any(alive(pid) for pid in prefix_processes()-baseline),'Qt exit left untracked native child',timeout=5)
                    reports.append({'ending':ending,'actualUid':65534,'trustedHttpsAndPairing':True,
                        'realClipboardBothControls':True,'realNewCodeAndLivePairState':True,
                        'pairedWithoutRtcNeverConnected':True,'stopInsideWindow':True,'stopOnScreen':True,'separateSystemQtMediaRuntime':True,
                        'inputReleaseSeconds':released,'allOwnedChildrenStopped':True})
                    reports[-1]['guiSocketsNotInheritedAndPairingSecretsAbsentFromArgv']=True
                    if ending=='stop':reports[-1]['staleGuiRetainsActualControllerAndHeldInput']=True
                    if ending=='stop' and os.environ.get('TRAVERSE_TEST_HOST_EXPIRY')=='1':
                        reports[-1]['actualFiveMinuteCodeExpiryAndRefresh']=True
                finally:
                    if process.poll() is None:
                        process.stdin.close()
                        try:process.wait(timeout=20)
                        except subprocess.TimeoutExpired:
                            process.kill();process.wait(timeout=5)
                    if not process.stdin.closed:process.stdin.close()
                    process.stdout.close()
            print(json.dumps({'status':'passed','scope':'internal configured Qt window/native SDK on isolated X11; no Settings/first-run/desktop acceptance',
                'cases':reports,'ownerLogsReadOrExported':False,'publicCA':False}),flush=True)
        finally:ca.close()


if __name__=='__main__':main()
