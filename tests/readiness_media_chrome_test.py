"""Ordinary Chrome pairs through a live synthetic check and controls desktop."""
import base64
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import unittest
X11=sys.argv[6]
import readiness_media_service_test as media
from chrome_fixture import Browser,CLIENT_UID,CLIENT_GID,PAIRING_READY,ensure_client_identity
from installed_standalone import wait
media.fixture.X11_PROBE=X11

class ChromeMediaTests(media.MediaServiceTests):
    def browser(self):
        client=self.root/'client';client.mkdir(mode=0o700);os.chown(client,CLIENT_UID,CLIENT_GID)
        runtime=client/'runtime';runtime.mkdir(mode=0o700);os.chown(runtime,CLIENT_UID,CLIENT_GID)
        nss=client/'.local/share/pki/nssdb';nss.mkdir(parents=True)
        for path in (client/'.local',client/'.local/share',client/'.local/share/pki',nss):
            path.chmod(0o700);os.chown(path,CLIENT_UID,CLIENT_GID)
        public=client/'fixture-ca.pem';shutil.copyfile(self.certificate,public)
        public.chmod(0o644);os.chown(public,CLIENT_UID,CLIENT_GID)
        environment=dict(self.clean_env,HOME=str(client),XDG_RUNTIME_DIR=str(runtime),
            XDG_CONFIG_HOME=str(client/'.config'),XDG_DATA_HOME=str(client/'.local/share'),XDG_CACHE_HOME=str(client/'.cache'))
        subprocess.run(['certutil','-N','--empty-password','-d','sql:'+str(nss)],env=environment,
                       user=CLIENT_UID,group=CLIENT_GID,extra_groups=[],check=True,capture_output=True)
        subprocess.run(['certutil','-A','-d','sql:'+str(nss),'-t','C,,','-n','Traverse private media fixture',
                        '-i',str(public)],env=environment,user=CLIENT_UID,group=CLIENT_GID,extra_groups=[],
                       check=True,capture_output=True)
        browser=Browser(client,client/'profile',environment)
        # Observe actual DTLS sends before the app's module loads. Module-private
        # variables stay private; no test/control API is shipped in client.js.
        browser.send('Page.addScriptToEvaluateOnNewDocument',{'source':"""
          window.testChannels={};window.healthReceipts=[];window.inputMessages=[];
          const originalCreate=RTCPeerConnection.prototype.createDataChannel;
          RTCPeerConnection.prototype.createDataChannel=function(...args){
            const channel=originalCreate.apply(this,args);testChannels[channel.label]=channel;
            const originalSend=channel.send.bind(channel);
            channel.send=value=>{
              const row=JSON.parse(value);
              if(channel.label==='input')inputMessages.push(row);
              if(channel.label==='health' && row.type==='receipt')healthReceipts.push(row);
              originalSend(value);
              if(channel.label==='health' && row.type==='receipt' && window.pauseAfterHealthReceipt){
                window.pauseAfterHealthReceipt=false;document.getElementById('desktop').pause();
              }
            };
            return channel;
          };
        """})
        return browser
    def connect(self,browser):
        self.assertFalse(browser.navigate(self.origin+self.base).get('errorText'))
        browser.wait(PAIRING_READY,'Actual trusted Chrome pairing form')
        authority=self.authority();self.assertEqual(authority['codeStatus'],'available')
        browser.evaluate("document.getElementById('code').value="+json.dumps(authority['code']))
        browser.evaluate("document.getElementById('pairForm').requestSubmit()")
        browser.wait("document.body.classList.contains('connected') && document.getElementById('desktop').videoWidth===640 && document.getElementById('desktop').videoHeight===480 && document.getElementById('desktop').getVideoPlaybackQuality().totalVideoFrames>1",'Actual640x480 desktop decoded by ordinary Chrome')
        browser.wait("document.getElementById('metrics').textContent!=='Waiting for video'",'Existing Chrome video metrics updated')
        wait(lambda:self.health().get('status')=='observed','Actual Chrome fresh decoded-frame health receipt')
        print(json.dumps(dict(browser=browser.version['product'],desktop=[640,480],secureContext=browser.evaluate('window.isSecureContext'))),flush=True)
        evidence=os.environ.get('TRAVERSE_MEDIA_CHROME_EVIDENCE')
        if evidence:
            directory=Path(evidence);directory.mkdir(parents=True,exist_ok=True)
            (directory/(self._testMethodName+'.png')).write_bytes(base64.b64decode(browser.send('Page.captureScreenshot',{'format':'png'})['data']))
    def health(self):
        return self.private_call('/state',{})[1].get('health',{})
    def test_chrome_pairs_during_check_and_preserves_held_input(self):
        lease=self.reserve();observer,pid=self.start_media(lease);browser=None
        try:
            browser=self.browser();self.connect(browser)
            self.assertFalse(Path(f'/proc/{pid}').exists(),'Chrome connected before synthetic child reap')
            self.assertEqual(self.events(lease)[0],403)
            observer.close();observer=None
            browser.evaluate("document.getElementById('desktop').focus()")
            browser.key('keyDown','Shift','ShiftLeft',16)
            wait(lambda:self.query()['shift']==1,'Chrome input did not reach host',timeout=5)
            try:
                browser.wait('healthReceipts.length>0','Actual fresh health message captured from ordinary Chrome')
                receipt=browser.evaluate('healthReceipts.at(-1)')
                wait(lambda:self.health().get('lastObservation',{}).get('decodedFrames',0)>=receipt['decodedFrames'],'Native owner accepted captured health receipt')
                rejected=self.health()['rejected']
                self.assertTrue(browser.evaluate("(()=>{const before=inputMessages.length;testChannels.health.send(JSON.stringify(healthReceipts.at(-1)));testChannels.health.send(JSON.stringify({schemaVersion:1,type:'receipt'}));RTCDataChannel.prototype.send.call(testChannels.health,'{');RTCDataChannel.prototype.send.call(testChannels.input,JSON.stringify({schemaVersion:1,type:'request'}));return inputMessages.length===before;})()"))
                wait(lambda:self.health()['rejected']>=rejected+4,'Replay, malformed and wrong-channel health messages were ignored')
                self.assertEqual(self.query()['shift'],1,'Health messages released a real held key')
                self.assertEqual(self.private_call('/media/reserve',dict(schemaVersion=1,id='e'*32))[0],409)
                self.assertEqual(self.events(lease)[0],403)
                self.assertEqual(self.private_call('/media/end',dict(schemaVersion=1,id=lease['id']))[0],200)
                self.assertEqual(self.query()['shift'],1,'Rejected/ended check released real controller input')
                frames=browser.evaluate("document.getElementById('desktop').getVideoPlaybackQuality().totalVideoFrames")
                browser.wait("document.getElementById('desktop').getVideoPlaybackQuality().totalVideoFrames>"+str(frames),'Real controller video stopped after rejected check')
                browser.evaluate('window.pauseAfterHealthReceipt=true')
                browser.wait("document.getElementById('desktop').paused && pauseAfterHealthReceipt===false",'Chrome pauses after its preceding frame receipt')
                wait(lambda:self.health()['pending'],'Fresh health challenge while presentation is paused')
                observed=self.health()['lastObservation']['observedMonotonicMs']
                received=browser.evaluate('(async()=> (await traverseStats()).incoming.bytesReceived)()')
                browser.wait('(async()=> (await traverseStats()).incoming.bytesReceived>'+str(received)+')()', 'RTP still arrives while video presentation is paused')
                self.assertEqual(self.health()['lastObservation']['observedMonotonicMs'],observed,'A paused video fabricated fresh presentation health')
                self.assertEqual(self.query()['shift'],1,'Missing video health released a held key')
                browser.evaluate("document.getElementById('desktop').play()")
                wait(lambda:self.health()['lastObservation']['observedMonotonicMs']>observed,'Fresh frame health resumes after presentation')
                browser.evaluate('testChannels.health.close()')
                wait(lambda:self.health()['status']=='unavailable','Closed health channel reported without ending control')
                self.assertEqual(self.query()['shift'],1,'Closing health released a held key')
                self.assertTrue(browser.evaluate("document.body.classList.contains('connected')"))
            finally:
                browser.key('keyUp','Shift','ShiftLeft',16)
                wait(lambda:self.query()['shift']==0,'Chrome key release did not reach host',timeout=5)
            previous=self.private_call('/state',{})[1]['generation']
            browser.evaluate("document.getElementById('reconnect').click()")
            wait(lambda:self.private_call('/state',{})[1].get('generation',0)>previous and
                self.health().get('status')=='observed','Reconnected Chrome presents a fresh frame under a new native peer')
            browser.evaluate("document.getElementById('desktop').focus()")
            browser.key('keyDown','Shift','ShiftLeft',16)
            wait(lambda:self.query()['shift']==1,'Reconnected keyboard input reaches Linux')
            try:
                rejected=self.health()['rejected']
                browser.evaluate('testChannels.health.send('+json.dumps(json.dumps(receipt))+')')
                wait(lambda:self.health()['rejected']>rejected,'Old-peer health receipt rejected after reconnect')
                self.assertEqual(self.query()['shift'],1,'Old generation health released new controller input')
            finally:
                browser.key('keyUp','Shift','ShiftLeft',16)
                wait(lambda:self.query()['shift']==0,'Reconnected key release reaches Linux')
        finally:
            if browser:browser.close()
            if observer:observer.close()
    def test_chrome_without_media_baseline(self):
        self.service.terminate();self.service.wait(timeout=8)
        self.media_enabled=False;self.start_service()
        browser=self.browser()
        try:self.connect(browser)
        finally:browser.close()

if __name__=='__main__':
    ensure_client_identity()
    unittest.main(defaultTest=['ChromeMediaTests.test_chrome_without_media_baseline',
                              'ChromeMediaTests.test_chrome_pairs_during_check_and_preserves_held_input'])
