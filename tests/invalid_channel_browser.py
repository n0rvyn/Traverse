"""Real Chrome regression: malformed input must preserve the authenticated peer.

TRAVERSE_URL=https://host/ TRAVERSE_PAIR_CODE=... TRAVERSE_TEST_HEADED=1 \
  python3 tests/invalid_channel_browser.py
Requires Playwright and installed ordinary Chrome. Use a disposable consented host.
"""
import asyncio
import json
import os
from playwright.async_api import async_playwright

CAPTURE_SCRIPT="""(() => {
 const Native=window.RTCPeerConnection;
 window.RTCPeerConnection=class extends Native {
  constructor(...args){super(...args);window.__invalidPeer=this;}
  createDataChannel(...args){const c=super.createDataChannel(...args);
   if(args[0]==='input')window.__invalidChannel=c;return c;}
 };
})();"""

async def connect(page,url,code):
    await page.goto(url)
    await page.get_by_label('Pairing code',exact=True).fill(code)
    await page.get_by_role('button',name='Connect',exact=False).click()
    await page.evaluate("""() => new Promise((resolve,reject)=>{
      const end=performance.now()+45000;
      const next=()=>{if(window.__invalidPeer?.connectionState==='connected' &&
         window.__invalidChannel?.readyState==='open' && document.getElementById('desktop').readyState>=2)resolve();
        else if(performance.now()>end)reject(new Error('Initial peer did not connect'));
        else setTimeout(next,20);};next();})""")

async def exercise(page):
    results=[]
    for name,payload in [('empty',''),('whitespace',' '),('broken JSON','{'),('null JSON','null'),('missing event','{}'),('invalid event','{"event":1}')]:
        before=await page.evaluate('window.traverseStats()')
        await page.evaluate("""payload=>new Promise((resolve,reject)=>{
          const peer=window.__invalidPeer,c=window.__invalidChannel;let expected;
          const clean=()=>{clearTimeout(timer);c.removeEventListener('message',message);c.removeEventListener('close',closed);};
          const closed=()=>{clean();reject(new Error('Malformed input closed the peer'));};
          const message=e=>{try{const m=JSON.parse(e.data);
            if(expected && m.ack===expected.seq && m.sent===expected.sent){
              clean();if(window.__invalidPeer!==peer)reject(new Error('Peer was replaced'));else resolve();}
          }catch{}};
          const timer=setTimeout(()=>{clean();reject(new Error('No valid heartbeat acknowledgement after malformed input'));},10000);
          c.addEventListener('message',message);c.addEventListener('close',closed);
          try{c.send(payload);
            window.__invalidProbeSequence=(window.__invalidProbeSequence??1000000)+1;
            expected={seq:window.__invalidProbeSequence,sent:performance.now()};
            c.send(JSON.stringify({...expected,event:{type:'heartbeat'}}));}
          catch(e){clean();reject(e);}
        })""",payload)
        after=await page.evaluate("""before=>new Promise((resolve,reject)=>{
          const peer=window.__invalidPeer,end=performance.now()+10000;
          const next=async()=>{const stats=await window.traverseStats();
            if(peer!==window.__invalidPeer || peer.connectionState!=='connected')reject(new Error('Malformed input interrupted the peer'));
            else if(stats?.incoming?.ssrc===before.ssrc && stats.incoming.framesDecoded>before.framesDecoded)resolve(stats);
            else if(performance.now()>end)reject(new Error('Video stopped after malformed input'));
            else setTimeout(next,20);};next();})""",before['incoming'])
        results.append({'case':name,'samePeer':True,'sameVideoSource':True,'videoAdvanced':after['incoming']['framesDecoded']>before['incoming']['framesDecoded'],'heartbeatAcknowledged':True})
    return results

async def main():
    url=os.environ['TRAVERSE_URL'];code=os.environ['TRAVERSE_PAIR_CODE']
    report={'scope':'Authenticated malformed-input regression in ordinary Chrome','results':[]}
    try:
        async with async_playwright() as p:
            browser=await p.chromium.launch(channel='chrome',headless=os.environ.get('TRAVERSE_TEST_HEADED')!='1')
            try:
                context=await browser.new_context()
                await context.add_init_script(script=CAPTURE_SCRIPT)
                page=await context.new_page();await connect(page,url,code)
                report['results']=await exercise(page)
                await page.get_by_role('button',name='Disconnect',exact=True).click()
                report['status']='passed';report['browser']=browser.version
            finally:await browser.close()
    except Exception as error:
        report.update(status='failed',error=str(error).replace(code,'[redacted]'))
    print(json.dumps(report,indent=2))
    if report['status']!='passed':raise SystemExit(1)

if __name__=='__main__':asyncio.run(main())
