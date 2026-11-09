const $ = id => document.getElementById(id);
const video = $('desktop');
let token, peer, channel, heartbeat, reconnectTimer, sequence = 0, retry = true;
let iceServers = [];
let iceTransportPolicy = 'all';
let lastStats, rtts = [], generation = 0;
const held = new Set();
const syntheticModifiers = new Set();
const modifierGroups = [
  ['shiftKey', ['ShiftLeft','ShiftRight']], ['ctrlKey', ['ControlLeft','ControlRight']],
  ['altKey', ['AltLeft','AltRight']], ['metaKey', ['MetaLeft','MetaRight']]
];
const modifierCodes = new Set(modifierGroups.flatMap(([,codes])=>codes));
function acquireModifiers(event) {
  for (const [flag,codes] of modifierGroups) {
    if (!codes.includes(event.code) && event[flag] && !codes.some(code=>held.has(code))) {
      const code=codes[0]; send({type:'key',code,down:true}); held.add(code); syntheticModifiers.add(code);
    }
  }
}
function releaseSyntheticModifiers() {
  if ([...held].some(code=>!modifierCodes.has(code))) return;
  for (const code of syntheticModifiers) {send({type:'key',code,down:false});held.delete(code);}
  syntheticModifiers.clear();
}
const keys = new Set([...Array.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ', c=>'Key'+c), ...Array.from('0123456789', n=>'Digit'+n), ...Array.from({length:12},(_,n)=>'F'+(n+1)), 'Space','Enter','Tab','Escape','Backspace','Delete','Insert','Home','End','PageUp','PageDown','ArrowLeft','ArrowRight','ArrowUp','ArrowDown','ShiftLeft','ShiftRight','ControlLeft','ControlRight','AltLeft','AltRight','MetaLeft','MetaRight','Minus','Equal','BracketLeft','BracketRight','Backslash','Semicolon','Quote','Backquote','Comma','Period','Slash']);
function status(text, live=false) { $('state').textContent=text; document.body.classList.toggle('connected',live); $('overlay').hidden=live; $('overlay').textContent=text; }
async function api(path, body) {
  const r = await fetch('/api/'+path, {method:'POST', headers:{'Content-Type':'application/json', ...(token?{Authorization:'Bearer '+token}:{})}, body:JSON.stringify(body)});
  if (!r.ok) { let text=await r.text();try{text=JSON.parse(text).error??text;}catch{} const e=new Error(text); e.status=r.status; throw e; }
  return r.json();
}
function send(event) {
  if (channel?.readyState !== 'open') return;
  channel.send(JSON.stringify({seq:++sequence, sent:performance.now(), event}));
}
function release() { send({type:'release'}); held.clear(); syntheticModifiers.clear(); $('inputState').textContent='Click the desktop to control'; }
function closeLocal() {clearInterval(heartbeat); clearTimeout(reconnectTimer); release(); const old=peer; peer=null; channel=null; if(old)old.close();}
async function connect() {
  const gen=++generation;
  closeLocal(); status('Connecting…'); lastStats=undefined;
  const pc=peer=new RTCPeerConnection({iceServers,iceTransportPolicy,bundlePolicy:'max-bundle'});
  pc.addTransceiver('video',{direction:'recvonly'});
  const dc=channel=pc.createDataChannel('input',{ordered:true});
  dc.onopen=()=>{ if(gen!==generation)return; status('Connected',true); heartbeat=setInterval(()=>send({type:'heartbeat'}),500); };
  dc.onmessage=e=>{const m=JSON.parse(e.data); if(typeof m.sent==='number')rtts.push(performance.now()-m.sent);};
  dc.onclose=()=>{if(gen===generation && peer===pc)lost();};
  pc.ontrack=e=>{video.srcObject=new MediaStream([e.track]);};
  pc.onconnectionstatechange=()=>{if(gen===generation && ['failed','disconnected','closed'].includes(pc.connectionState))lost();};
  try {
    await pc.setLocalDescription(await pc.createOffer());
    if(pc.iceGatheringState!=='complete') await new Promise((resolve,reject)=>{
      const timeout=setTimeout(()=>reject(new Error('ICE gathering timed out')),15000);
      pc.addEventListener('icegatheringstatechange',()=>{if(pc.iceGatheringState==='complete'){clearTimeout(timeout);resolve();}});
    });
    const answer=await api('offer',{sdp:pc.localDescription.sdp,type:pc.localDescription.type});
    if(gen===generation)await pc.setRemoteDescription(answer);
  } catch(e) {if(gen!==generation)return; closeLocal(); status(e.message); if(e.status===403){token=undefined;retry=false;} else if(retry)reconnectTimer=setTimeout(connect,2000);}
}
function lost() {closeLocal(); status('Disconnected · reconnecting…'); if(retry&&token)reconnectTimer=setTimeout(connect,1500);}
$('pairForm').onsubmit=async e=>{e.preventDefault();$('connect').disabled=true;$('error').textContent='';try{const result=await api('pair',{code:$('code').value.trim()});token=result.token;iceServers=result.iceServers??[];iceTransportPolicy=result.iceTransportPolicy??'all';$('code').value='';retry=true;$('pairing').hidden=true;$('session').hidden=false;await connect();}catch(e){$('error').textContent=e.message;}finally{$('connect').disabled=false;}};
$('reconnect').onclick=()=>{if(token){retry=true;connect();}else{ $('session').hidden=true;$('pairing').hidden=false;status('Pair again from the host');}};
$('disconnect').onclick=async()=>{retry=false;++generation;closeLocal();try{await api('disconnect',{});}catch{}status('Disconnected');};
$('fullscreen').onclick=()=>{if(document.fullscreenElement)document.exitFullscreen();else $('stage').requestFullscreen();};
function position(e) {
  const r=video.getBoundingClientRect(); const scale=Math.min(r.width/video.videoWidth,r.height/video.videoHeight);
  const w=video.videoWidth*scale,h=video.videoHeight*scale,left=r.left+(r.width-w)/2,top=r.top+(r.height-h)/2;
  const x=(e.clientX-left)/w,y=(e.clientY-top)/h;
  return Number.isFinite(x)&&Number.isFinite(y)&&x>=0&&x<=1&&y>=0&&y<=1?{type:'move',x,y}:null;
}
video.onpointermove=e=>{const p=position(e);if(p)send(p);};
video.onpointerdown=e=>{const p=position(e);if(!p)return;e.preventDefault();video.focus();video.setPointerCapture(e.pointerId);send(p);send({type:'button',button:e.button,down:true});$('inputState').textContent='Controlling · leave focus to release keys';};
video.onpointerup=e=>{send({type:'button',button:e.button,down:false});if(video.hasPointerCapture(e.pointerId))video.releasePointerCapture(e.pointerId);};
video.onlostpointercapture=()=>send({type:'release'});
video.oncontextmenu=e=>e.preventDefault();
video.onwheel=e=>{e.preventDefault();const p=position(e);if(!p)return;send(p);if(e.deltaY)send({type:'wheel',axis:'y',direction:Math.sign(e.deltaY)});if(e.deltaX)send({type:'wheel',axis:'x',direction:Math.sign(e.deltaX)});};
video.addEventListener('keydown',e=>{if(!keys.has(e.code))return;e.preventDefault();if(e.repeat)return;syntheticModifiers.delete(e.code);acquireModifiers(e);held.add(e.code);send({type:'key',code:e.code,down:true});});
video.addEventListener('keyup',e=>{if(!keys.has(e.code))return;e.preventDefault();held.delete(e.code);send({type:'key',code:e.code,down:false});releaseSyntheticModifiers();});
video.onblur=release;window.addEventListener('blur',release);document.addEventListener('visibilitychange',()=>{if(document.hidden)release();});window.addEventListener('pagehide',()=>{release();peer?.close();});
video.onresize=()=>{$('resolution').textContent=`${video.videoWidth} × ${video.videoHeight}`;};
async function snapshotStats() {
  if(!peer)return null;
  const report=await peer.getStats();let incoming,pair,transport;
  report.forEach(s=>{if(s.type==='inbound-rtp'&&s.kind==='video')incoming=s;if(s.type==='transport')transport=s;});
  if(transport?.selectedCandidatePairId)pair=report.get(transport.selectedCandidatePairId);
  if(!pair)report.forEach(s=>{if(s.type==='candidate-pair'&&s.state==='succeeded'&&s.nominated)pair=s;});
  return {incoming,pair,local:pair&&report.get(pair.localCandidateId),remote:pair&&report.get(pair.remoteCandidateId),rtts:[...rtts],browser:navigator.userAgent};
}
// Read-only diagnostics used by the measurement harness; no privileged control API.
window.traverseStats=snapshotStats;
setInterval(async()=>{try{const s=await snapshotStats();if(!s?.incoming)return;const v=s.incoming;let rate='';if(lastStats){const dt=(v.timestamp-lastStats.timestamp)/1000;rate=`${((v.bytesReceived-lastStats.bytesReceived)*8/dt/1e6).toFixed(2)} Mb/s`;}$('metrics').textContent=`${v.framesPerSecond??0} fps · ${rate} · input RTT ${rtts.length?Math.round(rtts.at(-1)):'–'} ms · ${s.remote?.candidateType??'ICE'}`;lastStats=v;}catch{}},1000);
