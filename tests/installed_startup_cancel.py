"""Cancel the actual installed launcher at its initial HTTPS verification boundary.

Runs only on an owned synthetic X11 display in disposable package containers.
No owner logs or application stderr are read; cleanup is observed independently.
"""
import json,os,shutil,signal,socket,subprocess,tempfile,time
from pathlib import Path
from installed_standalone import descendants,alive,free_port,wait
expected=0;label="installed-startup-cancel"
with tempfile.TemporaryDirectory(prefix='traverse-stop-probe-') as temporary:
 root=Path(temporary);root.chmod(0o755)
 home=root/'home';home.mkdir(mode=0o700);os.chown(home,65534,65534)
 runtime=home/'runtime';runtime.mkdir(mode=0o700);os.chown(runtime,65534,65534)
 auth=home/'Xauthority';shutil.copyfile(os.environ['XAUTHORITY'],auth);os.chown(auth,65534,65534);auth.chmod(0o600)
 cert=root/'cert.pem';key=home/'key.pem'
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 key.chmod(0o600);os.chown(key,65534,65534)
 port=free_port();config=home/'config.json';config.write_text(json.dumps(dict(schemaVersion=1,domain='localhost',port=port,certificate=str(cert),privateKey=str(key),listenAddress='127.0.0.1')));config.chmod(0o600);os.chown(config,65534,65534)
 marker=home/'cancelled'
 env=dict(os.environ,HOME=str(home),XDG_RUNTIME_DIR=str(runtime),XDG_CACHE_HOME=str(home/'cache'),XAUTHORITY=str(auth),SSL_CERT_FILE=str(cert),LD_PRELOAD='/tmp/connect_cancel.so',TRAVERSE_TEST_CANCEL_PORT=str(port),TRAVERSE_TEST_CANCEL_MARKER=str(marker))
 validation=subprocess.run(['/opt/traverse/bin/traverse','--config',str(config),'--check-config'],env=env,user=65534,group=65534,extra_groups=[],cwd=str(home),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 assert validation.returncode==0,('Config validation',validation.returncode)
 launch=subprocess.Popen(['/opt/traverse/bin/traverse','--config',str(config)],env=env,user=65534,group=65534,extra_groups=[],cwd=str(home),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 owned=set()
 try:
  deadline=time.monotonic()+25
  while launch.poll() is None and time.monotonic()<deadline:
   owned.update(descendants(launch.pid));time.sleep(.01)
  assert launch.poll() is not None,'Cancellation did not stop launcher'
  assert marker.read_bytes()==b'signal-before-probe','Probe boundary was not reached'
  assert marker.stat().st_uid==65534
  assert launch.returncode==expected,('exit',launch.returncode,expected)
  wait(lambda:not any(alive(pid) for pid in owned),'Owned child survived',timeout=10)
  assert not list((runtime/'traverse').glob('instance-*'))
  with socket.socket() as listener:listener.bind(('127.0.0.1',port))
  print(json.dumps(dict(label=label,signalAtHTTPSProbe=True,exit=launch.returncode,ownedChildrenGone=True,privateInstanceGone=True,listenerReleased=True)),flush=True)
 finally:
  if launch.poll() is None:
   os.killpg(launch.pid,signal.SIGTERM);launch.wait(timeout=12)
