"""Exercise default installed adapter dialog through real X11, no --no-dialog."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

with tempfile.TemporaryDirectory(prefix='traverse-installed-') as tmp:
    socket=tmp+'/adapter.sock'
    env=dict(os.environ,XDG_CACHE_HOME=tmp+'/cache')
    adapter=subprocess.Popen(['traverse-adapter','--display',os.environ['DISPLAY'],'--socket',socket],env=env,stdout=subprocess.DEVNULL)
    def state():
        return json.loads(subprocess.check_output(['traverse-adapter','--socket',socket,'--control','state'],env=env,text=True,stderr=subprocess.DEVNULL))
    try:
        end=time.monotonic()+15
        while time.monotonic()<end:
            if adapter.poll() is not None:raise RuntimeError('Installed adapter exited before dialog readiness')
            try:
                before=state()
                dialog=json.loads(subprocess.check_output(['/tmp/x11-probe','focus','Traverse sharing'],env=env,text=True))
                break
            except (subprocess.CalledProcessError,FileNotFoundError):time.sleep(.05)
        else:raise RuntimeError('No actual installed local sharing dialog')
        assert before['armed'] and dialog['mapped']
        subprocess.run(['/tmp/x11-probe','move',str(dialog['x']+40),str(dialog['y']+dialog['height']-15)],env=env,check=True,stdout=subprocess.DEVNULL)
        subprocess.run(['/tmp/x11-probe','click'],env=env,check=True,stdout=subprocess.DEVNULL)
        end=time.monotonic()+10
        while time.monotonic()<end:
            after=state()
            if not after['armed'] and not after['capturing']:break
            time.sleep(.05)
        else:raise RuntimeError('Installed Stop sharing did not revoke')
        print(json.dumps({'installedDialog':'passed','before':before,'after':after}))
    finally:
        adapter.terminate();adapter.wait(timeout=20)
