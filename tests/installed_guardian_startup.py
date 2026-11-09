"""Run under Xvfb with XTEST disabled: no pairing or IPC without an injector."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


with tempfile.TemporaryDirectory(prefix='traverse-unavailable-input-') as tmp:
    directory = Path(tmp)
    directory.chmod(0o700);os.chown(directory, 65534, 65534)
    authority = directory/'Xauthority'
    shutil.copyfile(os.environ['XAUTHORITY'], authority)
    authority.chmod(0o600);os.chown(authority, 65534, 65534)
    env = dict(os.environ, HOME=str(directory), XDG_CACHE_HOME=str(directory/'cache'),
               XAUTHORITY=str(authority))
    path = directory/'adapter.sock'
    result = subprocess.run(['traverse-adapter', '--display', env['DISPLAY'], '--socket', str(path),
                             '--no-dialog'], env=env, user=65534, group=65534, extra_groups=[],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert 'XTest unavailable' in result.stderr, result.stderr
    assert not path.exists(), 'Adapter advertised IPC without an input guardian'
    assert 'Pairing code:' not in result.stdout, 'Adapter offered pairing without an input guardian'
    print('Missing XTest rejected before pairing and IPC startup')
