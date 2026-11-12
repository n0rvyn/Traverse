"""Failure-only fresh native-owner replay; fixed metadata, never owner logs.

This diagnoses startup through the existing broker, not native UI acceptance.
"""
import json
from contextlib import ExitStack
import os
from pathlib import Path
import shutil
import tempfile
import time
from types import SimpleNamespace


def replay(configuration, environment, prefix, evidence):
    from host_supervisor_test import OwnerFixture

    report = {'scope': 'Fresh local startup through existing native-owner broker; no UI or Chrome acceptance',
              'ownerLogsReadOrExported': False, 'states': []}
    try:
        with tempfile.TemporaryDirectory(prefix='startup-owner-') as temporary, ExitStack() as cleanup:
            root = Path(temporary)
            root.chmod(0o755)
            home = root/'home'
            home.mkdir(mode=0o700)
            os.chown(home, 65534, 65534)
            runtime = home/'runtime'
            runtime.mkdir(mode=0o700)
            os.chown(runtime, 65534, 65534)
            path = home/'config.json'
            shutil.copyfile(configuration, path)
            path.chmod(0o600)
            os.chown(path, 65534, 65534)
            env = dict(environment, HOME=str(home), XDG_RUNTIME_DIR=str(runtime),
                       XDG_DATA_HOME=str(home/'data'), XDG_CACHE_HOME=str(home/'cache'),
                       TRAVERSE_TEST_DISCARD_NATIVE_STDERR='1',
                       PATH=str(prefix/'libexec/traverse')+':'+os.environ['TRAVERSE_TEST_HOST_TOOL_PATH'])
            owner = OwnerFixture(SimpleNamespace(path=path, env=env, home=home))
            cleanup.callback(owner.close)
            deadline = time.monotonic()+35
            while time.monotonic() < deadline:
                state = owner.call('status')
                row = {key: state.get(key) for key in ('phase', 'stage', 'supervisorPid', 'localHttps')}
                row['certificateStatus'] = (state.get('certificate') or {}).get('status')
                row['authorityStatus'] = (state.get('authority') or {}).get('codeStatus')
                if not report['states'] or row != report['states'][-1]:
                    report['states'].append(row)
                if state.get('phase') == 'ready':
                    report['ending'] = owner.call('stop')
                    break
                if state.get('phase') == 'failed':
                    report['ending'] = owner.call('wait-stopped')
                    break
                time.sleep(.1)
            else:
                report['ending'] = {'startupWaitExpired': True}
    except Exception as failure:
        report['diagnosticError'] = type(failure).__name__
    finally:
        (evidence/'startup-owner-diagnostics.json').write_text(json.dumps(report, indent=2)+'\n')
