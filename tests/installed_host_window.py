"""Actual packaged entry, system Qt maps and fresh setup without build tools."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile


def main():
    prefix=Path(sys.argv[1] if len(sys.argv)>1 else os.environ.get('TRAVERSE_TEST_PREFIX','/opt/traverse')).resolve()
    os.environ['TRAVERSE_TEST_PREFIX']=str(prefix)
    from installed_managed_certificates import require_disposable_environment
    require_disposable_environment()
    manifest=json.loads((prefix/'share/traverse/runtime-manifest.json').read_text());ui=manifest['hostUi']
    assert ui['executable']=='libexec/traverse/traverse-host' and ui['entry']=='bin/traverse-host'
    for name,sha in manifest['payloadSha256'].items():assert hashlib.sha256((prefix/name).read_bytes()).hexdigest()==sha, name
    assert hashlib.sha256((prefix/ui['executable']).read_bytes()).hexdigest()==ui['build']['binarySha256']
    assert not any(p.name in ('host-window-driver','public-certificate-probe') or p.name.endswith('-test') for p in (prefix/'libexec').rglob('*')),'Test executable entered installed payload'
    with tempfile.TemporaryDirectory(prefix='host-system-tools-') as temporary:
        utilities=Path(temporary);utilities.chmod(0o755)
        for name in ('readlink','dirname','basename','mkdir','uname'):
            path=shutil.which(name);assert path,name;(utilities/name).symlink_to(path)
        for name in ('cc','c++','gcc','g++','clang','cmake','make','ninja','go','python3'):
            assert shutil.which(name,path=str(utilities)) is None,'Build tool entered application PATH'
        entry=Path('/usr/bin/traverse-host') if prefix==Path('/opt/traverse') else prefix/ui['entry']
        assert entry.resolve()==(prefix/ui['entry']).resolve(),'Installed host symlink points elsewhere'
        os.environ.update(TRAVERSE_TEST_HOST_EXECUTABLE=str(entry),TRAVERSE_TEST_HOST_PACKAGED_ENTRY='1',TRAVERSE_TEST_HOST_TOOL_PATH=str(utilities))
        import setup_host_lifecycle
        ports=json.loads(os.environ.get('TRAVERSE_TEST_SETUP_PORTS','[443,9443]'))
        assert ports and all(isinstance(port,int) and 1<=port<=65535 for port in ports)
        for port in ports:
            os.environ['TRAVERSE_TEST_SETUP_PORT']=str(port);setup_host_lifecycle.main()
        print(json.dumps({'status':'passed','prefix':str(prefix),'exactPackagedEntry':True,'allPayloadHashesChecked':True,'systemQtMapsChecked':True,'inheritedPrivateMediaEnvironmentRemoved':True,'appPATHHasNoToolchainOrPython':True,'actualFreshSetupAndRelaunch':True,'scope':'Native installed/relocated X11 fixture; Chrome is a separate exact-artifact journey'}),flush=True)


if __name__=='__main__':main()
