"""Read back real fixture owner configuration/CA data across package lifecycle."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def snapshot(root):
    assert root.is_absolute() and Path('/tmp') in root.parents and not root.is_symlink()
    assert root.is_dir() and root.stat().st_uid==os.geteuid()
    result={}
    for workspace in root.iterdir():
        assert workspace.is_dir() and not workspace.is_symlink()
        for relative in ('home/.config/traverse','home/alternate-config/traverse','home/data/traverse/certificates'):
            folder=workspace/relative
            if not folder.exists():continue
            for path in [folder,*folder.rglob('*')]:
                info=path.lstat();assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),'Unexpected owner-data object'
                row={'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode),'directory':stat.S_ISDIR(info.st_mode)}
                if path.is_file():row['sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
                result[str(path.relative_to(root))]=row
    assert any(name.endswith('/config.json') for name in result),'Real saved configuration positive control missing'
    assert any(name.endswith('/local-authority.pem') for name in result),'Real generated CA positive control missing'
    return result


def main():
    from installed_managed_certificates import require_disposable_environment
    require_disposable_environment()
    assert len(sys.argv)==4 and sys.argv[1] in ('record','check')
    root=Path(sys.argv[2]);path=Path(sys.argv[3]);actual=snapshot(root)
    if sys.argv[1]=='record':
        assert not path.exists();path.write_text(json.dumps(actual,sort_keys=True,indent=2)+'\n');path.chmod(0o600)
    else:assert actual==json.loads(path.read_text()),'Package lifecycle changed saved owner configuration or CA state'
    print(json.dumps({'status':'passed','operation':sys.argv[1],'actualOwnerDataEntries':len(actual),'privateKeyBytesReported':False}),flush=True)


if __name__=='__main__':main()
