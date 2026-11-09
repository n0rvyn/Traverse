"""Fetch pinned release archives and reject corrupt or unsafe source payloads."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent.parent


def safe_extract(archive, target):
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise ValueError('Unsafe source archive member: '+member.name)
        tar.extractall(target, members=members)


def main():
    dest = Path(sys.argv[1]); dest.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT/'packaging/runtime-manifest.json').read_text())
    for source in manifest['sources']:
        archive = dest/source['url'].split('/')[-1]
        if not archive.exists():
            subprocess.run(['curl','--fail','--location','--retry','3','--output',str(archive),source['url']],check=True)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != source['sha256']:
            raise ValueError('Source digest mismatch: '+source['name'])
        target = dest/source['name']
        if target.exists():
            raise ValueError('Refusing to reuse an extracted source tree: '+str(target))
        unpack = dest/(source['name']+'-extract'); unpack.mkdir()
        safe_extract(archive, unpack)
        roots = list(unpack.iterdir())
        if len(roots)!=1 or not roots[0].is_dir():
            raise ValueError('Expected one source root: '+source['name'])
        roots[0].rename(target); unpack.rmdir()


if __name__=='__main__': main()
