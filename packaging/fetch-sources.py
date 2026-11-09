"""Fetch pinned release archives and reject corrupt or unsafe source payloads."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parent.parent


def safe_extract(archive, target, exclude_paths=()):
    exclusions = []
    for name in exclude_paths:
        path = Path(name)
        if path.is_absolute() or not path.parts or '..' in path.parts:
            raise ValueError('Unsafe source exclusion')
        exclusions.append(path.parts)
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        selected = []
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts:
                raise ValueError('Unsafe source archive member: '+member.name)
            relative = path.parts[1:]
            if any(relative[:len(exclusion)] == exclusion for exclusion in exclusions):
                continue
            if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                raise ValueError('Unsafe source archive member: '+member.name)
            selected.append(member)
        tar.extractall(target, members=selected)


def main():
    dest = Path(sys.argv[1]); dest.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT/'packaging/runtime-manifest.json').read_text())
    for source in manifest['sources']:
        archive = dest/source['url'].split('/')[-1]
        if not archive.exists():
            subprocess.run(['curl','--fail','--location','--retry','3','--retry-all-errors','--output',str(archive),source['url']],check=True)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != source['sha256']:
            raise ValueError('Source digest mismatch: '+source['name'])
        target = dest/source['name']
        if target.exists():
            raise ValueError('Refusing to reuse an extracted source tree: '+str(target))
        unpack = dest/(source['name']+'-extract'); unpack.mkdir()
        safe_extract(archive, unpack, source.get('build_exclude_paths', ()))
        roots = list(unpack.iterdir())
        if len(roots)!=1 or not roots[0].is_dir():
            raise ValueError('Expected one source root: '+source['name'])
        roots[0].rename(target); unpack.rmdir()


if __name__=='__main__': main()
