"""Read back each produced format and check every private payload byte."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import stat
import subprocess
import tarfile


MANIFEST = 'share/traverse/runtime-manifest.json'


def record(stream, size, name, records, manifests):
    if name in records:
        raise ValueError('Duplicate artifact payload path')
    digest = hashlib.sha256()
    material = bytearray() if name == MANIFEST else None
    while size:
        data = stream.read(min(size, 1024*1024))
        if not data:
            raise ValueError('Truncated artifact payload')
        digest.update(data)
        if material is not None:
            material.extend(data)
        size -= len(data)
    records[name] = digest.hexdigest()
    if material is not None:
        manifests.append(json.loads(material))


def from_tar(stream, prefix):
    records, manifests, links = {}, [], {}
    with tarfile.open(fileobj=stream, mode='r|*') as archive:
        for entry in archive:
            name = entry.name.removeprefix('./')
            if name.startswith(prefix) and entry.isfile():
                record(archive.extractfile(entry), entry.size, name[len(prefix):], records, manifests)
            if name=='usr/bin/traverse-host':
                if name in links:raise ValueError('Duplicate native host package entry')
                links[name]=entry.linkname if entry.issym() else None
    return records, manifests, links


def exact(stream, size):
    result = stream.read(size)
    if len(result) != size:
        raise ValueError('Truncated RPM cpio payload')
    return result


def from_cpio(stream):
    records, manifests, links = {}, [], {}
    while True:
        header = exact(stream, 110)
        if header[:6] not in (b'070701', b'070702'):
            raise ValueError('Unexpected RPM cpio format')
        fields = [int(header[i:i+8], 16) for i in range(6, 110, 8)]
        mode, size, name_size = fields[1], fields[6], fields[11]
        raw_name = exact(stream, name_size)
        if not raw_name.endswith(b'\0'):
            raise ValueError('Invalid RPM cpio path')
        name = raw_name[:-1].decode().removeprefix('./')
        exact(stream, (-(110+name_size)) % 4)
        if name == 'TRAILER!!!':
            break
        prefix = 'opt/traverse/'
        if name=='usr/bin/traverse-host':
            if name in links:raise ValueError('Duplicate native host package entry')
            value=exact(stream,size);links[name]=value.decode() if stat.S_ISLNK(mode) else None
        elif name.startswith(prefix) and stat.S_ISREG(mode):
            record(stream, size, name[len(prefix):], records, manifests)
        else:
            # Still consume non-payload entries without extracting anything.
            remaining = size
            while remaining:
                data = exact(stream, min(remaining, 1024*1024)); remaining -= len(data)
        exact(stream, (-size) % 4)
    # rpm2cpio can pad the stream after the trailer. Drain it before waiting.
    while stream.read(1024*1024):
        pass
    return records, manifests, links


def verify(path):
    if path.suffix == '.rpm':
        process = subprocess.Popen(['rpm2cpio', str(path)], stdout=subprocess.PIPE)
        reader = from_cpio
    elif path.suffix == '.deb':
        process = subprocess.Popen(['dpkg-deb', '--fsys-tarfile', str(path)], stdout=subprocess.PIPE)
        reader = lambda stream: from_tar(stream, 'opt/traverse/')
    else:
        with path.open('rb') as stream:
            records, manifests, links = from_tar(stream, 'traverse/')
        process = None
    if process is not None:
        try:
            records, manifests, links = reader(process.stdout)
            if process.wait(timeout=30) != 0:
                raise ValueError('Artifact reader failed')
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill(); process.wait()
    if len(manifests) != 1:
        raise ValueError('Artifact manifest absent or duplicated')
    manifest = manifests[0]
    if 'sourceSnapshot' in manifest:
        source=manifest['sourceSnapshot']
        digest=hashlib.sha256(json.dumps(source['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if source['kind'] not in ('private-source-snapshot','verified-git-checkout') or source['gitBasis']!=manifest['sourceCommit'] or source['sha256']!=digest:
            raise ValueError('Artifact source snapshot identity is inconsistent')
    expected = manifest['payloadSha256']
    if set(records) != set(expected) | {MANIFEST} or any(records.get(name) != digest for name, digest in expected.items()):
        raise ValueError('Artifact bytes differ from payload inventory: '+path.name)
    if records['libexec/traverse/traverse-issuer'] != manifest['certificateIssuer']['build']['binarySha256']:
        raise ValueError('Packaged issuer differs from verified build')
    if 'hostUi' in manifest:
        ui=manifest['hostUi']
        if ui['executable']!='libexec/traverse/traverse-host' or ui['entry']!='bin/traverse-host' or \
                records.get(ui['executable'])!=ui['build']['binarySha256'] or ui['entry'] not in records:
            raise ValueError('Packaged native host differs from checked system UI build')
        if any(Path(name).name.startswith(('libQt5','libQt6')) for name in records):
            raise ValueError('Distribution Qt must not enter the private media payload')
        if path.suffix in ('.deb','.rpm') and links.get('usr/bin/traverse-host') not in ('/opt/traverse/bin/traverse-host','../../opt/traverse/bin/traverse-host'):
            raise ValueError('Native host package entry is absent or points elsewhere')
        if path.suffix=='.deb':
            actual=subprocess.check_output(['dpkg-deb','-f',str(path),'Depends'],text=True)
            required=re.split(r',\s*',ui['build']['debianDepends'])+ui['platformPackages']['deb']
            if any(value.strip() not in actual for value in required):raise ValueError('DEB omits system UI dependencies')
        elif path.suffix=='.rpm':
            actual=set(subprocess.check_output(['rpm','-qp','--requires',str(path)],text=True).splitlines())
            if not set(ui['build']['rpmRequires']+ui['platformPackages']['rpm']).issubset(actual):
                raise ValueError('RPM omits system UI dependencies')
    return {'artifact': path.name, 'verifiedPayloadFiles': len(expected), 'sourceCommit': manifest['sourceCommit']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    paths = sorted(args.directory.glob('*.deb')) + sorted(args.directory.glob('*.rpm'))
    paths += sorted(p for p in args.directory.glob('traverse-*.tar.gz') if not p.name.endswith('-third-party-sources.tar.gz'))
    if len(paths) != 3:
        raise ValueError('Expected one DEB, RPM and portable artifact')
    print(json.dumps({'artifactPayloads': [verify(path) for path in paths]}))


if __name__ == '__main__':
    main()
