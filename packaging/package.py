"""Assemble the private ELF closure and create native DEB/RPM/portable artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

ROOT=Path(__file__).resolve().parent.parent
GLIBC_LIBS={'libc.so.6','libm.so.6','libpthread.so.0','libdl.so.2','librt.so.1','libresolv.so.2','libutil.so.1'}


def version_from_cmake(text):
    match=re.search(r'project\(traverse VERSION (\d+\.\d+\.\d+)\b',text)
    if not match:raise ValueError('Missing semantic project version')
    return match.group(1)


def validate_version(value):
    if not re.fullmatch(r'\d+\.\d+\.\d+',value):raise ValueError('Invalid release version')
    return value


def is_elf(path):
    return path.is_file() and path.open('rb').read(4)==b'\x7fELF'


def glibc_versions(text):
    return [tuple(map(int,m.split('.'))) for m in re.findall(r'\bGLIBC_(\d+(?:\.\d+)+)\b',text)]


def validate_abi(text, maximum):
    versions=glibc_versions(text)
    if versions and max(versions)>tuple(map(int,maximum.split('.'))):
        raise ValueError('ELF requires glibc newer than '+maximum)


def run(args,**kwargs):return subprocess.check_output([str(x) for x in args],text=True,**kwargs)


def collect_dependencies(elf, libdir, env, origins=None):
    output=run(['ldd',elf],env=env)
    if 'not found' in output:raise ValueError('Unresolved ELF dependency: '+str(elf)+'\n'+output)
    copied=[]
    for line in output.splitlines():
        match=re.match(r'\s*(\S+) => (/\S+) ',line)
        if not match:continue
        name,source=match.groups()
        if origins is not None:origins.add(source)
        if name in GLIBC_LIBS or name.startswith('ld-linux'):continue
        destination=libdir/name
        if destination.exists():
            if hashlib.sha256(destination.read_bytes()).digest()!=hashlib.sha256(Path(source).read_bytes()).digest():
                raise ValueError('Conflicting runtime library: '+name)
        else:
            shutil.copy2(source,destination);copied.append(destination)
    return copied


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--stage',type=Path,required=True);parser.add_argument('--runtime',type=Path,required=True);parser.add_argument('--sources',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();stage=args.stage.resolve();runtime=args.runtime.resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
    prefix=stage/'opt/traverse';libdir=prefix/'lib';libdir.mkdir(parents=True,exist_ok=True)
    manifest=json.loads((ROOT/'packaging/runtime-manifest.json').read_text())
    version=validate_version(version_from_cmake((ROOT/'native/CMakeLists.txt').read_text()))
    architecture=run(['uname','-m']).strip()
    arch={'x86_64':('amd64','x86_64'),'aarch64':('arm64','aarch64')}.get(architecture)
    if not arch:raise ValueError('Unsupported build architecture '+architecture)
    helpers=prefix/'libexec/traverse';helpers.mkdir(parents=True,exist_ok=True)
    shutil.copy2('/usr/bin/xmessage',helpers/'xmessage')
    scanner=runtime/'libexec/gstreamer-1.0/gst-plugin-scanner'
    scanner_dest=prefix/'libexec/gstreamer-1.0/gst-plugin-scanner';scanner_dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(scanner,scanner_dest)
    plugins=libdir/'gstreamer-1.0';plugins.mkdir()
    for source in (runtime/'lib/gstreamer-1.0').glob('*.so'):
        shutil.copy2(source,plugins/source.name)
    env=dict(os.environ,LD_LIBRARY_PATH=str(runtime/'lib'))
    pending=[p for p in prefix.rglob('*') if is_elf(p)];seen=set();origins=set()
    while pending:
        elf=pending.pop()
        if elf in seen:continue
        seen.add(elf)
        pending.extend(collect_dependencies(elf,libdir,env,origins))
    # Remove build-directory RUNPATHs only after dependency resolution.
    for elf in seen:
        validate_abi(run(['readelf','--version-info',elf]),manifest['baseline']['glibc_max'])
        subprocess.run(['patchelf','--remove-rpath',str(elf)],check=True)
    bindir=prefix/'bin';bindir.mkdir()
    entry=(ROOT/'packaging/runtime-entry.sh').read_text().replace('@VERSION@',version)
    for name in ['traverse','traverse-adapter','traverse-service','traverse-runtime-check']:
        path=bindir/name;path.write_text(entry);path.chmod(0o755)
    links=stage/'usr/bin';links.mkdir(parents=True)
    for name in ['traverse','traverse-adapter','traverse-service']:
        (links/name).symlink_to('/opt/traverse/bin/'+name)
    notices=prefix/'share/traverse/licenses';notices.mkdir(parents=True)
    for source in args.sources.iterdir():
        if source.is_dir():
            target=notices/source.name;target.mkdir()
            for pattern in ['COPYING*','LICENSE*','NOTICE*']:
                for file in source.glob(pattern):
                    if file.is_file():shutil.copy2(file,target/file.name)
    # Include notices for the distribution-provided runtime libraries/executable.
    packages=set()
    for source in sorted(origins):
        if Path(source).is_relative_to(runtime):continue
        try:
            for line in run(['dpkg-query','-S',source],stderr=subprocess.DEVNULL).splitlines():
                packages.add(line.rsplit(': ',1)[0])
        except subprocess.CalledProcessError:
            raise ValueError('Cannot identify source/notice owner for '+source)
    packages.add('x11-utils')
    for package in sorted(packages):
        source=Path('/usr/share/doc')/package.split(':')[0]/'copyright'
        if source.is_file():shutil.copy2(source,notices/(package.replace(':','-')+'.copyright'))
    manifest.update(version=version,architecture=architecture,sourceCommit=run(['git','-c','safe.directory='+str(ROOT),'-C',ROOT,'rev-parse','HEAD']).strip(),baselineImage=os.environ.get('BUILD_BASE_IMAGE','ubuntu:22.04'),distributionPackages=run(['dpkg-query','-W','-f=${Package}=${Version}\n']).splitlines())
    manifest['payloadSha256']={str(p.relative_to(prefix)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(prefix.rglob('*')) if p.is_file()}
    (prefix/'share/traverse/runtime-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    shutil.copy2(ROOT/'patches/libnice-0.1.24-passive-tcp-reuse.patch',prefix/'share/traverse/libnice.patch')
    run([bindir/'traverse','--check-runtime'])
    epoch=int(os.environ['SOURCE_DATE_EPOCH'])
    def normalize(info):
        info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=epoch;info.pax_headers={};return info
    portable=out/f'traverse-{version}-{architecture}.tar.gz'
    # gzip timestamps are controlled explicitly for repeatable archive output.
    import gzip
    with portable.open('wb') as raw, gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=epoch) as compressed, tarfile.open(fileobj=compressed,mode='w') as archive:
        archive.add(prefix,arcname='traverse',filter=normalize)
    control=stage/'DEBIAN';control.mkdir()
    (control/'control').write_text(f'Package: traverse\nVersion: {version}\nArchitecture: {arch[0]}\nMaintainer: Traverse project\nDepends: libc6 (>= 2.35), ca-certificates\nDescription: Native existing-session Linux desktop sharing in Chrome\n')
    subprocess.run(['dpkg-deb','--root-owner-group','--build',str(stage),str(out/f'traverse_{version}_{arch[0]}.deb')],check=True)
    shutil.rmtree(control)
    rpmroot=out/'rpm-build';rpmroot.mkdir()
    spec=rpmroot/'traverse.spec'
    spec.write_text(f'''Name: traverse
Version: {version}
Release: 1
Summary: Native existing-session Linux desktop sharing in Chrome
License: LicenseRef-Not-Specified
BuildArch: {arch[1]}
AutoReqProv: no
Requires: glibc >= 2.35, ca-certificates
%description
Native existing-session Linux desktop sharing. Project license not yet selected.
%install
mkdir -p %{{buildroot}}
cp -a {stage}/opt {stage}/usr %{{buildroot}}/
%files
/opt/traverse
/usr/bin/traverse
/usr/bin/traverse-adapter
/usr/bin/traverse-service
''')
    subprocess.run(['rpmbuild','-bb','--define','_topdir '+str(rpmroot),'--define','_build_id_links none',str(spec)],check=True)
    for rpm in (rpmroot/'RPMS').rglob('*.rpm'):shutil.copy2(rpm,out/rpm.name)
    # Download corresponding distribution source archives, including distribution patches.
    distro_sources=args.sources/'distribution-sources';distro_sources.mkdir()
    source_packages=set()
    for package in sorted(packages):
        source_packages.add(run(['dpkg-query','-W','-f=${source:Package}=${source:Version}',package]).strip())
    for source_package in sorted(source_packages):
        subprocess.run(['apt-get','source','--download-only','--only-source',source_package],cwd=distro_sources,check=True)
    # Ship exact pinned/distribution source archives and modified-library patch/build recipe.
    with tarfile.open(out/f'traverse-{version}-{architecture}-third-party-sources.tar.gz','w:gz') as archive:
        for file in sorted(args.sources.iterdir()):
            if file.is_file():archive.add(file,arcname=file.name,filter=normalize)
            elif file.name=='distribution-sources':archive.add(file,arcname=file.name,filter=normalize)
        for file in [ROOT/'patches/libnice-0.1.24-passive-tcp-reuse.patch',ROOT/'packaging/build-runtime.sh',ROOT/'packaging/runtime-manifest.json']:
            archive.add(file,arcname=file.name,filter=normalize)
    artifacts=[p for p in out.iterdir() if p.is_file() and p.name!='SHA256SUMS']
    (out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(artifacts)))
    print(json.dumps({'version':version,'artifacts':[p.name for p in artifacts]},indent=2))


if __name__=='__main__':main()
