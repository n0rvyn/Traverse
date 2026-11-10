"""Assemble the private ELF closure and create native DEB/RPM/portable artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
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


def static_executable(elf):
    """Classify actual headers; never hide a failing dynamic dependency query."""
    header=run(['readelf','-hW',elf])
    program=run(['readelf','-lW',elf])
    dynamic=run(['readelf','-dW',elf])
    entry=re.search(r'Entry point address:\s*(0x[0-9a-fA-F]+)',header)
    return (bool(re.search(r'Type:\s+EXEC\b',header)) and entry is not None and int(entry.group(1),16)!=0
            and not re.search(r'^\s*INTERP\s',program,re.M) and '(NEEDED)' not in dynamic)


def validate_elf_architecture(elf,architecture):
    with Path(elf).open('rb') as source:header=source.read(20)
    machine={'x86_64':62,'aarch64':183}.get(architecture)
    if len(header)!=20 or header[:6]!=b'\x7fELF\x02\x01' or machine is None or int.from_bytes(header[18:20],'little')!=machine:
        raise ValueError('ELF does not match declared package architecture: '+str(elf))


def collect_dependencies(elf, libdir, env, origins=None):
    if static_executable(elf):return []
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


def distribution_owners(source):
    # Ubuntu's merged-/usr loader paths and dpkg paths can name the same file differently.
    original=Path(source)
    candidates=[original,original.resolve()]
    for path in list(candidates):
        value=str(path)
        for before,after in [('/lib/','/usr/lib/'),('/usr/lib/','/lib/'),('/bin/','/usr/bin/'),('/usr/bin/','/bin/')]:
            if value.startswith(before):candidates.append(Path(after+value[len(before):]))
    for candidate in dict.fromkeys(candidates):
        if not candidate.exists() or not os.path.samefile(original,candidate):continue
        try:
            return {line.rsplit(': ',1)[0] for line in run(['dpkg-query','-S',candidate],stderr=subprocess.DEVNULL).splitlines()}
        except subprocess.CalledProcessError:pass
    raise ValueError('Cannot identify source/notice owner for '+str(source))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--stage',type=Path,required=True);parser.add_argument('--runtime',type=Path,required=True);parser.add_argument('--sources',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--issuer-build',type=Path,required=True)
    args=parser.parse_args();stage=args.stage.resolve();runtime=args.runtime.resolve();out=args.output.resolve();out.mkdir(parents=True,exist_ok=True)
    prefix=stage/'opt/traverse';libdir=prefix/'lib';libdir.mkdir(parents=True,exist_ok=True)
    manifest=json.loads((ROOT/'packaging/runtime-manifest.json').read_text())
    issuer_build=json.loads(args.issuer_build.read_text())
    issuer_binary=prefix/'libexec/traverse/traverse-issuer'
    if issuer_build['binarySha256']!=hashlib.sha256(issuer_binary.read_bytes()).hexdigest():
        raise ValueError('Issuer build identity differs from staged executable')
    manifest['certificateIssuer']['build']=issuer_build
    version=validate_version(version_from_cmake((ROOT/'native/CMakeLists.txt').read_text()))
    architecture=run(['uname','-m']).strip()
    arch={'x86_64':('amd64','x86_64'),'aarch64':('arm64','aarch64')}.get(architecture)
    if not arch:raise ValueError('Unsupported build architecture '+architecture)
    helpers=prefix/'libexec/traverse';helpers.mkdir(parents=True,exist_ok=True)
    shutil.copy2('/usr/bin/xmessage',helpers/'xmessage')
    shutil.copy2(runtime/'bin/turnserver',helpers/'turnserver')
    shutil.copy2(ROOT/'packaging/configure-runtime.sh',helpers/'configure-runtime')
    (helpers/'configure-runtime').chmod(0o755)
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
    # NSS loads its providers with dlopen: they are not in DT_NEEDED/ldd output.
    # Keep paired .so/.chk bytes intact; mutation would break provider integrity checks.
    preserved=set();provider_assets=[]
    for provider in manifest.get('dynamic_provider_packages',[]):
        if not (libdir/provider['trigger']).exists():continue
        candidates=[Path(p).resolve().parent/provider['subdirectory'] for p in origins if Path(p).name==provider['trigger']]
        candidates=[p for p in candidates if p.is_dir()]
        if len(set(candidates))!=1:raise ValueError('Cannot locate matching provider directory: '+provider['trigger'])
        directory=candidates[0]
        for required in provider['required']:
            if not (directory/required).is_file():raise ValueError('Missing required provider: '+required)
        for pattern in provider['patterns']:
            for file in sorted(directory.glob(pattern)):
                target=libdir/file.name
                if target.exists() and target.read_bytes()!=file.read_bytes():raise ValueError('Provider name collision: '+file.name)
                shutil.copy2(file,target);origins.add(str(file))
                provider_assets.append(str(target.relative_to(prefix)))
                if is_elf(target):pending.append(target);preserved.add(target)
        while pending:
            elf=pending.pop()
            if elf in seen:continue
            seen.add(elf);pending.extend(collect_dependencies(elf,libdir,env,origins))
    manifest['dynamicProviderAssets']=sorted(provider_assets)
    # Remove build-directory RUNPATHs only after dependency resolution, never from
    # integrity-checked provider binaries paired with vendor .chk files.
    for elf in seen:
        validate_elf_architecture(elf,architecture)
        validate_abi(run(['readelf','--version-info',elf]),manifest['baseline']['glibc_max'])
        if elf not in preserved and not static_executable(elf):subprocess.run(['patchelf','--remove-rpath',str(elf)],check=True)
    bindir=prefix/'bin';bindir.mkdir()
    entry=(ROOT/'packaging/runtime-entry.sh').read_text().replace('@VERSION@',version)
    for name in ['traverse','traverse-adapter','traverse-service','traverse-runtime-check']:
        path=bindir/name;path.write_text(entry);path.chmod(0o755)
    links=stage/'usr/bin';links.mkdir(parents=True)
    for name in ['traverse','traverse-adapter','traverse-service']:
        (links/name).symlink_to('/opt/traverse/bin/'+name)
    notices=prefix/'share/traverse/licenses';notices.mkdir(parents=True,exist_ok=True)
    for source in args.sources.iterdir():
        if source.is_dir():
            target=notices/source.name;target.mkdir()
            for pattern in ['COPYING*','LICENSE*','NOTICE*']:
                for file in source.glob(pattern):
                    if file.is_file():
                        shutil.copy2(file,target/file.name)
                        # Upstream source notices can be group-writable (0664).
                        # Installed runtime files must satisfy the helper trust policy.
                        (target/file.name).chmod(0o644)
    # Include notices for the distribution-provided runtime libraries/executable.
    packages=set()
    for source in sorted(origins):
        if Path(source).is_relative_to(runtime):continue
        packages.update(distribution_owners(source))
    packages.add('x11-utils')
    packages.add('nlohmann-json3-dev') # Header-only code also needs its distribution notice/source identity.
    for package in sorted(packages):
        source=Path('/usr/share/doc')/package.split(':')[0]/'copyright'
        if source.is_file():shutil.copy2(source,notices/(package.replace(':','-')+'.copyright'))
    manifest.update(version=version,architecture=architecture,sourceCommit=os.environ.get('SOURCE_COMMIT') or run(['git','-c','safe.directory='+str(ROOT),'-C',ROOT,'rev-parse','HEAD']).strip(),baselineImage=os.environ.get('BUILD_BASE_IMAGE','ubuntu:22.04'),distributionPackages=run(['dpkg-query','-W','-f=${Package}=${Version}\n']).splitlines())
    if not re.fullmatch(r'[a-f0-9]{40}',manifest['sourceCommit']):raise ValueError('Invalid source commit identity')
    shutil.copy2(ROOT/'patches/libnice-0.1.24-passive-tcp-reuse.patch',prefix/'share/traverse/libnice.patch')
    manifest['payloadSha256']={str(p.relative_to(prefix)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(prefix.rglob('*')) if p.is_file()}
    (prefix/'share/traverse/runtime-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
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
    (control/'control').write_text(f'Package: traverse\nVersion: {version}\nArchitecture: {arch[0]}\nMaintainer: Traverse project\nDepends: libc6 (>= 2.35), ca-certificates, libcap2-bin\nDescription: Native existing-session Linux desktop sharing in Chrome\n')
    for action in ['postinst','postrm']:
        shutil.copy2(ROOT/f'packaging/deb-{action}.sh',control/action)
        (control/action).chmod(0o755)
    subprocess.run(['dpkg-deb','--root-owner-group','--build',str(stage),str(out/f'traverse_{version}_{arch[0]}.deb')],check=True)
    shutil.rmtree(control)
    rpmroot=out/'rpm-build';rpmroot.mkdir()
    spec=rpmroot/'traverse.spec'
    rpm_files=[]
    for path in sorted(prefix.rglob('*')):
        attribute='%dir ' if path.is_dir() else '%caps(cap_net_bind_service=ep) ' if path==helpers/'traverse-bind-helper' else ''
        rpm_files.append(attribute+'/'+str(path.relative_to(stage)))
    rpm_files.insert(0,'%dir /opt/traverse')
    rpm_files.append('%ghost %attr(0644,root,root) /opt/traverse/share/traverse/registry.bin')
    # This is a preassembled private runtime. RPM's generic stripping/compression
    # would invalidate payload hashes and the NSS providers' paired checksums.
    spec.write_text(f'''%global __os_install_post %{{nil}}
%global debug_package %{{nil}}
Name: traverse
Version: {version}
Release: 1
Summary: Native existing-session Linux desktop sharing in Chrome
License: LicenseRef-Not-Specified
BuildArch: {arch[1]}
AutoReqProv: no
Requires: glibc >= 2.35, ca-certificates, libcap
%description
Native existing-session Linux desktop sharing. Project license not yet selected.
%install
mkdir -p %{{buildroot}}
cp -a {stage}/opt {stage}/usr %{{buildroot}}/
%post
/opt/traverse/libexec/traverse/configure-runtime
%postun
if [ "$1" = 0 ]; then rm -f /opt/traverse/share/traverse/registry.bin; fi
%files
{chr(10).join(rpm_files)}
/usr/bin/traverse
/usr/bin/traverse-adapter
/usr/bin/traverse-service
''')
    subprocess.run(['rpmbuild','-bb','--define','_topdir '+str(rpmroot),'--define','_build_id_links none','--define','_buildhost traverse-builder',str(spec)],check=True)
    for rpm in (rpmroot/'RPMS').rglob('*.rpm'):shutil.copy2(rpm,out/rpm.name)
    subprocess.run([sys.executable,ROOT/'tests/artifact_payload.py',out],check=True)
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
        for file in [ROOT/'patches/libnice-0.1.24-passive-tcp-reuse.patch',ROOT/'patches/pebble-v2.10.1-authz-reuse-percent.patch',ROOT/'packaging/build-runtime.sh',ROOT/'packaging/build-issuer.py',ROOT/'packaging/fetch-sources.py',ROOT/'packaging/runtime-manifest.json',args.issuer_build]:
            archive.add(file,arcname=file.name,filter=normalize)
    artifacts=[p for p in out.iterdir() if p.is_file() and p.name!='SHA256SUMS']
    (out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n' for p in sorted(artifacts)))
    print(json.dumps({'version':version,'artifacts':[p.name for p in artifacts]},indent=2))


if __name__=='__main__':main()
