"""Pinned build-only Go toolchain and static cold issuer; no host installation."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import runpy
import shutil
import subprocess
import tarfile

ROOT=Path(__file__).resolve().parent.parent
safe_extract=runpy.run_path(str(ROOT/'packaging/fetch-sources.py'))['safe_extract']


def command(arguments,**options):
    return subprocess.check_output([str(a) for a in arguments],text=True,timeout=600,**options)


def download(entry,path):
    path.parent.mkdir(parents=True,exist_ok=True)
    if not path.exists():
        temporary=path.with_suffix(path.suffix+'.partial')
        try:
            subprocess.run(['curl','--fail','--location','--connect-timeout','20','--max-time','300',
                            '--retry','3','--retry-all-errors','--output',str(temporary),entry['url']],check=True,timeout=1250)
            if hashlib.sha256(temporary.read_bytes()).hexdigest()!=entry['sha256']:
                raise ValueError('Issuer build download digest mismatch')
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)
    if hashlib.sha256(path.read_bytes()).hexdigest()!=entry['sha256']:
        raise ValueError('Issuer build cache digest mismatch')


def json_stream(text):
    decoder=json.JSONDecoder();position=0
    while position<len(text):
        while position<len(text) and text[position].isspace():position+=1
        if position==len(text):break
        value,position=decoder.raw_decode(text,position);yield value


def normalize(info,epoch):
    info.uid=info.gid=0;info.uname=info.gname='root';info.mtime=epoch;info.pax_headers={}
    return info


def archive_tree(source,path,epoch):
    with path.open('wb') as raw,gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=epoch) as compressed,tarfile.open(fileobj=compressed,mode='w') as archive:
        archive.add(source,arcname='certificate-issuer',filter=lambda item:normalize(item,epoch))


def copy_notices(source,destination):
    destination.mkdir(parents=True,exist_ok=True)
    found=False
    for pattern in ('LICENSE*','COPYING*','NOTICE*','PATENTS*'):
        for file in source.glob(pattern):
            if file.is_file():
                shutil.copy2(file,destination/file.name);(destination/file.name).chmod(0o644);found=True
    if not found:raise ValueError('Missing issuer dependency license notice')


def build_private_test_ca(go,tools,policy,environment):
    test_policy=policy['privateTestCA']
    test_source=tools/'private-ca';test_source.mkdir()
    (test_source/'go.mod').write_text('module traverse.local/private-ca\n\ngo '+policy['goVersion']+'\n')
    record=json.loads(command([go,'mod','download','-json',test_policy['module']+'@'+test_policy['version']],cwd=test_source,env=environment))
    if record.get('Sum')!=test_policy['sum'] or record.get('GoModSum')!=test_policy['goModSum']:
        raise ValueError('Private CA test source checksum mismatch')
    # The pinned CA's zero-percent setting otherwise still reuses a valid
    # authorization on draw0. Keep real fresh-validation assertions strict.
    # Patch only a fresh owned copy, never the verified module cache.
    patched_source=tools/'private-ca-source'
    shutil.copytree(record['Dir'],patched_source,copy_function=shutil.copyfile)
    for directory in [patched_source,*[p for p in patched_source.rglob('*') if p.is_dir()]]:
        directory.chmod((directory.stat().st_mode&0o777)|0o200)
    ca_patch=ROOT/'patches/pebble-v2.10.1-authz-reuse-percent.patch'
    command(['patch','--forward','-p1','-i',ca_patch],cwd=patched_source,env=environment)
    command([go,'build','-mod=readonly','-buildvcs=false','-trimpath','-o',tools/'pebble','./cmd/pebble'],cwd=patched_source,env=environment)
    private_ca_build={'module':test_policy['module'],'version':test_policy['version'],
                      'originalModuleSum':record['Sum'],'originalGoModSum':record['GoModSum'],
                      'patchSha256':hashlib.sha256(ca_patch.read_bytes()).hexdigest(),
                      'binarySha256':hashlib.sha256((tools/'pebble').read_bytes()).hexdigest(),
                      'runtimeInstalled':False}
    return private_ca_build


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work',type=Path,required=True)
    parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--sources',type=Path,required=True)
    parser.add_argument('--test-ca',action='store_true',help='Build the pinned private CA fixture, never part of runtime')
    parser.add_argument('--test-ca-only',action='store_true',help='Build only the pinned private CA for exact-package reproduction; leave the runtime stage unchanged')
    args=parser.parse_args()
    work=args.work.resolve();stage=args.stage.resolve();sources=args.sources.resolve()
    policy=json.loads((ROOT/'packaging/runtime-manifest.json').read_text())['certificateIssuer']
    architecture=platform.machine();go_arch={'x86_64':'amd64','aarch64':'arm64'}.get(architecture)
    if go_arch is None:raise ValueError('Unsupported issuer build architecture')
    tools=work/'issuer-tools';tools.mkdir(parents=True,exist_ok=True)
    archive=tools/('go'+policy['goVersion']+'-'+architecture+'.tar.gz')
    download(policy['toolchains'][architecture],archive)
    toolchain=tools/'go'
    if toolchain.exists():raise ValueError('Refusing to reuse an extracted issuer toolchain')
    safe_extract(archive,tools)
    go=toolchain/'bin/go'
    configuration=work/'issuer-config';telemetry=configuration/'go/telemetry'
    telemetry.mkdir(parents=True,exist_ok=True);(telemetry/'mode').write_text('off\n')
    environment=dict(os.environ,GOROOT=str(toolchain),GOTOOLCHAIN='local',GOWORK='off',GOMAXPROCS='2',
                     XDG_CONFIG_HOME=str(configuration),
                     GOCACHE=str(work/'issuer-go-cache'),GOMODCACHE=str(work/'issuer-go-modules'),
                     GOPATH=str(work/'issuer-go-path'),GOSUMDB='sum.golang.org',CGO_ENABLED='0',GOOS='linux',GOARCH=go_arch)
    # All module bytes remain authenticated against the committed sums/policy.
    for name in ('GOFLAGS','GONOSUMDB','GOPRIVATE','GONOPROXY'):
        environment.pop(name,None)
    environment['GOPROXY']='https://proxy.golang.org,direct'
    if command([go,'env','GOVERSION'],env=environment).strip()!='go'+policy['goVersion']:
        raise ValueError('Issuer toolchain version mismatch')
    if args.test_ca_only:
        metadata=build_private_test_ca(go,tools,policy,environment)
        metadata['goVersion']=policy['goVersion']
        (work/'private-ca-build.json').write_text(json.dumps(metadata,indent=2)+'\n')
        return
    source=work/'issuer-source'
    if source.exists():raise ValueError('Refusing to reuse an issuer source tree')
    shutil.copytree(ROOT/'issuer',source,ignore=shutil.ignore_patterns('vendor','._*','__pycache__'))
    # Project licensing remains an owner decision; dependency notices are copied below.
    before={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in ('go.mod','go.sum')}
    for module in policy['modules']:
        record=json.loads(command([go,'mod','download','-json',module['path']+'@'+module['version']],cwd=source,env=environment))
        if record.get('Sum')!=module['sum'] or record.get('GoModSum')!=module['goModSum']:
            raise ValueError('Issuer module checksum policy mismatch')
    command([go,'mod','vendor'],cwd=source,env=environment)
    if before!={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in before}:
        raise ValueError('Issuer build changed locked module metadata')
    packages=list(json_stream(command([go,'list','-buildvcs=false','-mod=vendor','-deps','-json','./cmd/traverse-issuer'],cwd=source,env=environment)))
    actual={(p['Module']['Path'],p['Module']['Version']) for p in packages if p.get('Module') and not p['Module'].get('Main')}
    expected={(m['path'],m['version']) for m in policy['modules']}
    if actual!=expected:raise ValueError('Issuer compiled module closure differs from declared policy')
    # Tests run with the same declared compiler. Installed artifacts need no Go.
    print(command([go,'test','-buildvcs=false','-mod=vendor','./...'],cwd=source,env=environment),end='')
    destination=stage/'opt/traverse/libexec/traverse/traverse-issuer'
    destination.parent.mkdir(parents=True,exist_ok=True)
    command([go,'build','-mod=vendor','-buildvcs=false','-trimpath','-ldflags=-s -w','-o',destination,'./cmd/traverse-issuer'],cwd=source,env=environment)
    destination.chmod(0o755)
    headers=command(['readelf','-lW',destination]);dynamic=command(['readelf','-dW',destination])
    if 'INTERP' in headers or '(NEEDED)' in dynamic:raise ValueError('Issuer is not a standalone static executable')
    notices=stage/'opt/traverse/share/traverse/licenses/certificate-issuer'
    copy_notices(toolchain,notices/'go')
    # Keep the standard library's vendored notices as well as its root license.
    for file in (toolchain/'src/vendor').rglob('*'):
        if file.is_file() and any(file.name.startswith(name) for name in ('LICENSE','COPYING','NOTICE','PATENTS')):
            target=notices/'go-vendor'/file.relative_to(toolchain/'src/vendor');target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(file,target);target.chmod(0o644)
    for module in policy['modules']:
        copy_notices(source/'vendor'/module['path'],notices/'modules'/module['path'])
    sources.mkdir(parents=True,exist_ok=True)
    download(policy['goSources'],sources/('go'+policy['goVersion']+'.src.tar.gz'))
    epoch=int(os.environ['SOURCE_DATE_EPOCH'])
    archive_tree(source,sources/'certificate-issuer-sources.tar.gz',epoch)
    metadata={'goVersion':policy['goVersion'],'toolchainSha256':policy['toolchains'][architecture]['sha256'],
              'goSourceSha256':policy['goSources']['sha256'],'modules':policy['modules'],
              'sourceArchiveSha256':hashlib.sha256((sources/'certificate-issuer-sources.tar.gz').read_bytes()).hexdigest(),
              'binarySha256':hashlib.sha256(destination.read_bytes()).hexdigest(),'cgoEnabled':False,'static':True}
    (work/'issuer-build.json').write_text(json.dumps(metadata,indent=2)+'\n')
    private_ca_build=None
    if args.test_ca:
        private_ca_build=build_private_test_ca(go,tools,policy,environment)
        (work/'private-ca-build.json').write_text(json.dumps(private_ca_build,indent=2)+'\n')
    print(json.dumps({'issuerBuild':metadata,'architecture':architecture,'privateTestCA':private_ca_build}))


if __name__=='__main__':main()
