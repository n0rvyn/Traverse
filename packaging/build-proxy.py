"""Build an optional gateway from an owned copy of the operator's Caddy source.

No installation, service change, certificate access or public CA request.
The Linux test binaries must pass on the target before the candidate is used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess

ROOT = Path(__file__).resolve().parent.parent
MODULE = 'github.com/n0rvyn/Traverse/packaging/proxy'
LAYER4 = 'v0.0.0-20251001194302-2e3e6cf60b25'


def command(arguments, directory, environment, capture=False):
    process = subprocess.Popen([str(value) for value in arguments], cwd=directory,
        env=environment, stdout=subprocess.PIPE if capture else None, text=capture,
        start_new_session=True)
    try:
        output, _ = process.communicate()
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, arguments)
        return output
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        raise


def tree_identity(root):
    rows = {}
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories if name not in ('vendor', '.git'))
        for name in list(directories):
            path = Path(current)/name
            if path.is_symlink():
                rows[str(path.relative_to(root))] = hashlib.sha256(os.readlink(path).encode()).hexdigest()
                directories.remove(name)
        for name in sorted(files):
            path = Path(current)/name
            value = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
            rows[str(path.relative_to(root))] = hashlib.sha256(value).hexdigest()
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--caddy-source', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--go', default='go')
    parser.add_argument('--architecture', choices=('amd64', 'arm64'), default='amd64')
    parser.add_argument('--version-label', default='traverse-proxy-candidate')
    args = parser.parse_args()
    source, work = args.caddy_source.resolve(), args.work.resolve()
    if work.exists() or work.is_relative_to(source):
        raise ValueError('Use a new owned work directory outside the input source')
    if not (source/'go.mod').read_text().startswith('module github.com/caddyserver/caddy/v2\n'):
        raise ValueError('Expected the operator-selected Caddy v2 source')
    if not args.version_label or any(character.isspace() for character in args.version_label):
        raise ValueError('Use a nonempty version label without whitespace')
    work.mkdir(parents=True)
    environment = dict(os.environ, GOTOOLCHAIN='local', GOWORK='off', GOENV='off',
        CGO_ENABLED='0', GOOS='linux', GOARCH=args.architecture, GOEXPERIMENT='nodwarf5',
        GOSUMDB='sum.golang.org', GOPROXY='https://proxy.golang.org,direct',
        GOCACHE=str(work/'go-cache'), GOPATH=str(work/'go-path'),
        GOMODCACHE=os.environ.get('GOMODCACHE', str(work/'modules')))
    for name in ('GOFLAGS', 'GONOSUMDB', 'GOPRIVATE', 'GONOPROXY'):
        environment.pop(name, None)
    version = command([args.go, 'env', 'GOVERSION'], ROOT, environment, True).strip()
    if not version.startswith('go1.27.'):
        raise ValueError('This matching gateway candidate requires Go1.27')
    original = tree_identity(source)
    prepared, plugin = work/'source', work/'plugin'
    shutil.copytree(source, prepared, symlinks=True, ignore=shutil.ignore_patterns('vendor', '.git'))
    shutil.copytree(ROOT/'packaging/proxy', plugin, ignore=shutil.ignore_patterns('.work'))
    entry = prepared/'cmd/caddy/main.go'
    text = entry.read_text()
    marker = '// plug in Caddy modules here'
    if text.count(marker) != 1:
        raise ValueError('Caddy entry point has no unambiguous module import location')
    imports = [MODULE, 'github.com/mholt/caddy-l4/layer4',
        'github.com/mholt/caddy-l4/modules/l4proxy',
        'github.com/mholt/caddy-l4/modules/l4regexp', 'github.com/mholt/caddy-l4/modules/l4tls']
    additions = ''.join('\n\t_ "'+name+'"' for name in imports if '"'+name+'"' not in text)
    entry.write_text(text.replace(marker, marker+additions, 1))
    shutil.copy2(plugin/'testdata/caddy_identity_test.go', prepared/'traverse_proxy_identity_test.go')
    run = lambda *values, capture=False: command([args.go, *values], prepared, environment, capture)
    run('mod', 'edit', '-require='+MODULE+'@v0.0.0', '-replace='+MODULE+'=../plugin',
        '-require=github.com/mholt/caddy-l4@'+LAYER4, '-require=golang.org/x/net@v0.59.0',
        '-godebug=default=go1.25')
    run('mod', 'tidy')
    run('mod', 'verify')
    run('test', '-mod=readonly', '-p', '1', '-c', '-o', work/'caddy-identity-test', '.')
    run('test', '-mod=readonly', '-p', '1', '-c', '-o', work/'probe-matcher-test', MODULE)
    run('build', '-mod=readonly', '-p', '1', '-trimpath', '-ldflags',
        '-X github.com/caddyserver/caddy/v2.CustomVersion='+args.version_label,
        '-o', work/'caddy', './cmd/caddy')
    metadata = run('version', '-m', work/'caddy', capture=True)
    (work/'build-info.txt').write_text(metadata)
    if tree_identity(source) != original:
        raise ValueError('Input Caddy source changed during the build')
    files = {name: hashlib.sha256((work/name).read_bytes()).hexdigest()
        for name in ('caddy', 'caddy-identity-test', 'probe-matcher-test', 'build-info.txt')}
    report = {'status': 'built; target test execution pending', 'goVersion': version,
        'architecture': args.architecture, 'sourceInputDigest': original,
        'sourceUnchanged': True, 'files': files, 'layer4Version': LAYER4,
        'http2BridgeVersion': 'v0.59.0', 'legacyRuntimeDefaults': 'go1.25',
        'sourceGoModSha256': hashlib.sha256((prepared/'go.mod').read_bytes()).hexdigest(),
        'sourceGoSumSha256': hashlib.sha256((prepared/'go.sum').read_bytes()).hexdigest(),
        'installedOrDeployed': False}
    (work/'build.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    def interrupted(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    main()
