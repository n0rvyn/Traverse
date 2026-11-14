#!/usr/bin/env bash
# Disposable Gentoo userland acceptance; host and ordinary Chrome keep separate UIDs.
set -euo pipefail
test "$(id -u)" -eq 0
source_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
prepare=0
if test "$#" -eq 1 && test "$1" = --prepare; then prepare=1; else test "$#" -eq 0; fi
evidence="$source_root/.work/gentoo-chrome"
mkdir -p "$evidence"
trial=/tmp/traverse-gentoo-ci
name=traverse-gentoo-ci
repository_name="$name-repository"
stage_image=gentoo/stage3@sha256:f0aca526f458cfca27604df37bfab668d311daeed77e08cb55ccbf20f70dde31
repository_image=gentoo/portage@sha256:95b5c08a2f5211054c8f093ab137b4f7154c76a82df5a2ae90a66641920bd65d
commit=$(git -C "$source_root" rev-parse HEAD)
if test "$prepare" -eq 1; then
# Fail on a pre-existing path rather than reuse or remove anything unknown.
mkdir -m 0755 "$trial"
repository_created=0; root_created=0
cleanup() {
    if test "$root_created" -eq 1; then docker rm -f "$name" >/dev/null 2>&1 || true; fi
    if test "$repository_created" -eq 1; then docker rm -f "$repository_name" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
timeout --signal=TERM --kill-after=15s 300s docker pull "$stage_image"
timeout --signal=TERM --kill-after=15s 300s docker pull "$repository_image"
docker create --name "$repository_name" "$repository_image" >/dev/null
repository_created=1
docker create --name "$name" --sysctl net.ipv4.ip_unprivileged_port_start=1024 "$stage_image" /bin/bash /tmp/prepare.sh >/dev/null
root_created=1
docker cp "$repository_name:/var/db/repos/gentoo" - | docker cp - "$name:/var/db/repos/"
git -C "$source_root" archive HEAD tests | docker cp - "$name:/tmp/"
cat > "$trial/prepare.sh" <<'PREPARE'
set -euo pipefail
mkdir -p /etc/portage/package.use /etc/portage/package.license
# Package policy applies only to this disposable Chrome test installation.
printf 'www-client/google-chrome google-chrome\n' > /etc/portage/package.license/traverse-test
printf 'dev-qt/qtbase X gui widgets dbus\nx11-base/xorg-server xvfb\ndev-libs/nss utils\n' > /etc/portage/package.use/traverse-test
# Runtime Qt must come from the signed binhost, never an unnoticed local build.
emerge --nospinner --getbinpkg --usepkgonly --binpkg-respect-use=y 'dev-qt/qtbase:6[X,gui,widgets,dbus]'
# Xvfb and browser observers are test prerequisites. Portage can build these
# when a matching binary is absent; package logs and installed USE are retained.
emerge --nospinner --getbinpkg --jobs=2 --load-average=2 \
    x11-base/xorg-server x11-misc/xvfb-run x11-apps/xauth x11-libs/libXtst \
    media-fonts/font-misc-misc dev-python/websocket-client 'dev-libs/nss[utils]' \
    sys-libs/libcap sys-apps/iproute2 www-client/google-chrome
test -x /usr/bin/Xvfb && test -x /usr/bin/xvfb-run
test -x /usr/bin/google-chrome-stable && test -x /usr/bin/certutil
python3 -c 'import websocket'
PYTHONPATH=/tmp/tests python3 - <<'CLIENT'
import grp,json,pwd
from chrome_fixture import ensure_client_identity,CLIENT_UID,CLIENT_GID
ensure_client_identity()
ensure_client_identity()  # Reopening the same prepared root is idempotent.
print(json.dumps({'fixtureClient':pwd.getpwuid(CLIENT_UID).pw_name,'uid':CLIENT_UID,
    'gid':CLIENT_GID,'group':grp.getgrgid(CLIENT_GID).gr_name}),flush=True)
CLIENT
PREPARE
docker cp "$trial/prepare.sh" "$name:/tmp/prepare.sh"
# A timeout reaches the EXIT trap, which stops only our named containers.
timeout --signal=TERM --kill-after=15s 3600s docker start --attach "$name"
test "$(docker inspect --format '{{.State.ExitCode}}' "$name")" -eq 0
docker export --output "$trial/rootfs.tar" "$name"
mkdir "$trial/root"
python3 - "$trial/rootfs.tar" "$trial/root" <<'EXTRACT'
import os, sys, tarfile
# Preserve image symlink semantics inside the future chroot without exposing
# absolute links to the runner during extraction. data_filter still rejects
# traversal, special files and links that escape the new root.
def confined(member, destination):
    # The journey supplies its own private device filesystem. Never restore
    # image device nodes, sockets or symlinks from this subtree on the runner.
    if member.name.startswith('dev/'):
        return None
    if member.issym() and member.linkname.startswith('/'):
        target=os.path.normpath(member.linkname).lstrip('/')
        member=member.replace(linkname=os.path.relpath(target, os.path.dirname(member.name) or '.'))
    return tarfile.data_filter(member, destination)
with tarfile.open(sys.argv[1]) as archive:
    archive.extractall(sys.argv[2], filter=confined)
EXTRACT
umask 077
printf '%s\n%s\n%s\n' "$stage_image" "$repository_image" "$commit" > "$trial/prepared"
exit 0
fi
python3 - "$trial" "$stage_image" "$repository_image" "$commit" <<'PREPARED'
import stat, sys
from pathlib import Path
trial=Path(sys.argv[1])
for path in (trial, trial/'root'):
    info=path.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_mode & 0o777==0o755
info=(trial/'prepared').lstat()
assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_mode & 0o777==0o600
assert (trial/'prepared').read_text().splitlines()==sys.argv[2:]
PREPARED
(cd "$source_root/dist" && sha256sum -c SHA256SUMS)
archives=("$source_root"/dist/traverse-*-x86_64.tar.gz)
test "${#archives[@]}" -eq 1 && test -f "${archives[0]}"
original_mnt=$(readlink /proc/self/ns/mnt)
original_net=$(readlink /proc/self/ns/net)
original_pid=$(readlink /proc/self/ns/pid)
export TRAVERSE_TEST_ORIGINAL_MNT_NS="$original_mnt"
export TRAVERSE_TEST_ORIGINAL_NET_NS="$original_net"
export TRAVERSE_TEST_ORIGINAL_PID_NS="$original_pid"
timeout --signal=TERM --kill-after=15s 300s unshare --mount --net --pid --ipc --fork --kill-child=KILL \
    /bin/bash -s -- "$trial/root" "$source_root/tests" "${archives[0]}" "$evidence" "$commit" "$stage_image" "$repository_image" <<'CHECK'
set -euo pipefail
root="$1"; tests="$2"; archive="$3"; evidence="$4"; commit="$5"; stage="$6"; repository="$7"
mount --make-rprivate /
for directory in run tmp dev; do
    mount -t tmpfs -o mode=0755 tmpfs "$root/$directory"
done
chmod 1777 "$root/tmp"
mount -t proc proc "$root/proc"
mount --bind /sys "$root/sys"
mount -o remount,bind,ro "$root/sys"
for spec in null:3 zero:5 random:8 urandom:9; do
    mknod -m 666 "$root/dev/${spec%:*}" c 1 "${spec#*:}"
done
mkdir "$root/dev/pts" "$root/dev/shm"
mount -t devpts -o newinstance,ptmxmode=0666,mode=620 devpts "$root/dev/pts"
mount -t tmpfs -o mode=1777 tmpfs "$root/dev/shm"
ln -s pts/ptmx "$root/dev/ptmx"
ln -s /proc/self/fd "$root/dev/fd"
mkdir -p "$root/run/traverse-test-source/tests" "$root/run/evidence"
mount --bind "$tests" "$root/run/traverse-test-source/tests"
mount -o remount,bind,ro "$root/run/traverse-test-source/tests"
mount --bind "$evidence" "$root/run/evidence"
cp "$archive" "$root/run/package.tar.gz"
ip link set lo up
ip link add traverse-test0 type dummy
ip addr add 192.0.2.2/24 dev traverse-test0
ip link set traverse-test0 up
printf 1024 > /proc/sys/net/ipv4/ip_unprivileged_port_start
# Replace only the disposable image resolver, never the runner's /etc.
if test -L "$root/etc/resolv.conf"; then unlink "$root/etc/resolv.conf"; fi
printf 'nameserver 127.0.0.1\n' > "$root/etc/resolv.conf"
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8 \
    EXPECTED_COMMIT="$commit" STAGE_IMAGE="$stage" REPOSITORY_IMAGE="$repository" \
    TRAVERSE_TEST_ORIGINAL_MNT_NS="$TRAVERSE_TEST_ORIGINAL_MNT_NS" \
    TRAVERSE_TEST_ORIGINAL_NET_NS="$TRAVERSE_TEST_ORIGINAL_NET_NS" \
    TRAVERSE_TEST_ORIGINAL_PID_NS="$TRAVERSE_TEST_ORIGINAL_PID_NS" \
    chroot "$root" /bin/bash -s <<'GENTOO'
set -euo pipefail
python3 - <<'INSTALL'
import hashlib, json, os, tarfile
from pathlib import Path
with tarfile.open('/run/package.tar.gz') as archive:
    archive.extractall('/opt', filter='data')
prefix=Path('/opt/traverse')
manifest=json.loads((prefix/'share/traverse/runtime-manifest.json').read_text())
assert manifest['sourceCommit']==os.environ['EXPECTED_COMMIT']
for name, sha in manifest['payloadSha256'].items():
    assert hashlib.sha256((prefix/name).read_bytes()).hexdigest()==sha, name
assert hashlib.sha256((prefix/manifest['hostUi']['executable']).read_bytes()).hexdigest()==manifest['hostUi']['build']['binarySha256']
Path('/usr/bin/traverse-host').symlink_to(prefix/'bin/traverse-host')
# Safe public metadata only. CPVs/USE distinguish this userland from its kernel.
packages={}
for atom in ('dev-qt/qtbase', 'www-client/google-chrome', 'x11-base/xorg-server'):
    matches=list(Path('/var/db/pkg').glob(atom+'-*'))
    assert matches, atom
    for path in matches: packages[str(path.relative_to('/var/db/pkg'))]=(path/'USE').read_text().split()
assert any('gui' in use and 'widgets' in use and 'dbus' in use for key,use in packages.items() if key.startswith('dev-qt/qtbase-'))
Path('/run/evidence/gentoo-install-summary.json').write_text(json.dumps({
    'sourceCommit':manifest['sourceCommit'], 'payloadHashesChecked':True,
    'userland':Path('/etc/gentoo-release').read_text().strip(), 'kernel':os.uname().release,
    'stageImage':os.environ['STAGE_IMAGE'], 'repositoryImage':os.environ['REPOSITORY_IMAGE'],
    'packages':packages, 'scope':'Gentoo userland on disposable CI kernel; synthetic X11, no physical or GNOME/KDE acceptance'
},indent=2)+'\n')
INSTALL
/opt/traverse/libexec/traverse/configure-runtime
setcap cap_net_bind_service=ep /opt/traverse/libexec/traverse/traverse-bind-helper
test "$(getcap /opt/traverse/libexec/traverse/traverse-bind-helper)" = '/opt/traverse/libexec/traverse/traverse-bind-helper cap_net_bind_service=ep'
test -z "$(getcap /opt/traverse/libexec/traverse/traverse-host)"
# Preserve the standard Chrome sandbox installation metadata stripped by the
# safe archive filter. This is an owned, disposable package installation.
test -f /opt/google/chrome/chrome-sandbox
chown root:root /opt/google/chrome/chrome-sandbox
chmod 4755 /opt/google/chrome/chrome-sandbox
gcc /run/traverse-test-source/tests/x11_input_probe.c -o /tmp/x11-probe -lX11 -lXtst
mkdir /tmp/host-system-tools
for tool in readlink dirname basename mkdir uname; do
    ln -s "$(command -v "$tool")" "/tmp/host-system-tools/$tool"
done
python3 - <<'IDENTITY'
import json, subprocess
probe='''import os,socket
assert os.getuid()==65533 and os.getgid()==65533 and os.getgroups()==[]
assert int(next(x.split(':')[1] for x in open('/proc/self/status') if x.startswith('CapEff:')),16)==0
s=socket.socket()
try:s.bind(('127.0.0.1',443))
except PermissionError:pass
else:raise AssertionError('Ordinary Chrome UID bound protected443')
'''
subprocess.run(['/usr/bin/python3','-c',probe],user=65533,group=65533,extra_groups=[],check=True)
print(json.dumps({'clientUid':65533,'clientGroupsEmpty':True,'clientCapabilitiesZero':True,'protected443Rejected':True}),flush=True)
IDENTITY
export PYTHONPATH=/run/traverse-test-source/tests PYTHONDONTWRITEBYTECODE=1
export TRAVERSE_TEST_HOST_EXECUTABLE=/usr/bin/traverse-host TRAVERSE_TEST_HOST_PACKAGED_ENTRY=1
export TRAVERSE_TEST_HOST_TOOL_PATH=/tmp/host-system-tools TRAVERSE_TEST_CHROME_INITIAL_PORT=443
export TRAVERSE_TEST_EVIDENCE=/run/evidence QT_SCALE_FACTOR=1
xvfb-run -a -s '-screen 0 1280x1024x24' python3 /run/traverse-test-source/tests/setup_export_chrome.py
python3 - <<'VERIFY'
import json
from pathlib import Path
value=json.loads(Path('/run/evidence/fresh-export-summary.json').read_text())
assert value['status']=='passed' and value['packagedEntry']
assert value['sourceVideoSize']=={'width':1280,'height':1024}
assert value['pausedPresentationStoppedReceiptsWithoutDisconnect']
assert value['resumedPresentationAdvancedSameGeneration']
assert value['nativePeerState']['peerActive'] and value['nativePeerState']['controlOpen']
assert value['nativePeerState']['rtcState']=='connected'
assert value['nativePeerState']['health']['status']=='observed'
assert value['nativePeerState']['health']['generation']==value['nativePeerState']['generation']
VERIFY
GENTOO
CHECK
