#!/usr/bin/env bash
# Installed-package Chrome check on a disposable CI VM. No client/system trust changes.
set -euo pipefail
test "$(id -u)" -eq 0
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
evidence="$root/.work/installed-chrome"
test -x /usr/bin/google-chrome-stable
test -x /usr/bin/traverse-host
mkdir -p "$evidence"
original_mnt=$(readlink /proc/self/ns/mnt)
original_net=$(readlink /proc/self/ns/net)
original_pid=$(readlink /proc/self/ns/pid)
export TRAVERSE_TEST_ORIGINAL_MNT_NS="$original_mnt"
export TRAVERSE_TEST_ORIGINAL_NET_NS="$original_net"
export TRAVERSE_TEST_ORIGINAL_PID_NS="$original_pid"
timeout --signal=TERM --kill-after=15s 300s unshare --mount --net --pid --ipc --fork --kill-child=TERM \
    /bin/bash -s -- "$root" "$evidence" <<'CHECK'
set -euo pipefail
root="$1";evidence="$2"
test "$(readlink /proc/self/ns/mnt)" != "$TRAVERSE_TEST_ORIGINAL_MNT_NS"
test "$(readlink /proc/self/ns/net)" != "$TRAVERSE_TEST_ORIGINAL_NET_NS"
mount --make-rprivate /
mount -t proc proc /proc
mount -t tmpfs -o mode=0755 tmpfs /run
mkdir /run/traverse-original-etc
mount --bind /etc /run/traverse-original-etc
mount -o remount,bind,ro /run/traverse-original-etc
mount -t tmpfs -o mode=0755 tmpfs /etc
cp -a /run/traverse-original-etc/. /etc/
# The copied resolver can point into the host's now-hidden /run. Only this
# namespace-owned copy is replaced; DNS below is synthetic and private.
if test -L /etc/resolv.conf; then unlink /etc/resolv.conf; fi
printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
mount -t tmpfs -o mode=1777 tmpfs /tmp
mount -t tmpfs -o mode=1777 tmpfs /dev/shm
mount -t tmpfs -o mode=0755 tmpfs /var/log
# Give the unprivileged diagnostic broker a read-only source path independent
# of the runner account's home-directory permissions.
mkdir /run/traverse-test-source
mount --bind "$root" /run/traverse-test-source
mount -o remount,bind,ro /run/traverse-test-source
ip link set lo up
ip link add traverse-test0 type dummy
ip addr add 192.0.2.2/24 dev traverse-test0
ip link set traverse-test0 up
printf 1024 > /proc/sys/net/ipv4/ip_unprivileged_port_start
gcc "$root/tests/x11_input_probe.c" -o /tmp/x11-probe -lX11 -lXtst
mkdir /tmp/host-system-tools
for tool in readlink dirname basename mkdir uname; do
    ln -s "$(command -v "$tool")" "/tmp/host-system-tools/$tool"
done
export PYTHONPATH=/run/traverse-test-source/tests TRAVERSE_TEST_HOST_EXECUTABLE=/usr/bin/traverse-host
export TRAVERSE_TEST_HOST_PACKAGED_ENTRY=1 TRAVERSE_TEST_HOST_TOOL_PATH=/tmp/host-system-tools
export TRAVERSE_TEST_CHROME_INITIAL_PORT=443 TRAVERSE_TEST_RESOURCE_TRACE=1
export TRAVERSE_TEST_STARTUP_REPLAY=1
export TRAVERSE_TEST_EVIDENCE="$evidence" QT_SCALE_FACTOR=1 PYTHONDONTWRITEBYTECODE=1
xvfb-run -a -s '-screen 0 1280x1024x24' python3 /run/traverse-test-source/tests/setup_export_chrome.py
python3 - "$evidence/fresh-export-summary.json" <<'VERIFY'
import json,sys
from pathlib import Path
report=json.loads(Path(sys.argv[1]).read_text())
assert report['status']=='passed' and report['packagedEntry']
assert report['sourceVideoSize']=={'width':1280,'height':1024}
VERIFY
CHECK
