#!/usr/bin/env bash
set -euo pipefail
# Reinstall the same dependency payload even if a mirror rotates during tests.
# This cache exists only inside the disposable package-test container.
dnf_command=(dnf --setopt=keepcache=True)
app_repositories=()
test_repositories=()
# Repository definitions and enablement are confined to this disposable test.
# The application itself must resolve without development repositories.
source /etc/os-release
if [[ "$ID" == almalinux && "${VERSION_ID%%.*}" == 10 ]]; then
  app_repositories=(--disablerepo='*' --enablerepo=baseos --enablerepo=appstream --enablerepo=extras)
  test_repositories=("${app_repositories[@]}" --enablerepo=crb --enablerepo=devel)
fi
"${dnf_command[@]}" "${app_repositories[@]}" install -y /src/dist/*.rpm
export TRAVERSE_EXPECTED_RUNTIME_MANIFEST="${TRAVERSE_BUILD_WORK:-/src/.work}/stage/opt/traverse/share/traverse/runtime-manifest.json"
traverse --check-runtime
if [[ "$ID" == almalinux && "${VERSION_ID%%.*}" == 10 ]]; then
  "${dnf_command[@]}" "${app_repositories[@]}" install -y almalinux-release-devel
fi
"${dnf_command[@]}" "${test_repositories[@]}" install -y python3 python3-gobject dbus-daemon openssl util-linux xorg-x11-server-Xvfb xorg-x11-fonts-misc gcc libX11-devel libXtst-devel
if [[ -n "${TRAVERSE_TEST_SETUP_EVIDENCE:-}" ]]; then
  test "${TRAVERSE_TEST_SETUP_EVIDENCE:0:1}" = /
  test ! -e "$TRAVERSE_TEST_SETUP_EVIDENCE"
  test ! -L "$TRAVERSE_TEST_SETUP_EVIDENCE"
  mkdir "$TRAVERSE_TEST_SETUP_EVIDENCE"
  python3 - <<'PY'
import json,os,shlex,subprocess
from pathlib import Path
manifest=json.loads(Path('/opt/traverse/share/traverse/runtime-manifest.json').read_text())
release={}
for line in Path('/etc/os-release').read_text().splitlines():
    key,separator,value=line.partition('=')
    if separator and key in ('ID','VERSION_ID','PRETTY_NAME'):release[key]=shlex.split(value)[0]
versions=subprocess.run(['rpm','-q','--qf','%{NAME} %{VERSION}-%{RELEASE}.%{ARCH}\n',
    'glibc','qt6-qtbase','qt6-qtbase-gui','qt6-qtwayland','xorg-x11-server-Xvfb'],check=True,text=True,capture_output=True).stdout.splitlines()
Path(os.environ['TRAVERSE_TEST_SETUP_EVIDENCE'],'summary.json').write_text(json.dumps({
    'status':'pending','sourceCommit':manifest['sourceCommit'],'architecture':manifest['architecture'],
    'baseImage':os.environ['TRAVERSE_TEST_RPM_BASE_IMAGE'],'userland':release,'kernel':os.uname().release,
    'packages':versions,'appRuntimeCheckedBeforeTestTools':True,
    'appRepositories':['baseos','appstream','extras'] if release['ID']=='almalinux' else 'distribution defaults',
    'scope':'Installed RPM and synthetic X11 userland; no normal GNOME/KDE or physical acceptance'
},indent=2)+'\n')
PY
fi
python3 /src/tests/installed_wayland_controller.py
python3 /src/tests/installed_turn.py
setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs python3 /src/tests/installed_issuer.py
python3 /src/tests/bind_helper_test.py
"${dnf_command[@]}" "${app_repositories[@]}" reinstall -y /src/dist/*.rpm
test "$(getcap /opt/traverse/libexec/traverse/traverse-bind-helper)" = '/opt/traverse/libexec/traverse/traverse-bind-helper cap_net_bind_service=ep'
test "$(stat -c '%u:%g:%a' /opt/traverse/share/traverse/registry.bin)" = '0:0:644'
rpm -V traverse
gcc /src/tests/x11_input_probe.c -o /tmp/x11-probe -lX11 -lXtst
gcc /src/tests/x11_capture.c -o /tmp/x11-capture -lX11
gcc -shared -fPIC -Wall -Wextra -Werror /src/tests/launcher_probe_cancel.c -o /tmp/connect_cancel.so -ldl
test -z "$(getcap /opt/traverse/libexec/traverse/traverse-host)"
TRAVERSE_TEST_PRESERVE_HOST_DATA=/tmp/traverse-preserved-host-data xvfb-run -a python3 /src/tests/installed_host_window.py
python3 /src/tests/installed_host_persistence.py record /tmp/traverse-preserved-host-data /tmp/traverse-host-owner-snapshot.json
python3 /src/tests/readiness_observer_test.py --prefix /opt/traverse
python3 /src/tests/readiness_service_test.py --prefix /opt/traverse --agent /opt/traverse/libexec/traverse/traverse-readiness-agent
xvfb-run -a python3 /src/tests/installed_readiness.py
xvfb-run -a python3 /src/tests/installed_host_url_check.py
xvfb-run -a python3 /src/tests/installed_local_certificates.py
TRAVERSE_TEST_LISTEN_PORT=18443 xvfb-run -a python3 /src/tests/installed_local_certificates.py
TRAVERSE_TEST_APP_PORT=9443 xvfb-run -a python3 /src/tests/installed_local_certificates.py
export TRAVERSE_TEST_FAILURE_ARTIFACTS=/src/.work/managed-failure-images
bash /src/packaging/test-host-owner.sh
xvfb-run -a python3 /src/tests/installed_startup_cancel.py
xvfb-run -a python3 /src/tests/installed_managed_certificates.py
"${dnf_command[@]}" "${app_repositories[@]}" remove -y traverse
python3 /src/tests/installed_host_persistence.py check /tmp/traverse-preserved-host-data /tmp/traverse-host-owner-snapshot.json
"${dnf_command[@]}" "${app_repositories[@]}" install -y /src/dist/*.rpm
python3 /src/tests/installed_host_persistence.py check /tmp/traverse-preserved-host-data /tmp/traverse-host-owner-snapshot.json
"${dnf_command[@]}" "${app_repositories[@]}" remove -y traverse
python3 /src/tests/installed_host_persistence.py check /tmp/traverse-preserved-host-data /tmp/traverse-host-owner-snapshot.json
test ! -e /opt/traverse/libexec/traverse/traverse-service
test ! -e /opt/traverse/share/traverse/registry.bin
if [[ -n "${TRAVERSE_TEST_SETUP_EVIDENCE:-}" ]]; then
  python3 - <<'PY'
import json,os
from pathlib import Path
path=Path(os.environ['TRAVERSE_TEST_SETUP_EVIDENCE'],'summary.json')
value=json.loads(path.read_text())
for name in ('default-port-fresh-setup.ppm','certificate-method-focused.ppm'):
    image=path.parent/name
    assert image.is_file() and image.stat().st_size>0
value.update(status='passed',fullRpmLifecycle=True,ownerDataPreservedAfterReinstallAndRemoval=True,
    installedPayloadRemoved=True,safePreStartRenders=True)
path.write_text(json.dumps(value,indent=2)+'\n')
PY
fi
