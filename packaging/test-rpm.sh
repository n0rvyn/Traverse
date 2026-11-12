#!/usr/bin/env bash
set -euo pipefail
dnf install -y python3 python3-gobject dbus-daemon openssl util-linux xorg-x11-server-Xvfb xorg-x11-fonts-misc gcc libX11-devel libXtst-devel /src/dist/*.rpm
export TRAVERSE_EXPECTED_RUNTIME_MANIFEST="${TRAVERSE_BUILD_WORK:-/src/.work}/stage/opt/traverse/share/traverse/runtime-manifest.json"
traverse --check-runtime
python3 /src/tests/installed_wayland_controller.py
python3 /src/tests/installed_turn.py
setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs python3 /src/tests/installed_issuer.py
python3 /src/tests/bind_helper_test.py
dnf reinstall -y /src/dist/*.rpm
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
TRAVERSE_TEST_APP_PORT=9443 xvfb-run -a python3 /src/tests/installed_local_certificates.py
export TRAVERSE_TEST_FAILURE_ARTIFACTS=/src/.work/managed-failure-images
bash /src/packaging/test-host-owner.sh
xvfb-run -a python3 /src/tests/installed_startup_cancel.py
xvfb-run -a python3 /src/tests/installed_managed_certificates.py
dnf remove -y traverse
python3 /src/tests/installed_host_persistence.py check /tmp/traverse-preserved-host-data /tmp/traverse-host-owner-snapshot.json
dnf install -y /src/dist/*.rpm
python3 /src/tests/installed_host_persistence.py check /tmp/traverse-preserved-host-data /tmp/traverse-host-owner-snapshot.json
dnf remove -y traverse
python3 /src/tests/installed_host_persistence.py check /tmp/traverse-preserved-host-data /tmp/traverse-host-owner-snapshot.json
test ! -e /opt/traverse/libexec/traverse/traverse-service
test ! -e /opt/traverse/share/traverse/registry.bin
