#!/usr/bin/env bash
set -euo pipefail
dnf install -y python3 openssl util-linux xorg-x11-server-Xvfb xorg-x11-fonts-misc gcc libX11-devel libXtst-devel /src/dist/*.rpm
traverse --check-runtime
python3 /src/tests/installed_turn.py
setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs python3 /src/tests/installed_issuer.py
python3 /src/tests/bind_helper_test.py
dnf reinstall -y /src/dist/*.rpm
test "$(getcap /opt/traverse/libexec/traverse/traverse-bind-helper)" = '/opt/traverse/libexec/traverse/traverse-bind-helper cap_net_bind_service=ep'
test "$(stat -c '%u:%g:%a' /opt/traverse/share/traverse/registry.bin)" = '0:0:644'
rpm -V traverse
gcc /src/tests/x11_input_probe.c -o /tmp/x11-probe -lX11 -lXtst
gcc /src/tests/x11_capture.c -o /tmp/x11-capture -lX11
export TRAVERSE_TEST_FAILURE_ARTIFACTS=/src/.work/managed-failure-images
xvfb-run -a python3 /src/tests/installed_managed_certificates.py
dnf remove -y traverse
test ! -e /opt/traverse/libexec/traverse/traverse-service
test ! -e /opt/traverse/share/traverse/registry.bin
