#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates xvfb xauth xfonts-base gcc libc6-dev libx11-dev libxtst-dev python3 openssl curl
apt-get install -y /src/dist/*.deb
traverse --check-runtime
python3 /src/tests/installed_turn.py
python3 /src/tests/bind_helper_test.py
apt-get install -y --reinstall /src/dist/*.deb
test "$(getcap /opt/traverse/libexec/traverse/traverse-bind-helper)" = '/opt/traverse/libexec/traverse/traverse-bind-helper cap_net_bind_service=ep'
test "$(stat -c '%u:%g:%a' /opt/traverse/share/traverse/registry.bin)" = '0:0:644'
mkdir -p /tmp/relocated
archive=$(find /src/dist -maxdepth 1 -name "traverse-*-$(uname -m).tar.gz" -print -quit)
tar -xf "$archive" -C /tmp/relocated
/tmp/relocated/traverse/bin/traverse --check-runtime
python3 /src/tests/installed_turn.py /tmp/relocated/traverse
# The TURN executable is required even when host packages provide another server.
mv /tmp/relocated/traverse/libexec/traverse/turnserver /tmp/relocated/traverse/libexec/traverse/turnserver.missing
if /tmp/relocated/traverse/bin/traverse --check-runtime; then
  echo 'Missing private TURN executable incorrectly passed runtime checks' >&2; exit 1
fi
mv /tmp/relocated/traverse/libexec/traverse/turnserver.missing /tmp/relocated/traverse/libexec/traverse/turnserver
# Missing a dynamically loaded crypto provider must fail even if host NSS is installed.
mv /tmp/relocated/traverse/lib/libsoftokn3.so /tmp/relocated/traverse/lib/libsoftokn3.so.missing
if /tmp/relocated/traverse/bin/traverse --check-runtime; then
  echo 'Incomplete crypto payload incorrectly passed runtime checks' >&2; exit 1
fi
mv /tmp/relocated/traverse/lib/libsoftokn3.so.missing /tmp/relocated/traverse/lib/libsoftokn3.so
/tmp/relocated/traverse/bin/traverse --check-runtime
# The default adapter must show its real Stop sharing dialog, and release on local activation.
gcc /src/tests/x11_input_probe.c -o /tmp/x11-probe -lX11 -lXtst
xvfb-run -a python3 /src/tests/desktop_fixture_test.py
xvfb-run -a python3 /src/tests/installed_dialog.py
xvfb-run -a python3 /src/tests/installed_launcher.py
xvfb-run -a python3 /src/tests/installed_standalone.py
xvfb-run -a -s '-screen 0 1280x800x24 -extension XTEST' python3 /src/tests/installed_guardian_startup.py
apt-get remove -y traverse
test ! -e /opt/traverse/libexec/traverse/traverse-service
test ! -e /opt/traverse/share/traverse/registry.bin
