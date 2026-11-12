#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates xvfb xauth xfonts-base gcc libc6-dev libx11-dev libxtst-dev python3 python3-gi dbus openssl curl util-linux
apt-get install -y /src/dist/*.deb
export TRAVERSE_EXPECTED_RUNTIME_MANIFEST="${TRAVERSE_BUILD_WORK:-/src/.work}/stage/opt/traverse/share/traverse/runtime-manifest.json"
traverse --check-runtime
python3 /src/tests/installed_wayland_controller.py
python3 /src/tests/installed_turn.py
setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs python3 /src/tests/installed_issuer.py
python3 /src/tests/bind_helper_test.py
apt-get install -y --reinstall /src/dist/*.deb
test "$(getcap /opt/traverse/libexec/traverse/traverse-bind-helper)" = '/opt/traverse/libexec/traverse/traverse-bind-helper cap_net_bind_service=ep'
test "$(stat -c '%u:%g:%a' /opt/traverse/share/traverse/registry.bin)" = '0:0:644'
mkdir -p /tmp/relocated
archive=$(find /src/dist -maxdepth 1 -name "traverse-*-$(uname -m).tar.gz" -print -quit)
tar -xf "$archive" -C /tmp/relocated
/tmp/relocated/traverse/bin/traverse --check-runtime
python3 /src/tests/installed_wayland_controller.py /tmp/relocated/traverse
mv /tmp/relocated/traverse/lib/libei.so.1 /tmp/relocated/traverse/lib/libei.so.1.missing
if /tmp/relocated/traverse/bin/traverse --check-runtime; then
  mv /tmp/relocated/traverse/lib/libei.so.1.missing /tmp/relocated/traverse/lib/libei.so.1
  echo 'Missing private Wayland client incorrectly passed runtime checks' >&2; exit 1
fi
mv /tmp/relocated/traverse/lib/libei.so.1.missing /tmp/relocated/traverse/lib/libei.so.1
python3 /src/tests/installed_turn.py /tmp/relocated/traverse
setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs python3 /src/tests/installed_issuer.py /tmp/relocated/traverse
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
gcc /src/tests/x11_capture.c -o /tmp/x11-capture -lX11
gcc -shared -fPIC -Wall -Wextra -Werror /src/tests/launcher_probe_cancel.c -o /tmp/connect_cancel.so -ldl
test -z "$(getcap /opt/traverse/libexec/traverse/traverse-host)"
TRAVERSE_TEST_PRESERVE_HOST_DATA=/tmp/traverse-preserved-host-data xvfb-run -a python3 /src/tests/installed_host_window.py
python3 /src/tests/installed_host_persistence.py record /tmp/traverse-preserved-host-data /tmp/traverse-host-owner-snapshot.json
TRAVERSE_TEST_SETUP_PORTS='[9443]' xvfb-run -a python3 /src/tests/installed_host_window.py /tmp/relocated/traverse
python3 /src/tests/readiness_observer_test.py --prefix /opt/traverse
python3 /src/tests/readiness_service_test.py --prefix /opt/traverse --agent /opt/traverse/libexec/traverse/traverse-readiness-agent
xvfb-run -a python3 /src/tests/installed_readiness.py
xvfb-run -a python3 /src/tests/installed_host_url_check.py
xvfb-run -a python3 /src/tests/installed_local_certificates.py
TRAVERSE_TEST_PREFIX=/tmp/relocated/traverse TRAVERSE_TEST_APP_PORT=9443 xvfb-run -a python3 /src/tests/installed_local_certificates.py
export TRAVERSE_TEST_FAILURE_ARTIFACTS=/src/.work/managed-failure-images
xvfb-run -a python3 /src/tests/desktop_fixture_test.py
xvfb-run -a python3 /src/tests/installed_dialog.py
xvfb-run -a python3 /src/tests/installed_launcher.py
xvfb-run -a python3 /src/tests/installed_standalone.py
bash /src/packaging/test-host-owner.sh
xvfb-run -a python3 /src/tests/installed_startup_cancel.py
xvfb-run -a python3 /src/tests/installed_managed_certificates.py
xvfb-run -a -s '-screen 0 1280x800x24 -extension XTEST' python3 /src/tests/installed_guardian_startup.py
apt-get remove -y traverse
python3 /src/tests/installed_host_persistence.py check /tmp/traverse-preserved-host-data /tmp/traverse-host-owner-snapshot.json
apt-get install -y /src/dist/*.deb
python3 /src/tests/installed_host_persistence.py check /tmp/traverse-preserved-host-data /tmp/traverse-host-owner-snapshot.json
apt-get remove -y traverse
python3 /src/tests/installed_host_persistence.py check /tmp/traverse-preserved-host-data /tmp/traverse-host-owner-snapshot.json
test ! -e /opt/traverse/libexec/traverse/traverse-service
test ! -e /opt/traverse/share/traverse/registry.bin
