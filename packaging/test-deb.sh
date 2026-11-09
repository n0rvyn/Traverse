#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends ca-certificates xvfb xauth xfonts-base gcc libc6-dev libx11-dev libxtst-dev python3 openssl curl
apt-get install -y /src/dist/*.deb
traverse --check-runtime
mkdir -p /tmp/relocated
archive=$(find /src/dist -maxdepth 1 -name "traverse-*-$(uname -m).tar.gz" -print -quit)
tar -xf "$archive" -C /tmp/relocated
/tmp/relocated/traverse/bin/traverse --check-runtime
# Missing a dynamically loaded crypto provider must fail even if host NSS is installed.
mv /tmp/relocated/traverse/lib/libsoftokn3.so /tmp/relocated/traverse/lib/libsoftokn3.so.missing
if /tmp/relocated/traverse/bin/traverse --check-runtime; then
  echo 'Incomplete crypto payload incorrectly passed runtime checks' >&2; exit 1
fi
mv /tmp/relocated/traverse/lib/libsoftokn3.so.missing /tmp/relocated/traverse/lib/libsoftokn3.so
/tmp/relocated/traverse/bin/traverse --check-runtime
# The default adapter must show its real Stop sharing dialog, and release on local activation.
gcc /src/tests/x11_input_probe.c -o /tmp/x11-probe -lX11 -lXtst
xvfb-run -a python3 /src/tests/installed_dialog.py
xvfb-run -a python3 /src/tests/installed_launcher.py
apt-get remove -y traverse
test ! -e /opt/traverse/libexec/traverse/traverse-service
