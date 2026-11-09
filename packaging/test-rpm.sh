#!/usr/bin/env bash
set -euo pipefail
dnf install -y python3 /src/dist/*.rpm
traverse --check-runtime
python3 /src/tests/installed_turn.py
python3 /src/tests/bind_helper_test.py
dnf reinstall -y /src/dist/*.rpm
test "$(getcap /opt/traverse/libexec/traverse/traverse-bind-helper)" = '/opt/traverse/libexec/traverse/traverse-bind-helper cap_net_bind_service=ep'
test "$(stat -c '%u:%g:%a' /opt/traverse/share/traverse/registry.bin)" = '0:0:644'
rpm -V traverse
dnf remove -y traverse
test ! -e /opt/traverse/libexec/traverse/traverse-service
test ! -e /opt/traverse/share/traverse/registry.bin
