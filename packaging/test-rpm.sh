#!/usr/bin/env bash
set -euo pipefail
dnf install -y python3 /src/dist/*.rpm
traverse --check-runtime
python3 /src/tests/installed_turn.py
rpm -V traverse
dnf remove -y traverse
test ! -e /opt/traverse/libexec/traverse/traverse-service
