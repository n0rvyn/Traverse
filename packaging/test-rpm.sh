#!/usr/bin/env bash
set -euo pipefail
dnf install -y /src/dist/*.rpm
traverse --check-runtime
rpm -V traverse
dnf remove -y traverse
test ! -e /opt/traverse/libexec/traverse/traverse-service
