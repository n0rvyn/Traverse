#!/usr/bin/env bash
# Real installed owner/native lifecycle; synthetic delay helper is never shipped.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d /tmp/traverse-owner-fixture-XXXXXX)
trap 'rm -rf "$fixture"' EXIT
chmod 0755 "$fixture"
gcc -O2 -Wall -Wextra -Werror "$root/tests/delayed_service_fixture.c" -o "$fixture/delayed-service"
export TRAVERSE_TEST_DELAYED_SERVICE="$fixture/delayed-service"
# This backend fixture needs no desktop geometry change. The existing managed
# certificate acceptance still uses its distribution's default Xvfb geometry.
xvfb-run -a -s '-screen 0 1280x1024x24' python3 "$root/tests/host_supervisor_test.py"
